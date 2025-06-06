/**
 * @file dns.c
 * @brief Cross-platform asynchronous DNS resolver implementation
 *
 * This file implements a cross-platform asynchronous DNS resolver that uses
 * platform-specific APIs for optimal performance:
 * - Windows: GetAddrInfoExW with OVERLAPPED I/O
 * - Linux: getaddrinfo_a with signalfd and atomic request management
 * - macOS: libinfo.dylib async functions with Mach ports
 * - Generic: Fallback synchronous implementation
 */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "dns.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma region Platform Detection and Headers

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define PLATFORM_WINDOWS
#elif defined(__linux__)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>
#define PLATFORM_LINUX
#elif defined(__APPLE__)
#include <arpa/inet.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define PLATFORM_MACOS
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#define PLATFORM_GENERIC
#endif

#pragma endregion

#pragma region Internal Structures

/**
 * @brief Internal DNS request structure
 *
 * Contains platform-specific data and common request information.
 * Each platform uses different fields within the union for async operations.
 */
struct dns_request {
  dns_resolver_t *resolver; /**< Parent resolver instance */
  char *hostname;           /**< Hostname to resolve (owned) */
  char *service;            /**< Service/port string (owned, optional) */
  dns_callback_t callback;  /**< User callback function */
  void *user_data;          /**< User-provided data for callback */
  _Atomic(bool)
      cancelled; /**< Request cancellation flag (atomic for thread safety) */
  _Atomic(bool) completed; /**< Completion flag */
#ifdef PLATFORM_WINDOWS
  OVERLAPPED overlapped; /**< Windows OVERLAPPED structure */
  ADDRINFOEXW *result;   /**< Windows result structure */
  HANDLE cancel_handle;  /**< Windows cancellation handle */
#elif defined(PLATFORM_LINUX)
  struct gaicb gaicb;       /**< Linux async getaddrinfo control block */
  struct addrinfo hints;    /**< Linux address hints */
  struct sigevent sigevent; /**< Linux signal event for completion */
#elif defined(PLATFORM_MACOS)
  mach_port_t machport; /**< macOS Mach port for async operations */
#else
  dns_result_t *stored_result; /**< Generic stored result */
#endif

  struct dns_request *next; /**< Next request in linked list */
};

/**
 * @brief Internal DNS resolver structure
 *
 * Contains configuration, active requests, and platform-specific state.
 */
struct dns_resolver {
  dns_config_t config;             /**< Resolver configuration */
  dns_request_t *pending_requests; /**< Linked list of pending requests */
  _Atomic(int) active_count;       /**< Number of active requests (atomic) */

#ifdef PLATFORM_LINUX
  int signal_fd;        /**< Linux signalfd for async notifications */
  sigset_t signal_mask; /**< Linux signal mask */
#elif defined(PLATFORM_MACOS)
  void *libinfo_handle; /**< macOS libinfo.dylib handle */

  int32_t (*getaddrinfo_async_start)(
      mach_port_t *port, const char *hostname, const char *servname,
      const struct addrinfo *hints,
      void (*callback)(int32_t, struct addrinfo *, void *), void *context);
  int32_t (*getaddrinfo_async_handle_reply)(void *reply);
  void (*getaddrinfo_async_cancel)(mach_port_t port);
#endif
};

#pragma endregion

#pragma region Platform-Specific Implementations

#ifdef PLATFORM_WINDOWS
#pragma region Windows Implementation

/**
 * @brief Convert Windows ADDRINFOEXW result to our DNS result format
 */
static dns_result_t *convert_windows_result(ADDRINFOEXW *ai,
                                            const char *hostname, int error) {
  dns_result_t *result = calloc(1, sizeof(dns_result_t));
  if (!result)
    return NULL;

  result->hostname = strdup(hostname);
  if (!result->hostname) {
    free(result);
    return NULL;
  }

  result->error_code = error;

  if (error != 0 || !ai) {
    return result;
  }

  size_t count = 0;
  for (ADDRINFOEXW *p = ai; p; p = p->ai_next) {
    count++;
  }

  result->addresses = malloc(count * sizeof(dns_address_t));
  if (!result->addresses) {
    dns_result_free(result);
    return NULL;
  }

  size_t index = 0;
  for (ADDRINFOEXW *p = ai; p && index < count; p = p->ai_next) {
    dns_address_t *addr = &result->addresses[index];

    addr->family = p->ai_family;
    addr->socktype = p->ai_socktype;
    addr->protocol = p->ai_protocol;

    wchar_t wide_address[46];
    DWORD addr_len = sizeof(wide_address) / sizeof(wchar_t);

    if (WSAAddressToStringW(p->ai_addr, (DWORD)p->ai_addrlen, NULL,
                            wide_address, &addr_len) == 0) {
      if (WideCharToMultiByte(CP_UTF8, 0, wide_address, -1, addr->address,
                              sizeof(addr->address), NULL, NULL) > 0) {
        index++;
      }
    }
  }

  result->count = index;
  return result;
}

/**
 * @brief Windows completion callback for GetAddrInfoExW
 */
static void WINAPI windows_completion_callback(DWORD error, DWORD bytes,
                                               LPOVERLAPPED overlapped) {
  (void)bytes;

  dns_request_t *request =
      (dns_request_t *)((char *)overlapped -
                        offsetof(dns_request_t, overlapped));

  if (atomic_load(&request->cancelled)) {
    if (request->result) {
      FreeAddrInfoExW(request->result);
      request->result = NULL;
    }
    return;
  }

  dns_result_t *result =
      convert_windows_result(request->result, request->hostname, error);

  if (request->callback && result) {
    request->callback(result, request->user_data);
  }

  dns_result_free(result);

  if (request->result) {
    FreeAddrInfoExW(request->result);
    request->result = NULL;
  }

  atomic_store(&request->completed, true);
}

static bool platform_init(dns_resolver_t *resolver) {
  (void)resolver;
  return true;
}

static void platform_cleanup(dns_resolver_t *resolver) { (void)resolver; }

static dns_request_t *platform_resolve_async(dns_request_t *request) {
  ADDRINFOEXW hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  size_t hostname_len = strlen(request->hostname);
  if (hostname_len > INT_MAX - 1) {
    return NULL;
  }

  wchar_t *wide_hostname = malloc((hostname_len + 1) * sizeof(wchar_t));
  if (!wide_hostname) {
    return NULL;
  }

  if (MultiByteToWideChar(CP_UTF8, 0, request->hostname, -1, wide_hostname,
                          (int)(hostname_len + 1)) == 0) {
    free(wide_hostname);
    return NULL;
  }

  wchar_t *wide_service = NULL;
  if (request->service) {
    size_t service_len = strlen(request->service);
    if (service_len > INT_MAX - 1) {
      free(wide_hostname);
      return NULL;
    }

    wide_service = malloc((service_len + 1) * sizeof(wchar_t));
    if (!wide_service) {
      free(wide_hostname);
      return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, request->service, -1, wide_service,
                            (int)(service_len + 1)) == 0) {
      free(wide_hostname);
      free(wide_service);
      return NULL;
    }
  }

  DWORD error =
      GetAddrInfoExW(wide_hostname, wide_service, NS_DNS, NULL, &hints,
                     &request->result, NULL, &request->overlapped,
                     windows_completion_callback, &request->cancel_handle);

  free(wide_hostname);
  free(wide_service);

  if (error != WSA_IO_PENDING && error != 0) {
    return NULL;
  }

  return request;
}

static void platform_cancel_request(dns_request_t *request) {
  if (request->cancel_handle) {
    GetAddrInfoExCancel(&request->cancel_handle);
  }
}

static void platform_process_events(dns_resolver_t *resolver) {
  dns_request_t *req = resolver->pending_requests;
  dns_request_t *prev = NULL;

  while (req) {
    if (atomic_load(&req->completed) || atomic_load(&req->cancelled)) {
      dns_request_t *next = req->next;

      if (prev) {
        prev->next = next;
      } else {
        resolver->pending_requests = next;
      }

      atomic_fetch_sub(&resolver->active_count, 1);

      free(req->hostname);
      free(req->service);
      free(req);

      req = next;
    } else {
      prev = req;
      req = req->next;
    }
  }
}

#pragma endregion
#endif

#ifdef PLATFORM_LINUX
#pragma region Linux Implementation

static dns_result_t *convert_linux_result(struct addrinfo *ai,
                                          const char *hostname, int error) {
  dns_result_t *result = calloc(1, sizeof(dns_result_t));
  if (!result)
    return NULL;

  result->hostname = strdup(hostname);
  if (!result->hostname) {
    free(result);
    return NULL;
  }

  result->error_code = error;

  if (error != 0 || !ai) {
    return result;
  }

  size_t count = 0;
  for (struct addrinfo *p = ai; p; p = p->ai_next) {
    count++;
  }

  result->addresses = malloc(count * sizeof(dns_address_t));
  if (!result->addresses) {
    dns_result_free(result);
    return NULL;
  }

  size_t index = 0;
  for (struct addrinfo *p = ai; p && index < count; p = p->ai_next) {
    dns_address_t *addr = &result->addresses[index];

    addr->family = p->ai_family;
    addr->socktype = p->ai_socktype;
    addr->protocol = p->ai_protocol;

    if (getnameinfo(p->ai_addr, p->ai_addrlen, addr->address,
                    sizeof(addr->address), NULL, 0, NI_NUMERICHOST) == 0) {
      index++;
    }
  }

  result->count = index;
  return result;
}

/**
 * @brief Find a DNS request by its gaicb pointer (atomic-safe)
 */
static dns_request_t *find_request_by_gaicb(dns_resolver_t *resolver,
                                            struct gaicb *gaicb) {
  if (!resolver || !gaicb) {
    return NULL;
  }

  dns_request_t *req = resolver->pending_requests;
  while (req) {
    if (&req->gaicb == gaicb && !atomic_load(&req->cancelled)) {
      return req;
    }
    req = req->next;
  }
  return NULL;
}

static bool init_linux_signals(dns_resolver_t *resolver) {
  sigemptyset(&resolver->signal_mask);
  sigaddset(&resolver->signal_mask, SIGRTMIN);

  if (sigprocmask(SIG_BLOCK, &resolver->signal_mask, NULL) == -1) {
    return false;
  }

  resolver->signal_fd =
      signalfd(-1, &resolver->signal_mask, SFD_NONBLOCK | SFD_CLOEXEC);
  return resolver->signal_fd != -1;
}

static bool platform_init(dns_resolver_t *resolver) {
  return init_linux_signals(resolver);
}

static void platform_cleanup(dns_resolver_t *resolver) {
  if (resolver->signal_fd != -1) {
    close(resolver->signal_fd);
    resolver->signal_fd = -1;
  }
}

static dns_request_t *platform_resolve_async(dns_request_t *request) {
  request->hints.ai_family = AF_UNSPEC;
  request->hints.ai_socktype = SOCK_STREAM;

  request->gaicb.ar_name = request->hostname;
  request->gaicb.ar_service = request->service;
  request->gaicb.ar_request = &request->hints;

  request->sigevent.sigev_notify = SIGEV_SIGNAL;
  request->sigevent.sigev_signo = SIGRTMIN;
  // Store the gaicb pointer in the signal value for identification
  request->sigevent.sigev_value.sival_ptr = &request->gaicb;

  struct gaicb *list[1] = {&request->gaicb};

  if (getaddrinfo_a(GAI_NOWAIT, list, 1, &request->sigevent) != 0) {
    return NULL;
  }

  return request;
}

static void platform_cancel_request(dns_request_t *request) {
  gai_cancel(&request->gaicb);
  atomic_store(&request->cancelled, true);
}

static void platform_process_events(dns_resolver_t *resolver) {
  struct signalfd_siginfo ssi;
  ssize_t bytes;

  while ((bytes = read(resolver->signal_fd, &ssi, sizeof(ssi))) > 0) {
    if (ssi.ssi_code == SI_ASYNCNL) {
      struct gaicb *gaicb = (struct gaicb *)ssi.ssi_ptr;

      dns_request_t *request = find_request_by_gaicb(resolver, gaicb);
      if (!request) {
        continue;
      }

      if (atomic_load(&request->cancelled)) {
        continue;
      }

      int error = gai_error(&request->gaicb);
      dns_result_t *result = convert_linux_result(request->gaicb.ar_result,
                                                  request->hostname, error);

      if (request->callback) {
        request->callback(result, request->user_data);
      }

      dns_result_free(result);

      if (request->gaicb.ar_result) {
        freeaddrinfo(request->gaicb.ar_result);
      }

      atomic_store(&request->completed, true);
    }
  }

  // Clean up completed/cancelled requests
  dns_request_t *req = resolver->pending_requests;
  dns_request_t *prev = NULL;

  while (req) {
    if (atomic_load(&req->completed) || atomic_load(&req->cancelled)) {
      dns_request_t *next = req->next;

      if (prev) {
        prev->next = next;
      } else {
        resolver->pending_requests = next;
      }

      atomic_fetch_sub(&resolver->active_count, 1);

      free(req->hostname);
      free(req->service);
      free(req);

      req = next;
    } else {
      prev = req;
      req = req->next;
    }
  }
}

#pragma endregion
#endif

#ifdef PLATFORM_MACOS
#pragma region macOS Implementation

typedef struct {
  mach_msg_header_t header;
  mach_msg_body_t body;
  char data[4096];
} mach_reply_msg_t;

static dns_result_t *convert_macos_result(struct addrinfo *ai,
                                          const char *hostname, int error) {
  dns_result_t *result = calloc(1, sizeof(dns_result_t));
  if (!result)
    return NULL;

  result->hostname = strdup(hostname);
  if (!result->hostname) {
    free(result);
    return NULL;
  }

  result->error_code = error;

  if (error != 0 || !ai) {
    return result;
  }

  size_t count = 0;
  for (struct addrinfo *p = ai; p; p = p->ai_next) {
    count++;
  }

  result->addresses = malloc(count * sizeof(dns_address_t));
  if (!result->addresses) {
    dns_result_free(result);
    return NULL;
  }

  size_t index = 0;
  for (struct addrinfo *p = ai; p && index < count; p = p->ai_next) {
    dns_address_t *addr = &result->addresses[index];

    addr->family = p->ai_family;
    addr->socktype = p->ai_socktype;
    addr->protocol = p->ai_protocol;

    if (getnameinfo(p->ai_addr, p->ai_addrlen, addr->address,
                    sizeof(addr->address), NULL, 0, NI_NUMERICHOST) == 0) {
      index++;
    }
  }

  result->count = index;
  return result;
}

static void macos_completion_callback(int32_t status, struct addrinfo *res,
                                      void *context) {
  dns_request_t *request = (dns_request_t *)context;

  if (atomic_load(&request->cancelled)) {
    if (res)
      freeaddrinfo(res);
    return;
  }

  dns_result_t *result = convert_macos_result(res, request->hostname, status);

  if (request->callback) {
    request->callback(result, request->user_data);
  }

  dns_result_free(result);

  if (res)
    freeaddrinfo(res);

  atomic_store(&request->completed, true);
}

static bool load_libinfo_functions(dns_resolver_t *resolver) {
  resolver->libinfo_handle = dlopen("libinfo.dylib", RTLD_LAZY | RTLD_LOCAL);
  if (!resolver->libinfo_handle) {
    return false;
  }

  union {
    void *ptr;
    int32_t (*getaddrinfo_async_start_fn)(
        mach_port_t *port, const char *hostname, const char *servname,
        const struct addrinfo *hints,
        void (*callback)(int32_t, struct addrinfo *, void *), void *context);
  } start_conv;

  union {
    void *ptr;
    int32_t (*getaddrinfo_async_handle_reply_fn)(void *reply);
  } handle_conv;

  union {
    void *ptr;
    void (*getaddrinfo_async_cancel_fn)(mach_port_t port);
  } cancel_conv;

  start_conv.ptr = dlsym(resolver->libinfo_handle, "getaddrinfo_async_start");
  handle_conv.ptr =
      dlsym(resolver->libinfo_handle, "getaddrinfo_async_handle_reply");
  cancel_conv.ptr = dlsym(resolver->libinfo_handle, "getaddrinfo_async_cancel");

  if (!start_conv.ptr || !handle_conv.ptr || !cancel_conv.ptr) {
    dlclose(resolver->libinfo_handle);
    resolver->libinfo_handle = NULL;
    return false;
  }

  resolver->getaddrinfo_async_start = start_conv.getaddrinfo_async_start_fn;
  resolver->getaddrinfo_async_handle_reply =
      handle_conv.getaddrinfo_async_handle_reply_fn;
  resolver->getaddrinfo_async_cancel = cancel_conv.getaddrinfo_async_cancel_fn;

  return true;
}

static bool check_mach_port(mach_port_t port, dns_resolver_t *resolver) {
  mach_reply_msg_t reply_msg;

  kern_return_t kr =
      mach_msg(&reply_msg.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
               sizeof(reply_msg), port, 0, MACH_PORT_NULL);

  if (kr == KERN_SUCCESS) {
    resolver->getaddrinfo_async_handle_reply(&reply_msg);
    return true;
  }

  return false;
}

static bool platform_init(dns_resolver_t *resolver) {
  return load_libinfo_functions(resolver);
}

static void platform_cleanup(dns_resolver_t *resolver) {
  if (resolver->libinfo_handle) {
    dlclose(resolver->libinfo_handle);
    resolver->libinfo_handle = NULL;
  }
}

static dns_request_t *platform_resolve_async(dns_request_t *request) {
  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  mach_port_t machport = MACH_PORT_NULL;

  int32_t error = request->resolver->getaddrinfo_async_start(
      &machport, request->hostname, request->service, &hints,
      macos_completion_callback, request);
  if (error != 0 || machport == MACH_PORT_NULL) {
    return NULL;
  }

  request->machport = machport;
  return request;
}

static void platform_cancel_request(dns_request_t *request) {
  if (request->machport != MACH_PORT_NULL) {
    request->resolver->getaddrinfo_async_cancel(request->machport);
    request->machport = MACH_PORT_NULL;
  }
}

static void platform_process_events(dns_resolver_t *resolver) {
  dns_request_t *req = resolver->pending_requests;
  dns_request_t *prev = NULL;

  while (req) {
    if (!atomic_load(&req->cancelled) && req->machport != MACH_PORT_NULL) {
      check_mach_port(req->machport, resolver);
    }

    if (atomic_load(&req->completed)) {
      dns_request_t *next = req->next;

      if (prev) {
        prev->next = next;
      } else {
        resolver->pending_requests = next;
      }

      if (req->machport != MACH_PORT_NULL) {
        req->machport = MACH_PORT_NULL;
      }
      atomic_fetch_sub(&resolver->active_count, 1);
      free(req->hostname);
      free(req->service);
      free(req);

      req = next;
    } else {
      prev = req;
      req = req->next;
    }
  }
}

#pragma endregion
#endif

#ifdef PLATFORM_GENERIC
#pragma region Generic Implementation (Fallback)

static dns_result_t *convert_generic_result(struct addrinfo *ai,
                                            const char *hostname, int error) {
  dns_result_t *result = calloc(1, sizeof(dns_result_t));
  if (!result)
    return NULL;

  result->hostname = strdup(hostname);
  if (!result->hostname) {
    free(result);
    return NULL;
  }

  result->error_code = error;

  if (error != 0 || !ai) {
    return result;
  }

  size_t count = 0;
  for (struct addrinfo *p = ai; p; p = p->ai_next) {
    count++;
  }

  result->addresses = malloc(count * sizeof(dns_address_t));
  if (!result->addresses) {
    dns_result_free(result);
    return NULL;
  }

  size_t index = 0;
  for (struct addrinfo *p = ai; p && index < count; p = p->ai_next) {
    dns_address_t *addr = &result->addresses[index];

    addr->family = p->ai_family;
    addr->socktype = p->ai_socktype;
    addr->protocol = p->ai_protocol;

    if (getnameinfo(p->ai_addr, p->ai_addrlen, addr->address,
                    sizeof(addr->address), NULL, 0, NI_NUMERICHOST) == 0) {
      index++;
    }
  }

  result->count = index;
  return result;
}

static bool platform_init(dns_resolver_t *resolver) {
  (void)resolver;
  return true;
}

static void platform_cleanup(dns_resolver_t *resolver) { (void)resolver; }

static dns_request_t *platform_resolve_async(dns_request_t *request) {
  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *result_ai = NULL;
  int error =
      getaddrinfo(request->hostname, request->service, &hints, &result_ai);

  atomic_store(&request->completed, true);
  request->stored_result =
      convert_generic_result(result_ai, request->hostname, error);

  if (result_ai) {
    freeaddrinfo(result_ai);
  }

  return request;
}

static void platform_cancel_request(dns_request_t *request) { (void)request; }

static void platform_process_events(dns_resolver_t *resolver) {
  dns_request_t *req = resolver->pending_requests;
  dns_request_t *prev = NULL;

  while (req) {
    if (atomic_load(&req->completed) && !atomic_load(&req->cancelled)) {
      if (req->callback && req->stored_result) {
        req->callback(req->stored_result, req->user_data);
      }

      dns_result_free(req->stored_result);
      req->stored_result = NULL;

      dns_request_t *next = req->next;

      if (prev) {
        prev->next = next;
      } else {
        resolver->pending_requests = next;
      }

      atomic_fetch_sub(&resolver->active_count, 1);
      free(req->hostname);
      free(req->service);
      free(req);

      req = next;
    } else {
      prev = req;
      req = req->next;
    }
  }
}

#pragma endregion
#endif

#pragma endregion

dns_config_t dns_config_default(void) {
  dns_config_t config = {0};
  config.timeout_ms = 5000;
  config.max_concurrent = 10;
  config.prefer_ipv4 = false;
  config.prefer_ipv6 = false;
  return config;
}

dns_resolver_t *dns_resolver_create(const dns_config_t *config) {
  dns_resolver_t *resolver = calloc(1, sizeof(dns_resolver_t));
  if (!resolver)
    return NULL;

  if (config) {
    resolver->config = *config;
  } else {
    resolver->config = dns_config_default();
  }

  atomic_store(&resolver->active_count, 0);

  if (!platform_init(resolver)) {
    free(resolver);
    return NULL;
  }

  return resolver;
}

void dns_resolver_destroy(dns_resolver_t *resolver) {
  if (!resolver)
    return;

  // Cancel all pending requests
  dns_request_t *req = resolver->pending_requests;
  while (req) {
    atomic_store(&req->cancelled, true);
    platform_cancel_request(req);
    req = req->next;
  }

  // Process any completions and clean up
  platform_process_events(resolver);

  // Final cleanup of any remaining requests
  req = resolver->pending_requests;
  while (req) {
    dns_request_t *next = req->next;
    free(req->hostname);
    free(req->service);
    free(req);
    req = next;
  }

  platform_cleanup(resolver);
  free(resolver);
}

dns_request_t *dns_resolve_async(dns_resolver_t *resolver, const char *hostname,
                                 const char *service, dns_callback_t callback,
                                 void *user_data) {
  if (!resolver || !hostname || !callback)
    return NULL;

  int current_active = atomic_load(&resolver->active_count);
  if (resolver->config.max_concurrent > 0 &&
      current_active >= resolver->config.max_concurrent) {
    return NULL;
  }

  dns_request_t *request = calloc(1, sizeof(dns_request_t));
  if (!request)
    return NULL;

  request->resolver = resolver;
  request->hostname = strdup(hostname);
  if (!request->hostname) {
    free(request);
    return NULL;
  }

  request->service = service ? strdup(service) : NULL;
  if (service && !request->service) {
    free(request->hostname);
    free(request);
    return NULL;
  }

  request->callback = callback;
  request->user_data = user_data;
  atomic_store(&request->cancelled, false);
  atomic_store(&request->completed, false);

#ifdef PLATFORM_MACOS
  request->machport = MACH_PORT_NULL;
#elif defined(PLATFORM_GENERIC)
  request->stored_result = NULL;
#endif

  request->next = resolver->pending_requests;
  resolver->pending_requests = request;
  atomic_fetch_add(&resolver->active_count, 1);

  if (!platform_resolve_async(request)) {
    dns_request_cancel(request);
    return NULL;
  }

  return request;
}

bool dns_request_cancel(dns_request_t *request) {
  if (!request || atomic_load(&request->cancelled))
    return false;

  atomic_store(&request->cancelled, true);
  platform_cancel_request(request);

  return true;
}

void dns_resolver_process(dns_resolver_t *resolver) {
  if (!resolver)
    return;
  platform_process_events(resolver);
}

void dns_result_free(dns_result_t *result) {
  if (!result)
    return;

  free(result->addresses);
  free(result->hostname);
  free(result);
}

const char *dns_error_string(int error_code) {
  if (error_code == 0)
    return "Success";

#ifdef PLATFORM_WINDOWS
  switch (error_code) {
  case WSAHOST_NOT_FOUND:
    return "Host not found";
  case WSATRY_AGAIN:
    return "Try again";
  case WSANO_RECOVERY:
    return "Non-recoverable error";
  case WSANO_DATA:
    return "No data";
  default:
    return "Unknown error";
  }
#else
  return gai_strerror(error_code);
#endif
}