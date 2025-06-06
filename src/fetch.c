#ifdef __linux__
#define _GNU_SOURCE
#endif
#include "fetch.h"
#include "ada_c.h"

#include "cookie.h"
#include "dns.h"
#include "picohttpparser.h"
#include "sets.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(LIBFETCH_TLS_ENABLED)
#include "root.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "win32/str_win32.h"
// clang-format on

#pragma comment(lib, "ws2_32.lib")
#if defined(LIBFETCH_TLS_ENABLED)
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif

#define FETCH_SOCKET SOCKET
#define FETCH_INVALID_SOCKET INVALID_SOCKET
#define fetch_close_socket closesocket
#define fetch_socket_error WSAGetLastError()

typedef HANDLE fetch_event_handle_t;
typedef OVERLAPPED fetch_overlapped_t;

#define FETCH_EVENT_INVALID INVALID_HANDLE_VALUE
#define FETCH_WAIT_INFINITE INFINITE

#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define FETCH_SOCKET int
#define FETCH_INVALID_SOCKET (-1)
#define fetch_close_socket close
#define fetch_socket_error errno

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
typedef int fetch_event_handle_t;
#define FETCH_EVENT_INVALID -1
#define FETCH_WAIT_INFINITE -1
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
#include <sys/event.h>
typedef int fetch_event_handle_t;
#define FETCH_EVENT_INVALID (-1)
#define FETCH_WAIT_INFINITE (-1)
#else

typedef int fetch_event_handle_t;
#define FETCH_EVENT_INVALID -1
#define FETCH_WAIT_INFINITE -1
#endif

#endif

#include <stdatomic.h>
#define fetch_atomic_load(ptr) atomic_load_explicit((ptr), memory_order_acquire)
#define fetch_atomic_store(ptr, val)                                           \
  atomic_store_explicit((ptr), (val), memory_order_release)
#define fetch_atomic_cas(ptr, expected, desired)                               \
  atomic_compare_exchange_strong_explicit((ptr), &(expected), (desired),       \
                                          memory_order_acq_rel,                \
                                          memory_order_acquire)
#define fetch_atomic_inc(ptr)                                                  \
  (atomic_fetch_add_explicit((ptr), 1, memory_order_acq_rel) + 1)
#define fetch_atomic_dec(ptr)                                                  \
  (atomic_fetch_sub_explicit((ptr), 1, memory_order_acq_rel) + 1)

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) ||             \
    defined(_M_IX86)
#define SIMD_X86
#include <emmintrin.h>
#ifdef __SSE4_1__
#include <smmintrin.h>
#endif
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__)
#define SIMD_ARM
#include <arm_neon.h>
#endif

#define FETCH_MAX_URL_LENGTH 8192
#define FETCH_MAX_HOSTNAME_LENGTH 253
#define FETCH_MAX_HEADER_VALUE_LENGTH 8192
#define FETCH_MAX_HEADER_NAME_LENGTH 256
#define FETCH_MAX_METHOD_LENGTH 16
#define FETCH_MAX_PATH_LENGTH 4096
#define FETCH_MAX_BODY_SIZE (50 * 1024 * 1024)
#define FETCH_MAX_STRING_LENGTH 4096
#define FETCH_MAX_FORM_PARAM_LENGTH 1024
#define FETCH_MAX_CONTENT_TYPE_LENGTH 256

static char to_lower(const char x) { return x | 0x20; }

static int fetch_strcasecmp(const char *s1, const char *s2) {
  if (!s1 || !s2)
    return s1 == s2 ? 0 : (s1 ? 1 : -1);

  const unsigned char *us1 = (const unsigned char *)s1;
  const unsigned char *us2 = (const unsigned char *)s2;

#ifdef SIMD_X86

  while (*us1 && *us2) {

    size_t remaining1 = strnlen((const char *)us1, FETCH_MAX_STRING_LENGTH);
    size_t remaining2 = strnlen((const char *)us2, FETCH_MAX_STRING_LENGTH);

    if (remaining1 >= 16 && remaining2 >= 16) {
      __m128i str1 = _mm_loadu_si128((__m128i *)us1);
      __m128i str2 = _mm_loadu_si128((__m128i *)us2);

      __m128i mask1 = _mm_and_si128(_mm_cmpgt_epi8(str1, _mm_set1_epi8(0x40)),
                                    _mm_cmplt_epi8(str1, _mm_set1_epi8(0x5B)));
      __m128i mask2 = _mm_and_si128(_mm_cmpgt_epi8(str2, _mm_set1_epi8(0x40)),
                                    _mm_cmplt_epi8(str2, _mm_set1_epi8(0x5B)));

      __m128i lower1 =
          _mm_add_epi8(str1, _mm_and_si128(mask1, _mm_set1_epi8(0x20)));
      __m128i lower2 =
          _mm_add_epi8(str2, _mm_and_si128(mask2, _mm_set1_epi8(0x20)));

      __m128i cmp = _mm_cmpeq_epi8(lower1, lower2);
      int mask = _mm_movemask_epi8(cmp);

      if (mask != 0xFFFF) {

        for (int i = 0; i < 16; i++) {
          int c1 = to_lower(us1[i]);
          int c2 = to_lower(us2[i]);
          if (c1 != c2 || c1 == 0) {
            return c1 - c2;
          }
        }
      }

      __m128i nulls1 = _mm_cmpeq_epi8(str1, _mm_setzero_si128());
      __m128i nulls2 = _mm_cmpeq_epi8(str2, _mm_setzero_si128());
      int null_mask1 = _mm_movemask_epi8(nulls1);
      int null_mask2 = _mm_movemask_epi8(nulls2);

      if (null_mask1 || null_mask2) {

        break;
      }

      us1 += 16;
      us2 += 16;
    } else {
      break;
    }
  }
#elif defined(SIMD_ARM)

  while (*us1 && *us2) {
    size_t remaining1 = strnlen((const char *)us1, FETCH_MAX_STRING_LENGTH);
    size_t remaining2 = strnlen((const char *)us2, FETCH_MAX_STRING_LENGTH);

    if (remaining1 >= 16 && remaining2 >= 16) {
      uint8x16_t str1 = vld1q_u8(us1);
      uint8x16_t str2 = vld1q_u8(us2);

      uint8x16_t mask1 = vandq_u8(vcgeq_u8(str1, vdupq_n_u8('A')),
                                  vcleq_u8(str1, vdupq_n_u8('Z')));
      uint8x16_t mask2 = vandq_u8(vcgeq_u8(str2, vdupq_n_u8('A')),
                                  vcleq_u8(str2, vdupq_n_u8('Z')));

      uint8x16_t lower1 = vaddq_u8(str1, vandq_u8(mask1, vdupq_n_u8(0x20)));
      uint8x16_t lower2 = vaddq_u8(str2, vandq_u8(mask2, vdupq_n_u8(0x20)));

      uint8x16_t cmp = vceqq_u8(lower1, lower2);

      const uint64x2_t cmp64 = vreinterpretq_u64_u8(cmp);
      const uint64_t combined =
          vgetq_lane_u64(cmp64, 0) & vgetq_lane_u64(cmp64, 1);

      if (combined != 0xFFFFFFFFFFFFFFFFULL) {

        break;
      }

      uint8x16_t nulls1 = vceqq_u8(str1, vdupq_n_u8(0));
      uint8x16_t nulls2 = vceqq_u8(str2, vdupq_n_u8(0));
      const uint64x2_t nulls1_64 = vreinterpretq_u64_u8(nulls1);
      const uint64x2_t nulls2_64 = vreinterpretq_u64_u8(nulls2);

      if ((vgetq_lane_u64(nulls1_64, 0) | vgetq_lane_u64(nulls1_64, 1)) ||
          (vgetq_lane_u64(nulls2_64, 0) | vgetq_lane_u64(nulls2_64, 1))) {
        break;
      }

      us1 += 16;
      us2 += 16;
    } else {
      break;
    }
  }
#endif

  while (*us1 && *us2) {
    int c1 = to_lower((char)*us1++);
    int c2 = to_lower((char)*us2++);
    if (c1 != c2)
      return c1 - c2;
  }
  return (int)to_lower((char)*us1) - (int)to_lower((char)*us2);
}

typedef enum {
  CONN_STATE_NONE = 0,
  CONN_STATE_RESOLVING,
  CONN_STATE_CONNECTING,
  CONN_STATE_TLS_HANDSHAKE,
  CONN_STATE_SENDING,
  CONN_STATE_RECEIVING,
  CONN_STATE_REDIRECTING,
  CONN_STATE_COMPLETE,
  CONN_STATE_ERROR,
  CONN_STATE_CANCELLED
} connection_state_t;

#if defined(LIBFETCH_TLS_ENABLED)
typedef struct tls_context {
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  bool handshake_complete;
  bool want_read;
  bool want_write;
  char *hostname;

  SSL_SESSION *cached_session;
  bool session_reused;
  bool session_resumption_attempted;
} tls_context_t;
#else
typedef struct tls_context {
  char dummy;

} tls_context_t;
#endif

typedef enum {
  IO_OP_CONNECT = 1,
  IO_OP_SEND = 2,
  IO_OP_RECV = 4,
  IO_OP_TIMEOUT = 8
} io_operation_t;

struct fetch_connection;
struct fetch_event_loop;
struct http_parse_context;
static void http_parse_context_free(struct http_parse_context *ctx);
static struct http_parse_context *http_parse_context_new(void);
static bool is_response_complete(const struct http_parse_context *ctx);

static size_t format_chunk_header(char *buffer, size_t data_size);
static size_t format_chunk_trailer(char *buffer);
static size_t format_final_chunk(char *buffer);
static size_t read_file_chunk(struct fetch_connection *conn, char *buffer,
                              size_t buffer_size);
static bool has_more_file_data(struct fetch_connection *conn);
typedef enum host_type_t {
  HOST_TYPE_DOMAIN = 0,
  HOST_TYPE_IPV4 = 1,
  HOST_TYPE_IPV6 = 2,
} fetch_host_type_t;

typedef struct fetch_url {
  char *full_url;
  char *protocol;
  char *hostname;
  char *path;
  uint16_t port;
  fetch_host_type_t host_type;
  bool is_https;
} fetch_url_t;

typedef struct fetch_request {
  fetch_url_t *url;
  http_method_t method;
  fetch_headers_t *headers;
  fetch_body_t *body;

  fetch_mode_t mode;
  fetch_credentials_t credentials;
  fetch_cache_t cache;
  fetch_redirect_t redirect;
  char *referrer;
  char *referrer_policy;
  char *integrity;
  bool keepalive;

  uint32_t timeout_ms;
  uint32_t max_redirects;

  fetch_abort_controller_t *signal;
} fetch_request_t;

static fetch_url_t *fetch_url_parse(const char *url) {
  if (!url || strnlen(url, FETCH_MAX_URL_LENGTH) == 0)
    return NULL;

  const size_t url_len = strnlen(url, FETCH_MAX_URL_LENGTH);
  const ada_url parsed = ada_parse(url, url_len);

  if (!ada_is_valid(parsed)) {
    ada_free(parsed);
    return NULL;
  }

  fetch_url_t *fetch_url = calloc(1, sizeof(fetch_url_t));
  if (!fetch_url) {
    ada_free(parsed);
    return NULL;
  }

  fetch_url->full_url = strndup(url, url_len);
  if (!fetch_url->full_url) {
    goto error_cleanup;
  }

  const ada_string protocol = ada_get_protocol(parsed);
  if (protocol.length > 0) {

    size_t proto_len = protocol.length;
    if (proto_len > 0 && protocol.data[proto_len - 1] == ':') {
      proto_len--;
    }
    fetch_url->protocol = strndup(protocol.data, proto_len);
  }

  if (!fetch_url->protocol) {
    goto error_cleanup;
  }

  fetch_url->is_https = (fetch_strcasecmp(fetch_url->protocol, "https") == 0);

  const ada_string hostname = ada_get_hostname(parsed);
  if (hostname.length == 0) {
    goto error_cleanup;
  }

  fetch_url->hostname = strndup(hostname.data, hostname.length);
  if (!fetch_url->hostname) {
    goto error_cleanup;
  }

  fetch_url->host_type = ada_get_host_type(parsed);

  const ada_string port_str = ada_get_port(parsed);
  if (port_str.length > 0) {
    char *port_cstr = strndup(port_str.data, port_str.length);
    if (port_cstr) {
      const long port_long = strtol(port_cstr, NULL, 10);
      free(port_cstr);

      if (port_long > 0 && port_long <= 65535) {
        fetch_url->port = (uint16_t)port_long;
      } else {
        goto error_cleanup;
      }
    } else {
      goto error_cleanup;
    }
  } else {

    fetch_url->port = fetch_url->is_https ? 443 : 80;
  }

  const ada_string pathname = ada_get_pathname(parsed);
  const ada_string search = ada_get_search(parsed);

  size_t path_len = pathname.length;
  if (search.length > 0) {
    path_len += search.length;
  }

  if (path_len == 0) {
    fetch_url->path = strdup("/");
  } else {
    fetch_url->path = malloc(path_len + 1);
    if (!fetch_url->path) {
      goto error_cleanup;
    }

    memcpy(fetch_url->path, pathname.data, pathname.length);
    if (search.length > 0) {
      memcpy(fetch_url->path + pathname.length, search.data, search.length);
    }
    fetch_url->path[path_len] = '\0';
  }

  ada_free(parsed);
  return fetch_url;

error_cleanup:
  if (fetch_url) {
    free(fetch_url->full_url);
    free(fetch_url->protocol);
    free(fetch_url->hostname);
    free(fetch_url->path);
    free(fetch_url);
  }
  ada_free(parsed);
  return NULL;
}

static void fetch_url_free(fetch_url_t *fetch_url) {
  if (!fetch_url)
    return;

  free(fetch_url->full_url);
  free(fetch_url->protocol);
  free(fetch_url->hostname);
  free(fetch_url->path);
  free(fetch_url);
}

static bool fetch_url_is_same_origin(const fetch_url_t *url1,
                                     const fetch_url_t *url2) {
  if (!url1 || !url2)
    return false;

  if (!url1->protocol || !url2->protocol ||
      fetch_strcasecmp(url1->protocol, url2->protocol) != 0) {
    return false;
  }

  if (!url1->hostname || !url2->hostname ||
      fetch_strcasecmp(url1->hostname, url2->hostname) != 0) {
    return false;
  }

  if (url1->port != url2->port) {
    return false;
  }

  return true;
}

static fetch_response_t *create_response_from_context(
    const struct http_parse_context *ctx, const fetch_url_t *final_url,
    bool *supports_keep_alive, const fetch_request_t *request);

typedef struct pooled_connection {
  FETCH_SOCKET socket;
  char *host;
  uint16_t port;
  uint64_t last_used_ms;
  uint64_t keep_alive_timeout_ms;
  bool in_use;
  bool validated;
  bool is_tls;
#if defined(LIBFETCH_TLS_ENABLED)
  tls_context_t *tls_context;
#endif
  struct pooled_connection *next;
  struct pooled_connection *prev;
} pooled_connection_t;

typedef struct connection_pool {
  char *host;
  uint16_t port;
  pooled_connection_t *available;
  pooled_connection_t *available_tail;
  size_t available_count;
  size_t active_count;
  size_t max_per_host;
  uint64_t last_cleanup_ms;
  struct connection_pool *next;
} connection_pool_t;

typedef struct {
  connection_pool_t *pools;
  size_t total_pooled;
  size_t max_total_pooled;
  uint64_t last_global_cleanup_ms;
} connection_pool_manager_t;

#if defined(_WIN32) || defined(_WIN64)

typedef struct win_io_context {
  OVERLAPPED overlapped;
  io_operation_t operation;
  SOCKET socket;
  WSABUF wsa_buf;
  char buffer[8192];
  DWORD bytes_transferred;
  struct fetch_connection *conn;
#if defined(LIBFETCH_TLS_ENABLED)
  bool tls_handshake_pending;
  bool tls_data_pending;
#endif
} win_io_context_t;
#endif

typedef struct fetch_connection {

  uint64_t connection_id;
  fetch_promise_t *promise;

  fetch_request_t *request;

  FETCH_SOCKET socket;
  connection_state_t state;
  struct sockaddr_storage addr;
  int addr_family;
  bool addr_resolved;

  char *host;
#if defined(LIBFETCH_TLS_ENABLED)
  tls_context_t *tls;
#endif
  bool is_https;
  fetch_host_type_t host_type;
  uint16_t port;
  dns_request_t *dns_request;
  char *request_buffer;
  size_t request_size;
  size_t bytes_sent;

  enum { SEND_MODE_MEMORY, SEND_MODE_FILE } send_mode;

  union {
    struct {
      char dummy;

    } memory;
    struct {
      size_t headers_sent;
      size_t file_bytes_sent;
      char buffer[8192];
      size_t buffer_size;
      size_t buffer_sent;
      bool use_chunked_encoding;
      enum {
        CHUNK_STATE_HEADER,
        CHUNK_STATE_DATA,
        CHUNK_STATE_TRAILER,
        CHUNK_STATE_FINAL
      } chunk_state;
      char chunk_header[16];
      size_t chunk_header_size;
      size_t chunk_header_sent;
    } file;
  } send_state;

  char *response_buffer;
  size_t response_capacity;
  size_t response_size;
  size_t bytes_received;
  bool response_supports_keep_alive;

  struct http_parse_context *parse_ctx;

  uint64_t start_time_ms;
  uint64_t last_activity_ms;

  uint32_t redirect_count;
  bool following_redirect;
  char *redirect_url;

  _Atomic(bool) cancelled;
  const char *cancel_reason;

#if defined(_WIN32) || defined(_WIN64)

  win_io_context_t *current_io_ctx;
  bool socket_bound;
#else
  uint32_t events;
  io_operation_t pending_op;
#endif

  struct fetch_connection *next;
  struct fetch_connection *prev;
} fetch_connection_t;

typedef struct fetch_timer {
  uint64_t expiry_time_ms;
  uint64_t connection_id;
  struct fetch_timer *next;
} fetch_timer_t;

struct fetch_event_loop {

  _Atomic(bool) running;
  _Atomic(bool) shutdown_requested;
  _Atomic(uint64_t) next_connection_id;

#if defined(_WIN32) || defined(_WIN64)
  HANDLE iocp;
  HANDLE wakeup_event;
#elif defined(__linux__)
  int epoll_fd;
  int eventfd;
  int timerfd;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  int kqueue_fd;
  int wakeup_pipe[2];
#else
  fd_set read_fds, write_fds;
  FETCH_SOCKET max_fd;
  int wakeup_pipe[2];
#endif

  fetch_connection_t *active_connections;
  fetch_connection_t *completed_connections;
  size_t active_count;
  size_t max_connections;

  fetch_timer_t *timers;
  uint64_t next_timer_check_ms;

  _Atomic(uint64_t) total_requests;
  _Atomic(uint64_t) successful_requests;
  _Atomic(uint64_t) failed_requests;
  _Atomic(uint64_t) cancelled_requests;
};

static struct fetch_event_loop g_event_loop = {0};

static connection_pool_manager_t g_pool_manager = {0};

static dns_resolver_t *g_dns_resolver = NULL;

#if defined(_WIN32) || defined(_WIN64)

static LPFN_CONNECTEX g_connect_ex_func = NULL;
#endif

static fetch_config_t g_fetch_config = {
    .user_agent = FETCH_USER_AGENT,
    .origin = NULL,
    .cookie_jar = NULL,
    .default_timeout_ms = 30000,
    .max_connections = 1000,
    .max_connections_per_host = 6,
    .keep_alive_timeout_ms = 115000,
    .pool_cleanup_interval_ms = 30000,
    .max_pooled_connections = 100,
    .flags = (1U << FETCH_FLAG_KEEP_ALIVE_DEFAULT) |
             (1U << FETCH_FLAG_FOLLOW_REDIRECTS) |
             (1U << FETCH_FLAG_ENABLE_COMPRESSION) |
             (1U << FETCH_FLAG_ENABLE_COOKIES)};

static void fetch_request_free(fetch_request_t *request) {
  if (!request) {
    return;
  }

  fetch_url_free(request->url);
  fetch_headers_free(request->headers);
  if (request->body) {
    fetch_body_free(request->body);
  }
  free(request->referrer);
  free(request->referrer_policy);
  free(request->integrity);

  free(request);
}

static fetch_request_t *fetch_request_new(fetch_url_t *parsed_url,
                                          fetch_init_t *init) {
  if (!parsed_url) {
    return NULL;
  }

  fetch_request_t *request = calloc(1, sizeof(fetch_request_t));
  if (!request) {
    return NULL;
  }

  request->url = parsed_url;

  request->method = HTTP_METHOD_GET;
  request->mode = FETCH_MODE_NO_CORS;
  request->credentials = FETCH_CREDENTIALS_INCLUDE;
  request->cache = FETCH_CACHE_DEFAULT;
  request->redirect = FETCH_REDIRECT_FOLLOW;
  request->keepalive = fetch_config_get_flag(g_fetch_config.flags,
                                             FETCH_FLAG_KEEP_ALIVE_DEFAULT);
  request->timeout_ms = g_fetch_config.default_timeout_ms;
  request->max_redirects = 20;

  if (init) {
    request->method = init->method;
    request->mode = init->mode;
    request->credentials = init->credentials;
    request->cache = init->cache;
    request->redirect = init->redirect;
    request->keepalive = init->keepalive;
    request->signal = init->signal;
    request->timeout_ms =
        init->timeout_ms ? init->timeout_ms : g_fetch_config.default_timeout_ms;
    request->max_redirects = init->max_redirects;

    if (init->headers) {
      request->headers = fetch_headers_new();
      if (!request->headers) {
        goto error_cleanup;
      }

      for (size_t i = 0; i < init->headers->count; i++) {
        if (init->headers->keys[i] && init->headers->values[i]) {
          fetch_headers_set(request->headers, init->headers->keys[i],
                            init->headers->values[i]);
        }
      }
    }

    if (init->body) {

      request->body = init->body;
      ((fetch_init_t *)init)->body = NULL;
    }

    if (init->referrer) {
      request->referrer = strdup(init->referrer);
    }
    if (init->referrer_policy) {
      request->referrer_policy = strdup(init->referrer_policy);
    }
    if (init->integrity) {
      request->integrity = strdup(init->integrity);
    }
  }

  return request;

error_cleanup:
  fetch_request_free(request);
  return NULL;
}

static uint64_t get_connection_timeout_ms(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->timeout_ms
                               : g_fetch_config.default_timeout_ms;
}

static uint32_t get_connection_max_redirects(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->max_redirects : 20;
}

static bool get_connection_keepalive(const fetch_connection_t *conn) {
  return conn && conn->request
             ? conn->request->keepalive
             : fetch_config_get_flag(g_fetch_config.flags,
                                     FETCH_FLAG_KEEP_ALIVE_DEFAULT);
}

static http_method_t get_connection_method(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->method : HTTP_METHOD_GET;
}

static const fetch_url_t *get_connection_url(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->url : NULL;
}

static fetch_headers_t *get_connection_headers(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->headers : NULL;
}

static fetch_body_t *get_connection_body(const fetch_connection_t *conn) {
  return conn && conn->request ? conn->request->body : NULL;
}

static bool should_include_credentials(fetch_credentials_t credentials,
                                       const fetch_url_t *request_url,
                                       const char *origin) {
  if (!fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES) ||
      !g_fetch_config.cookie_jar) {
    return false;
  }

  switch (credentials) {
  case FETCH_CREDENTIALS_OMIT:
    return false;

  case FETCH_CREDENTIALS_SAME_ORIGIN:
    if (!origin || !request_url) {
      return false;
    }

    fetch_url_t *origin_url = fetch_url_parse(origin);
    if (!origin_url) {
      return false;
    }
    bool same_origin = fetch_url_is_same_origin(request_url, origin_url);
    fetch_url_free(origin_url);
    return same_origin;

  case FETCH_CREDENTIALS_INCLUDE:
    return true;

  default:
    return false;
  }
}
#if defined(LIBFETCH_TLS_ENABLED)
static SSL_CTX *g_client_ssl_ctx = NULL;
static bool g_tls_initialized = false;

typedef struct tls_session_cache_entry {
  char *hostname;
  uint16_t port;
  SSL_SESSION *session;
  uint64_t created_time_ms;
  uint64_t last_used_ms;
  uint32_t use_count;
  bool is_valid;
  struct tls_session_cache_entry *next;
  struct tls_session_cache_entry *prev;
} tls_session_cache_entry_t;

typedef struct tls_session_cache {
  tls_session_cache_entry_t *entries;
  tls_session_cache_entry_t *entries_tail;
  size_t count;
  size_t max_entries;
  uint64_t session_timeout_ms;
  uint64_t last_cleanup_ms;
} tls_session_cache_t;

static tls_session_cache_t g_tls_session_cache = {0};
#endif
static bool g_fetch_initialized = false;
static bool g_user_agent_allocated = false;

static uint64_t fetch_get_time_ms(void) {
#if defined(_WIN32) || defined(_WIN64)
  FILETIME ft;
  ULARGE_INTEGER uli;
  GetSystemTimeAsFileTime(&ft);
  uli.LowPart = ft.dwLowDateTime;
  uli.HighPart = ft.dwHighDateTime;

  return uli.QuadPart / 10000ULL;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

#if defined(LIBFETCH_TLS_ENABLED)

static bool init_tls_session_cache(void) {
  memset(&g_tls_session_cache, 0, sizeof(g_tls_session_cache));
  g_tls_session_cache.max_entries = 100;
  g_tls_session_cache.session_timeout_ms = 300000;
  g_tls_session_cache.last_cleanup_ms = fetch_get_time_ms();
  return true;
}

static void cleanup_tls_session_cache(void) {
  tls_session_cache_entry_t *entry = g_tls_session_cache.entries;
  while (entry) {
    tls_session_cache_entry_t *next = entry->next;
    free(entry->hostname);
    if (entry->session) {
      SSL_SESSION_free(entry->session);
    }
    free(entry);
    entry = next;
  }
  memset(&g_tls_session_cache, 0, sizeof(g_tls_session_cache));
}

static void remove_session_entry(tls_session_cache_entry_t *entry) {
  if (!entry)
    return;

  if (entry->prev) {
    entry->prev->next = entry->next;
  } else {
    g_tls_session_cache.entries = entry->next;
  }

  if (entry->next) {
    entry->next->prev = entry->prev;
  } else {
    g_tls_session_cache.entries_tail = entry->prev;
  }

  g_tls_session_cache.count--;

  free(entry->hostname);
  if (entry->session) {
    SSL_SESSION_free(entry->session);
  }
  free(entry);
}

static void cleanup_expired_sessions(void) {
  uint64_t current_time = fetch_get_time_ms();

  if (current_time - g_tls_session_cache.last_cleanup_ms < 30000) {
    return;
  }

  g_tls_session_cache.last_cleanup_ms = current_time;

  tls_session_cache_entry_t *entry = g_tls_session_cache.entries;
  while (entry) {
    tls_session_cache_entry_t *next = entry->next;

    if (!entry->is_valid ||
        (current_time - entry->created_time_ms >
         g_tls_session_cache.session_timeout_ms) ||
        (current_time - entry->last_used_ms >
         g_tls_session_cache.session_timeout_ms)) {
      remove_session_entry(entry);
    }

    entry = next;
  }
}

static void evict_oldest_session(void) {
  if (!g_tls_session_cache.entries_tail)
    return;

  remove_session_entry(g_tls_session_cache.entries_tail);
}

static tls_session_cache_entry_t *find_session(const char *hostname,
                                               uint16_t port) {
  if (!hostname)
    return NULL;

  cleanup_expired_sessions();

  tls_session_cache_entry_t *entry = g_tls_session_cache.entries;
  while (entry) {
    if (entry->port == port && entry->hostname &&
        fetch_strcasecmp(entry->hostname, hostname) == 0 && entry->is_valid &&
        entry->session) {

      if (entry != g_tls_session_cache.entries) {

        if (entry->prev)
          entry->prev->next = entry->next;
        if (entry->next)
          entry->next->prev = entry->prev;
        if (entry == g_tls_session_cache.entries_tail) {
          g_tls_session_cache.entries_tail = entry->prev;
        }

        entry->prev = NULL;
        entry->next = g_tls_session_cache.entries;
        if (g_tls_session_cache.entries) {
          g_tls_session_cache.entries->prev = entry;
        }
        g_tls_session_cache.entries = entry;

        if (!g_tls_session_cache.entries_tail) {
          g_tls_session_cache.entries_tail = entry;
        }
      }

      entry->last_used_ms = fetch_get_time_ms();
      return entry;
    }
    entry = entry->next;
  }

  return NULL;
}

static bool store_session(const char *hostname, uint16_t port,
                          SSL_SESSION *session) {
  if (!hostname || !session)
    return false;

  tls_session_cache_entry_t *existing = find_session(hostname, port);
  if (existing) {

    if (existing->session) {
      SSL_SESSION_free(existing->session);
    }
    existing->session = session;
    SSL_SESSION_up_ref(session);
    existing->created_time_ms = fetch_get_time_ms();
    existing->last_used_ms = existing->created_time_ms;
    existing->use_count = 0;
    existing->is_valid = true;
    return true;
  }

  while (g_tls_session_cache.count >= g_tls_session_cache.max_entries) {
    evict_oldest_session();
  }

  tls_session_cache_entry_t *entry =
      calloc(1, sizeof(tls_session_cache_entry_t));
  if (!entry)
    return false;

  entry->hostname = strdup(hostname);
  if (!entry->hostname) {
    free(entry);
    return false;
  }

  entry->port = port;
  entry->session = session;
  SSL_SESSION_up_ref(session);
  entry->created_time_ms = fetch_get_time_ms();
  entry->last_used_ms = entry->created_time_ms;
  entry->use_count = 0;
  entry->is_valid = true;

  entry->next = g_tls_session_cache.entries;
  if (g_tls_session_cache.entries) {
    g_tls_session_cache.entries->prev = entry;
  } else {
    g_tls_session_cache.entries_tail = entry;
  }
  g_tls_session_cache.entries = entry;
  g_tls_session_cache.count++;

  return true;
}

static SSL_SESSION *get_cached_session(const char *hostname, uint16_t port) {
  tls_session_cache_entry_t *entry = find_session(hostname, port);
  if (entry && entry->session) {
    entry->use_count++;
    SSL_SESSION_up_ref(entry->session);
    return entry->session;
  }
  return NULL;
}

static void invalidate_session(const char *hostname, uint16_t port) {
  tls_session_cache_entry_t *entry = find_session(hostname, port);
  if (entry) {
    entry->is_valid = false;
  }
}
static bool init_tls(void) {
  if (g_tls_initialized)
    return true;

  g_client_ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!g_client_ssl_ctx) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (!SSL_CTX_set_min_proto_version(g_client_ssl_ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version(g_client_ssl_ctx, TLS1_3_VERSION) ||
      !SSL_CTX_set_ciphersuites(g_client_ssl_ctx,
                                "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
                                "TLS_CHACHA20_POLY1305_SHA256") ||
      !SSL_CTX_set_cipher_list(
          g_client_ssl_ctx,
          "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-"
          "ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-"
          "CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:"
          "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:"
          "AES256-SHA") ||
      !SSL_CTX_set1_groups_list(g_client_ssl_ctx, "X25519:P-256:P-384")) {
    SSL_CTX_free(g_client_ssl_ctx);
    g_client_ssl_ctx = NULL;
    return false;
  }

  SSL_CTX_set_security_level(g_client_ssl_ctx, 2);
  SSL_CTX_set_options(g_client_ssl_ctx,
                      SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                          SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_verify(g_client_ssl_ctx, SSL_VERIFY_PEER, NULL);

  X509_VERIFY_PARAM *param = SSL_CTX_get0_param(g_client_ssl_ctx);
  if (param) {
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN |
                                           X509_V_FLAG_TRUSTED_FIRST |
                                           X509_V_FLAG_CHECK_SS_SIGNATURE);
  }

  // Load platform-specific root certificates
  if (!load_platform_root_certificates(g_client_ssl_ctx)) {
    SSL_CTX_free(g_client_ssl_ctx);
    g_client_ssl_ctx = NULL;
    return false;
  }

  if (!init_tls_session_cache()) {
    SSL_CTX_free(g_client_ssl_ctx);
    g_client_ssl_ctx = NULL;
    return false;
  }

  g_tls_initialized = true;
  return true;
}

static tls_context_t *tls_context_new(const char *hostname) {
  tls_context_t *tls = NULL;
  bool success = false;

  if (!g_tls_initialized && !init_tls()) {
    goto cleanup;
  }

  tls = calloc(1, sizeof(tls_context_t));
  if (!tls) {
    goto cleanup;
  }

  tls->rbio = BIO_new(BIO_s_mem());
  tls->wbio = BIO_new(BIO_s_mem());
  if (!tls->rbio || !tls->wbio) {
    goto cleanup;
  }

  BIO_set_nbio(tls->rbio, 1);
  BIO_set_nbio(tls->wbio, 1);

  tls->ssl = SSL_new(g_client_ssl_ctx);
  if (!tls->ssl) {
    goto cleanup;
  }

  SSL_set_connect_state(tls->ssl);

  SSL_set_bio(tls->ssl, tls->rbio, tls->wbio);

  if (hostname) {
    tls->hostname = strdup(hostname);
    if (!tls->hostname) {
      goto cleanup;
    }

    if (SSL_set_tlsext_host_name(tls->ssl, hostname) != 1) {
      goto cleanup;
    }

    SSL_set_hostflags(tls->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (SSL_set1_host(tls->ssl, hostname) != 1) {
      goto cleanup;
    }

    X509_VERIFY_PARAM *param = SSL_get0_param(tls->ssl);
    if (param) {

      X509_VERIFY_PARAM_set1_host(param, hostname, 0);
    }
  }

  tls->handshake_complete = false;
  tls->want_read = false;
  tls->want_write = false;
  tls->cached_session = NULL;
  tls->session_reused = false;
  tls->session_resumption_attempted = false;

  success = true;

cleanup:
  if (!success && tls) {
    if (tls->ssl) {
      SSL_free(tls->ssl);
    } else {

      BIO_free(tls->rbio);
      BIO_free(tls->wbio);
    }
    free(tls->hostname);
    free(tls);
    tls = NULL;
  }

  return tls;
}

static void tls_context_free(tls_context_t *tls) {
  if (!tls)
    return;

  if (tls->ssl) {
    SSL_free(tls->ssl);
  }

  if (tls->cached_session) {
    SSL_SESSION_free(tls->cached_session);
  }

  free(tls->hostname);
  free(tls);
}

static bool tls_context_prepare_session_resumption(tls_context_t *tls,
                                                   const char *hostname,
                                                   uint16_t port) {
  if (!tls || !hostname)
    return false;

  SSL_SESSION *cached_session = get_cached_session(hostname, port);
  if (cached_session) {

    if (SSL_set_session(tls->ssl, cached_session) == 1) {
      tls->cached_session = cached_session;
      tls->session_resumption_attempted = true;
      return true;
    } else {

      SSL_SESSION_free(cached_session);
      invalidate_session(hostname, port);
    }
  }

  return false;
}

static bool tls_context_save_session(tls_context_t *tls, const char *hostname,
                                     uint16_t port) {
  if (!tls || !tls->ssl || !hostname)
    return false;

  if (!tls->handshake_complete)
    return false;

  SSL_SESSION *session = SSL_get1_session(tls->ssl);
  if (session) {

    if (!SSL_session_reused(tls->ssl)) {
      bool stored = store_session(hostname, port, session);
      SSL_SESSION_free(session);
      return stored;
    } else {

      tls_session_cache_entry_t *entry = find_session(hostname, port);
      if (entry) {
        entry->last_used_ms = fetch_get_time_ms();
        entry->use_count++;
      }
      SSL_SESSION_free(session);
      return true;
    }
  }

  return false;
}

static bool tls_context_check_session_reuse(tls_context_t *tls) {
  if (!tls || !tls->ssl)
    return false;

  if (tls->handshake_complete) {
    tls->session_reused = SSL_session_reused(tls->ssl);
    return tls->session_reused;
  }

  return false;
}

#endif

static pooled_connection_t *pooled_connection_new(FETCH_SOCKET socket,
                                                  const char *host,
                                                  uint16_t port, bool is_tls,
                                                  tls_context_t *tls_context) {
  if (socket == FETCH_INVALID_SOCKET || !host)
    return NULL;

  pooled_connection_t *conn = calloc(1, sizeof(pooled_connection_t));
  if (!conn)
    return NULL;

  conn->host = strndup(host, FETCH_MAX_HOSTNAME_LENGTH);
  if (!conn->host) {
    free(conn);
    return NULL;
  }

  conn->socket = socket;
  conn->port = port;
  conn->last_used_ms = fetch_get_time_ms();
  conn->keep_alive_timeout_ms = g_fetch_config.keep_alive_timeout_ms;
  conn->in_use = false;
  conn->validated = false;
#if defined(LIBFETCH_TLS_ENABLED)
  conn->is_tls = is_tls;
  conn->tls_context = tls_context;
#else
  conn->is_tls = false;
#endif
  conn->next = NULL;
  conn->prev = NULL;

  return conn;
}

static void pooled_connection_free(pooled_connection_t *conn) {
  if (!conn)
    return;

  if (conn->socket != FETCH_INVALID_SOCKET) {
    fetch_close_socket(conn->socket);
  }

#if defined(LIBFETCH_TLS_ENABLED)
  if (conn->tls_context) {
    tls_context_free(conn->tls_context);
    conn->tls_context = NULL;
  }
#endif

  free(conn->host);
  free(conn);
}

static bool pooled_connection_is_valid(pooled_connection_t *conn) {
  if (!conn || conn->socket == FETCH_INVALID_SOCKET)
    return false;

  const uint64_t current_time = fetch_get_time_ms();

  if (current_time - conn->last_used_ms > conn->keep_alive_timeout_ms)
    return false;

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);

  if (getpeername(conn->socket, (struct sockaddr *)&addr, &addr_len) != 0) {
    return false;
  }

#if defined(LIBFETCH_TLS_ENABLED)

  if (conn->is_tls && conn->tls_context) {

    if (!conn->tls_context->handshake_complete) {
      return false;
    }

    if (!conn->tls_context->ssl) {
      return false;
    }

    if (conn->tls_context->cached_session) {

      time_t current_time_sec = time(NULL);
      if (SSL_SESSION_get_time_ex(conn->tls_context->cached_session) +
              SSL_SESSION_get_timeout(conn->tls_context->cached_session) <
          current_time_sec) {
        return false;
      }
    }
  }
#endif

  return true;
}

static connection_pool_t *find_or_create_pool(const char *host, uint16_t port) {
  if (!host)
    return NULL;

  connection_pool_t *pool = g_pool_manager.pools;
  while (pool) {
    if (pool->port == port && fetch_strcasecmp(pool->host, host) == 0) {
      return pool;
    }
    pool = pool->next;
  }

  pool = calloc(1, sizeof(connection_pool_t));
  if (!pool)
    return NULL;

  pool->host = strndup(host, FETCH_MAX_HOSTNAME_LENGTH);
  pool->port = port;
  pool->max_per_host = g_fetch_config.max_connections_per_host;
  pool->last_cleanup_ms = fetch_get_time_ms();

  if (!pool->host) {
    free(pool);
    return NULL;
  }

  pool->next = g_pool_manager.pools;
  g_pool_manager.pools = pool;

  return pool;
}

static void remove_from_available(connection_pool_t *pool,
                                  pooled_connection_t *conn) {
  if (!pool || !conn)
    return;

  if (conn->prev)
    conn->prev->next = conn->next;
  else
    pool->available = conn->next;

  if (conn->next)
    conn->next->prev = conn->prev;
  else
    pool->available_tail = conn->prev;

  conn->next = conn->prev = NULL;
  pool->available_count--;
  g_pool_manager.total_pooled--;
}

static void add_to_available(connection_pool_t *pool,
                             pooled_connection_t *conn) {
  if (!pool || !conn)
    return;

  conn->next = pool->available;
  conn->prev = NULL;

  if (pool->available)
    pool->available->prev = conn;
  else
    pool->available_tail = conn;

  pool->available = conn;
  pool->available_count++;
  g_pool_manager.total_pooled++;
}

static void cleanup_expired_connections(connection_pool_t *pool) {
  if (!pool)
    return;

  const uint64_t current_time = fetch_get_time_ms();

  if (current_time - pool->last_cleanup_ms <
      g_fetch_config.pool_cleanup_interval_ms)
    return;

  pool->last_cleanup_ms = current_time;

  pooled_connection_t *conn = pool->available_tail;
  while (conn) {
    pooled_connection_t *prev = conn->prev;

    if (!pooled_connection_is_valid(conn)) {
      remove_from_available(pool, conn);
      pooled_connection_free(conn);
    }

    conn = prev;
  }
}

static void evict_if_needed(connection_pool_t *pool) {
  if (!pool)
    return;

  while (pool->available_count > 0 &&
         (pool->available_count + pool->active_count) > pool->max_per_host) {
    pooled_connection_t *oldest = pool->available_tail;
    if (oldest) {
      remove_from_available(pool, oldest);
      pooled_connection_free(oldest);
    }
  }

  while (g_pool_manager.total_pooled > g_fetch_config.max_pooled_connections) {

    pooled_connection_t *oldest = NULL;
    connection_pool_t *oldest_pool = NULL;
    uint64_t oldest_time = UINT64_MAX;

    connection_pool_t *current_pool = g_pool_manager.pools;
    while (current_pool) {
      if (current_pool->available_tail &&
          current_pool->available_tail->last_used_ms < oldest_time) {
        oldest = current_pool->available_tail;
        oldest_pool = current_pool;
        oldest_time = oldest->last_used_ms;
      }
      current_pool = current_pool->next;
    }

    if (oldest && oldest_pool) {
      remove_from_available(oldest_pool, oldest);
      pooled_connection_free(oldest);
    } else {
      break;
    }
  }
}

static pooled_connection_t *
acquire_pooled_connection(const char *host, uint16_t port, bool is_tls) {
  if (!host)
    return NULL;

  connection_pool_t *pool = find_or_create_pool(host, port);
  if (!pool)
    return NULL;

  cleanup_expired_connections(pool);

  pooled_connection_t *conn = pool->available;
  while (conn) {
    pooled_connection_t *next = conn->next;

    bool matches = true;
#if defined(LIBFETCH_TLS_ENABLED)
    if (conn->is_tls != is_tls) {
      matches = false;
    }
#else
    if (is_tls) {
      matches = false;
    }
#endif

    if (matches && pooled_connection_is_valid(conn)) {

      remove_from_available(pool, conn);
      pool->active_count++;

      conn->last_used_ms = fetch_get_time_ms();
      conn->in_use = true;

      return conn;
    } else {

      remove_from_available(pool, conn);
      pooled_connection_free(conn);
    }

    conn = next;
  }

  return NULL;
}

static bool return_connection_to_pool(FETCH_SOCKET socket, const char *host,
                                      uint16_t port, bool keep_alive,
                                      bool is_tls, tls_context_t *tls_context) {
  if (socket == FETCH_INVALID_SOCKET || !host || !keep_alive) {
    if (socket != FETCH_INVALID_SOCKET)
      fetch_close_socket(socket);
#if defined(LIBFETCH_TLS_ENABLED)
    if (tls_context)
      tls_context_free(tls_context);
#endif
    return false;
  }

  connection_pool_t *pool = find_or_create_pool(host, port);
  if (!pool) {
    fetch_close_socket(socket);
#if defined(LIBFETCH_TLS_ENABLED)
    if (tls_context)
      tls_context_free(tls_context);
#endif
    return false;
  }

  pool->active_count--;

  pooled_connection_t *conn =
      pooled_connection_new(socket, host, port, is_tls, tls_context);
  if (!conn) {
    fetch_close_socket(socket);
#if defined(LIBFETCH_TLS_ENABLED)
    if (tls_context)
      tls_context_free(tls_context);
#endif
    return false;
  }

  add_to_available(pool, conn);
  evict_if_needed(pool);

  return true;
}

static uint64_t fetch_next_connection_id(void) {
  return fetch_atomic_inc(&g_event_loop.next_connection_id);
}

static void insert_timer(fetch_timer_t *timer) {
  if (!timer)
    return;

  fetch_timer_t **current = &g_event_loop.timers;

  while (*current && (*current)->expiry_time_ms <= timer->expiry_time_ms) {
    current = &(*current)->next;
  }

  timer->next = *current;
  *current = timer;
}

static fetch_timer_t *extract_expired_timers(uint64_t current_time_ms) {
  fetch_timer_t *expired = NULL;
  fetch_timer_t **current = &g_event_loop.timers;

  while (*current && (*current)->expiry_time_ms <= current_time_ms) {
    fetch_timer_t *timer = *current;
    *current = timer->next;

    timer->next = expired;
    expired = timer;
  }

  return expired;
}

static bool add_connection_timeout(fetch_connection_t *conn) {
  if (!conn) {
    return true;
  }

  const uint64_t timeout_ms = get_connection_timeout_ms(conn);
  if (timeout_ms == 0) {
    return true;
  }

  fetch_timer_t *timer = malloc(sizeof(fetch_timer_t));
  if (!timer)
    return false;

  timer->expiry_time_ms = conn->start_time_ms + timeout_ms;
  timer->connection_id = conn->connection_id;
  timer->next = NULL;

  insert_timer(timer);
  return true;
}

static void remove_connection_timeout(uint64_t connection_id) {
  fetch_timer_t **current = &g_event_loop.timers;

  while (*current) {
    if ((*current)->connection_id == connection_id) {
      fetch_timer_t *timer = *current;
      *current = timer->next;
      free(timer);
      return;
    }
    current = &(*current)->next;
  }
}

#if defined(_WIN32) || defined(_WIN64)

static win_io_context_t *create_win_io_context(io_operation_t op, SOCKET socket,
                                               fetch_connection_t *conn) {
  win_io_context_t *ctx = calloc(1, sizeof(win_io_context_t));
  if (!ctx) {
    return NULL;
  }

  ctx->operation = op;
  ctx->socket = socket;
  ctx->conn = conn;
  ctx->wsa_buf.buf = ctx->buffer;
  ctx->wsa_buf.len = sizeof(ctx->buffer);

  return ctx;
}

static void free_win_io_context(win_io_context_t *ctx) {
  if (ctx) {
    free(ctx);
  }
}
#endif

static fetch_connection_t *fetch_connection_new(fetch_promise_t *promise,
                                                fetch_request_t *request) {
  if (!promise || !request || !request->url) {
    return NULL;
  }

  fetch_connection_t *conn = calloc(1, sizeof(fetch_connection_t));
  if (!conn) {
    return NULL;
  }

  conn->connection_id = fetch_next_connection_id();
  conn->promise = promise;
  conn->request = request;
  conn->socket = FETCH_INVALID_SOCKET;
  conn->state = CONN_STATE_NONE;
  conn->addr_resolved = false;
  conn->response_supports_keep_alive = false;
  conn->dns_request = NULL;

  fetch_body_t *body = get_connection_body(conn);
  if (body && body->type == FETCH_BODY_FILE) {
    conn->send_mode = SEND_MODE_FILE;
    memset(&conn->send_state.file, 0, sizeof(conn->send_state.file));

    conn->send_state.file.use_chunked_encoding =
        (body->data.file.continue_cb != NULL);
    if (conn->send_state.file.use_chunked_encoding) {
      conn->send_state.file.chunk_state = CHUNK_STATE_HEADER;
    }
  } else {
    conn->send_mode = SEND_MODE_MEMORY;
  }

  conn->start_time_ms = fetch_get_time_ms();
  conn->last_activity_ms = conn->start_time_ms;

  conn->redirect_count = 0;
  conn->following_redirect = false;
  conn->redirect_url = NULL;

  conn->response_capacity = 8192;
  conn->response_buffer = malloc(conn->response_capacity);
  if (!conn->response_buffer) {
    goto error_cleanup;
  }

  const fetch_url_t *url = request->url;

  conn->host = strdup(url->hostname);
  if (!conn->host) {
    goto error_cleanup;
  }

  conn->port = url->port;
  conn->host_type = url->host_type;
  conn->is_https = url->is_https;

#if defined(LIBFETCH_TLS_ENABLED)

  if (conn->is_https) {
    conn->tls = tls_context_new(url->hostname);
    if (!conn->tls) {
      goto error_cleanup;
    }

    tls_context_prepare_session_resumption(conn->tls, url->hostname, url->port);
  }
#else

  if (url->is_https) {
    goto error_cleanup;
  }
#endif

#if defined(_WIN32) || defined(_WIN64)
  conn->current_io_ctx = NULL;
  conn->socket_bound = false;
#else
  conn->events = 0;
  conn->pending_op = 0;
#endif

  return conn;

error_cleanup:
  if (conn) {
    fetch_request_free(conn->request);
    free(conn->response_buffer);
    free(conn->host);
#if defined(LIBFETCH_TLS_ENABLED)
    if (conn->tls) {
      tls_context_free(conn->tls);
    }
#endif
    free(conn);
  }
  return NULL;
}

#if defined(_WIN32) || defined(_WIN64)

static inline void remove_socket_from_event_system(FETCH_SOCKET socket) {
  (void)socket;
}
#elif defined(__linux__)
static void remove_socket_from_epoll(FETCH_SOCKET socket);
static inline void remove_socket_from_event_system(FETCH_SOCKET socket) {
  remove_socket_from_epoll(socket);
}
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
static void remove_socket_from_kqueue(FETCH_SOCKET socket);
static inline void remove_socket_from_event_system(FETCH_SOCKET socket) {
  remove_socket_from_kqueue(socket);
}
#else

static inline void remove_socket_from_event_system(FETCH_SOCKET socket) {
  (void)socket;
}
#endif

static void fetch_connection_free(fetch_connection_t *conn) {
  if (!conn)
    return;

  if (!conn->request) {
    return;
  }

  if (conn->promise) {
    if (!conn->promise->detached) {
      conn->promise->internal_state = NULL;
    }

    conn->promise = NULL;
  }

  if (conn->socket != FETCH_INVALID_SOCKET) {
    remove_socket_from_event_system(conn->socket);
    fetch_close_socket(conn->socket);
    conn->socket = FETCH_INVALID_SOCKET;
  }

#if defined(_WIN32) || defined(_WIN64)
  if (conn->current_io_ctx) {
    free_win_io_context(conn->current_io_ctx);
    conn->current_io_ctx = NULL;
  }
#endif

  remove_connection_timeout(conn->connection_id);

  if (conn->dns_request) {
    dns_request_cancel(conn->dns_request);
    conn->dns_request = NULL;
  }

  fetch_request_free(conn->request);
  conn->request = NULL;

  free(conn->host);
  conn->host = NULL;

  free(conn->request_buffer);
  conn->request_buffer = NULL;

  free(conn->response_buffer);
  conn->response_buffer = NULL;

  free(conn->redirect_url);
  conn->redirect_url = NULL;

  if (conn->parse_ctx) {
    http_parse_context_free(conn->parse_ctx);
    conn->parse_ctx = NULL;
  }

#if defined(LIBFETCH_TLS_ENABLED)
  if (conn->tls) {
    tls_context_free(conn->tls);
    conn->tls = NULL;
  }
#endif

  if (conn->next)
    conn->next->prev = conn->prev;
  if (conn->prev)
    conn->prev->next = conn->next;

  if (g_event_loop.active_connections == conn) {
    g_event_loop.active_connections = conn->next;
  }
  if (g_event_loop.completed_connections == conn) {
    g_event_loop.completed_connections = conn->next;
  }

  conn->next = NULL;
  conn->prev = NULL;

  free(conn);
}

static void add_active_connection(fetch_connection_t *conn) {
  if (!conn)
    return;

  conn->next = g_event_loop.active_connections;
  conn->prev = NULL;

  if (g_event_loop.active_connections) {
    g_event_loop.active_connections->prev = conn;
  }

  g_event_loop.active_connections = conn;
  g_event_loop.active_count++;
}

static void remove_active_connection(fetch_connection_t *conn) {
  if (!conn)
    return;

  if (conn->next)
    conn->next->prev = conn->prev;
  if (conn->prev)
    conn->prev->next = conn->next;

  if (g_event_loop.active_connections == conn) {
    g_event_loop.active_connections = conn->next;
  }

  if (g_event_loop.active_count > 0) {
    g_event_loop.active_count--;
  }

  conn->next = conn->prev = NULL;
}

static void move_to_completed(fetch_connection_t *conn) {
  if (!conn)
    return;

  remove_active_connection(conn);

  const fetch_connection_t *check = g_event_loop.completed_connections;
  while (check) {
    if (check == conn) {

      return;
    }
    check = check->next;
  }

  conn->next = g_event_loop.completed_connections;
  conn->prev = NULL;

  if (g_event_loop.completed_connections) {
    g_event_loop.completed_connections->prev = conn;
  }

  g_event_loop.completed_connections = conn;
}

static fetch_connection_t *find_connection_by_id(uint64_t connection_id) {
  fetch_connection_t *conn = g_event_loop.active_connections;

  while (conn) {
    if (conn->connection_id == connection_id) {
      return conn;
    }
    conn = conn->next;
  }

  return NULL;
}

static void set_connection_error(fetch_connection_t *conn, fetch_error_t error,
                                 const char *message) {
  if (!conn || conn->state == CONN_STATE_ERROR ||
      conn->state == CONN_STATE_CANCELLED ||
      conn->state == CONN_STATE_COMPLETE) {
    return;
  }

  conn->state = CONN_STATE_ERROR;

  if (conn->parse_ctx) {
    http_parse_context_free(conn->parse_ctx);
    conn->parse_ctx = NULL;
  }

  if (conn->promise && !conn->promise->detached) {
    conn->promise->state = FETCH_PROMISE_REJECTED;
    conn->promise->error = error;

    free((char *)conn->promise->error_message);
    conn->promise->error_message =
        strdup(message ? message : fetch_error_to_string(error));
  }

  remove_connection_timeout(conn->connection_id);

  move_to_completed(conn);

  fetch_atomic_inc(&g_event_loop.failed_requests);
}

static void set_connection_cancelled(fetch_connection_t *conn,
                                     const char *reason) {
  if (!conn || conn->state == CONN_STATE_ERROR ||
      conn->state == CONN_STATE_CANCELLED ||
      conn->state == CONN_STATE_COMPLETE) {
    return;
  }

  conn->state = CONN_STATE_CANCELLED;
  fetch_atomic_store(&conn->cancelled, true);
  conn->cancel_reason = reason;

  if (conn->parse_ctx) {
    http_parse_context_free(conn->parse_ctx);
    conn->parse_ctx = NULL;
  }

  if (conn->promise && !conn->promise->detached) {
    conn->promise->state = FETCH_PROMISE_REJECTED;
    conn->promise->error = FETCH_ERROR_ABORTED;

    free((void *)conn->promise->error_message);
    conn->promise->error_message =
        strdup(reason ? reason : "Request cancelled");
  }

  remove_connection_timeout(conn->connection_id);

  move_to_completed(conn);

  fetch_atomic_inc(&g_event_loop.cancelled_requests);
}

static void set_connection_complete(fetch_connection_t *conn,
                                    fetch_response_t *response) {
  if (!conn || !response) {
    return;
  }

  if (conn->state == CONN_STATE_ERROR || conn->state == CONN_STATE_CANCELLED ||
      conn->state == CONN_STATE_COMPLETE) {
    return;
  }

  conn->state = CONN_STATE_COMPLETE;

  response->redirected = (conn->redirect_count > 0);

  if (conn->promise && !conn->promise->detached) {
    conn->promise->state = FETCH_PROMISE_FULFILLED;
    conn->promise->response = response;
    conn->promise->error = FETCH_ERROR_NONE;

    free((void *)conn->promise->error_message);
    conn->promise->error_message = NULL;
  } else {
    fetch_response_free(response);
  }

  remove_connection_timeout(conn->connection_id);

  bool should_pool = false;
  tls_context_t *tls_context_to_pool = NULL;

  if (conn->socket != FETCH_INVALID_SOCKET && conn->host) {
#if defined(LIBFETCH_TLS_ENABLED)
    if (conn->is_https && conn->tls) {

      should_pool = conn->response_supports_keep_alive &&
                    get_connection_keepalive(conn) &&
                    conn->tls->handshake_complete;

      if (should_pool) {

        tls_context_save_session(conn->tls, conn->host, conn->port);

        tls_context_to_pool = conn->tls;
        conn->tls = NULL;
      }
    } else {

      should_pool =
          conn->response_supports_keep_alive && get_connection_keepalive(conn);
    }
#else

    should_pool =
        conn->response_supports_keep_alive && get_connection_keepalive(conn);
#endif
  }

  if (should_pool) {
    if (return_connection_to_pool(conn->socket, conn->host, conn->port, true,
                                  conn->is_https, tls_context_to_pool)) {
      conn->socket = FETCH_INVALID_SOCKET;
    } else {

#if defined(LIBFETCH_TLS_ENABLED)
      if (tls_context_to_pool) {
        tls_context_free(tls_context_to_pool);
      }
#endif
    }
  } else {

#if defined(LIBFETCH_TLS_ENABLED)
    if (tls_context_to_pool) {
      tls_context_free(tls_context_to_pool);
    }
#endif
  }

  move_to_completed(conn);
  fetch_atomic_inc(&g_event_loop.successful_requests);
}

static void update_connection_activity(fetch_connection_t *conn) {
  if (conn) {
    conn->last_activity_ms = fetch_get_time_ms();
  }
}

static bool is_connection_timed_out(fetch_connection_t *conn,
                                    uint64_t current_time_ms) {
  if (!conn) {
    return false;
  }

  const uint64_t timeout_ms = get_connection_timeout_ms(conn);
  if (timeout_ms == 0) {
    return false;
  }

  return (current_time_ms - conn->start_time_ms) >= timeout_ms;
}

static void process_completed_connections(void) {
  fetch_connection_t *conn = g_event_loop.completed_connections;

  while (conn) {
    fetch_connection_t *next = conn->next;

    if (conn->next)
      conn->next->prev = conn->prev;
    if (conn->prev)
      conn->prev->next = conn->next;

    if (g_event_loop.completed_connections == conn) {
      g_event_loop.completed_connections = conn->next;
    }

    if (conn->promise && !conn->promise->detached) {

      if (conn->promise->state == FETCH_PROMISE_FULFILLED &&
          conn->promise->on_fulfilled) {
        conn->promise->on_fulfilled(conn->promise->response,
                                    conn->promise->userdata);
      } else if (conn->promise->state == FETCH_PROMISE_REJECTED &&
                 conn->promise->on_rejected) {
        conn->promise->on_rejected(conn->promise->error,
                                   conn->promise->error_message,
                                   conn->promise->userdata);
      }
    }

    fetch_connection_free(conn);
    conn = next;
  }
}

static bool is_redirect_status(int status_code) {
  return (status_code == 301 || status_code == 302 || status_code == 303 ||
          status_code == 307 || status_code == 308);
}

static char *resolve_redirect_url(const fetch_url_t *base_url,
                                  const char *location) {
  if (!base_url || !location) {
    return NULL;
  }

  if (strstr(location, "://") != NULL) {
    return strndup(location, FETCH_MAX_URL_LENGTH);
  }

  size_t result_capacity = strlen(base_url->protocol) + 3 +
                           strlen(base_url->hostname) +
                           (base_url->host_type == HOST_TYPE_IPV6 ? 2 : 0) + 6 +
                           strlen(location) + 1;

  char *result = malloc(result_capacity);
  if (!result) {
    return NULL;
  }

  if (base_url->host_type == HOST_TYPE_IPV6) {

    if ((base_url->port == 80 && !base_url->is_https) ||
        (base_url->port == 443 && base_url->is_https)) {

      snprintf(result, result_capacity, "%s://[%s]%s%s", base_url->protocol,
               base_url->hostname, location[0] == '/' ? "" : "/", location);
    } else {

      snprintf(result, result_capacity, "%s://[%s]:%u%s%s", base_url->protocol,
               base_url->hostname, base_url->port,
               location[0] == '/' ? "" : "/", location);
    }
  } else {

    if ((base_url->port == 80 && !base_url->is_https) ||
        (base_url->port == 443 && base_url->is_https)) {

      snprintf(result, result_capacity, "%s://%s%s%s", base_url->protocol,
               base_url->hostname, location[0] == '/' ? "" : "/", location);
    } else {

      snprintf(result, result_capacity, "%s://%s:%u%s%s", base_url->protocol,
               base_url->hostname, base_url->port,
               location[0] == '/' ? "" : "/", location);
    }
  }

  return result;
}

static http_method_t get_redirect_method(http_method_t original_method,
                                         int status_code) {

  if (status_code == 303) {
    return HTTP_METHOD_GET;
  }

  if ((status_code == 301 || status_code == 302) &&
      original_method == HTTP_METHOD_POST) {
    return HTTP_METHOD_GET;
  }

  return original_method;
}

static bool reset_connection_for_redirect(fetch_connection_t *conn,
                                          const char *new_url,
                                          http_method_t new_method) {
  if (!conn || !new_url || !conn->request) {
    return false;
  }

  free(conn->redirect_url);
  conn->redirect_url = strndup(new_url, FETCH_MAX_URL_LENGTH);
  if (!conn->redirect_url) {
    return false;
  }

  fetch_url_t *new_parsed_url = fetch_url_parse(new_url);
  if (!new_parsed_url) {
    return false;
  }

  bool need_dns_resolution = true;
  if (conn->host && new_parsed_url->hostname &&
      fetch_strcasecmp(conn->host, new_parsed_url->hostname) == 0 &&
      conn->port == new_parsed_url->port) {
    need_dns_resolution = false;
  }

  if (conn->socket != FETCH_INVALID_SOCKET) {
    fetch_close_socket(conn->socket);
    conn->socket = FETCH_INVALID_SOCKET;
  }

  if (conn->dns_request) {
    dns_request_cancel(conn->dns_request);
    conn->dns_request = NULL;
  }

#if defined(LIBFETCH_TLS_ENABLED)

  if (conn->tls) {
    tls_context_free(conn->tls);
    conn->tls = NULL;
  }

  if (new_parsed_url->is_https) {
    conn->tls = tls_context_new(new_parsed_url->hostname);
    if (!conn->tls) {
      fetch_url_free(new_parsed_url);
      return false;
    }
  }
#else

  if (new_parsed_url->is_https) {
    fetch_url_free(new_parsed_url);
    return false;
  }
#endif

  conn->is_https = new_parsed_url->is_https;

#if defined(_WIN32) || defined(_WIN64)
  if (conn->current_io_ctx) {
    free_win_io_context(conn->current_io_ctx);
    conn->current_io_ctx = NULL;
  }
  conn->socket_bound = false;
#endif

  if (conn->parse_ctx) {
    http_parse_context_free(conn->parse_ctx);
    conn->parse_ctx = NULL;
  }

  if (need_dns_resolution) {
    conn->addr_resolved = false;
    memset(&conn->addr, 0, sizeof(conn->addr));

    free(conn->host);
    conn->host = strdup(new_parsed_url->hostname);
    if (!conn->host) {
      fetch_url_free(new_parsed_url);
      return false;
    }
    conn->port = new_parsed_url->port;
    conn->host_type = new_parsed_url->host_type;
  }

  fetch_url_free(conn->request->url);
  conn->request->url = new_parsed_url;
  conn->request->method = new_method;

  if (new_method == HTTP_METHOD_GET && conn->request->body) {
    fetch_body_free(conn->request->body);
    conn->request->body = NULL;
  }

  free(conn->request_buffer);
  conn->request_buffer = NULL;
  conn->request_size = 0;
  conn->bytes_sent = 0;

  conn->response_size = 0;
  conn->bytes_received = 0;

  conn->last_activity_ms = fetch_get_time_ms();

  return true;
}

#if defined(_WIN32) || defined(_WIN64)

static bool init_event_loop_windows(void) {
  bool success = false;

  g_event_loop.iocp = NULL;
  g_event_loop.wakeup_event = NULL;

  g_event_loop.iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
  if (g_event_loop.iocp == NULL) {
    goto cleanup;
  }

  g_event_loop.wakeup_event = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (g_event_loop.wakeup_event == NULL) {
    goto cleanup;
  }

  success = true;

cleanup:
  if (!success) {
    if (g_event_loop.wakeup_event) {
      CloseHandle(g_event_loop.wakeup_event);
      g_event_loop.wakeup_event = NULL;
    }
    if (g_event_loop.iocp) {
      CloseHandle(g_event_loop.iocp);
      g_event_loop.iocp = NULL;
    }
  }

  return success;
}

static void cleanup_event_loop_windows(void) {
  if (g_event_loop.iocp) {
    CloseHandle(g_event_loop.iocp);
    g_event_loop.iocp = NULL;
  }

  if (g_event_loop.wakeup_event) {
    CloseHandle(g_event_loop.wakeup_event);
    g_event_loop.wakeup_event = NULL;
  }
}

static bool add_socket_to_iocp(FETCH_SOCKET socket, fetch_connection_t *conn) {
  HANDLE result = CreateIoCompletionPort((HANDLE)socket, g_event_loop.iocp,
                                         (ULONG_PTR)conn, 0);

  return (result != NULL);
}

static void wakeup_event_loop_windows(void) {
  if (g_event_loop.wakeup_event) {
    SetEvent(g_event_loop.wakeup_event);
  }
}
#elif defined(__linux__)

static bool init_event_loop_linux(void) {
  bool success = false;

  g_event_loop.epoll_fd = -1;
  g_event_loop.eventfd = -1;
  g_event_loop.timerfd = -1;

  g_event_loop.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (g_event_loop.epoll_fd == -1) {
    goto cleanup;
  }

  g_event_loop.eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (g_event_loop.eventfd == -1) {
    goto cleanup;
  }

  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.ptr = NULL;

  if (epoll_ctl(g_event_loop.epoll_fd, EPOLL_CTL_ADD, g_event_loop.eventfd,
                &ev) == -1) {
    goto cleanup;
  }

  g_event_loop.timerfd =
      timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (g_event_loop.timerfd == -1) {
    goto cleanup;
  }

  ev.events = EPOLLIN;
  ev.data.ptr = (void *)0x1;

  if (epoll_ctl(g_event_loop.epoll_fd, EPOLL_CTL_ADD, g_event_loop.timerfd,
                &ev) == -1) {
    goto cleanup;
  }

  success = true;

cleanup:
  if (!success) {
    if (g_event_loop.timerfd != -1) {
      close(g_event_loop.timerfd);
      g_event_loop.timerfd = -1;
    }
    if (g_event_loop.eventfd != -1) {
      close(g_event_loop.eventfd);
      g_event_loop.eventfd = -1;
    }
    if (g_event_loop.epoll_fd != -1) {
      close(g_event_loop.epoll_fd);
      g_event_loop.epoll_fd = -1;
    }
  }

  return success;
}

static void cleanup_event_loop_linux(void) {
  if (g_event_loop.timerfd != -1) {
    close(g_event_loop.timerfd);
    g_event_loop.timerfd = -1;
  }

  if (g_event_loop.eventfd != -1) {
    close(g_event_loop.eventfd);
    g_event_loop.eventfd = -1;
  }

  if (g_event_loop.epoll_fd != -1) {
    close(g_event_loop.epoll_fd);
    g_event_loop.epoll_fd = -1;
  }
}

static bool add_socket_to_epoll(FETCH_SOCKET socket, fetch_connection_t *conn,
                                uint32_t events) {
  struct epoll_event ev;
  ev.events = events | EPOLLET;
  ev.data.ptr = conn;

  return epoll_ctl(g_event_loop.epoll_fd, EPOLL_CTL_ADD, socket, &ev) == 0;
}

static bool modify_socket_in_epoll(FETCH_SOCKET socket,
                                   fetch_connection_t *conn, uint32_t events) {
  struct epoll_event ev;
  ev.events = events | EPOLLET;
  ev.data.ptr = conn;

  return epoll_ctl(g_event_loop.epoll_fd, EPOLL_CTL_MOD, socket, &ev) == 0;
}

static void remove_socket_from_epoll(FETCH_SOCKET socket) {
  epoll_ctl(g_event_loop.epoll_fd, EPOLL_CTL_DEL, socket, NULL);
}

static void wakeup_event_loop_linux(void) {
  if (g_event_loop.eventfd != -1) {
    uint64_t val = 1;
    ssize_t result = write(g_event_loop.eventfd, &val, sizeof(val));
    (void)result;
  }
}

static void update_timer_linux(uint64_t next_timeout_ms) {
  if (g_event_loop.timerfd == -1)
    return;

  struct itimerspec timer_spec;
  memset(&timer_spec, 0, sizeof(timer_spec));

  if (next_timeout_ms > 0) {
    uint64_t current_time_ms = fetch_get_time_ms();

    if (next_timeout_ms > current_time_ms) {
      uint64_t delay_ms = next_timeout_ms - current_time_ms;
      timer_spec.it_value.tv_sec = delay_ms / 1000;
      timer_spec.it_value.tv_nsec = (delay_ms % 1000) * 1000000;
    } else {

      timer_spec.it_value.tv_nsec = 1;
    }
  }

  timerfd_settime(g_event_loop.timerfd, 0, &timer_spec, NULL);
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)

#define KQUEUE_TIMER_IDENT 1

static bool init_event_loop_kqueue(void) {
  bool success = false;

  g_event_loop.kqueue_fd = -1;
  g_event_loop.wakeup_pipe[0] = -1;
  g_event_loop.wakeup_pipe[1] = -1;

  g_event_loop.kqueue_fd = kqueue();
  if (g_event_loop.kqueue_fd == -1) {
    goto cleanup;
  }

  if (pipe(g_event_loop.wakeup_pipe) == -1) {
    goto cleanup;
  }

  fcntl(g_event_loop.wakeup_pipe[0], F_SETFL, O_NONBLOCK);
  fcntl(g_event_loop.wakeup_pipe[1], F_SETFL, O_NONBLOCK);

  struct kevent kev;
  EV_SET(&kev, g_event_loop.wakeup_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);

  if (kevent(g_event_loop.kqueue_fd, &kev, 1, NULL, 0, NULL) == -1) {
    goto cleanup;
  }

  success = true;

cleanup:
  if (!success) {
    if (g_event_loop.wakeup_pipe[0] != -1) {
      close(g_event_loop.wakeup_pipe[0]);
      g_event_loop.wakeup_pipe[0] = -1;
    }
    if (g_event_loop.wakeup_pipe[1] != -1) {
      close(g_event_loop.wakeup_pipe[1]);
      g_event_loop.wakeup_pipe[1] = -1;
    }
    if (g_event_loop.kqueue_fd != -1) {
      close(g_event_loop.kqueue_fd);
      g_event_loop.kqueue_fd = -1;
    }
  }

  return success;
}

static void cleanup_event_loop_kqueue(void) {
  if (g_event_loop.kqueue_fd != -1) {
    close(g_event_loop.kqueue_fd);
    g_event_loop.kqueue_fd = -1;
  }

  if (g_event_loop.wakeup_pipe[0] != -1) {
    close(g_event_loop.wakeup_pipe[0]);
    g_event_loop.wakeup_pipe[0] = -1;
  }

  if (g_event_loop.wakeup_pipe[1] != -1) {
    close(g_event_loop.wakeup_pipe[1]);
    g_event_loop.wakeup_pipe[1] = -1;
  }
}

static bool add_socket_to_kqueue(FETCH_SOCKET socket, fetch_connection_t *conn,
                                 int16_t filter) {
  struct kevent kev;
  EV_SET(&kev, socket, filter, EV_ADD, 0, 0, conn);

  return kevent(g_event_loop.kqueue_fd, &kev, 1, NULL, 0, NULL) == 0;
}

static bool modify_socket_in_kqueue(FETCH_SOCKET socket,
                                    fetch_connection_t *conn, int16_t filter) {
  if (socket == FETCH_INVALID_SOCKET || g_event_loop.kqueue_fd == -1) {
    return false;
  }

  struct kevent kev[2];
  int nchanges = 0;

  EV_SET(&kev[nchanges++], socket, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&kev[nchanges++], socket, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

  kevent(g_event_loop.kqueue_fd, kev, nchanges, NULL, 0, NULL);

  EV_SET(&kev[0], socket, filter, EV_ADD | EV_ENABLE, 0, 0, conn);

  return kevent(g_event_loop.kqueue_fd, kev, 1, NULL, 0, NULL) == 0;
}

static void remove_socket_from_kqueue(FETCH_SOCKET socket) {
  if (socket == FETCH_INVALID_SOCKET || g_event_loop.kqueue_fd == -1) {
    return;
  }

  struct kevent kev[2];

  EV_SET(&kev[0], socket, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&kev[1], socket, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

  kevent(g_event_loop.kqueue_fd, kev, 2, NULL, 0, NULL);
}

static void wakeup_event_loop_kqueue(void) {
  if (g_event_loop.wakeup_pipe[1] != -1) {
    const char byte = 1;
    write(g_event_loop.wakeup_pipe[1], &byte, 1);
  }
}

#else

static bool init_event_loop_select(void) {
  bool success = false;

  g_event_loop.wakeup_pipe[0] = -1;
  g_event_loop.wakeup_pipe[1] = -1;

  FD_ZERO(&g_event_loop.read_fds);
  FD_ZERO(&g_event_loop.write_fds);
  g_event_loop.max_fd = 0;

  if (pipe(g_event_loop.wakeup_pipe) == -1) {
    goto cleanup;
  }

  fcntl(g_event_loop.wakeup_pipe[0], F_SETFL, O_NONBLOCK);
  fcntl(g_event_loop.wakeup_pipe[1], F_SETFL, O_NONBLOCK);

  success = true;

cleanup:
  if (!success) {
    if (g_event_loop.wakeup_pipe[0] != -1) {
      close(g_event_loop.wakeup_pipe[0]);
      g_event_loop.wakeup_pipe[0] = -1;
    }
    if (g_event_loop.wakeup_pipe[1] != -1) {
      close(g_event_loop.wakeup_pipe[1]);
      g_event_loop.wakeup_pipe[1] = -1;
    }
  }

  return success;
}

static void cleanup_event_loop_select(void) {
  if (g_event_loop.wakeup_pipe[0] != -1) {
    close(g_event_loop.wakeup_pipe[0]);
    g_event_loop.wakeup_pipe[0] = -1;
  }

  if (g_event_loop.wakeup_pipe[1] != -1) {
    close(g_event_loop.wakeup_pipe[1]);
    g_event_loop.wakeup_pipe[1] = -1;
  }
}

static void wakeup_event_loop_select(void) {
  if (g_event_loop.wakeup_pipe[1] != -1) {
    char byte = 1;
    write(g_event_loop.wakeup_pipe[1], &byte, 1);
  }
}

#endif

static bool init_event_loop_platform(void) {
#if defined(_WIN32) || defined(_WIN64)
  return init_event_loop_windows();
#elif defined(__linux__)
  return init_event_loop_linux();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  return init_event_loop_kqueue();
#else
  return init_event_loop_select();
#endif
}

static void cleanup_event_loop_platform(void) {
#if defined(_WIN32) || defined(_WIN64)
  cleanup_event_loop_windows();
#elif defined(__linux__)
  cleanup_event_loop_linux();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  cleanup_event_loop_kqueue();
#else
  cleanup_event_loop_select();
#endif
}

static void wakeup_event_loop(void) {
#if defined(_WIN32) || defined(_WIN64)
  wakeup_event_loop_windows();
#elif defined(__linux__)
  wakeup_event_loop_linux();
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  wakeup_event_loop_kqueue();
#else
  wakeup_event_loop_select();
#endif
}

typedef enum {
  SOCKET_OP_SUCCESS,
  SOCKET_OP_WOULD_BLOCK,
  SOCKET_OP_ERROR,
  SOCKET_OP_CLOSED,
  SOCKET_OP_IN_PROGRESS
} socket_op_result_t;

static FETCH_SOCKET create_nonblocking_socket(int family) {
  FETCH_SOCKET sock = socket(family, SOCK_STREAM, 0);
  if (sock == FETCH_INVALID_SOCKET) {
    return FETCH_INVALID_SOCKET;
  }

#if defined(_WIN32) || defined(_WIN64)
  u_long mode = 1;
  if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
    fetch_close_socket(sock);
    return FETCH_INVALID_SOCKET;
  }
#else
  const int flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
    fetch_close_socket(sock);
    return FETCH_INVALID_SOCKET;
  }
#endif

  const int reuse = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
             sizeof(reuse));

  const int nodelay = 1;
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay,
             sizeof(nodelay));

  return sock;
}

static void dns_resolution_callback(dns_result_t *result, void *user_data) {
  fetch_connection_t *conn = (fetch_connection_t *)user_data;

  if (!conn) {
    return;
  }

  conn->dns_request = NULL;

  if (!result) {
    set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                         "DNS resolution failed");
    return;
  }

  if (result->error_code != 0 || result->count == 0) {
    const char *error_msg = dns_error_string(result->error_code);
    set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION, error_msg);
    return;
  }

  dns_address_t *addr = &result->addresses[0];
  if (addr->family != AF_INET && addr->family != AF_INET6) {
    set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                         "Unsupported address family");
    return;
  }

  memset(&conn->addr, 0, sizeof(conn->addr));
  conn->addr_family = addr->family;

  if (addr->family == AF_INET) {
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&conn->addr;
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(conn->port);

#if defined(_WIN32) || defined(_WIN64)

    wchar_t wide_address[INET6_ADDRSTRLEN];
    if (MultiByteToWideChar(CP_UTF8, 0, addr->address, -1, wide_address,
                            sizeof(wide_address) / sizeof(wchar_t)) == 0) {
      set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                           "Failed to convert address string");
      return;
    }
    if (InetPtonW(AF_INET, wide_address, &addr4->sin_addr) != 1)
#else
    if (inet_pton(AF_INET, addr->address, &addr4->sin_addr) != 1)
#endif
    {
      set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                           "Invalid IPv4 address format");
      return;
    }
  } else if (addr->family == AF_INET6) {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&conn->addr;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(conn->port);

#if defined(_WIN32) || defined(_WIN64)

    wchar_t wide_address_v6[INET6_ADDRSTRLEN];
    if (MultiByteToWideChar(CP_UTF8, 0, addr->address, -1, wide_address_v6,
                            sizeof(wide_address_v6) / sizeof(wchar_t)) == 0) {
      set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                           "Failed to convert IPv6 address string");
      return;
    }
    if (InetPtonW(AF_INET6, wide_address_v6, &addr6->sin6_addr) != 1)
#else
    if (inet_pton(AF_INET6, addr->address, &addr6->sin6_addr) != 1)
#endif
    {
      set_connection_error(conn, FETCH_ERROR_DNS_RESOLUTION,
                           "Invalid IPv6 address format");
      return;
    }
  }

  conn->addr_resolved = true;
  update_connection_activity(conn);
}

static socket_op_result_t start_connect(fetch_connection_t *conn) {
  if (!conn || !conn->host)
    return SOCKET_OP_ERROR;

  pooled_connection_t *pooled =
      acquire_pooled_connection(conn->host, conn->port, conn->is_https);
  if (pooled) {

    conn->socket = pooled->socket;
    pooled->socket = FETCH_INVALID_SOCKET;

#if defined(LIBFETCH_TLS_ENABLED)
    if (pooled->is_tls && pooled->tls_context) {

      if (conn->tls) {
        tls_context_free(conn->tls);
      }
      conn->tls = pooled->tls_context;
      pooled->tls_context = NULL;
    }
#endif

    socklen_t addr_len = sizeof(conn->addr);
    if (getpeername(conn->socket, (struct sockaddr *)&conn->addr, &addr_len) ==
        0) {
      conn->addr_family = conn->addr.ss_family;
      conn->addr_resolved = true;

      conn->state = CONN_STATE_SENDING;

#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls) {
        conn->tls->handshake_complete = true;
        conn->tls->want_read = false;
        conn->tls->want_write = false;
      }
#endif

      update_connection_activity(conn);

      pooled_connection_free(pooled);
      return SOCKET_OP_SUCCESS;
    } else {

      fetch_close_socket(conn->socket);
      conn->socket = FETCH_INVALID_SOCKET;
#if defined(LIBFETCH_TLS_ENABLED)
      if (conn->tls) {
        tls_context_free(conn->tls);
        conn->tls = NULL;
      }
#endif
      pooled_connection_free(pooled);
    }
  }

#if defined(LIBFETCH_TLS_ENABLED)
  if (conn->is_https && !conn->tls) {
    conn->tls = tls_context_new(conn->host);
    if (!conn->tls) {
      return SOCKET_OP_ERROR;
    }

    tls_context_prepare_session_resumption(conn->tls, conn->host, conn->port);
  }
#endif

  if (!conn->addr_resolved) {
    if (conn->host_type == HOST_TYPE_IPV4 ||
        conn->host_type == HOST_TYPE_IPV6) {
      memset(&conn->addr, 0, sizeof(conn->addr));

      if (conn->host_type == HOST_TYPE_IPV4) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&conn->addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(conn->port);
        conn->addr_family = AF_INET;

#if defined(_WIN32) || defined(_WIN64)

        wchar_t wide_address[INET6_ADDRSTRLEN];
        if (MultiByteToWideChar(CP_UTF8, 0, conn->host, -1, wide_address,
                                sizeof(wide_address) / sizeof(wchar_t)) == 0) {
          return SOCKET_OP_ERROR;
        }
        if (InetPtonW(AF_INET, wide_address, &addr4->sin_addr) == 1)
#else
        if (inet_pton(AF_INET, conn->host, &addr4->sin_addr) == 1)
#endif
        {
          conn->addr_resolved = true;
        } else {
          return SOCKET_OP_ERROR;
        }
      } else if (conn->host_type == HOST_TYPE_IPV6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&conn->addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(conn->port);
        conn->addr_family = AF_INET6;

#if defined(_WIN32) || defined(_WIN64)

        wchar_t wide_address_v6[INET6_ADDRSTRLEN];
        if (MultiByteToWideChar(CP_UTF8, 0, conn->host, -1, wide_address_v6,
                                sizeof(wide_address_v6) / sizeof(wchar_t)) ==
            0) {
          return SOCKET_OP_ERROR;
        }
        if (InetPtonW(AF_INET6, wide_address_v6, &addr6->sin6_addr) == 1)
#else
        if (inet_pton(AF_INET6, conn->host, &addr6->sin6_addr) == 1)
#endif
        {
          conn->addr_resolved = true;
        } else {
          return SOCKET_OP_ERROR;
        }
      }
    } else {
      if (conn->dns_request) {
        return SOCKET_OP_IN_PROGRESS;
      }

      conn->dns_request = dns_resolve_async(g_dns_resolver, conn->host, NULL,
                                            dns_resolution_callback, conn);
      if (!conn->dns_request) {
        return SOCKET_OP_ERROR;
      }

      conn->state = CONN_STATE_RESOLVING;
      return SOCKET_OP_IN_PROGRESS;
    }
  }

  if (conn->socket == FETCH_INVALID_SOCKET) {
#if defined(_WIN32) || defined(_WIN64)
    conn->socket = WSASocket(conn->addr_family, SOCK_STREAM, IPPROTO_TCP, NULL,
                             0, WSA_FLAG_OVERLAPPED);
#else
    conn->socket = create_nonblocking_socket(conn->addr_family);
#endif

    if (conn->socket == FETCH_INVALID_SOCKET) {
      return SOCKET_OP_ERROR;
    }

#if defined(_WIN32) || defined(_WIN64)
    u_long mode = 1;
    if (ioctlsocket(conn->socket, FIONBIO, &mode) != 0) {
      fetch_close_socket(conn->socket);
      conn->socket = FETCH_INVALID_SOCKET;
      return SOCKET_OP_ERROR;
    }

    if (!add_socket_to_iocp(conn->socket, conn)) {
      fetch_close_socket(conn->socket);
      conn->socket = FETCH_INVALID_SOCKET;
      return SOCKET_OP_ERROR;
    }

    if (!conn->socket_bound) {
      if (conn->addr_family == AF_INET) {
        struct sockaddr_in local_addr = {0};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = 0;

        if (bind(conn->socket, (struct sockaddr *)&local_addr,
                 sizeof(local_addr)) != 0) {
          fetch_close_socket(conn->socket);
          conn->socket = FETCH_INVALID_SOCKET;
          return SOCKET_OP_ERROR;
        }
      } else if (conn->addr_family == AF_INET6) {
        struct sockaddr_in6 local_addr = {0};
        local_addr.sin6_family = AF_INET6;
        local_addr.sin6_addr = in6addr_any;
        local_addr.sin6_port = 0;

        if (bind(conn->socket, (struct sockaddr *)&local_addr,
                 sizeof(local_addr)) != 0) {
          fetch_close_socket(conn->socket);
          conn->socket = FETCH_INVALID_SOCKET;
          return SOCKET_OP_ERROR;
        }
      }
      conn->socket_bound = true;
    }

    conn->current_io_ctx =
        create_win_io_context(IO_OP_CONNECT, conn->socket, conn);
    if (!conn->current_io_ctx) {
      fetch_close_socket(conn->socket);
      conn->socket = FETCH_INVALID_SOCKET;
      return SOCKET_OP_ERROR;
    }

    DWORD bytes_sent;
    socklen_t addr_len = (conn->addr_family == AF_INET)
                             ? sizeof(struct sockaddr_in)
                             : sizeof(struct sockaddr_in6);
    if (!g_connect_ex_func(conn->socket, (struct sockaddr *)&conn->addr,
                           addr_len, NULL, 0, &bytes_sent,
                           &conn->current_io_ctx->overlapped)) {
      int error = WSAGetLastError();
      if (error != ERROR_IO_PENDING) {
        free_win_io_context(conn->current_io_ctx);
        conn->current_io_ctx = NULL;
        fetch_close_socket(conn->socket);
        conn->socket = FETCH_INVALID_SOCKET;
        return SOCKET_OP_ERROR;
      }
    }

    conn->state = CONN_STATE_CONNECTING;
    return SOCKET_OP_IN_PROGRESS;
#else
    socklen_t addr_len = (conn->addr_family == AF_INET)
                             ? sizeof(struct sockaddr_in)
                             : sizeof(struct sockaddr_in6);
    int result =
        connect(conn->socket, (struct sockaddr *)&conn->addr, addr_len);

    if (result == -1) {
      if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
        conn->state = CONN_STATE_CONNECTING;

#ifdef __linux__
        if (!add_socket_to_epoll(conn->socket, conn, EPOLLOUT)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!add_socket_to_kqueue(conn->socket, conn, EVFILT_WRITE)) {
          return SOCKET_OP_ERROR;
        }
#endif

        return SOCKET_OP_IN_PROGRESS;
      } else {
        return SOCKET_OP_ERROR;
      }
    }

    conn->state = CONN_STATE_SENDING;
    update_connection_activity(conn);
    return SOCKET_OP_SUCCESS;
#endif
  }

  return SOCKET_OP_ERROR;
}

static bool is_socket_connected(FETCH_SOCKET socket) {
  if (socket == FETCH_INVALID_SOCKET)
    return false;

  struct sockaddr_storage peer_addr;
  socklen_t peer_len = sizeof(peer_addr);
  if (getpeername(socket, (struct sockaddr *)&peer_addr, &peer_len) == 0) {
    return true;
  }

  if (errno == ENOTCONN) {
    return false;
  }

#if defined(_WIN32) || defined(_WIN64)
  int socket_error = 0;
  int len = sizeof(socket_error);
  if (getsockopt(socket, SOL_SOCKET, SO_ERROR, (char *)&socket_error, &len) ==
      0) {
    return socket_error == 0;
  }
#else
  int socket_error = 0;
  socklen_t len = sizeof(socket_error);
  if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0) {
    return socket_error == 0;
  }
#endif

  return false;
}

static socket_op_result_t check_connect_completion(fetch_connection_t *conn) {
  if (!conn || conn->socket == FETCH_INVALID_SOCKET)
    return SOCKET_OP_ERROR;

#if defined(_WIN32) || defined(_WIN64)

  return SOCKET_OP_SUCCESS;
#else

  if (!is_socket_connected(conn->socket)) {

    return SOCKET_OP_WOULD_BLOCK;
  }

  int socket_error = 0;
  socklen_t len = sizeof(socket_error);
  if (getsockopt(conn->socket, SOL_SOCKET, SO_ERROR, &socket_error, &len) !=
      0) {
    return SOCKET_OP_ERROR;
  }

  if (socket_error != 0) {

    return SOCKET_OP_ERROR;
  }

  conn->state = CONN_STATE_SENDING;
  update_connection_activity(conn);

  return SOCKET_OP_SUCCESS;
#endif
}

#if defined(LIBFETCH_TLS_ENABLED)

#if defined(_WIN32) || defined(_WIN64)
#define SOCKET_WOULD_BLOCK(err)                                                \
  ((err) == WSAEWOULDBLOCK || (err) == WSAEINPROGRESS)
#define GET_SOCKET_ERROR() WSAGetLastError()
#define SOCKET_EINTR WSAEINTR
#else
#define SOCKET_WOULD_BLOCK(err)                                                \
  ((err) == EWOULDBLOCK || (err) == EAGAIN || (err) == EINPROGRESS)
#define GET_SOCKET_ERROR() errno
#define SOCKET_EINTR EINTR
#endif
static socket_op_result_t perform_tls_handshake(fetch_connection_t *conn) {
  if (!conn || !conn->tls || !conn->tls->ssl) {
    return SOCKET_OP_ERROR;
  }

  if (conn->tls->handshake_complete) {
    return SOCKET_OP_SUCCESS;
  }

  conn->tls->want_read = false;
  conn->tls->want_write = false;

#if defined(_WIN32) || defined(_WIN64)
  if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_SEND) {
    return SOCKET_OP_IN_PROGRESS;
  }

  if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_RECV &&
      conn->current_io_ctx->bytes_transferred > 0) {
    int bio_written = BIO_write(conn->tls->rbio, conn->current_io_ctx->buffer,
                                conn->current_io_ctx->bytes_transferred);
    if (bio_written > 0) {
      free_win_io_context(conn->current_io_ctx);
      conn->current_io_ctx = NULL;
    }
  }
#else
  char network_buffer[8192];
  ssize_t received =
      recv(conn->socket, network_buffer, sizeof(network_buffer), 0);

  if (received > 0) {
    int bio_written = BIO_write(conn->tls->rbio, network_buffer, received);
    if (bio_written <= 0) {
      return SOCKET_OP_ERROR;
    }
  } else if (received < 0 && !SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR()) &&
             GET_SOCKET_ERROR() != SOCKET_EINTR) {
    return SOCKET_OP_ERROR;
  }
#endif

  int ret = SSL_do_handshake(conn->tls->ssl);

  if (ret == 1) {

    conn->tls->handshake_complete = true;

    tls_context_check_session_reuse(conn->tls);

    long verify_result = SSL_get_verify_result(conn->tls->ssl);
    if (verify_result != X509_V_OK) {
      return SOCKET_OP_ERROR;
    }

    if (conn->host) {
      tls_context_save_session(conn->tls, conn->host, conn->port);
    }

    char send_buffer[8192];
    int bio_read = BIO_read(conn->tls->wbio, send_buffer, sizeof(send_buffer));
    if (bio_read > 0) {
#if defined(_WIN32) || defined(_WIN64)
      if (conn->current_io_ctx) {
        free_win_io_context(conn->current_io_ctx);
      }

      conn->current_io_ctx =
          create_win_io_context(IO_OP_SEND, conn->socket, conn);
      if (!conn->current_io_ctx) {
        return SOCKET_OP_ERROR;
      }

      size_t copy_size = (bio_read > sizeof(conn->current_io_ctx->buffer))
                             ? sizeof(conn->current_io_ctx->buffer)
                             : bio_read;
      memcpy(conn->current_io_ctx->buffer, send_buffer, copy_size);
      conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

      DWORD bytes_sent = 0;
      if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1, &bytes_sent,
                  0, &conn->current_io_ctx->overlapped, NULL) != 0) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
          return SOCKET_OP_ERROR;
        }
      }
      return SOCKET_OP_IN_PROGRESS;
#else
      ssize_t sent = send(conn->socket, send_buffer, bio_read, MSG_NOSIGNAL);
      if (sent < 0) {
        if (SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {

          BIO_reset(conn->tls->wbio);
          BIO_write(conn->tls->wbio, send_buffer, bio_read);
          conn->tls->want_write = true;
#ifdef __linux__
          if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
            return SOCKET_OP_ERROR;
          }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
          if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
            return SOCKET_OP_ERROR;
          }
#endif
          return SOCKET_OP_WOULD_BLOCK;
        } else {
          return SOCKET_OP_ERROR;
        }
      } else if (sent < bio_read) {

        BIO_reset(conn->tls->wbio);
        BIO_write(conn->tls->wbio, send_buffer + sent, bio_read - sent);
        conn->tls->want_write = true;
#ifdef __linux__
        if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
          return SOCKET_OP_ERROR;
        }
#endif
        return SOCKET_OP_WOULD_BLOCK;
      }
#endif
    }

    return SOCKET_OP_SUCCESS;
  }

  int ssl_error = SSL_get_error(conn->tls->ssl, ret);

  char send_buffer[8192];
  int bio_read = BIO_read(conn->tls->wbio, send_buffer, sizeof(send_buffer));
  bool has_data_to_send = (bio_read > 0);

  if (has_data_to_send) {
#if defined(_WIN32) || defined(_WIN64)
    if (conn->current_io_ctx) {
      free_win_io_context(conn->current_io_ctx);
    }

    conn->current_io_ctx =
        create_win_io_context(IO_OP_SEND, conn->socket, conn);
    if (!conn->current_io_ctx) {
      return SOCKET_OP_ERROR;
    }

    size_t copy_size = (bio_read > sizeof(conn->current_io_ctx->buffer))
                           ? sizeof(conn->current_io_ctx->buffer)
                           : bio_read;
    memcpy(conn->current_io_ctx->buffer, send_buffer, copy_size);
    conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

    DWORD bytes_sent = 0;
    if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1, &bytes_sent, 0,
                &conn->current_io_ctx->overlapped, NULL) != 0) {
      int error = WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return SOCKET_OP_ERROR;
      }
    }
    return SOCKET_OP_IN_PROGRESS;
#else
    ssize_t sent = send(conn->socket, send_buffer, bio_read, MSG_NOSIGNAL);
    if (sent < 0) {
      if (SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {
        conn->tls->want_write = true;
#ifdef __linux__
        if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
          return SOCKET_OP_ERROR;
        }
#endif
        return SOCKET_OP_WOULD_BLOCK;
      }
      return SOCKET_OP_ERROR;
    } else if (sent < bio_read) {
      return SOCKET_OP_ERROR;
    }
#endif
  }

  switch (ssl_error) {
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
#if defined(_WIN32) || defined(_WIN64)
    if (conn->current_io_ctx) {
      free_win_io_context(conn->current_io_ctx);
    }

    conn->current_io_ctx =
        create_win_io_context(IO_OP_RECV, conn->socket, conn);
    if (!conn->current_io_ctx) {
      return SOCKET_OP_ERROR;
    }

    DWORD bytes_received = 0;
    DWORD flags = 0;
    if (WSARecv(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                &bytes_received, &flags, &conn->current_io_ctx->overlapped,
                NULL) != 0) {
      int error = WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return SOCKET_OP_ERROR;
      }
    }
    return SOCKET_OP_IN_PROGRESS;
#else
    if (ssl_error == SSL_ERROR_WANT_READ) {
      conn->tls->want_read = true;
      conn->tls->want_write = false;
#ifdef __linux__
      if (!modify_socket_in_epoll(conn->socket, conn, EPOLLIN)) {
        return SOCKET_OP_ERROR;
      }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
      if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_READ)) {
        return SOCKET_OP_ERROR;
      }
#endif
    } else {
      conn->tls->want_read = false;
      conn->tls->want_write = true;
#ifdef __linux__
      if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
        return SOCKET_OP_ERROR;
      }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
      if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
        return SOCKET_OP_ERROR;
      }
#endif
    }
    return SOCKET_OP_WOULD_BLOCK;
#endif

  case SSL_ERROR_ZERO_RETURN:
    return SOCKET_OP_CLOSED;

  case SSL_ERROR_SYSCALL:
    if (ret == 0) {
      return SOCKET_OP_CLOSED;
    } else if (ret == -1) {
      int sock_error = GET_SOCKET_ERROR();
      if (SOCKET_WOULD_BLOCK(sock_error) || sock_error == SOCKET_EINTR) {
#if defined(_WIN32) || defined(_WIN64)
        return SOCKET_OP_IN_PROGRESS;
#else
        return SOCKET_OP_WOULD_BLOCK;
#endif
      }
    }
    return SOCKET_OP_ERROR;

  case SSL_ERROR_SSL:

    if (conn->tls->session_resumption_attempted && conn->host) {
      invalidate_session(conn->host, conn->port);
    }
    return SOCKET_OP_ERROR;

  default:
    return SOCKET_OP_ERROR;
  }
}

#endif

static socket_op_result_t send_data(fetch_connection_t *conn) {
  if (!conn || conn->socket == FETCH_INVALID_SOCKET) {
    return SOCKET_OP_ERROR;
  }

#if defined(LIBFETCH_TLS_ENABLED)
  const bool use_tls = conn->is_https && conn->tls && conn->tls->ssl;
#else
  const bool use_tls = false;
#endif

  if (conn->send_mode == SEND_MODE_FILE) {
    fetch_body_t *body = get_connection_body(conn);
    if (!body || body->type != FETCH_BODY_FILE)
      return SOCKET_OP_ERROR;

    if (!conn->send_state.file.use_chunked_encoding &&
        body->data.file.continue_cb != NULL) {
      conn->send_state.file.use_chunked_encoding = true;
      conn->send_state.file.chunk_state = CHUNK_STATE_HEADER;
    }

#if !defined(_WIN32) && !defined(_WIN64)
  restart_chunk_logic:
#endif

    if (conn->send_state.file.headers_sent < conn->request_size) {
      size_t remaining_headers =
          conn->request_size - conn->send_state.file.headers_sent;

#if defined(LIBFETCH_TLS_ENABLED)
      if (use_tls) {
        int ret =
            SSL_write(conn->tls->ssl,
                      conn->request_buffer + conn->send_state.file.headers_sent,
                      (int)remaining_headers);

        if (ret > 0) {
          conn->send_state.file.headers_sent += (size_t)ret;
          update_connection_activity(conn);

          if (conn->send_state.file.headers_sent < conn->request_size) {
            goto handle_tls_bio;
          }

        } else {
          int ssl_error = SSL_get_error(conn->tls->ssl, ret);
          if (ssl_error == SSL_ERROR_WANT_READ ||
              ssl_error == SSL_ERROR_WANT_WRITE) {
            goto handle_tls_bio;
          }
          return SOCKET_OP_ERROR;
        }
      } else
#endif
      {
#if defined(_WIN32) || defined(_WIN64)
        if (conn->current_io_ctx &&
            conn->current_io_ctx->operation == IO_OP_SEND) {
          return SOCKET_OP_IN_PROGRESS;
        }

        if (conn->current_io_ctx &&
            conn->current_io_ctx->operation != IO_OP_SEND) {
          free_win_io_context(conn->current_io_ctx);
          conn->current_io_ctx = NULL;
        }

        if (!conn->current_io_ctx) {
          conn->current_io_ctx =
              create_win_io_context(IO_OP_SEND, conn->socket, conn);
          if (!conn->current_io_ctx) {
            return SOCKET_OP_ERROR;
          }
        }

        size_t bytes_to_send =
            remaining_headers > sizeof(conn->current_io_ctx->buffer)
                ? sizeof(conn->current_io_ctx->buffer)
                : remaining_headers;

        memcpy(conn->current_io_ctx->buffer,
               conn->request_buffer + conn->send_state.file.headers_sent,
               bytes_to_send);
        conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

        DWORD bytes_sent = 0;
        if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                    &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                    NULL) != 0) {
          int error = WSAGetLastError();
          if (error != WSA_IO_PENDING) {
            return SOCKET_OP_ERROR;
          }
        }
        return SOCKET_OP_IN_PROGRESS;
#else
        ssize_t result =
            send(conn->socket,
                 conn->request_buffer + conn->send_state.file.headers_sent,
                 remaining_headers, MSG_NOSIGNAL);

        if (result > 0) {
          conn->send_state.file.headers_sent += (size_t)result;
          update_connection_activity(conn);

          if (conn->send_state.file.headers_sent < conn->request_size) {
            return SOCKET_OP_WOULD_BLOCK;
          }

        } else if (result == 0) {
          return SOCKET_OP_CLOSED;
        } else {
          if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return SOCKET_OP_WOULD_BLOCK;
          } else {
            return SOCKET_OP_ERROR;
          }
        }
#endif
      }
    }

    if (conn->send_state.file.headers_sent >= conn->request_size) {
      if (conn->send_state.file.use_chunked_encoding) {

        switch (conn->send_state.file.chunk_state) {
        case CHUNK_STATE_HEADER: {

          if (conn->send_state.file.buffer_size == 0) {

            fetch_body_t *stream_body = get_connection_body(conn);
            if (stream_body && stream_body->data.file.continue_cb != NULL) {
              fetch_stream_result_t result = stream_body->data.file.continue_cb(
                  stream_body->data.file.userdata);

              if (result == FETCH_STREAM_DONE) {

                conn->send_state.file.chunk_header_size =
                    format_final_chunk(conn->send_state.file.chunk_header);
                conn->send_state.file.chunk_header_sent = 0;
                conn->send_state.file.chunk_state = CHUNK_STATE_FINAL;
                return SOCKET_OP_WOULD_BLOCK;
              } else if (result == FETCH_STREAM_SKIP) {

                return SOCKET_OP_WOULD_BLOCK;
              }
            }

            if (!has_more_file_data(conn)) {

              conn->send_state.file.chunk_header_size =
                  format_final_chunk(conn->send_state.file.chunk_header);
              conn->send_state.file.chunk_header_sent = 0;
              conn->send_state.file.chunk_state = CHUNK_STATE_FINAL;
              return SOCKET_OP_WOULD_BLOCK;
            }

            size_t bytes_read =
                read_file_chunk(conn, conn->send_state.file.buffer,
                                sizeof(conn->send_state.file.buffer));
            if (bytes_read == 0) {
              return SOCKET_OP_WOULD_BLOCK;
            }
            conn->send_state.file.buffer_size = bytes_read;
            conn->send_state.file.buffer_sent = 0;
          }

          if (conn->send_state.file.chunk_header_sent == 0) {
            conn->send_state.file.chunk_header_size =
                format_chunk_header(conn->send_state.file.chunk_header,
                                    conn->send_state.file.buffer_size);
          }

          size_t remaining_header = conn->send_state.file.chunk_header_size -
                                    conn->send_state.file.chunk_header_sent;

#if defined(LIBFETCH_TLS_ENABLED)
          if (use_tls) {
            int ret = SSL_write(conn->tls->ssl,
                                conn->send_state.file.chunk_header +
                                    conn->send_state.file.chunk_header_sent,
                                (int)remaining_header);

            if (ret > 0) {
              conn->send_state.file.chunk_header_sent += (size_t)ret;
              update_connection_activity(conn);

              if (conn->send_state.file.chunk_header_sent >=
                  conn->send_state.file.chunk_header_size) {
                conn->send_state.file.chunk_state = CHUNK_STATE_DATA;
#if !defined(_WIN32) && !defined(_WIN64)
                goto restart_chunk_logic;
#endif
              }
              goto handle_tls_bio;
            } else {
              int ssl_error = SSL_get_error(conn->tls->ssl, ret);
              if (ssl_error == SSL_ERROR_WANT_READ ||
                  ssl_error == SSL_ERROR_WANT_WRITE) {
                goto handle_tls_bio;
              }
              return SOCKET_OP_ERROR;
            }
          } else
#endif
          {
#if defined(_WIN32) || defined(_WIN64)
            if (conn->current_io_ctx &&
                conn->current_io_ctx->operation == IO_OP_SEND) {
              return SOCKET_OP_IN_PROGRESS;
            }

            if (!conn->current_io_ctx) {
              conn->current_io_ctx =
                  create_win_io_context(IO_OP_SEND, conn->socket, conn);
              if (!conn->current_io_ctx) {
                return SOCKET_OP_ERROR;
              }
            }

            size_t bytes_to_send =
                remaining_header > sizeof(conn->current_io_ctx->buffer)
                    ? sizeof(conn->current_io_ctx->buffer)
                    : remaining_header;

            memcpy(conn->current_io_ctx->buffer,
                   conn->send_state.file.chunk_header +
                       conn->send_state.file.chunk_header_sent,
                   bytes_to_send);
            conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

            DWORD bytes_sent = 0;
            if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                        &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                        NULL) != 0) {
              int error = WSAGetLastError();
              if (error != WSA_IO_PENDING) {
                return SOCKET_OP_ERROR;
              }
            }
            return SOCKET_OP_IN_PROGRESS;
#else
            ssize_t result = send(conn->socket,
                                  conn->send_state.file.chunk_header +
                                      conn->send_state.file.chunk_header_sent,
                                  remaining_header, MSG_NOSIGNAL);

            if (result > 0) {
              conn->send_state.file.chunk_header_sent += (size_t)result;
              update_connection_activity(conn);

              if (conn->send_state.file.chunk_header_sent >=
                  conn->send_state.file.chunk_header_size) {
                conn->send_state.file.chunk_state = CHUNK_STATE_DATA;
                goto restart_chunk_logic;
              }
              return SOCKET_OP_WOULD_BLOCK;
            } else if (result == 0) {
              return SOCKET_OP_CLOSED;
            } else {
              if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return SOCKET_OP_WOULD_BLOCK;
              } else {
                return SOCKET_OP_ERROR;
              }
            }
#endif
          }
          break;
        }

        case CHUNK_STATE_DATA: {

          size_t remaining_data = conn->send_state.file.buffer_size -
                                  conn->send_state.file.buffer_sent;

#if defined(LIBFETCH_TLS_ENABLED)
          if (use_tls) {
            int ret = SSL_write(conn->tls->ssl,
                                conn->send_state.file.buffer +
                                    conn->send_state.file.buffer_sent,
                                (int)remaining_data);

            if (ret > 0) {
              conn->send_state.file.buffer_sent += (size_t)ret;
              conn->send_state.file.file_bytes_sent += (size_t)ret;
              update_connection_activity(conn);

              if (conn->send_state.file.buffer_sent >=
                  conn->send_state.file.buffer_size) {
                conn->send_state.file.chunk_state = CHUNK_STATE_TRAILER;
#if !defined(_WIN32) && !defined(_WIN64)
                goto restart_chunk_logic;
#endif
              }
              goto handle_tls_bio;
            } else {
              int ssl_error = SSL_get_error(conn->tls->ssl, ret);
              if (ssl_error == SSL_ERROR_WANT_READ ||
                  ssl_error == SSL_ERROR_WANT_WRITE) {
                goto handle_tls_bio;
              }
              return SOCKET_OP_ERROR;
            }
          } else
#endif
          {
#if defined(_WIN32) || defined(_WIN64)
            if (conn->current_io_ctx &&
                conn->current_io_ctx->operation == IO_OP_SEND) {
              return SOCKET_OP_IN_PROGRESS;
            }

            if (!conn->current_io_ctx) {
              conn->current_io_ctx =
                  create_win_io_context(IO_OP_SEND, conn->socket, conn);
              if (!conn->current_io_ctx) {
                return SOCKET_OP_ERROR;
              }
            }

            size_t bytes_to_send =
                remaining_data > sizeof(conn->current_io_ctx->buffer)
                    ? sizeof(conn->current_io_ctx->buffer)
                    : remaining_data;

            memcpy(conn->current_io_ctx->buffer,
                   conn->send_state.file.buffer +
                       conn->send_state.file.buffer_sent,
                   bytes_to_send);
            conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

            DWORD bytes_sent = 0;
            if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                        &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                        NULL) != 0) {
              int error = WSAGetLastError();
              if (error != WSA_IO_PENDING) {
                return SOCKET_OP_ERROR;
              }
            }
            return SOCKET_OP_IN_PROGRESS;
#else
            ssize_t result = send(conn->socket,
                                  conn->send_state.file.buffer +
                                      conn->send_state.file.buffer_sent,
                                  remaining_data, MSG_NOSIGNAL);

            if (result > 0) {
              conn->send_state.file.buffer_sent += (size_t)result;
              conn->send_state.file.file_bytes_sent += (size_t)result;
              update_connection_activity(conn);

              if (conn->send_state.file.buffer_sent >=
                  conn->send_state.file.buffer_size) {
                conn->send_state.file.chunk_state = CHUNK_STATE_TRAILER;
                goto restart_chunk_logic;
              }
              return SOCKET_OP_WOULD_BLOCK;
            } else if (result == 0) {
              return SOCKET_OP_CLOSED;
            } else {
              if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return SOCKET_OP_WOULD_BLOCK;
              } else {
                return SOCKET_OP_ERROR;
              }
            }
#endif
          }
          break;
        }

        case CHUNK_STATE_TRAILER: {

          char trailer[3];
          size_t trailer_size = format_chunk_trailer(trailer);

#if defined(LIBFETCH_TLS_ENABLED)
          if (use_tls) {
            int ret = SSL_write(conn->tls->ssl, trailer, (int)trailer_size);
            if (ret > 0) {
              update_connection_activity(conn);

              conn->send_state.file.buffer_size = 0;
              conn->send_state.file.buffer_sent = 0;
              conn->send_state.file.chunk_header_sent = 0;
              conn->send_state.file.chunk_state = CHUNK_STATE_HEADER;
#if !defined(_WIN32) && !defined(_WIN64)
              goto restart_chunk_logic;
#endif
            } else {
              int ssl_error = SSL_get_error(conn->tls->ssl, ret);
              if (ssl_error == SSL_ERROR_WANT_READ ||
                  ssl_error == SSL_ERROR_WANT_WRITE) {
                goto handle_tls_bio;
              }
              return SOCKET_OP_ERROR;
            }
          } else
#endif
          {
#if defined(_WIN32) || defined(_WIN64)
            if (conn->current_io_ctx &&
                conn->current_io_ctx->operation == IO_OP_SEND) {
              return SOCKET_OP_IN_PROGRESS;
            }

            if (!conn->current_io_ctx) {
              conn->current_io_ctx =
                  create_win_io_context(IO_OP_SEND, conn->socket, conn);
              if (!conn->current_io_ctx) {
                return SOCKET_OP_ERROR;
              }
            }

            memcpy(conn->current_io_ctx->buffer, trailer, trailer_size);
            conn->current_io_ctx->wsa_buf.len = (ULONG)trailer_size;

            DWORD bytes_sent = 0;
            if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                        &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                        NULL) != 0) {
              int error = WSAGetLastError();
              if (error != WSA_IO_PENDING) {
                return SOCKET_OP_ERROR;
              }
            }
            return SOCKET_OP_IN_PROGRESS;
#else
            ssize_t result =
                send(conn->socket, trailer, trailer_size, MSG_NOSIGNAL);
            if (result > 0) {
              update_connection_activity(conn);

              conn->send_state.file.buffer_size = 0;
              conn->send_state.file.buffer_sent = 0;
              conn->send_state.file.chunk_header_sent = 0;
              conn->send_state.file.chunk_state = CHUNK_STATE_HEADER;
              goto restart_chunk_logic;
            } else if (result == 0) {
              return SOCKET_OP_CLOSED;
            } else {
              if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return SOCKET_OP_WOULD_BLOCK;
              } else {
                return SOCKET_OP_ERROR;
              }
            }
#endif
          }
          break;
        }

        case CHUNK_STATE_FINAL: {

          size_t remaining_final = conn->send_state.file.chunk_header_size -
                                   conn->send_state.file.chunk_header_sent;

#if defined(LIBFETCH_TLS_ENABLED)
          if (use_tls) {
            int ret = SSL_write(conn->tls->ssl,
                                conn->send_state.file.chunk_header +
                                    conn->send_state.file.chunk_header_sent,
                                (int)remaining_final);

            if (ret > 0) {
              conn->send_state.file.chunk_header_sent += (size_t)ret;
              update_connection_activity(conn);

              if (conn->send_state.file.chunk_header_sent >=
                  conn->send_state.file.chunk_header_size) {
                return SOCKET_OP_SUCCESS;
              }
              goto handle_tls_bio;
            } else {
              int ssl_error = SSL_get_error(conn->tls->ssl, ret);
              if (ssl_error == SSL_ERROR_WANT_READ ||
                  ssl_error == SSL_ERROR_WANT_WRITE) {
                goto handle_tls_bio;
              }
              return SOCKET_OP_ERROR;
            }
          } else
#endif
          {
#if defined(_WIN32) || defined(_WIN64)
            if (conn->current_io_ctx &&
                conn->current_io_ctx->operation == IO_OP_SEND) {
              return SOCKET_OP_IN_PROGRESS;
            }

            if (!conn->current_io_ctx) {
              conn->current_io_ctx =
                  create_win_io_context(IO_OP_SEND, conn->socket, conn);
              if (!conn->current_io_ctx) {
                return SOCKET_OP_ERROR;
              }
            }

            size_t bytes_to_send =
                remaining_final > sizeof(conn->current_io_ctx->buffer)
                    ? sizeof(conn->current_io_ctx->buffer)
                    : remaining_final;

            memcpy(conn->current_io_ctx->buffer,
                   conn->send_state.file.chunk_header +
                       conn->send_state.file.chunk_header_sent,
                   bytes_to_send);
            conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

            DWORD bytes_sent = 0;
            if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                        &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                        NULL) != 0) {
              int error = WSAGetLastError();
              if (error != WSA_IO_PENDING) {
                return SOCKET_OP_ERROR;
              }
            }
            return SOCKET_OP_IN_PROGRESS;
#else
            ssize_t result = send(conn->socket,
                                  conn->send_state.file.chunk_header +
                                      conn->send_state.file.chunk_header_sent,
                                  remaining_final, MSG_NOSIGNAL);

            if (result > 0) {
              conn->send_state.file.chunk_header_sent += (size_t)result;
              update_connection_activity(conn);

              if (conn->send_state.file.chunk_header_sent >=
                  conn->send_state.file.chunk_header_size) {
                return SOCKET_OP_SUCCESS;
              }
              return SOCKET_OP_WOULD_BLOCK;
            } else if (result == 0) {
              return SOCKET_OP_CLOSED;
            } else {
              if (errno == EWOULDBLOCK || errno == EAGAIN) {
                return SOCKET_OP_WOULD_BLOCK;
              } else {
                return SOCKET_OP_ERROR;
              }
            }
#endif
          }
          break;
        }
        }
      } else {

#if !defined(_WIN32) && !defined(_WIN64)
      restart_file_logic:
#endif

        if (conn->send_state.file.buffer_sent >=
            conn->send_state.file.buffer_size) {
          if (has_more_file_data(conn)) {
            size_t bytes_read =
                read_file_chunk(conn, conn->send_state.file.buffer,
                                sizeof(conn->send_state.file.buffer));
            if (bytes_read == 0) {
              return SOCKET_OP_SUCCESS;
            }
            conn->send_state.file.buffer_size = bytes_read;
            conn->send_state.file.buffer_sent = 0;
          } else {
            return SOCKET_OP_SUCCESS;
          }
        }

        size_t remaining_buffer = conn->send_state.file.buffer_size -
                                  conn->send_state.file.buffer_sent;

#if defined(LIBFETCH_TLS_ENABLED)
        if (use_tls) {
          int ret = SSL_write(conn->tls->ssl,
                              conn->send_state.file.buffer +
                                  conn->send_state.file.buffer_sent,
                              (int)remaining_buffer);

          if (ret > 0) {
            conn->send_state.file.buffer_sent += (size_t)ret;
            conn->send_state.file.file_bytes_sent += (size_t)ret;
            update_connection_activity(conn);

            if (conn->send_state.file.buffer_sent >=
                conn->send_state.file.buffer_size) {
              if (has_more_file_data(conn)) {
#if !defined(_WIN32) && !defined(_WIN64)
                goto restart_file_logic;
#endif
              } else {
                return SOCKET_OP_SUCCESS;
              }
            }
            goto handle_tls_bio;
          } else {
            int ssl_error = SSL_get_error(conn->tls->ssl, ret);
            if (ssl_error == SSL_ERROR_WANT_READ ||
                ssl_error == SSL_ERROR_WANT_WRITE) {
              goto handle_tls_bio;
            }
            return SOCKET_OP_ERROR;
          }
        } else
#endif
        {
#if defined(_WIN32) || defined(_WIN64)
          if (conn->current_io_ctx &&
              conn->current_io_ctx->operation == IO_OP_SEND) {
            return SOCKET_OP_IN_PROGRESS;
          }

          if (!conn->current_io_ctx) {
            conn->current_io_ctx =
                create_win_io_context(IO_OP_SEND, conn->socket, conn);
            if (!conn->current_io_ctx) {
              return SOCKET_OP_ERROR;
            }
          }

          size_t bytes_to_send =
              remaining_buffer > sizeof(conn->current_io_ctx->buffer)
                  ? sizeof(conn->current_io_ctx->buffer)
                  : remaining_buffer;

          memcpy(conn->current_io_ctx->buffer,
                 conn->send_state.file.buffer +
                     conn->send_state.file.buffer_sent,
                 bytes_to_send);
          conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

          DWORD bytes_sent = 0;
          if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                      &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                      NULL) != 0) {
            int error = WSAGetLastError();
            if (error != WSA_IO_PENDING) {
              return SOCKET_OP_ERROR;
            }
          }
          return SOCKET_OP_IN_PROGRESS;
#else
          ssize_t result = send(conn->socket,
                                conn->send_state.file.buffer +
                                    conn->send_state.file.buffer_sent,
                                remaining_buffer, MSG_NOSIGNAL);

          if (result > 0) {
            conn->send_state.file.buffer_sent += (size_t)result;
            conn->send_state.file.file_bytes_sent += (size_t)result;
            update_connection_activity(conn);

            if (conn->send_state.file.buffer_sent >=
                conn->send_state.file.buffer_size) {

              if (has_more_file_data(conn)) {
                goto restart_file_logic;
              } else {
                return SOCKET_OP_SUCCESS;
              }
            }
            return SOCKET_OP_WOULD_BLOCK;
          } else if (result == 0) {
            return SOCKET_OP_CLOSED;
          } else {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
              return SOCKET_OP_WOULD_BLOCK;
            } else {
              return SOCKET_OP_ERROR;
            }
          }
#endif
        }
      }
    }

    return SOCKET_OP_WOULD_BLOCK;
  }

  if (conn->bytes_sent >= conn->request_size) {
    return SOCKET_OP_SUCCESS;
  }

  size_t remaining = conn->request_size - conn->bytes_sent;

#if defined(LIBFETCH_TLS_ENABLED)
  if (use_tls) {

#if defined(_WIN32) || defined(_WIN64)
    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_SEND) {
      return SOCKET_OP_IN_PROGRESS;
    }

    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_RECV &&
        conn->current_io_ctx->bytes_transferred > 0) {
      int bio_written = BIO_write(conn->tls->rbio, conn->current_io_ctx->buffer,
                                  conn->current_io_ctx->bytes_transferred);
      if (bio_written <= 0) {
        return SOCKET_OP_ERROR;
      }
      free_win_io_context(conn->current_io_ctx);
      conn->current_io_ctx = NULL;
    }
#else

    char network_buffer[8192];
    ssize_t received =
        recv(conn->socket, network_buffer, sizeof(network_buffer), 0);

    if (received > 0) {
      int bio_written = BIO_write(conn->tls->rbio, network_buffer, received);
      if (bio_written <= 0) {
        return SOCKET_OP_ERROR;
      }
    } else if (received < 0 && !SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR()) &&
               GET_SOCKET_ERROR() != SOCKET_EINTR) {
      return SOCKET_OP_ERROR;
    }
#endif

    int ret = SSL_write(conn->tls->ssl, conn->request_buffer + conn->bytes_sent,
                        (int)remaining);

    if (ret > 0) {
      conn->bytes_sent += (size_t)ret;
      update_connection_activity(conn);

      if (conn->bytes_sent >= conn->request_size) {
        return SOCKET_OP_SUCCESS;
      }

    } else {
      int ssl_error = SSL_get_error(conn->tls->ssl, ret);
      if (ssl_error != SSL_ERROR_WANT_READ &&
          ssl_error != SSL_ERROR_WANT_WRITE) {
        return SOCKET_OP_ERROR;
      }
    }

  handle_tls_bio: {}
    char ssl_buffer[8192];
    int ssl_bio_read =
        BIO_read(conn->tls->wbio, ssl_buffer, sizeof(ssl_buffer));
    if (ssl_bio_read > 0) {
#if defined(_WIN32) || defined(_WIN64)
      if (!conn->current_io_ctx) {
        conn->current_io_ctx =
            create_win_io_context(IO_OP_SEND, conn->socket, conn);
        if (!conn->current_io_ctx) {
          return SOCKET_OP_ERROR;
        }
      }

      size_t copy_size = (ssl_bio_read > sizeof(conn->current_io_ctx->buffer))
                             ? sizeof(conn->current_io_ctx->buffer)
                             : ssl_bio_read;
      memcpy(conn->current_io_ctx->buffer, ssl_buffer, copy_size);
      conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

      DWORD bytes_sent = 0;
      if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1, &bytes_sent,
                  0, &conn->current_io_ctx->overlapped, NULL) != 0) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
          return SOCKET_OP_ERROR;
        }
      }
      return SOCKET_OP_IN_PROGRESS;
#else
      ssize_t sent = send(conn->socket, ssl_buffer, ssl_bio_read, MSG_NOSIGNAL);
      if (sent < 0) {
        if (SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {
          BIO_reset(conn->tls->wbio);
          BIO_write(conn->tls->wbio, ssl_buffer, ssl_bio_read);
          conn->tls->want_write = true;
#ifdef __linux__
          modify_socket_in_epoll(conn->socket, conn, EPOLLOUT);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
          modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
#endif
          return SOCKET_OP_WOULD_BLOCK;
        }
        return SOCKET_OP_ERROR;
      } else if (sent < ssl_bio_read) {
        BIO_reset(conn->tls->wbio);
        BIO_write(conn->tls->wbio, ssl_buffer + sent, ssl_bio_read - sent);
        conn->tls->want_write = true;
#ifdef __linux__
        modify_socket_in_epoll(conn->socket, conn, EPOLLOUT);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
#endif
        return SOCKET_OP_WOULD_BLOCK;
      }
#endif
    }

#if defined(_WIN32) || defined(_WIN64)
    return SOCKET_OP_IN_PROGRESS;
#else
    return SOCKET_OP_WOULD_BLOCK;
#endif
  } else
#endif
  {

#if defined(_WIN32) || defined(_WIN64)
    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_SEND) {
      return SOCKET_OP_IN_PROGRESS;
    }

    if (conn->current_io_ctx && conn->current_io_ctx->operation != IO_OP_SEND) {
      free_win_io_context(conn->current_io_ctx);
      conn->current_io_ctx = NULL;
    }

    if (!conn->current_io_ctx) {
      conn->current_io_ctx =
          create_win_io_context(IO_OP_SEND, conn->socket, conn);
      if (!conn->current_io_ctx) {
        return SOCKET_OP_ERROR;
      }
    }

    size_t bytes_to_send = remaining > sizeof(conn->current_io_ctx->buffer)
                               ? sizeof(conn->current_io_ctx->buffer)
                               : remaining;

    memcpy(conn->current_io_ctx->buffer,
           conn->request_buffer + conn->bytes_sent, bytes_to_send);
    conn->current_io_ctx->wsa_buf.len = (ULONG)bytes_to_send;

    DWORD bytes_sent = 0;
    if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1, &bytes_sent, 0,
                &conn->current_io_ctx->overlapped, NULL) != 0) {
      int error = WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return SOCKET_OP_ERROR;
      }
    }

    return SOCKET_OP_IN_PROGRESS;
#else
    ssize_t result = send(conn->socket, conn->request_buffer + conn->bytes_sent,
                          remaining, MSG_NOSIGNAL);

    if (result > 0) {
      conn->bytes_sent += (size_t)result;
      update_connection_activity(conn);

      if (conn->bytes_sent >= conn->request_size) {
        return SOCKET_OP_SUCCESS;
      } else {
#ifdef __linux__
        if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
          return SOCKET_OP_ERROR;
        }
#endif
        return SOCKET_OP_WOULD_BLOCK;
      }
    } else if (result == 0) {
      return SOCKET_OP_CLOSED;
    } else {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
#ifdef __linux__
        if (!modify_socket_in_epoll(conn->socket, conn, EPOLLOUT)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE)) {
          return SOCKET_OP_ERROR;
        }
#endif
        return SOCKET_OP_WOULD_BLOCK;
      } else {
        return SOCKET_OP_ERROR;
      }
    }
#endif
  }
}

static size_t format_chunk_header(char *buffer, size_t data_size) {
  return snprintf(buffer, 16, "%zx\r\n", data_size);
}

static size_t format_chunk_trailer(char *buffer) {
  strcpy(buffer, "\r\n");
  return 2;
}

static size_t format_final_chunk(char *buffer) {
  strcpy(buffer, "0\r\n\r\n");
  return 5;
}

static size_t read_file_chunk(fetch_connection_t *conn, char *buffer,
                              size_t buffer_size) {
  if (!conn || conn->send_mode != SEND_MODE_FILE)
    return 0;

  fetch_body_t *body = get_connection_body(conn);
  if (!body || body->type != FETCH_BODY_FILE ||
      body->data.file.handle == FETCH_INVALID_FILE_HANDLE)
    return 0;

#if defined(_WIN32) || defined(_WIN64)
  DWORD bytes_read = 0;
  if (!ReadFile(body->data.file.handle, buffer, (DWORD)buffer_size, &bytes_read,
                NULL)) {
    return 0;
  }

  body->data.file.offset += bytes_read;
  return (size_t)bytes_read;
#else

  if (body->data.file.continue_cb != NULL) {
    clearerr(body->data.file.handle);
  }

  size_t bytes_read = fread(buffer, 1, buffer_size, body->data.file.handle);
  body->data.file.offset += bytes_read;
  return bytes_read;
#endif
}

static bool has_more_file_data(fetch_connection_t *conn) {
  if (!conn || conn->send_mode != SEND_MODE_FILE)
    return false;

  fetch_body_t *body = get_connection_body(conn);
  if (!body || body->type != FETCH_BODY_FILE)
    return false;

  if (body->data.file.continue_cb != NULL) {
    return true;
  }

  if (body->data.file.size > 0) {
    return conn->send_state.file.file_bytes_sent < body->data.file.size;
  }

  return true;
}

static socket_op_result_t receive_data(fetch_connection_t *conn) {
  if (!conn || conn->socket == FETCH_INVALID_SOCKET) {
    return SOCKET_OP_ERROR;
  }

#if defined(LIBFETCH_TLS_ENABLED)
  const bool use_tls = conn->is_https && conn->tls && conn->tls->ssl;
#else
  const bool use_tls = false;
#endif

  size_t available_space = conn->response_capacity - conn->response_size;
  if (available_space < 4096) {
    const size_t new_capacity = conn->response_capacity * 2;
    char *new_buffer = realloc(conn->response_buffer, new_capacity);
    if (!new_buffer) {
      return SOCKET_OP_ERROR;
    }
    conn->response_buffer = new_buffer;
    conn->response_capacity = new_capacity;
    available_space = new_capacity - conn->response_size;
  }

#if defined(LIBFETCH_TLS_ENABLED)
  if (use_tls) {
#if defined(_WIN32) || defined(_WIN64)

    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_RECV) {
      return SOCKET_OP_IN_PROGRESS;
    }

    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_SEND &&
        conn->current_io_ctx->bytes_transferred > 0) {
      free_win_io_context(conn->current_io_ctx);
      conn->current_io_ctx = NULL;
    }
#else

    char network_buffer[8192];
    ssize_t received =
        recv(conn->socket, network_buffer, sizeof(network_buffer), 0);

    if (received > 0) {
      int bio_written = BIO_write(conn->tls->rbio, network_buffer, received);
      if (bio_written <= 0) {
        return SOCKET_OP_ERROR;
      }
    } else if (received == 0) {
      return SOCKET_OP_CLOSED;
    } else {
      if (!SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR()) &&
          GET_SOCKET_ERROR() != SOCKET_EINTR) {
        return SOCKET_OP_ERROR;
      }
    }
#endif

#if defined(_WIN32) || defined(_WIN64)
    char ssl_buffer[8192];
    int ret = SSL_read(conn->tls->ssl, ssl_buffer, sizeof(ssl_buffer));
#else
    int ret =
        SSL_read(conn->tls->ssl, conn->response_buffer + conn->response_size,
                 available_space);
#endif

    if (ret > 0) {
#if defined(_WIN32) || defined(_WIN64)
      size_t copy_size = (ret > available_space) ? available_space : ret;
      memcpy(conn->response_buffer + conn->response_size, ssl_buffer,
             copy_size);
      conn->response_size += copy_size;
      conn->bytes_received += copy_size;
#else
      conn->response_size += (size_t)ret;
      conn->bytes_received += (size_t)ret;
#endif
      update_connection_activity(conn);

      char outbound_buffer[8192];
      int outbound_bytes =
          BIO_read(conn->tls->wbio, outbound_buffer, sizeof(outbound_buffer));
      if (outbound_bytes > 0) {
#if defined(_WIN32) || defined(_WIN64)
        if (!conn->current_io_ctx) {
          conn->current_io_ctx =
              create_win_io_context(IO_OP_SEND, conn->socket, conn);
          if (!conn->current_io_ctx) {
            return SOCKET_OP_ERROR;
          }
        }

        size_t copy_size =
            (outbound_bytes > sizeof(conn->current_io_ctx->buffer))
                ? sizeof(conn->current_io_ctx->buffer)
                : outbound_bytes;
        memcpy(conn->current_io_ctx->buffer, outbound_buffer, copy_size);
        conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

        DWORD bytes_sent = 0;
        if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                    &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                    NULL) != 0) {
          int error = WSAGetLastError();
          if (error != WSA_IO_PENDING) {
            return SOCKET_OP_ERROR;
          }
        }
        return SOCKET_OP_IN_PROGRESS;
#else
        ssize_t sent =
            send(conn->socket, outbound_buffer, outbound_bytes, MSG_NOSIGNAL);
        if (sent < 0) {
          if (SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {
            BIO_reset(conn->tls->wbio);
            BIO_write(conn->tls->wbio, outbound_buffer, outbound_bytes);
            conn->tls->want_write = true;
#ifdef __linux__
            modify_socket_in_epoll(conn->socket, conn, EPOLLOUT | EPOLLIN);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
            modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
            add_socket_to_kqueue(conn->socket, conn, EVFILT_READ);
#endif
            return SOCKET_OP_WOULD_BLOCK;
          }
          return SOCKET_OP_ERROR;
        } else if (sent < outbound_bytes) {
          BIO_reset(conn->tls->wbio);
          BIO_write(conn->tls->wbio, outbound_buffer + sent,
                    outbound_bytes - sent);
          conn->tls->want_write = true;
#ifdef __linux__
          modify_socket_in_epoll(conn->socket, conn, EPOLLOUT | EPOLLIN);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
          modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
          add_socket_to_kqueue(conn->socket, conn, EVFILT_READ);
#endif
          return SOCKET_OP_WOULD_BLOCK;
        }
#endif
      }

      return SOCKET_OP_SUCCESS;
    }

    int ssl_error = SSL_get_error(conn->tls->ssl, ret);

    switch (ssl_error) {
    case SSL_ERROR_WANT_READ:

    {
      char response_outbound[8192];
      int response_outbound_bytes = BIO_read(conn->tls->wbio, response_outbound,
                                             sizeof(response_outbound));
      if (response_outbound_bytes > 0) {
#if defined(_WIN32) || defined(_WIN64)
        if (!conn->current_io_ctx) {
          conn->current_io_ctx =
              create_win_io_context(IO_OP_SEND, conn->socket, conn);
          if (!conn->current_io_ctx) {
            return SOCKET_OP_ERROR;
          }
        }

        size_t copy_size =
            (response_outbound_bytes > sizeof(conn->current_io_ctx->buffer))
                ? sizeof(conn->current_io_ctx->buffer)
                : response_outbound_bytes;
        memcpy(conn->current_io_ctx->buffer, response_outbound, copy_size);
        conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

        DWORD bytes_sent = 0;
        if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                    &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                    NULL) != 0) {
          int error = WSAGetLastError();
          if (error != WSA_IO_PENDING) {
            return SOCKET_OP_ERROR;
          }
        }
        return SOCKET_OP_IN_PROGRESS;
#else
        ssize_t sent = send(conn->socket, response_outbound,
                            response_outbound_bytes, MSG_NOSIGNAL);
        if (sent < 0 && SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {
          BIO_reset(conn->tls->wbio);
          BIO_write(conn->tls->wbio, response_outbound,
                    response_outbound_bytes);
          conn->tls->want_write = true;
#ifdef __linux__
          modify_socket_in_epoll(conn->socket, conn, EPOLLOUT | EPOLLIN);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
          modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
          add_socket_to_kqueue(conn->socket, conn, EVFILT_READ);
#endif
          return SOCKET_OP_WOULD_BLOCK;
        }
#endif
      }
    }

#if defined(_WIN32) || defined(_WIN64)
      if (!conn->current_io_ctx) {
        conn->current_io_ctx =
            create_win_io_context(IO_OP_RECV, conn->socket, conn);
        if (!conn->current_io_ctx) {
          return SOCKET_OP_ERROR;
        }
      }

      DWORD bytes_received = 0;
      DWORD flags = 0;
      if (WSARecv(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                  &bytes_received, &flags, &conn->current_io_ctx->overlapped,
                  NULL) != 0) {
        int error = WSAGetLastError();
        if (error != WSA_IO_PENDING) {
          return SOCKET_OP_ERROR;
        }
      }
      return SOCKET_OP_IN_PROGRESS;
#else
      conn->tls->want_read = true;
      conn->tls->want_write = false;
#ifdef __linux__
      modify_socket_in_epoll(conn->socket, conn, EPOLLIN);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
      modify_socket_in_kqueue(conn->socket, conn, EVFILT_READ);
#endif
      return SOCKET_OP_WOULD_BLOCK;
#endif

    case SSL_ERROR_WANT_WRITE:

    {
      char write_outbound[8192];
      int write_outbound_bytes =
          BIO_read(conn->tls->wbio, write_outbound, sizeof(write_outbound));
      if (write_outbound_bytes > 0) {
#if defined(_WIN32) || defined(_WIN64)
        if (!conn->current_io_ctx) {
          conn->current_io_ctx =
              create_win_io_context(IO_OP_SEND, conn->socket, conn);
          if (!conn->current_io_ctx) {
            return SOCKET_OP_ERROR;
          }
        }

        size_t copy_size =
            (write_outbound_bytes > sizeof(conn->current_io_ctx->buffer))
                ? sizeof(conn->current_io_ctx->buffer)
                : write_outbound_bytes;
        memcpy(conn->current_io_ctx->buffer, write_outbound, copy_size);
        conn->current_io_ctx->wsa_buf.len = (ULONG)copy_size;

        DWORD bytes_sent = 0;
        if (WSASend(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                    &bytes_sent, 0, &conn->current_io_ctx->overlapped,
                    NULL) != 0) {
          int error = WSAGetLastError();
          if (error != WSA_IO_PENDING) {
            return SOCKET_OP_ERROR;
          }
        }
        return SOCKET_OP_IN_PROGRESS;
#else
        ssize_t sent = send(conn->socket, write_outbound, write_outbound_bytes,
                            MSG_NOSIGNAL);
        if (sent < 0 && SOCKET_WOULD_BLOCK(GET_SOCKET_ERROR())) {
          BIO_reset(conn->tls->wbio);
          BIO_write(conn->tls->wbio, write_outbound, write_outbound_bytes);
        }
#endif
      }
    }

#if defined(_WIN32) || defined(_WIN64)
      return SOCKET_OP_IN_PROGRESS;
#else
      conn->tls->want_read = false;
      conn->tls->want_write = true;
#ifdef __linux__
      modify_socket_in_epoll(conn->socket, conn, EPOLLOUT);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
      modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
#endif
      return SOCKET_OP_WOULD_BLOCK;
#endif

    case SSL_ERROR_ZERO_RETURN:
      return SOCKET_OP_CLOSED;

    case SSL_ERROR_SYSCALL:
      if (ret == 0) {
        return SOCKET_OP_CLOSED;
      } else if (ret == -1) {
        int sock_error = GET_SOCKET_ERROR();
        if (SOCKET_WOULD_BLOCK(sock_error) || sock_error == SOCKET_EINTR) {
#if defined(_WIN32) || defined(_WIN64)
          return SOCKET_OP_IN_PROGRESS;
#else
          return SOCKET_OP_WOULD_BLOCK;
#endif
        }
      }
      return SOCKET_OP_ERROR;

    case SSL_ERROR_SSL:
      return SOCKET_OP_ERROR;

    default:
      return SOCKET_OP_ERROR;
    }
  } else
#endif
  {

#if defined(_WIN32) || defined(_WIN64)
    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_RECV) {
      return SOCKET_OP_IN_PROGRESS;
    }

    if (conn->current_io_ctx && conn->current_io_ctx->operation != IO_OP_RECV) {
      free_win_io_context(conn->current_io_ctx);
      conn->current_io_ctx = NULL;
    }

    if (!conn->current_io_ctx) {
      conn->current_io_ctx =
          create_win_io_context(IO_OP_RECV, conn->socket, conn);
      if (!conn->current_io_ctx) {
        return SOCKET_OP_ERROR;
      }
    }

    size_t buffer_size = available_space > sizeof(conn->current_io_ctx->buffer)
                             ? sizeof(conn->current_io_ctx->buffer)
                             : available_space;
    conn->current_io_ctx->wsa_buf.len = (ULONG)buffer_size;

    DWORD bytes_received = 0;
    DWORD flags = 0;

    if (WSARecv(conn->socket, &conn->current_io_ctx->wsa_buf, 1,
                &bytes_received, &flags, &conn->current_io_ctx->overlapped,
                NULL) != 0) {
      int error = WSAGetLastError();
      if (error != WSA_IO_PENDING) {
        return SOCKET_OP_ERROR;
      }
    }

    return SOCKET_OP_IN_PROGRESS;
#else
    ssize_t result =
        recv(conn->socket, conn->response_buffer + conn->response_size,
             available_space, 0);

    if (result > 0) {
      conn->response_size += (size_t)result;
      conn->bytes_received += (size_t)result;
      update_connection_activity(conn);

      return SOCKET_OP_SUCCESS;
    } else if (result == 0) {
      return SOCKET_OP_CLOSED;
    } else {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
#ifdef __linux__
        if (!modify_socket_in_epoll(conn->socket, conn, EPOLLIN)) {
          return SOCKET_OP_ERROR;
        }
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
        if (!modify_socket_in_kqueue(conn->socket, conn, EVFILT_READ)) {
          return SOCKET_OP_ERROR;
        }
#endif
        return SOCKET_OP_WOULD_BLOCK;
      } else {
        return SOCKET_OP_ERROR;
      }
    }
#endif
  }
}

#if defined(_WIN32) || defined(_WIN64)
static void process_iocp_completion(win_io_context_t *ctx,
                                    DWORD bytes_transferred, DWORD error) {
  if (!ctx || !ctx->conn) {
    return;
  }

  fetch_connection_t *conn = ctx->conn;

  ctx->bytes_transferred = bytes_transferred;

  if (error != 0) {
    set_connection_error(conn, FETCH_ERROR_NETWORK, "I/O operation failed");
    free_win_io_context(ctx);
    conn->current_io_ctx = NULL;
    return;
  }

  switch (ctx->operation) {
  case IO_OP_CONNECT:

    if (setsockopt(conn->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL,
                   0) != 0) {
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Failed to update connect context");
    } else {
#if defined(LIBFETCH_TLS_ENABLED)
      if (conn->is_https) {
        conn->state = CONN_STATE_TLS_HANDSHAKE;
      } else {
        conn->state = CONN_STATE_SENDING;
      }
#else
      conn->state = CONN_STATE_SENDING;
#endif
      update_connection_activity(conn);
    }

    free_win_io_context(ctx);
    conn->current_io_ctx = NULL;
    break;

  case IO_OP_SEND:
#if defined(LIBFETCH_TLS_ENABLED)
    if (conn->is_https && conn->tls) {

      free_win_io_context(ctx);
      conn->current_io_ctx = NULL;

      if (conn->state == CONN_STATE_TLS_HANDSHAKE) {

        socket_op_result_t handshake_result = perform_tls_handshake(conn);
        if (handshake_result == SOCKET_OP_SUCCESS) {
          conn->state = CONN_STATE_SENDING;
        } else if (handshake_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "TLS handshake failed");
        }
      } else if (conn->state == CONN_STATE_SENDING) {

        socket_op_result_t send_result = send_data(conn);
        if (send_result == SOCKET_OP_SUCCESS) {
          conn->state = CONN_STATE_RECEIVING;
          if (!conn->parse_ctx) {
            conn->parse_ctx = http_parse_context_new();
            if (!conn->parse_ctx) {
              set_connection_error(conn, FETCH_ERROR_MEMORY,
                                   "Failed to allocate HTTP parser");
              return;
            }
          }
        } else if (send_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Failed to send request");
        }
      } else if (conn->state == CONN_STATE_RECEIVING) {

        socket_op_result_t recv_result = receive_data(conn);
        if (recv_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Failed to receive response");
        }
      }
    } else
#endif
    {

      if (conn->send_mode == SEND_MODE_FILE) {

        update_connection_activity(conn);

        fetch_body_t *body = get_connection_body(conn);
        if (!body || body->type != FETCH_BODY_FILE) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Invalid file body in completion");
          free_win_io_context(ctx);
          conn->current_io_ctx = NULL;
          return;
        }

        if (conn->send_state.file.headers_sent < conn->request_size) {

          conn->send_state.file.headers_sent += bytes_transferred;
        } else if (conn->send_state.file.use_chunked_encoding) {

          switch (conn->send_state.file.chunk_state) {
          case CHUNK_STATE_HEADER:
            conn->send_state.file.chunk_header_sent += bytes_transferred;
            if (conn->send_state.file.chunk_header_sent >=
                conn->send_state.file.chunk_header_size) {
              conn->send_state.file.chunk_state = CHUNK_STATE_DATA;
            }
            break;
          case CHUNK_STATE_DATA:
            conn->send_state.file.buffer_sent += bytes_transferred;
            conn->send_state.file.file_bytes_sent += bytes_transferred;
            if (conn->send_state.file.buffer_sent >=
                conn->send_state.file.buffer_size) {
              conn->send_state.file.chunk_state = CHUNK_STATE_TRAILER;
            }
            break;
          case CHUNK_STATE_TRAILER:

            conn->send_state.file.buffer_size = 0;
            conn->send_state.file.buffer_sent = 0;
            conn->send_state.file.chunk_header_sent = 0;
            conn->send_state.file.chunk_state = CHUNK_STATE_HEADER;
            break;
          case CHUNK_STATE_FINAL:
            conn->send_state.file.chunk_header_sent += bytes_transferred;
            if (conn->send_state.file.chunk_header_sent >=
                conn->send_state.file.chunk_header_size) {

              free_win_io_context(ctx);
              conn->current_io_ctx = NULL;
              conn->state = CONN_STATE_RECEIVING;
              if (!conn->parse_ctx) {
                conn->parse_ctx = http_parse_context_new();
                if (!conn->parse_ctx) {
                  set_connection_error(conn, FETCH_ERROR_MEMORY,
                                       "Failed to allocate HTTP parser");
                  return;
                }
              }
              return;
            }
            break;
          }
        } else {

          conn->send_state.file.buffer_sent += bytes_transferred;
          conn->send_state.file.file_bytes_sent += bytes_transferred;
        }

        free_win_io_context(ctx);
        conn->current_io_ctx = NULL;

        socket_op_result_t send_result = send_data(conn);
        if (send_result == SOCKET_OP_SUCCESS) {
          conn->state = CONN_STATE_RECEIVING;
          if (!conn->parse_ctx) {
            conn->parse_ctx = http_parse_context_new();
            if (!conn->parse_ctx) {
              set_connection_error(conn, FETCH_ERROR_MEMORY,
                                   "Failed to allocate HTTP parser");
              return;
            }
          }
        } else if (send_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Failed to send request");
        }

      } else {

        conn->bytes_sent += bytes_transferred;
        update_connection_activity(conn);

        free_win_io_context(ctx);
        conn->current_io_ctx = NULL;

        if (conn->bytes_sent >= conn->request_size) {
          conn->state = CONN_STATE_RECEIVING;
          if (!conn->parse_ctx) {
            conn->parse_ctx = http_parse_context_new();
            if (!conn->parse_ctx) {
              set_connection_error(conn, FETCH_ERROR_MEMORY,
                                   "Failed to allocate HTTP parser");
              return;
            }
          }
        }
      }
    }
    break;

  case IO_OP_RECV:
#if defined(LIBFETCH_TLS_ENABLED)
    if (conn->is_https && conn->tls) {
      if (bytes_transferred == 0) {

        free_win_io_context(ctx);
        conn->current_io_ctx = NULL;

        if (conn->parse_ctx && is_response_complete(conn->parse_ctx)) {
          bool supports_keep_alive = false;
          fetch_response_t *response = create_response_from_context(
              conn->parse_ctx, get_connection_url(conn), &supports_keep_alive,
              conn->request);

          if (response) {
            conn->response_supports_keep_alive = supports_keep_alive;
            set_connection_complete(conn, response);
          } else {
            set_connection_error(conn, FETCH_ERROR_MEMORY,
                                 "Failed to create response object");
          }
        } else {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Connection closed unexpectedly");
        }
        return;
      }

      int bio_written =
          BIO_write(conn->tls->rbio, ctx->buffer, bytes_transferred);
      if (bio_written <= 0) {
        set_connection_error(conn, FETCH_ERROR_NETWORK,
                             "Failed to process encrypted data");
        free_win_io_context(ctx);
        conn->current_io_ctx = NULL;
        return;
      }

      free_win_io_context(ctx);
      conn->current_io_ctx = NULL;

      if (conn->state == CONN_STATE_TLS_HANDSHAKE) {

        socket_op_result_t handshake_result = perform_tls_handshake(conn);
        if (handshake_result == SOCKET_OP_SUCCESS) {
          conn->state = CONN_STATE_SENDING;
        } else if (handshake_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "TLS handshake failed");
        }
      } else if (conn->state == CONN_STATE_SENDING) {

        socket_op_result_t send_result = send_data(conn);
        if (send_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Failed to send request");
        }
      } else if (conn->state == CONN_STATE_RECEIVING) {

        socket_op_result_t recv_result = receive_data(conn);
        if (recv_result == SOCKET_OP_SUCCESS) {
        } else if (recv_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "Failed to receive response");
        }
      }
    } else
#endif
    {

      if (bytes_transferred == 0) {

        conn->state = CONN_STATE_COMPLETE;
      } else {

        size_t bytes_to_copy = bytes_transferred;
        size_t available_space = conn->response_capacity - conn->response_size;

        if (bytes_to_copy > available_space) {

          size_t new_capacity = conn->response_capacity + bytes_to_copy + 4096;
          char *new_buffer = realloc(conn->response_buffer, new_capacity);
          if (new_buffer) {
            conn->response_buffer = new_buffer;
            conn->response_capacity = new_capacity;
          } else {
            bytes_to_copy = available_space;
          }
        }

        if (bytes_to_copy > 0) {
          memcpy(conn->response_buffer + conn->response_size, ctx->buffer,
                 bytes_to_copy);
          conn->response_size += bytes_to_copy;
          conn->bytes_received += bytes_to_copy;
        }

        update_connection_activity(conn);
      }

      free_win_io_context(ctx);
      conn->current_io_ctx = NULL;
    }
    break;

  default:
    set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                         "Unexpected I/O completion");
    free_win_io_context(ctx);
    conn->current_io_ctx = NULL;
    break;
  }
}
#endif

static bool prepare_socket_for_state(fetch_connection_t *conn) {
  if (!conn || conn->socket == FETCH_INVALID_SOCKET)
    return false;

#if defined(_WIN32) || defined(_WIN64)
  return true;
#else
  switch (conn->state) {
  case CONN_STATE_NONE:
  case CONN_STATE_RESOLVING:
  case CONN_STATE_CONNECTING:
  case CONN_STATE_TLS_HANDSHAKE:
  case CONN_STATE_REDIRECTING:
  case CONN_STATE_COMPLETE:
  case CONN_STATE_ERROR:
  case CONN_STATE_CANCELLED:
    return true;

  case CONN_STATE_SENDING:
#ifdef __linux__
    return modify_socket_in_epoll(conn->socket, conn, EPOLLOUT);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
    return modify_socket_in_kqueue(conn->socket, conn, EVFILT_WRITE);
#else
    return true;
#endif

  case CONN_STATE_RECEIVING:
#ifdef __linux__
    return modify_socket_in_epoll(conn->socket, conn, EPOLLIN);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
    return modify_socket_in_kqueue(conn->socket, conn, EVFILT_READ);
#else
    return true;
#endif
  }

  return true;
#endif
}

static void add_cookie_header_to_request(fetch_headers_t *headers,
                                         const fetch_url_t *url,
                                         const fetch_request_t *request) {
  if (!fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES) ||
      !g_fetch_config.cookie_jar || !url || !url->full_url || !headers) {
    return;
  }

  fetch_credentials_t credentials =
      request ? request->credentials : FETCH_CREDENTIALS_SAME_ORIGIN;

  if (!should_include_credentials(credentials, url, g_fetch_config.origin)) {
    return;
  }

  cookie_match_t *matches = cookie_jar_get_cookies_for_url(
      g_fetch_config.cookie_jar, url->full_url, true);
  if (!matches) {
    return;
  }

  char *cookie_header = cookie_match_to_header(matches);
  if (cookie_header) {
    fetch_headers_set(headers, "Cookie", cookie_header);
    free(cookie_header);
  }

  cookie_match_free(matches);
}

static void process_set_cookie_headers(const fetch_headers_t *response_headers,
                                       const fetch_url_t *url,
                                       const fetch_request_t *request) {
  if (!fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES) ||
      !g_fetch_config.cookie_jar || !response_headers || !url ||
      !url->full_url) {
    return;
  }

  fetch_credentials_t credentials =
      request ? request->credentials : FETCH_CREDENTIALS_SAME_ORIGIN;

  if (!should_include_credentials(credentials, url, g_fetch_config.origin)) {
    return;
  }

  for (size_t i = 0; i < response_headers->count; i++) {
    if (!response_headers->keys[i] || !response_headers->values[i]) {
      continue;
    }

    if (fetch_strcasecmp(response_headers->keys[i], "Set-Cookie") == 0) {
      cookie_t *cookie = NULL;
      cookie_parse_result_t result = cookie_parse_set_cookie(
          response_headers->values[i], url->full_url, &cookie);

      if (result == COOKIE_PARSE_SUCCESS && cookie) {
        if (!cookie_jar_add(g_fetch_config.cookie_jar, cookie)) {
          cookie_free(cookie);
        }
      } else if (cookie) {
        cookie_free(cookie);
      }
    }
  }
}

static char *build_request_line(const char *method, const fetch_url_t *url) {
  if (!method || !url || !url->path) {
    return NULL;
  }

  const size_t method_len = strlen(method);
  const size_t path_len = strlen(url->path);
  const char *http_suffix = " HTTP/1.1\r\n";
  const size_t http_suffix_len = strlen(http_suffix);

  if (method_len >= FETCH_MAX_METHOD_LENGTH) {
    return NULL;
  }

  size_t total_len = method_len + 1 + path_len + http_suffix_len + 1;

  char *line = malloc(total_len);
  if (!line) {
    return NULL;
  }

  int ret =
      snprintf(line, total_len, "%s %s%s", method, url->path, http_suffix);
  if (ret < 0 || (size_t)ret >= total_len) {
    free(line);
    return NULL;
  }

  return line;
}

static char *build_host_header(const fetch_url_t *url) {
  if (!url || !url->hostname) {
    return NULL;
  }

  const size_t hostname_len = strlen(url->hostname);
  bool is_ipv6 = (url->host_type == HOST_TYPE_IPV6);

  bool include_port = true;
  if ((url->port == 80 && !url->is_https) ||
      (url->port == 443 && url->is_https)) {
    include_port = false;
  }

  if (is_ipv6) {

    size_t needed = 1 + hostname_len + 1;
    if (include_port) {
      needed += 1 + 5;
    }
    needed += 1;

    char *host_header = malloc(needed);
    if (!host_header) {
      return NULL;
    }

    if (include_port) {
      snprintf(host_header, needed, "[%s]:%u", url->hostname, url->port);
    } else {
      snprintf(host_header, needed, "[%s]", url->hostname);
    }
    return host_header;
  } else {

    if (!include_port) {
      return strdup(url->hostname);
    }

    size_t needed = hostname_len + 1 + 5 + 1;
    char *host_header = malloc(needed);
    if (!host_header) {
      return NULL;
    }

    snprintf(host_header, needed, "%s:%u", url->hostname, url->port);
    return host_header;
  }
}

static char *build_http_headers(const fetch_headers_t *headers,
                                const char *host_header, const char *user_agent,
                                const char *content_type, size_t content_length,
                                bool has_body, bool use_chunked_encoding,
                                bool use_keep_alive, const fetch_url_t *url,
                                const fetch_request_t *request,
                                size_t *total_size) {
  fetch_headers_t *all_headers = NULL;
  char *buffer = NULL;
  bool success = false;

  if (!total_size) {
    goto cleanup;
  }

  all_headers = fetch_headers_new();
  if (!all_headers) {
    goto cleanup;
  }

  if (headers) {
    for (size_t i = 0; i < headers->count; i++) {
      if (headers->keys[i] && headers->values[i]) {
        fetch_headers_set(all_headers, headers->keys[i], headers->values[i]);
      }
    }
  }

  add_cookie_header_to_request(all_headers, url, request);

  size_t estimated_size = 0;

  if (host_header) {
    estimated_size += 6 + strlen(host_header) + 2;
  }

  if (user_agent) {
    estimated_size += 12 + strlen(user_agent) + 2;
  }

  if (has_body && content_type) {
    estimated_size += 14 + strlen(content_type) + 2;
  }

  if (has_body) {
    if (use_chunked_encoding) {

      estimated_size += 26 + 7 + 2;
    } else {

      estimated_size += 16 + 20 + 2;
    }
  }

  const char *connection_value = use_keep_alive ? "keep-alive" : "close";
  estimated_size += 12 + strlen(connection_value) + 2;

  if (use_keep_alive) {
    estimated_size += 12 + 64 + 2;
  }

  for (size_t i = 0; i < all_headers->count; i++) {
    if (!all_headers->keys[i] || !all_headers->values[i]) {
      continue;
    }

    if (fetch_strcasecmp(all_headers->keys[i], "host") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "user-agent") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "content-type") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "content-length") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "connection") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "keep-alive") == 0) {
      continue;
    }

    estimated_size +=
        strlen(all_headers->keys[i]) + 2 + strlen(all_headers->values[i]) + 2;
  }

  estimated_size += 2;
  estimated_size += 256;

  buffer = malloc(estimated_size);
  if (!buffer) {
    goto cleanup;
  }

  buffer[0] = '\0';
  size_t current_pos = 0;

#define SAFE_APPEND(str)                                                       \
  do {                                                                         \
    size_t len = strlen(str);                                                  \
    if (current_pos + len >= estimated_size) {                                 \
      goto cleanup;                                                            \
    }                                                                          \
    memcpy(buffer + current_pos, str, len);                                    \
    current_pos += len;                                                        \
  } while (0)

  if (host_header) {
    SAFE_APPEND("Host: ");
    SAFE_APPEND(host_header);
    SAFE_APPEND("\r\n");
  }

  if (user_agent) {
    SAFE_APPEND("User-Agent: ");
    SAFE_APPEND(user_agent);
    SAFE_APPEND("\r\n");
  }

  if (has_body && content_type) {
    SAFE_APPEND("Content-Type: ");
    SAFE_APPEND(content_type);
    SAFE_APPEND("\r\n");
  }

  if (has_body) {
    if (use_chunked_encoding) {
      SAFE_APPEND("Transfer-Encoding: chunked\r\n");
    } else {
      char content_len_str[32];
      int ret = snprintf(content_len_str, sizeof(content_len_str), "%zu",
                         content_length);
      if (ret < 0 || (size_t)ret >= sizeof(content_len_str)) {
        goto cleanup;
      }

      SAFE_APPEND("Content-Length: ");
      SAFE_APPEND(content_len_str);
      SAFE_APPEND("\r\n");
    }
  }

  SAFE_APPEND("Connection: ");
  SAFE_APPEND(connection_value);
  SAFE_APPEND("\r\n");

  if (use_keep_alive) {
    char keepalive_str[64];
    int ret =
        snprintf(keepalive_str, sizeof(keepalive_str), "timeout=%u, max=100",
                 g_fetch_config.keep_alive_timeout_ms / 1000);
    if (ret < 0 || (size_t)ret >= sizeof(keepalive_str)) {
      goto cleanup;
    }

    SAFE_APPEND("Keep-Alive: ");
    SAFE_APPEND(keepalive_str);
    SAFE_APPEND("\r\n");
  }

  for (size_t i = 0; i < all_headers->count; i++) {
    if (!all_headers->keys[i] || !all_headers->values[i]) {
      continue;
    }

    if (fetch_strcasecmp(all_headers->keys[i], "host") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "user-agent") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "content-type") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "content-length") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "connection") == 0 ||
        fetch_strcasecmp(all_headers->keys[i], "keep-alive") == 0) {
      continue;
    }

    SAFE_APPEND(all_headers->keys[i]);
    SAFE_APPEND(": ");
    SAFE_APPEND(all_headers->values[i]);
    SAFE_APPEND("\r\n");
  }

  SAFE_APPEND("\r\n");

  buffer[current_pos] = '\0';
  *total_size = current_pos;
  success = true;

#undef SAFE_APPEND

cleanup:
  fetch_headers_free(all_headers);

  if (!success) {
    free(buffer);
    buffer = NULL;
  }

  return buffer;
}

static bool build_http_request(fetch_connection_t *conn) {
  char *request_line = NULL;
  char *host_header = NULL;
  char *headers_section = NULL;
  bool success = false;

  if (!conn || !conn->request || !conn->request->url) {
    goto cleanup;
  }

  const fetch_url_t *url = conn->request->url;

  if (conn->host) {
    free(conn->host);
  }
  conn->host = strdup(url->hostname);
  if (!conn->host) {
    goto cleanup;
  }

  conn->port = url->port;
  conn->host_type = url->host_type;
  conn->is_https = url->is_https;

  const char *method = fetch_method_to_string(get_connection_method(conn));
  request_line = build_request_line(method, url);
  if (!request_line) {
    goto cleanup;
  }

  host_header = build_host_header(url);
  if (!host_header) {
    goto cleanup;
  }

  fetch_body_t *body = get_connection_body(conn);
  bool has_body = (body != NULL);
  bool is_file_body = (has_body && body->type == FETCH_BODY_FILE);
  bool use_chunked_encoding =
      is_file_body && body->data.file.continue_cb != NULL;
  size_t body_length = 0;
  if (has_body) {
    body_length = is_file_body ? body->data.file.size : body->data.memory.size;
  }
  const char *content_type = has_body ? body->content_type : NULL;

  bool use_keep_alive = get_connection_keepalive(conn);

  size_t headers_size = 0;
  headers_section = build_http_headers(
      get_connection_headers(conn), host_header, g_fetch_config.user_agent,
      content_type, body_length, has_body, use_chunked_encoding, use_keep_alive,
      url, conn->request, &headers_size);

  if (!headers_section) {
    goto cleanup;
  }

  size_t request_line_len = strlen(request_line);

  const size_t total_size =
      is_file_body ? (request_line_len + headers_size)
                   : (request_line_len + headers_size + body_length);

  conn->request_buffer = malloc(total_size);
  if (!conn->request_buffer) {
    goto cleanup;
  }

  size_t offset = 0;

  memcpy(conn->request_buffer + offset, request_line, request_line_len);
  offset += request_line_len;

  memcpy(conn->request_buffer + offset, headers_section, headers_size);
  offset += headers_size;

  if (has_body && !is_file_body && body->data.memory.data) {
    memcpy(conn->request_buffer + offset, body->data.memory.data, body_length);
    offset += body_length;
  }

  conn->request_size = offset;

  if (is_file_body) {
    conn->send_state.file.headers_sent = 0;
  }
  success = true;

cleanup:
  free(request_line);
  free(host_header);
  free(headers_section);

  return success;
}

typedef struct http_parse_context {

  enum {
    HTTP_PARSE_STATUS_LINE,
    HTTP_PARSE_HEADERS,
    HTTP_PARSE_BODY,
    HTTP_PARSE_COMPLETE
  } state;

  int minor_version;
  int status_code;
  char *status_msg;
  size_t status_msg_len;
  struct phr_header phr_headers[100];
  size_t num_headers;

  fetch_headers_t *headers;

  bool headers_complete;
  bool chunked_encoding;
  size_t content_length;

  struct phr_chunked_decoder chunked_decoder;

  char *body_buffer;
  size_t body_capacity;
  size_t body_size;

  size_t parse_position;
  size_t last_parse_position;
} http_parse_context_t;

static http_parse_context_t *http_parse_context_new(void) {
  http_parse_context_t *ctx = calloc(1, sizeof(http_parse_context_t));
  if (!ctx)
    return NULL;

  ctx->state = HTTP_PARSE_STATUS_LINE;
  ctx->content_length = SIZE_MAX;
  ctx->num_headers = sizeof(ctx->phr_headers) / sizeof(ctx->phr_headers[0]);

  memset(&ctx->chunked_decoder, 0, sizeof(ctx->chunked_decoder));
  ctx->chunked_decoder.consume_trailer = 1;

  ctx->headers = fetch_headers_new();
  if (!ctx->headers) {
    free(ctx);
    return NULL;
  }

  return ctx;
}

static void http_parse_context_free(http_parse_context_t *ctx) {
  if (!ctx)
    return;

  if (ctx->headers) {
    fetch_headers_free(ctx->headers);
    ctx->headers = NULL;
  }

  if (ctx->body_buffer) {
    free(ctx->body_buffer);
    ctx->body_buffer = NULL;
  }

  if (ctx->status_msg) {
    free(ctx->status_msg);
    ctx->status_msg = NULL;
  }

  memset(ctx->phr_headers, 0, sizeof(ctx->phr_headers));

  free(ctx);
}

static bool ensure_body_capacity(http_parse_context_t *ctx, size_t needed) {
  if (!ctx)
    return false;

  if (ctx->body_capacity >= needed)
    return true;

  size_t new_capacity = ctx->body_capacity;
  if (new_capacity == 0)
    new_capacity = 8192;

  while (new_capacity < needed) {
    new_capacity *= 2;
    if (new_capacity < ctx->body_capacity)
      return false;
  }

  char *new_buffer = realloc(ctx->body_buffer, new_capacity);
  if (!new_buffer)
    return false;

  ctx->body_buffer = new_buffer;
  ctx->body_capacity = new_capacity;
  return true;
}

static bool append_to_body(http_parse_context_t *ctx, const char *data,
                           size_t size) {
  if (!ctx || size == 0)
    return true;
  if (!data)
    return false;

  if (!ctx->headers_complete)
    return false;

  if (!ensure_body_capacity(ctx, ctx->body_size + size))
    return false;

  memcpy(ctx->body_buffer + ctx->body_size, data, size);
  ctx->body_size += size;
  return true;
}

static bool convert_phr_headers(http_parse_context_t *ctx) {
  if (!ctx || !ctx->headers)
    return false;

  for (size_t i = 0; i < ctx->headers->count; i++) {
    free(ctx->headers->keys[i]);
    free(ctx->headers->values[i]);
  }
  ctx->headers->count = 0;

  for (size_t i = 0; i < ctx->num_headers; i++) {
    if (ctx->phr_headers[i].name == NULL)
      continue;

    char *name =
        strndup(ctx->phr_headers[i].name, ctx->phr_headers[i].name_len);
    char *value =
        strndup(ctx->phr_headers[i].value, ctx->phr_headers[i].value_len);

    if (name && value) {
      fetch_headers_set(ctx->headers, name, value);
    }

    free(name);
    free(value);
  }

  return true;
}

static void analyze_headers(http_parse_context_t *ctx) {
  if (!ctx || !ctx->headers)
    return;

  const char *transfer_encoding =
      fetch_headers_get(ctx->headers, "Transfer-Encoding");
  if (transfer_encoding &&
      fetch_strcasecmp(transfer_encoding, "chunked") == 0) {
    ctx->chunked_encoding = true;
    ctx->content_length = SIZE_MAX;
  } else {
    const char *content_length_str =
        fetch_headers_get(ctx->headers, "Content-Length");
    if (content_length_str) {
      char *endptr;
      const unsigned long long content_length =
          strtoull(content_length_str, &endptr, 10);
      if (*endptr == '\0' && content_length <= SIZE_MAX) {
        ctx->content_length = (size_t)content_length;
      } else {
        ctx->content_length = 0;
      }
    } else {
      ctx->content_length = 0;
    }
  }
}

static bool parse_http_response(http_parse_context_t *ctx, const char *data,
                                size_t size, size_t *consumed) {
  if (!ctx || !data || !consumed)
    return false;

  *consumed = 0;

  if (ctx->state == HTTP_PARSE_STATUS_LINE ||
      ctx->state == HTTP_PARSE_HEADERS) {
    ctx->num_headers = sizeof(ctx->phr_headers) / sizeof(ctx->phr_headers[0]);

    const char *temp_status_msg;
    size_t temp_status_msg_len;

    const int result = phr_parse_response(
        data, size, &ctx->minor_version, &ctx->status_code, &temp_status_msg,
        &temp_status_msg_len, ctx->phr_headers, &ctx->num_headers,
        ctx->last_parse_position);

    if (result == -1)
      return false;

    if (result == -2) {

      ctx->last_parse_position = size;
      return true;
    }

    if (result > 0) {

      free(ctx->status_msg);
      if (temp_status_msg && temp_status_msg_len > 0) {
        ctx->status_msg = strndup(temp_status_msg, temp_status_msg_len);
        ctx->status_msg_len = temp_status_msg_len;
      } else {
        ctx->status_msg = NULL;
        ctx->status_msg_len = 0;
      }

      *consumed = (size_t)result;
      ctx->headers_complete = true;
      ctx->state = HTTP_PARSE_BODY;

      if (!convert_phr_headers(ctx))
        return false;

      analyze_headers(ctx);

      size_t remaining = size - (size_t)result;
      if (remaining > 0) {
        const char *body_data = data + result;

        if (ctx->chunked_encoding) {
          char *body_copy = malloc(remaining);
          if (!body_copy)
            return false;

          memcpy(body_copy, body_data, remaining);
          size_t body_size = remaining;

          const ssize_t decode_result =
              phr_decode_chunked(&ctx->chunked_decoder, body_copy, &body_size);

          if (decode_result == -1) {
            free(body_copy);
            return false;
          }

          if (body_size > 0) {
            append_to_body(ctx, body_copy, body_size);
          }

          free(body_copy);

          if (decode_result >= 0) {
            ctx->state = HTTP_PARSE_COMPLETE;
          }

          *consumed = size;
        } else if (ctx->content_length > 0) {
          const size_t bytes_to_read = (remaining < ctx->content_length)
                                           ? remaining
                                           : ctx->content_length;

          if (!append_to_body(ctx, body_data, bytes_to_read))
            return false;

          *consumed = (size_t)result + bytes_to_read;

          if (ctx->body_size >= ctx->content_length) {
            ctx->state = HTTP_PARSE_COMPLETE;
          }
        } else {
          ctx->state = HTTP_PARSE_COMPLETE;
        }
      }
    }
  } else if (ctx->state == HTTP_PARSE_BODY && size > 0) {
    if (ctx->chunked_encoding) {
      char *body_copy = malloc(size);
      if (!body_copy)
        return false;

      memcpy(body_copy, data, size);
      size_t body_size = size;

      const ssize_t decode_result =
          phr_decode_chunked(&ctx->chunked_decoder, body_copy, &body_size);

      if (decode_result == -1) {
        free(body_copy);
        return false;
      }

      if (body_size > 0) {
        append_to_body(ctx, body_copy, body_size);
      }

      free(body_copy);

      if (decode_result >= 0) {
        ctx->state = HTTP_PARSE_COMPLETE;
      }

      *consumed = size;
    } else if (ctx->content_length > 0) {
      const size_t bytes_needed = ctx->content_length - ctx->body_size;
      const size_t bytes_to_read = (size < bytes_needed) ? size : bytes_needed;

      if (!append_to_body(ctx, data, bytes_to_read))
        return false;

      *consumed = bytes_to_read;

      if (ctx->body_size >= ctx->content_length) {
        ctx->state = HTTP_PARSE_COMPLETE;
      }
    } else {
      ctx->state = HTTP_PARSE_COMPLETE;
      *consumed = 0;
    }
  }

  return true;
}

static bool is_response_complete(const http_parse_context_t *ctx) {
  if (!ctx)
    return false;

  return ctx->state == HTTP_PARSE_COMPLETE;
}

static fetch_response_t *create_response_from_context(
    const struct http_parse_context *ctx, const fetch_url_t *final_url,
    bool *supports_keep_alive, const fetch_request_t *request) {
  if (!ctx) {
    return NULL;
  }

  fetch_response_t *response = calloc(1, sizeof(fetch_response_t));
  if (!response) {
    return NULL;
  }

  response->status = (uint16_t)ctx->status_code;

  if (ctx->status_msg && ctx->status_msg_len > 0) {
    response->status_text = strndup(ctx->status_msg, ctx->status_msg_len);
    if (!response->status_text) {
      goto error_cleanup;
    }
  } else {
    response->status_text = strdup("Unknown");
    if (!response->status_text) {
      goto error_cleanup;
    }
  }

  response->ok = (ctx->status_code >= 200 && ctx->status_code < 300);

  if (final_url && final_url->full_url) {
    response->url = strndup(final_url->full_url, FETCH_MAX_URL_LENGTH);
    if (!response->url) {
      goto error_cleanup;
    }
  } else {
    response->url = strdup("");
    if (!response->url) {
      goto error_cleanup;
    }
  }

  response->headers = fetch_headers_new();
  if (!response->headers) {
    goto error_cleanup;
  }

  if (ctx->headers) {
    for (size_t i = 0; i < ctx->headers->count; i++) {
      if (ctx->headers->keys[i] && ctx->headers->values[i]) {
        fetch_headers_set(response->headers, ctx->headers->keys[i],
                          ctx->headers->values[i]);
      }
    }
  }

  if (final_url) {
    process_set_cookie_headers(response->headers, final_url, request);
  }

  if (supports_keep_alive) {
    *supports_keep_alive = false;
    if (ctx->headers) {
      const char *connection = fetch_headers_get(ctx->headers, "Connection");
      if (!connection) {
        *supports_keep_alive = (ctx->minor_version >= 1);
      } else if (fetch_strcasecmp(connection, "keep-alive") == 0) {
        *supports_keep_alive = true;
      } else if (fetch_strcasecmp(connection, "close") == 0) {
        *supports_keep_alive = false;
      } else {
        *supports_keep_alive = (ctx->minor_version >= 1);
      }
    }
  }

  if (ctx->body_size > 0 && ctx->body_buffer) {
    response->body = malloc(ctx->body_size + 1);
    if (!response->body) {
      goto error_cleanup;
    }

    memcpy((void *)response->body, ctx->body_buffer, ctx->body_size);
    ((char *)response->body)[ctx->body_size] = '\0';
    response->body_size = ctx->body_size;

    const char *content_type =
        fetch_headers_get(response->headers, "Content-Type");
    if (content_type) {
      if (strstr(content_type, "application/json")) {
        response->body_type = FETCH_BODY_JSON;
      } else if (strstr(content_type, "text/") ||
                 strstr(content_type, "application/xml") ||
                 strstr(content_type, "application/javascript")) {
        response->body_type = FETCH_BODY_TEXT;
      } else if (strstr(content_type, "application/x-www-form-urlencoded") ||
                 strstr(content_type, "multipart/form-data")) {
        response->body_type = FETCH_BODY_FORM_DATA;
      } else {
        response->body_type = FETCH_BODY_BINARY;
      }
    } else {
      response->body_type = FETCH_BODY_TEXT;
    }
  } else {
    response->body_type = FETCH_BODY_NONE;
    response->body = NULL;
    response->body_size = 0;
  }

  response->error = FETCH_ERROR_NONE;
  response->redirected = false;

  return response;

error_cleanup:
  if (response) {
    free((void *)response->status_text);
    free((void *)response->url);
    fetch_headers_free(response->headers);
    free((void *)response->body);
    free(response);
  }
  return NULL;
}

static void process_timeout_events(void) {
  const uint64_t current_time_ms = fetch_get_time_ms();

  fetch_timer_t *expired = extract_expired_timers(current_time_ms);

  while (expired) {
    fetch_timer_t *timer = expired;
    expired = timer->next;

    fetch_connection_t *conn = find_connection_by_id(timer->connection_id);
    if (conn) {
      set_connection_error(conn, FETCH_ERROR_TIMEOUT, "Request timed out");
    }

    free(timer);
  }

  if (g_event_loop.timers) {
    g_event_loop.next_timer_check_ms = g_event_loop.timers->expiry_time_ms;
  } else {
    g_event_loop.next_timer_check_ms = 0;
  }
}

static bool handle_redirect_response(fetch_connection_t *conn) {
  if (!conn || !conn->parse_ctx || !conn->parse_ctx->headers_complete)
    return false;

  if (!is_redirect_status(conn->parse_ctx->status_code))
    return false;

  if (!fetch_config_get_flag(g_fetch_config.flags,
                             FETCH_FLAG_FOLLOW_REDIRECTS)) {
    set_connection_error(conn, FETCH_ERROR_NETWORK,
                         "Redirects disabled by global configuration");
    return false;
  }

  if (conn->request && conn->request->redirect == FETCH_REDIRECT_ERROR) {
    set_connection_error(conn, FETCH_ERROR_NETWORK,
                         "Redirect not allowed by policy");
    return false;
  }

  if (conn->request && conn->request->redirect == FETCH_REDIRECT_MANUAL) {

    bool supports_keep_alive = false;
    fetch_response_t *response =
        create_response_from_context(conn->parse_ctx, get_connection_url(conn),
                                     &supports_keep_alive, conn->request);
    if (response) {
      response->redirected = (conn->redirect_count > 0);
      conn->response_supports_keep_alive = supports_keep_alive;
      set_connection_complete(conn, response);
    } else {
      set_connection_error(conn, FETCH_ERROR_MEMORY,
                           "Failed to create redirect response");
    }
    return true;
  }

  const uint32_t max_redirects = get_connection_max_redirects(conn);
  if (conn->redirect_count >= max_redirects) {
    set_connection_error(conn, FETCH_ERROR_TOO_MANY_REDIRECTS,
                         "Too many redirects");
    return false;
  }

  const char *location =
      fetch_headers_get(conn->parse_ctx->headers, "Location");

  if (!location || strlen(location) == 0) {
    set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                         "Redirect without Location header");
    return false;
  }

  char *redirect_url = resolve_redirect_url(get_connection_url(conn), location);

  if (!redirect_url) {
    set_connection_error(conn, FETCH_ERROR_MEMORY,
                         "Failed to resolve redirect URL");
    return false;
  }

  if (!fetch_is_valid_url(redirect_url)) {
    free(redirect_url);
    set_connection_error(conn, FETCH_ERROR_INVALID_URL, "Invalid redirect URL");
    return false;
  }

  http_method_t original_method = get_connection_method(conn);
  http_method_t new_method =
      get_redirect_method(original_method, conn->parse_ctx->status_code);

  if (conn->parse_ctx->headers) {
    process_set_cookie_headers(conn->parse_ctx->headers,
                               get_connection_url(conn), conn->request);
  }

  if (!reset_connection_for_redirect(conn, redirect_url, new_method)) {
    free(redirect_url);
    set_connection_error(conn, FETCH_ERROR_MEMORY,
                         "Failed to reset connection for redirect");
    return false;
  }

  free(redirect_url);

  conn->redirect_count++;
  conn->following_redirect = true;

  conn->state = CONN_STATE_REDIRECTING;

  return true;
}

static void process_connection_state(fetch_connection_t *conn) {
  if (!conn) {
    return;
  }

  if (fetch_atomic_load(&conn->cancelled)) {
    if (conn->state != CONN_STATE_CANCELLED) {
      set_connection_cancelled(conn, conn->cancel_reason
                                         ? conn->cancel_reason
                                         : "Connection cancelled");
    }
    return;
  }

  if (fetch_atomic_load(&g_event_loop.shutdown_requested)) {
    set_connection_cancelled(conn, "Event loop shutting down");
    return;
  }

  if (conn->state == CONN_STATE_COMPLETE || conn->state == CONN_STATE_ERROR ||
      conn->state == CONN_STATE_CANCELLED) {
    return;
  }

  if (!conn->request) {
    set_connection_error(conn, FETCH_ERROR_INVALID_URL,
                         "Connection missing request data");
    return;
  }

  switch (conn->state) {
  case CONN_STATE_NONE:
  case CONN_STATE_REDIRECTING: {
    if (!build_http_request(conn)) {
      set_connection_error(conn, FETCH_ERROR_INVALID_URL,
                           "Failed to build HTTP request");
      return;
    }

    const socket_op_result_t connect_result = start_connect(conn);

    switch (connect_result) {
    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                           "Failed to start connection");
      break;

    case SOCKET_OP_SUCCESS:
#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls && conn->tls->handshake_complete) {
        conn->state = CONN_STATE_SENDING;
      } else if (conn->is_https) {
        conn->state = CONN_STATE_TLS_HANDSHAKE;
      } else {
        conn->state = CONN_STATE_SENDING;
      }
#else
      conn->state = CONN_STATE_SENDING;
#endif
      break;

    case SOCKET_OP_IN_PROGRESS:
      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Unexpected connection result");
      break;
    }
    break;
  }

  case CONN_STATE_RESOLVING: {
    if (!conn->dns_request) {
      if (conn->addr_resolved) {
        const socket_op_result_t connect_result = start_connect(conn);
        switch (connect_result) {
        case SOCKET_OP_ERROR:
          set_connection_error(
              conn, FETCH_ERROR_CONNECTION_REFUSED,
              "Failed to start connection after DNS resolution");
          break;
        case SOCKET_OP_SUCCESS:
#if defined(LIBFETCH_TLS_ENABLED)
          if (conn->is_https) {
            conn->state = CONN_STATE_TLS_HANDSHAKE;
          } else {
            conn->state = CONN_STATE_SENDING;
          }
#else
          conn->state = CONN_STATE_SENDING;
#endif
          break;
        case SOCKET_OP_IN_PROGRESS:
          break;
        default:
          set_connection_error(
              conn, FETCH_ERROR_NETWORK,
              "Unexpected connection result after DNS resolution");
          break;
        }
      } else {
        set_connection_error(
            conn, FETCH_ERROR_DNS_RESOLUTION,
            "DNS resolution completed but address not resolved");
      }
    }
    break;
  }

  case CONN_STATE_CONNECTING: {
#if defined(_WIN32) || defined(_WIN64)

    break;
#else
    const socket_op_result_t connect_result = check_connect_completion(conn);

    switch (connect_result) {
    case SOCKET_OP_SUCCESS:
#if defined(LIBFETCH_TLS_ENABLED)
      if (conn->is_https) {
        conn->state = CONN_STATE_TLS_HANDSHAKE;

        socket_op_result_t tls_result = perform_tls_handshake(conn);
        if (tls_result == SOCKET_OP_ERROR) {
          set_connection_error(conn, FETCH_ERROR_NETWORK,
                               "TLS handshake failed after TCP connect");
        }
      } else {
        conn->state = CONN_STATE_SENDING;
      }
#else
      conn->state = CONN_STATE_SENDING;
#endif
      break;

    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                           "Connection failed");
      break;

    case SOCKET_OP_WOULD_BLOCK:

      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Unexpected connection result");
      break;
    }
    break;
#endif
  }

  case CONN_STATE_TLS_HANDSHAKE: {
#if defined(LIBFETCH_TLS_ENABLED)
    if (!conn->is_https || !conn->tls) {
      set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                           "TLS handshake requested for non-HTTPS connection");
      return;
    }

    if (conn->tls->handshake_complete) {

      conn->state = CONN_STATE_SENDING;
      if (!prepare_socket_for_state(conn)) {
        set_connection_error(conn, FETCH_ERROR_NETWORK,
                             "Failed to configure socket for sending");
        return;
      }
      break;
    }

#if defined(_WIN32) || defined(_WIN64)

    if (conn->current_io_ctx &&
        (conn->current_io_ctx->operation == IO_OP_SEND ||
         conn->current_io_ctx->operation == IO_OP_RECV)) {

      break;
    }

    const socket_op_result_t handshake_result = perform_tls_handshake(conn);

    switch (handshake_result) {
    case SOCKET_OP_SUCCESS:
      conn->state = CONN_STATE_SENDING;
      break;

    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_NETWORK, "TLS handshake failed");
      break;

    case SOCKET_OP_IN_PROGRESS:
    case SOCKET_OP_WOULD_BLOCK:

      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Unexpected TLS handshake result");
      break;
    }
#else
    const socket_op_result_t handshake_result = perform_tls_handshake(conn);

    switch (handshake_result) {
    case SOCKET_OP_SUCCESS:
      conn->state = CONN_STATE_SENDING;
      if (!prepare_socket_for_state(conn)) {
        set_connection_error(conn, FETCH_ERROR_NETWORK,
                             "Failed to configure socket for sending");
        return;
      }
      break;

    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_NETWORK, "TLS handshake failed");
      break;

    case SOCKET_OP_WOULD_BLOCK:
    case SOCKET_OP_IN_PROGRESS:
      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Unexpected TLS handshake result");
      break;
    }
#endif

#else

    set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                         "TLS handshake attempted without TLS support");
#endif
    break;
  }

  case CONN_STATE_SENDING: {
    if (!conn->request_buffer || conn->request_size == 0) {
      set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                           "No request data to send");
      return;
    }

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__)

    struct sockaddr_storage peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    if (getpeername(conn->socket, (struct sockaddr *)&peer_addr, &peer_len) !=
        0) {
      if (errno == ENOTCONN) {
        conn->state = CONN_STATE_CONNECTING;
        return;
      } else {
        set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                             "Socket connection verification failed");
        return;
      }
    }
#endif

    socket_op_result_t send_result;

#if defined(_WIN32) || defined(_WIN64)

    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_SEND) {

      break;
    }

    send_result = send_data(conn);

#else

    send_result = send_data(conn);
#endif

    switch (send_result) {
    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_NETWORK, "Failed to send request");
      break;

    case SOCKET_OP_CLOSED:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Connection closed while sending");
      break;

    case SOCKET_OP_SUCCESS:
      conn->state = CONN_STATE_RECEIVING;

      if (!conn->parse_ctx) {
        if (fetch_atomic_load(&conn->cancelled) ||
            fetch_atomic_load(&g_event_loop.shutdown_requested)) {
          set_connection_cancelled(
              conn, "Connection cancelled during state transition");
          return;
        }

        conn->parse_ctx = http_parse_context_new();
        if (!conn->parse_ctx) {
          set_connection_error(conn, FETCH_ERROR_MEMORY,
                               "Failed to allocate HTTP parser");
          return;
        }
      }

#if !defined(_WIN32) && !defined(_WIN64)

      if (!prepare_socket_for_state(conn)) {
        set_connection_error(conn, FETCH_ERROR_NETWORK,
                             "Failed to configure socket for reading");
        return;
      }
#endif
      break;

    case SOCKET_OP_WOULD_BLOCK:
    case SOCKET_OP_IN_PROGRESS:
      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK, "Unexpected send result");
      break;
    }
    break;
  }

  case CONN_STATE_RECEIVING: {
    if (fetch_atomic_load(&conn->cancelled) ||
        fetch_atomic_load(&g_event_loop.shutdown_requested)) {
      set_connection_cancelled(conn, "Connection cancelled during receive");
      return;
    }

    if (conn->response_size > 0) {
      if (!conn->parse_ctx) {
        conn->parse_ctx = http_parse_context_new();
        if (!conn->parse_ctx) {
          set_connection_error(conn, FETCH_ERROR_MEMORY,
                               "Failed to allocate HTTP parser");
          return;
        }
      }

      size_t total_consumed = 0;
      size_t parse_iterations = 0;
      const size_t MAX_PARSE_ITERATIONS = 100;

      while (total_consumed < conn->response_size &&
             parse_iterations < MAX_PARSE_ITERATIONS) {
        size_t consumed = 0;

        if (fetch_atomic_load(&conn->cancelled) ||
            fetch_atomic_load(&g_event_loop.shutdown_requested)) {
          set_connection_cancelled(conn,
                                   "Connection cancelled during HTTP parsing");
          return;
        }

        if (!parse_http_response(
                conn->parse_ctx, conn->response_buffer + total_consumed,
                conn->response_size - total_consumed, &consumed)) {
          set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                               "Invalid HTTP response format");
          return;
        }

        if (consumed == 0) {
          break;
        }

        total_consumed += consumed;
        parse_iterations++;

        if (conn->parse_ctx->state >= HTTP_PARSE_BODY &&
            conn->parse_ctx->headers_complete &&
            is_redirect_status(conn->parse_ctx->status_code)) {
          if (!handle_redirect_response(conn)) {
            return;
          }
          return;
        }

        if (is_response_complete(conn->parse_ctx)) {
          bool supports_keep_alive = false;
          fetch_response_t *response = create_response_from_context(
              conn->parse_ctx, get_connection_url(conn), &supports_keep_alive,
              conn->request);

          if (response) {
            conn->response_supports_keep_alive = supports_keep_alive;
            set_connection_complete(conn, response);
          } else {
            set_connection_error(conn, FETCH_ERROR_MEMORY,
                                 "Failed to create response object");
          }
          return;
        }
      }

      if (parse_iterations >= MAX_PARSE_ITERATIONS) {
        set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                             "HTTP parsing exceeded maximum iterations");
        return;
      }

      if (total_consumed > 0) {
        if (total_consumed >= conn->response_size) {
          conn->response_size = 0;
        } else {
          memmove(conn->response_buffer, conn->response_buffer + total_consumed,
                  conn->response_size - total_consumed);
          conn->response_size -= total_consumed;
        }
      }

      if (is_response_complete(conn->parse_ctx)) {
        bool supports_keep_alive = false;
        fetch_response_t *response = create_response_from_context(
            conn->parse_ctx, get_connection_url(conn), &supports_keep_alive,
            conn->request);

        if (response) {
          conn->response_supports_keep_alive = supports_keep_alive;
          set_connection_complete(conn, response);
        } else {
          set_connection_error(conn, FETCH_ERROR_MEMORY,
                               "Failed to create response object");
        }
        return;
      }
    }

    socket_op_result_t recv_result;

#if defined(_WIN32) || defined(_WIN64)

    if (conn->current_io_ctx && conn->current_io_ctx->operation == IO_OP_RECV) {

      break;
    }

    recv_result = receive_data(conn);

#else

    recv_result = receive_data(conn);
#endif

    switch (recv_result) {
    case SOCKET_OP_ERROR:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Failed to receive response");
      break;

    case SOCKET_OP_CLOSED:
      if (conn->parse_ctx && is_response_complete(conn->parse_ctx)) {
        if (is_redirect_status(conn->parse_ctx->status_code)) {
          if (!handle_redirect_response(conn)) {
            return;
          }
          return;
        }

        bool supports_keep_alive = false;
        fetch_response_t *response = create_response_from_context(
            conn->parse_ctx, get_connection_url(conn), &supports_keep_alive,
            conn->request);

        if (response) {
          conn->response_supports_keep_alive = supports_keep_alive;
          set_connection_complete(conn, response);
        } else {
          set_connection_error(conn, FETCH_ERROR_MEMORY,
                               "Failed to create response object");
        }
      } else {
        set_connection_error(conn, FETCH_ERROR_NETWORK,
                             "Connection closed unexpectedly");
      }
      break;

    case SOCKET_OP_SUCCESS:
      break;

    case SOCKET_OP_WOULD_BLOCK:
    case SOCKET_OP_IN_PROGRESS:
      break;

    default:
      set_connection_error(conn, FETCH_ERROR_NETWORK,
                           "Unexpected receive result");
      break;
    }
    break;
  }

  case CONN_STATE_COMPLETE:
  case CONN_STATE_ERROR:
  case CONN_STATE_CANCELLED:
    break;

  default:
    set_connection_error(conn, FETCH_ERROR_PROTOCOL_ERROR,
                         "Connection in invalid or unhandled state");
    break;
  }

  if (conn->state != CONN_STATE_COMPLETE && conn->state != CONN_STATE_ERROR &&
      conn->state != CONN_STATE_CANCELLED) {
    update_connection_activity(conn);
  }

  if (fetch_atomic_load(&conn->cancelled) &&
      conn->state != CONN_STATE_CANCELLED) {
    set_connection_cancelled(conn, conn->cancel_reason
                                       ? conn->cancel_reason
                                       : "Connection cancelled");
  }
}

#if defined(_WIN32) || defined(_WIN64)

static int process_events_windows(uint32_t timeout_ms) {
  int events_processed = 0;

  DWORD wait_timeout =
      (timeout_ms == FETCH_WAIT_INFINITE) ? INFINITE : timeout_ms;

  uint64_t current_time_ms = fetch_get_time_ms();
  if (g_event_loop.next_timer_check_ms > 0 &&
      current_time_ms >= g_event_loop.next_timer_check_ms) {
    process_timeout_events();
    events_processed++;
  }

  DWORD bytes_transferred;
  ULONG_PTR completion_key;
  LPOVERLAPPED overlapped;

  while (true) {
    BOOL result =
        GetQueuedCompletionStatus(g_event_loop.iocp, &bytes_transferred,
                                  &completion_key, &overlapped, wait_timeout);

    if (!result && overlapped == NULL) {
      DWORD error = GetLastError();
      if (error == WAIT_TIMEOUT) {
        break;
      } else {
        break;
      }
    }

    events_processed++;

    if (overlapped == NULL) {
      continue;
    }

    win_io_context_t *ctx = (win_io_context_t *)overlapped;

    if (!ctx || !ctx->conn) {
      continue;
    }

    DWORD error = result ? 0 : GetLastError();

    process_iocp_completion(ctx, bytes_transferred, error);

    wait_timeout = 0;
  }

  if (WaitForSingleObject(g_event_loop.wakeup_event, 0) == WAIT_OBJECT_0) {
    ResetEvent(g_event_loop.wakeup_event);
    events_processed++;
  }

  int connections_processed = 0;
  fetch_connection_t *conn = g_event_loop.active_connections;
  while (conn) {
    fetch_connection_t *next = conn->next;

    if (conn->current_io_ctx == NULL ||
        conn->state == CONN_STATE_TLS_HANDSHAKE ||
        conn->state == CONN_STATE_SENDING ||
        conn->state == CONN_STATE_RECEIVING) {
      process_connection_state(conn);
      connections_processed++;
    }

    conn = next;
  }

  return events_processed;
}

#elif defined(__linux__)

static int process_events_linux(uint32_t timeout_ms) {
  int events_processed = 0;

  if (g_event_loop.next_timer_check_ms > 0) {
    update_timer_linux(g_event_loop.next_timer_check_ms);
  }

  struct epoll_event events[64];
  int timeout = (timeout_ms == FETCH_WAIT_INFINITE) ? -1 : (int)timeout_ms;

  int nfds = epoll_wait(g_event_loop.epoll_fd, events, 64, timeout);

  if (nfds == -1) {
    if (errno == EINTR) {
      return 0;
    }
    return -1;
  }

  struct {
    fetch_connection_t *conn;
    uint32_t events;
  } valid_connections[64];
  int valid_conn_count = 0;

  for (int i = 0; i < nfds; i++) {
    events_processed++;

    void *data_ptr = events[i].data.ptr;
    uint32_t event_mask = events[i].events;

    if (data_ptr == NULL) {
      if (event_mask & EPOLLIN) {
        uint64_t val;
        ssize_t result = read(g_event_loop.eventfd, &val, sizeof(val));
        (void)result;
      }
      continue;
    } else if (data_ptr == (void *)0x1) {
      if (event_mask & EPOLLIN) {
        uint64_t expirations;
        ssize_t result =
            read(g_event_loop.timerfd, &expirations, sizeof(expirations));
        (void)result;
        process_timeout_events();
      }
      continue;
    }

    fetch_connection_t *conn = (fetch_connection_t *)data_ptr;
    if (!conn)
      continue;

    bool conn_valid = false;
    fetch_connection_t *check = g_event_loop.active_connections;
    while (check) {
      if (check == conn) {
        conn_valid = true;
        break;
      }
      check = check->next;
    }

    if (!conn_valid) {
      continue;
    }

    if (valid_conn_count < 64) {
      valid_connections[valid_conn_count].conn = conn;
      valid_connections[valid_conn_count].events = event_mask;
      valid_conn_count++;
    }
  }

  for (int i = 0; i < valid_conn_count; i++) {
    fetch_connection_t *conn = valid_connections[i].conn;
    uint32_t event_mask = valid_connections[i].events;

    bool conn_still_valid = false;
    fetch_connection_t *check = g_event_loop.active_connections;
    while (check) {
      if (check == conn) {
        conn_still_valid = true;
        break;
      }
      check = check->next;
    }

    if (!conn_still_valid) {
      continue;
    }

    if (event_mask & (EPOLLERR | EPOLLHUP)) {
      set_connection_error(conn, FETCH_ERROR_NETWORK, "Socket error");
      continue;
    }

#if defined(LIBFETCH_TLS_ENABLED)

    if (conn->state == CONN_STATE_TLS_HANDSHAKE) {
      if (conn->tls && (event_mask & (EPOLLIN | EPOLLOUT))) {
        process_connection_state(conn);
      }
      continue;
    }
#endif

    if (event_mask & EPOLLOUT) {
      if (conn->state == CONN_STATE_CONNECTING) {
        if (check_connect_completion(conn) == SOCKET_OP_SUCCESS) {
#if defined(LIBFETCH_TLS_ENABLED)
          if (conn->is_https) {
            conn->state = CONN_STATE_TLS_HANDSHAKE;
          } else {
            conn->state = CONN_STATE_SENDING;
          }
#else
          conn->state = CONN_STATE_SENDING;
#endif
        } else {
          set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                               "Connection failed");
          continue;
        }
      }

      if (conn->state == CONN_STATE_SENDING) {
        process_connection_state(conn);
      }

#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls && conn->state == CONN_STATE_RECEIVING) {
        if (conn->tls->want_write) {
          process_connection_state(conn);
        }
      }
#endif
    }

    if (event_mask & EPOLLIN) {

      if (conn->state == CONN_STATE_RECEIVING) {
        process_connection_state(conn);
      }

#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls && conn->state == CONN_STATE_SENDING) {
        if (conn->tls->want_read) {
          process_connection_state(conn);
        }
      }
#endif
    }
  }

  return events_processed;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)

static int process_events_kqueue(uint32_t timeout_ms) {
  int events_processed = 0;

  struct kevent events[64];
  struct timespec timeout_spec;
  const struct timespec *timeout_ptr = NULL;

  if (timeout_ms != (uint32_t)FETCH_WAIT_INFINITE) {
    timeout_spec.tv_sec = timeout_ms / 1000;
    timeout_spec.tv_nsec = (timeout_ms % 1000) * 1000000;
    timeout_ptr = &timeout_spec;
  }

  if (g_event_loop.next_timer_check_ms > 0) {
    const uint64_t current_time_ms = fetch_get_time_ms();
    if (current_time_ms < g_event_loop.next_timer_check_ms) {
      const uint64_t timer_delay_ms =
          g_event_loop.next_timer_check_ms - current_time_ms;

      struct kevent timer_kev;
      EV_SET(&timer_kev, KQUEUE_TIMER_IDENT, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
             0, timer_delay_ms, NULL);
      kevent(g_event_loop.kqueue_fd, &timer_kev, 1, NULL, 0, NULL);
    } else {
      process_timeout_events();
      events_processed++;
    }
  }

  const int nfds =
      kevent(g_event_loop.kqueue_fd, NULL, 0, events, 64, timeout_ptr);

  if (nfds == -1) {
    if (errno == EINTR) {
      return events_processed;
    }
    return -1;
  }

  struct {
    fetch_connection_t *conn;
    int filter;
    int flags;
  } valid_connections[64];
  int valid_conn_count = 0;

  for (int i = 0; i < nfds; i++) {
    events_processed++;

    const struct kevent *kev = &events[i];

    if (kev->ident == (uintptr_t)g_event_loop.wakeup_pipe[0]) {
      char buffer[256];
      read(g_event_loop.wakeup_pipe[0], buffer, sizeof(buffer));
      continue;
    }

    if (kev->filter == EVFILT_TIMER) {
      process_timeout_events();
      continue;
    }

    fetch_connection_t *conn = kev->udata;
    if (!conn) {
      continue;
    }

    bool conn_valid = false;
    fetch_connection_t *check = g_event_loop.active_connections;
    while (check) {
      if (check == conn) {
        conn_valid = true;
        break;
      }
      check = check->next;
    }

    if (!conn_valid) {
      continue;
    }

    if (valid_conn_count < 64) {
      valid_connections[valid_conn_count].conn = conn;
      valid_connections[valid_conn_count].filter = kev->filter;
      valid_connections[valid_conn_count].flags = kev->flags;
      valid_conn_count++;
    }
  }

  for (int i = 0; i < valid_conn_count; i++) {
    fetch_connection_t *conn = valid_connections[i].conn;

    bool conn_still_valid = false;
    fetch_connection_t *check = g_event_loop.active_connections;
    while (check) {
      if (check == conn) {
        conn_still_valid = true;
        break;
      }
      check = check->next;
    }

    if (!conn_still_valid) {
      continue;
    }

    if (valid_connections[i].flags & EV_ERROR) {
      set_connection_error(conn, FETCH_ERROR_NETWORK, "Socket error");
      continue;
    }

#if defined(LIBFETCH_TLS_ENABLED)

    if (conn->state == CONN_STATE_TLS_HANDSHAKE) {
      if (conn->tls && (valid_connections[i].filter == EVFILT_READ ||
                        valid_connections[i].filter == EVFILT_WRITE)) {
        process_connection_state(conn);
      }
      continue;
    }
#endif

    if (valid_connections[i].filter == EVFILT_WRITE) {
      if (conn->state == CONN_STATE_CONNECTING) {
        if (check_connect_completion(conn) == SOCKET_OP_SUCCESS) {
#if defined(LIBFETCH_TLS_ENABLED)
          if (conn->is_https) {
            conn->state = CONN_STATE_TLS_HANDSHAKE;
          } else {
            conn->state = CONN_STATE_SENDING;
          }
#else
          conn->state = CONN_STATE_SENDING;
#endif
        } else {
          set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                               "Connection failed");
          continue;
        }
      }

      if (conn->state == CONN_STATE_SENDING) {
        process_connection_state(conn);
      }

#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls && conn->state == CONN_STATE_RECEIVING) {
        if (conn->tls->want_write) {
          process_connection_state(conn);
        }
      }
#endif
    }

    if (valid_connections[i].filter == EVFILT_READ) {

      if (conn->state == CONN_STATE_RECEIVING) {
        process_connection_state(conn);
      }

#if defined(LIBFETCH_TLS_ENABLED)

      if (conn->is_https && conn->tls && conn->state == CONN_STATE_SENDING) {
        if (conn->tls->want_read) {
          process_connection_state(conn);
        }
      }
#endif
    }
  }

  return events_processed;
}

#else

static int process_events_select(uint32_t timeout_ms) {
  int events_processed = 0;

  uint64_t current_time_ms = fetch_get_time_ms();
  if (g_event_loop.next_timer_check_ms > 0 &&
      current_time_ms >= g_event_loop.next_timer_check_ms) {
    process_timeout_events();
    events_processed++;
  }

  fd_set read_fds, write_fds, error_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_ZERO(&error_fds);

  FETCH_SOCKET max_fd = 0;

  FD_SET(g_event_loop.wakeup_pipe[0], &read_fds);
  if (g_event_loop.wakeup_pipe[0] > max_fd) {
    max_fd = g_event_loop.wakeup_pipe[0];
  }

  fetch_connection_t *conn = g_event_loop.active_connections;
  while (conn) {
    if (conn->socket != FETCH_INVALID_SOCKET) {
      FD_SET(conn->socket, &error_fds);

#if defined(LIBFETCH_TLS_ENABLED)
      if (conn->state == CONN_STATE_CONNECTING ||
          conn->state == CONN_STATE_SENDING ||
          (conn->state == CONN_STATE_TLS_HANDSHAKE && conn->tls &&
           conn->tls->want_write)) {
        FD_SET(conn->socket, &write_fds);
      }

      if (conn->state == CONN_STATE_RECEIVING ||
          (conn->state == CONN_STATE_TLS_HANDSHAKE && conn->tls &&
           conn->tls->want_read)) {
        FD_SET(conn->socket, &read_fds);
      }
#else
      if (conn->state == CONN_STATE_CONNECTING ||
          conn->state == CONN_STATE_SENDING) {
        FD_SET(conn->socket, &write_fds);
      }

      if (conn->state == CONN_STATE_RECEIVING) {
        FD_SET(conn->socket, &read_fds);
      }
#endif

      if (conn->socket > max_fd) {
        max_fd = conn->socket;
      }
    }
    conn = conn->next;
  }

  struct timeval tv;
  struct timeval *tv_ptr = NULL;

  if (timeout_ms != FETCH_WAIT_INFINITE) {
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    tv_ptr = &tv;
  }

  int result = select(max_fd + 1, &read_fds, &write_fds, &error_fds, tv_ptr);

  if (result == -1) {
    if (errno == EINTR) {
      return events_processed;
    }
    return -1;
  }

  if (result == 0) {
    return events_processed;
  }

  if (FD_ISSET(g_event_loop.wakeup_pipe[0], &read_fds)) {
    char buffer[256];
    read(g_event_loop.wakeup_pipe[0], buffer, sizeof(buffer));
    events_processed++;
  }

  conn = g_event_loop.active_connections;
  while (conn) {
    fetch_connection_t *next = conn->next;

    if (conn->socket != FETCH_INVALID_SOCKET) {
      if (FD_ISSET(conn->socket, &error_fds)) {
        set_connection_error(conn, FETCH_ERROR_NETWORK, "Socket error");
        events_processed++;
      } else {
        bool process_state = false;

        if (FD_ISSET(conn->socket, &write_fds)) {
          if (conn->state == CONN_STATE_CONNECTING) {
            if (check_connect_completion(conn) == SOCKET_OP_SUCCESS) {
#if defined(LIBFETCH_TLS_ENABLED)
              if (conn->is_https) {
                conn->state = CONN_STATE_TLS_HANDSHAKE;
              } else {
                conn->state = CONN_STATE_SENDING;
              }
#else
              conn->state = CONN_STATE_SENDING;
#endif
            } else {
              set_connection_error(conn, FETCH_ERROR_CONNECTION_REFUSED,
                                   "Connection failed");
            }
          }
          process_state = true;
          events_processed++;
        }

        if (FD_ISSET(conn->socket, &read_fds)) {
          process_state = true;
          events_processed++;
        }

        if (process_state) {
          process_connection_state(conn);
        }
      }
    }

    conn = next;
  }

  return events_processed;
}

#endif

static void perform_pool_maintenance(void) {
  const uint64_t current_time = fetch_get_time_ms();

  if (current_time - g_pool_manager.last_global_cleanup_ms <
      g_fetch_config.pool_cleanup_interval_ms)
    return;

  g_pool_manager.last_global_cleanup_ms = current_time;

  connection_pool_t *pool = g_pool_manager.pools;
  while (pool) {
    cleanup_expired_connections(pool);
    pool = pool->next;
  }

  while (g_pool_manager.total_pooled > g_fetch_config.max_pooled_connections) {

    pooled_connection_t *oldest = NULL;
    connection_pool_t *oldest_pool = NULL;
    uint64_t oldest_time = UINT64_MAX;

    connection_pool_t *current_pool = g_pool_manager.pools;
    while (current_pool) {
      if (current_pool->available_tail &&
          current_pool->available_tail->last_used_ms < oldest_time) {
        oldest = current_pool->available_tail;
        oldest_pool = current_pool;
        oldest_time = oldest->last_used_ms;
      }
      current_pool = current_pool->next;
    }

    if (oldest && oldest_pool) {
      remove_from_available(oldest_pool, oldest);
      pooled_connection_free(oldest);
    } else {
      break;
    }
  }
}

int fetch_event_loop_process(uint32_t timeout_ms) {
  static uint64_t loop_iteration = 0;
  loop_iteration++;

  if ((loop_iteration % 100) == 0) {

    fetch_connection_t *conn = g_event_loop.active_connections;
    while (conn) {
      conn = conn->next;
    }
  }

  if (!fetch_event_loop_is_running()) {

    return -1;
  }
  perform_pool_maintenance();

  dns_resolver_process(g_dns_resolver);

  int events_processed = 0;

  process_completed_connections();

#if defined(_WIN32) || defined(_WIN64)
  events_processed = process_events_windows(timeout_ms);
#elif defined(__linux__)
  events_processed = process_events_linux(timeout_ms);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||    \
    defined(__NetBSD__)
  events_processed = process_events_kqueue(timeout_ms);
#else
  events_processed = process_events_select(timeout_ms);
#endif

  fetch_connection_t *conn = g_event_loop.active_connections;
  while (conn) {
    fetch_connection_t *next = conn->next;

    if (conn->promise && conn->promise->state == FETCH_PROMISE_REJECTED) {
      set_connection_cancelled(conn, "Promise rejected");
    } else {

      const uint64_t current_time_ms = fetch_get_time_ms();
      if (is_connection_timed_out(conn, current_time_ms)) {
        set_connection_error(conn, FETCH_ERROR_TIMEOUT, "Request timed out");
      } else if (conn->state != CONN_STATE_COMPLETE &&
                 conn->state != CONN_STATE_ERROR &&
                 conn->state != CONN_STATE_CANCELLED) {
#if defined(_WIN32) || defined(_WIN64)

        if (conn->current_io_ctx == NULL) {
          process_connection_state(conn);
        }
#else
        process_connection_state(conn);
#endif
      }
    }

    conn = next;
  }

  process_completed_connections();

  return events_processed;
}

bool fetch_event_loop_start(void) {

  if (fetch_atomic_load(&g_event_loop.running)) {

    return true;
  }

  if (!init_event_loop_platform()) {

    return false;
  }
  fetch_atomic_store(&g_event_loop.running, 1);
  fetch_atomic_store(&g_event_loop.shutdown_requested, 0);
  g_event_loop.active_connections = NULL;
  g_event_loop.completed_connections = NULL;
  g_event_loop.active_count = 0;
  g_event_loop.max_connections = g_fetch_config.max_connections;
  g_event_loop.timers = NULL;
  g_event_loop.next_timer_check_ms = 0;

  fetch_atomic_store(&g_event_loop.next_connection_id, 1);
  fetch_atomic_store(&g_event_loop.total_requests, 0);
  fetch_atomic_store(&g_event_loop.successful_requests, 0);
  fetch_atomic_store(&g_event_loop.failed_requests, 0);
  fetch_atomic_store(&g_event_loop.cancelled_requests, 0);

  return true;
}

void fetch_event_loop_stop(void) {
  if (!fetch_atomic_load(&g_event_loop.running)) {
    return;
  }

  fetch_atomic_store(&g_event_loop.shutdown_requested, true);

  fetch_connection_t *conn = g_event_loop.active_connections;
  while (conn) {
    fetch_connection_t *next = conn->next;
    set_connection_cancelled(conn, "Event loop shutting down");
    conn = next;
  }

  while (g_event_loop.completed_connections) {
    fetch_connection_t *fetch_connection = g_event_loop.completed_connections;
    g_event_loop.completed_connections = fetch_connection->next;
    fetch_connection_free(fetch_connection);
  }

  while (g_event_loop.active_connections) {
    fetch_connection_t *fetch_connection = g_event_loop.active_connections;
    remove_active_connection(fetch_connection);
    fetch_connection_free(fetch_connection);
  }

  while (g_event_loop.timers) {
    fetch_timer_t *timer = g_event_loop.timers;
    g_event_loop.timers = timer->next;
    free(timer);
  }

  cleanup_event_loop_platform();
  fetch_atomic_store(&g_event_loop.running, 0);
}

bool fetch_event_loop_is_running(void) {
  return fetch_atomic_load(&g_event_loop.running);
}

static bool submit_connection_to_event_loop(fetch_connection_t *conn) {

  if (!conn || !fetch_event_loop_is_running()) {

    return false;
  }

  if (g_event_loop.active_count >= g_fetch_config.max_connections) {

    return false;
  }

  add_active_connection(conn);

  if (!add_connection_timeout(conn)) {

    remove_active_connection(conn);
    return false;
  }

  fetch_atomic_inc(&g_event_loop.total_requests);

  wakeup_event_loop();

  return true;
}

#if defined(LIBFETCH_TLS_ENABLED)
static void cleanup_tls(void) {
  cleanup_tls_session_cache();

  if (g_client_ssl_ctx) {
    SSL_CTX_free(g_client_ssl_ctx);
    g_client_ssl_ctx = NULL;
  }

  EVP_cleanup();
  ERR_free_strings();
  g_tls_initialized = false;
}

#endif

void fetch_global_init(const fetch_config_t *config) {
  if (g_user_agent_allocated && g_fetch_config.user_agent) {
    free((char *)g_fetch_config.user_agent);
    g_fetch_config.user_agent = NULL;
    g_user_agent_allocated = false;
  }

  if (g_fetch_config.origin) {
    free((char *)g_fetch_config.origin);
    g_fetch_config.origin = NULL;
  }

  if (config) {
    g_fetch_config.default_timeout_ms = config->default_timeout_ms;
    g_fetch_config.max_connections = config->max_connections;
    g_fetch_config.max_connections_per_host = config->max_connections_per_host;
    g_fetch_config.keep_alive_timeout_ms = config->keep_alive_timeout_ms;
    g_fetch_config.pool_cleanup_interval_ms = config->pool_cleanup_interval_ms;
    g_fetch_config.max_pooled_connections = config->max_pooled_connections;

    g_fetch_config.flags = config->flags;

    if (config->origin) {
      g_fetch_config.origin = strdup(config->origin);
    } else {
      g_fetch_config.origin = NULL;
    }

    g_fetch_config.cookie_jar = config->cookie_jar;

    if (config->user_agent) {
      g_fetch_config.user_agent = strdup(config->user_agent);
      g_user_agent_allocated = true;
    } else {
      g_fetch_config.user_agent = FETCH_USER_AGENT;
      g_user_agent_allocated = false;
    }
  } else {
    g_fetch_config.default_timeout_ms = 30000;
    g_fetch_config.max_connections = 1000;
    g_fetch_config.max_connections_per_host = 6;
    g_fetch_config.keep_alive_timeout_ms = 115000;
    g_fetch_config.pool_cleanup_interval_ms = 30000;
    g_fetch_config.max_pooled_connections = 100;
    g_fetch_config.user_agent = FETCH_USER_AGENT;
    g_fetch_config.origin = NULL;
    g_fetch_config.cookie_jar = NULL;
    g_user_agent_allocated = false;

    g_fetch_config.flags = (1U << FETCH_FLAG_KEEP_ALIVE_DEFAULT) |
                           (1U << FETCH_FLAG_FOLLOW_REDIRECTS) |
                           (1U << FETCH_FLAG_ENABLE_COMPRESSION) |
                           (1U << FETCH_FLAG_ENABLE_COOKIES);
  }

  memset(&g_pool_manager, 0, sizeof(g_pool_manager));
  g_pool_manager.last_global_cleanup_ms = fetch_get_time_ms();

#if defined(_WIN32) || defined(_WIN64)
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);

  SOCKET temp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (temp_socket != INVALID_SOCKET) {
    GUID guid_connect_ex = WSAID_CONNECTEX;
    DWORD bytes_returned;
    WSAIoctl(temp_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid_connect_ex,
             sizeof(guid_connect_ex), &g_connect_ex_func,
             sizeof(g_connect_ex_func), &bytes_returned, NULL, NULL);
    closesocket(temp_socket);
  }
#endif

#if defined(LIBFETCH_TLS_ENABLED)

  if (!init_tls()) {
  }
#endif

  dns_config_t dns_config = dns_config_default();
  dns_config.timeout_ms = 5000;
  dns_config.max_concurrent = 10;
  g_dns_resolver = dns_resolver_create(&dns_config);

  if (!g_dns_resolver) {

#if defined(LIBFETCH_TLS_ENABLED)
    cleanup_tls();
#endif
#if defined(_WIN32) || defined(_WIN64)
    WSACleanup();
    g_connect_ex_func = NULL;
#endif
    memset(&g_pool_manager, 0, sizeof(g_pool_manager));
    g_fetch_initialized = false;
    return;
  }

  g_fetch_initialized = true;
}

void fetch_global_dispose(void) {
  if (!g_fetch_initialized) {
    return;
  }

  if (fetch_event_loop_is_running()) {
    fetch_event_loop_stop();
  }

  connection_pool_t *pool = g_pool_manager.pools;
  while (pool) {
    connection_pool_t *next_pool = pool->next;

    pooled_connection_t *conn = pool->available;
    while (conn) {
      pooled_connection_t *next_conn = conn->next;

      if (pool->available_count > 0) {
        pool->available_count--;
      }
      if (g_pool_manager.total_pooled > 0) {
        g_pool_manager.total_pooled--;
      }
      pooled_connection_free(conn);
      conn = next_conn;
    }

    free(pool->host);
    pool->host = NULL;
    pool->available = NULL;
    pool->available_tail = NULL;
    pool->available_count = 0;
    pool->active_count = 0;
    pool->next = NULL;
    free(pool);
    pool = next_pool;
  }

  g_pool_manager.pools = NULL;
  g_pool_manager.total_pooled = 0;
  g_pool_manager.max_total_pooled = 0;
  g_pool_manager.last_global_cleanup_ms = 0;

  if (g_user_agent_allocated && g_fetch_config.user_agent) {
    free((char *)g_fetch_config.user_agent);
    g_user_agent_allocated = false;
  }

  if (g_fetch_config.origin) {
    free((char *)g_fetch_config.origin);
  }

  dns_resolver_destroy(g_dns_resolver);
  g_dns_resolver = NULL;

#if defined(LIBFETCH_TLS_ENABLED)

  cleanup_tls();
#endif

  memset(&g_fetch_config, 0, sizeof(g_fetch_config));

  memset(&g_event_loop, 0, sizeof(g_event_loop));

#if defined(_WIN32) || defined(_WIN64)
  g_connect_ex_func = NULL;
  WSACleanup();
#endif

  g_fetch_initialized = false;
}

static fetch_error_t validate_request(const char *url, const fetch_init_t *init,
                                      fetch_url_t **parsed_url_out) {
  if (!parsed_url_out) {
    return FETCH_ERROR_INVALID_URL;
  }

  *parsed_url_out = NULL;

  if (!url || strnlen(url, FETCH_MAX_URL_LENGTH) == 0) {
    return FETCH_ERROR_INVALID_URL;
  }

  fetch_url_t *parsed_url = fetch_url_parse(url);
  if (!parsed_url) {
    return FETCH_ERROR_INVALID_URL;
  }

  if (!parsed_url->protocol ||
      (fetch_strcasecmp(parsed_url->protocol, "http") != 0 &&
       fetch_strcasecmp(parsed_url->protocol, "https") != 0)) {
    fetch_url_free(parsed_url);
    return FETCH_ERROR_INVALID_URL;
  }

  if (init) {

    if (init->method < HTTP_METHOD_GET || init->method > HTTP_METHOD_PATCH) {
      fetch_url_free(parsed_url);
      return FETCH_ERROR_INVALID_METHOD;
    }

    if ((init->method == HTTP_METHOD_GET || init->method == HTTP_METHOD_HEAD) &&
        init->body) {
      fetch_url_free(parsed_url);
      return FETCH_ERROR_INVALID_METHOD;
    }

    if (init->redirect == FETCH_REDIRECT_FOLLOW &&
        !fetch_config_get_flag(g_fetch_config.flags,
                               FETCH_FLAG_FOLLOW_REDIRECTS)) {
      fetch_url_free(parsed_url);
      return FETCH_ERROR_NETWORK;
    }
  }

  *parsed_url_out = parsed_url;
  return FETCH_ERROR_NONE;
}

static fetch_response_t *create_error_response(fetch_error_t error,
                                               const char *message,
                                               const char *url) {
  fetch_response_t *response = calloc(1, sizeof(fetch_response_t));
  if (!response)
    return NULL;

  response->status = 0;
  response->status_text = strdup("Error");
  response->ok = false;
  response->redirected = false;
  response->url = strndup(url ? url : "", FETCH_MAX_URL_LENGTH);
  response->headers = fetch_headers_new();
  response->body = NULL;
  response->body_size = 0;
  response->body_type = FETCH_BODY_NONE;
  response->error = error;
  response->error_message =
      strdup(message ? message : fetch_error_to_string(error));

  return response;
}

fetch_promise_t *fetch_async(const char *url, fetch_init_t *init) {

  if (!g_fetch_initialized) {
    fetch_global_init(NULL);
  }

  if (!fetch_event_loop_is_running()) {
    if (!fetch_event_loop_start()) {
      return NULL;
    }
  }

  fetch_url_t *parsed_url = NULL;
  const fetch_error_t validation_error =
      validate_request(url, init, &parsed_url);
  if (validation_error != FETCH_ERROR_NONE) {

    if (parsed_url) {
      fetch_url_free(parsed_url);
    }

    fetch_promise_t *promise = calloc(1, sizeof(fetch_promise_t));
    if (promise) {
      promise->state = FETCH_PROMISE_REJECTED;
      promise->error = validation_error;
      promise->error_message = strdup(fetch_error_to_string(validation_error));
      promise->detached = false;
    }
    return promise;
  }

  fetch_request_t *request = fetch_request_new(parsed_url, init);
  if (!request) {
    fetch_url_free(parsed_url);

    fetch_promise_t *promise = calloc(1, sizeof(fetch_promise_t));
    if (promise) {
      promise->state = FETCH_PROMISE_REJECTED;
      promise->error = FETCH_ERROR_MEMORY;
      promise->error_message = strdup("Failed to create request");
      promise->detached = false;
    }
    return promise;
  }

  fetch_promise_t *promise = calloc(1, sizeof(fetch_promise_t));
  if (!promise) {
    fetch_request_free(request);
    return NULL;
  }

  promise->state = FETCH_PROMISE_PENDING;
  promise->detached = false;

  fetch_connection_t *conn = fetch_connection_new(promise, request);
  if (!conn) {
    fetch_promise_free(promise);
    return NULL;
  }

  promise->internal_state = conn;

  if (!submit_connection_to_event_loop(conn)) {
    fetch_connection_free(conn);
    fetch_promise_free(promise);
    return NULL;
  }

  return promise;
}

fetch_response_t *fetch(const char *url, fetch_init_t *init) {

  fetch_promise_t *promise = fetch_async(url, init);
  if (!promise) {

    return create_error_response(FETCH_ERROR_MEMORY, "Failed to create promise",
                                 url);
  }

  if (promise->state == FETCH_PROMISE_REJECTED) {

    fetch_response_t *error_response =
        create_error_response(promise->error, promise->error_message, url);
    fetch_promise_free(promise);
    return error_response;
  }

  uint32_t timeout_ms =
      init ? init->timeout_ms : g_fetch_config.default_timeout_ms;
  if (timeout_ms == 0)
    timeout_ms = g_fetch_config.default_timeout_ms;

  const uint64_t start_time_ms = fetch_get_time_ms();

  while (promise->state == FETCH_PROMISE_PENDING) {
    const uint64_t current_time_ms = fetch_get_time_ms();
    const uint64_t elapsed_ms = current_time_ms - start_time_ms;

    if (elapsed_ms >= timeout_ms) {

      fetch_promise_cancel(promise, "Synchronous fetch timed out");
      break;
    }

    uint32_t remaining_timeout = (uint32_t)(timeout_ms - elapsed_ms);
    if (remaining_timeout > 100)
      remaining_timeout = 100;

    const int events_processed = fetch_event_loop_process(remaining_timeout);
    if (events_processed < 0) {

      break;
    }
  }

  fetch_response_t *response = NULL;

  if (promise->state == FETCH_PROMISE_FULFILLED && promise->response) {
    response = promise->response;
    promise->response = NULL;
  } else {

    const fetch_error_t error = (promise->state == FETCH_PROMISE_REJECTED)
                                    ? promise->error
                                    : FETCH_ERROR_TIMEOUT;
    const char *message = (promise->state == FETCH_PROMISE_REJECTED)
                              ? promise->error_message
                              : "Request timed out";
    response = create_error_response(error, message, url);
  }

  fetch_promise_free(promise);
  return response;
}

bool fetch_promise_poll(fetch_promise_t *promise) {
  if (!promise)
    return false;

  return (promise->state != FETCH_PROMISE_PENDING);
}

bool fetch_promise_await(fetch_promise_t *promise, uint32_t timeout_ms) {
  if (!promise)
    return false;

  if (promise->state != FETCH_PROMISE_PENDING) {
    return true;
  }

  const uint64_t start_time_ms = fetch_get_time_ms();

  while (promise->state == FETCH_PROMISE_PENDING) {
    const uint64_t current_time_ms = fetch_get_time_ms();
    const uint64_t elapsed_ms = current_time_ms - start_time_ms;

    if (timeout_ms > 0 && elapsed_ms >= timeout_ms) {
      return false;
    }

    uint32_t remaining_timeout = 0;
    if (timeout_ms > 0) {
      remaining_timeout = (uint32_t)(timeout_ms - elapsed_ms);
      if (remaining_timeout > 100)
        remaining_timeout = 100;
    } else {
      remaining_timeout = 100;
    }

    const int events_processed = fetch_event_loop_process(remaining_timeout);
    if (events_processed < 0) {
      return false;
    }
  }

  return true;
}

bool fetch_promise_cancel(fetch_promise_t *promise, const char *reason) {
  if (!promise || promise->state != FETCH_PROMISE_PENDING) {
    return false;
  }

  if (promise->detached) {

    promise->state = FETCH_PROMISE_REJECTED;
    promise->error = FETCH_ERROR_ABORTED;
    free((void *)promise->error_message);
    promise->error_message = strdup(reason ? reason : "Promise cancelled");
    return true;
  }

  fetch_connection_t *conn = (fetch_connection_t *)promise->internal_state;
  if (conn) {

    bool conn_valid = false;

    fetch_connection_t *check = g_event_loop.active_connections;
    while (check && !conn_valid) {
      if (check == conn) {
        conn_valid = true;
        break;
      }
      check = check->next;
    }

    if (conn_valid) {
      set_connection_cancelled(conn, reason ? reason : "Promise cancelled");
    } else {

      promise->state = FETCH_PROMISE_REJECTED;
      promise->error = FETCH_ERROR_ABORTED;
      free((void *)promise->error_message);
      promise->error_message = strdup(reason ? reason : "Promise cancelled");
      promise->internal_state = NULL;
    }
  } else {

    promise->state = FETCH_PROMISE_REJECTED;
    promise->error = FETCH_ERROR_ABORTED;
    free((void *)promise->error_message);
    promise->error_message = strdup(reason ? reason : "Promise cancelled");
  }

  return true;
}

bool fetch_promise_cancelled(const fetch_promise_t *promise) {
  if (!promise)
    return false;

  return (promise->state == FETCH_PROMISE_REJECTED &&
          promise->error == FETCH_ERROR_ABORTED);
}

fetch_response_t *fetch_promise_response(const fetch_promise_t *promise) {
  return promise ? promise->response : NULL;
}

fetch_promise_state_t fetch_promise_state(const fetch_promise_t *promise) {
  return promise ? promise->state : FETCH_PROMISE_REJECTED;
}

fetch_error_t fetch_promise_error(const fetch_promise_t *promise) {
  return promise ? promise->error : FETCH_ERROR_NONE;
}

const char *fetch_promise_error_message(const fetch_promise_t *promise) {
  return promise ? promise->error_message : NULL;
}

bool fetch_promise_pending(const fetch_promise_t *promise) {
  return promise ? (promise->state == FETCH_PROMISE_PENDING) : false;
}

bool fetch_promise_fulfilled(const fetch_promise_t *promise) {
  return promise ? (promise->state == FETCH_PROMISE_FULFILLED) : false;
}

bool fetch_promise_rejected(const fetch_promise_t *promise) {
  return promise ? (promise->state == FETCH_PROMISE_REJECTED) : false;
}

fetch_headers_t *fetch_headers_new(void) {
  fetch_headers_t *headers = NULL;
  bool success = false;

  headers = calloc(1, sizeof(fetch_headers_t));
  if (!headers) {
    goto cleanup;
  }

  headers->capacity = 8;
  headers->keys = calloc(headers->capacity, sizeof(char *));
  if (!headers->keys) {
    goto cleanup;
  }

  headers->values = calloc(headers->capacity, sizeof(char *));
  if (!headers->values) {
    goto cleanup;
  }

  success = true;

cleanup:
  if (!success && headers) {
    free(headers->keys);
    free(headers->values);
    free(headers);
    headers = NULL;
  }

  return headers;
}

void fetch_headers_free(fetch_headers_t *headers) {
  if (!headers)
    return;

  for (size_t i = 0; i < headers->count; i++) {
    free(headers->keys[i]);
    free(headers->values[i]);
  }

  free(headers->keys);
  free(headers->values);
  free(headers);
}

static bool fetch_headers_resize(fetch_headers_t *headers) {
  if (!headers)
    return false;

  const size_t new_capacity = headers->capacity * 2;

  char **new_keys = realloc(headers->keys, new_capacity * sizeof(char *));
  if (!new_keys) {
    return false;
  }

  char **new_values = realloc(headers->values, new_capacity * sizeof(char *));
  if (!new_values) {
    char **restored_keys =
        realloc(new_keys, headers->capacity * sizeof(char *));
    if (restored_keys) {
      headers->keys = restored_keys;
    }
    return false;
  }

  headers->keys = new_keys;
  headers->values = new_values;
  headers->capacity = new_capacity;

  memset(headers->keys + headers->count, 0,
         (new_capacity - headers->count) * sizeof(char *));
  memset(headers->values + headers->count, 0,
         (new_capacity - headers->count) * sizeof(char *));

  return true;
}

void fetch_headers_append(fetch_headers_t *headers, const char *name,
                          const char *value) {
  if (!headers || !name || !value)
    return;

  if (headers->count >= headers->capacity) {
    if (!fetch_headers_resize(headers))
      return;
  }

  headers->keys[headers->count] = strdup(name);
  headers->values[headers->count] = strdup(value);

  if (headers->keys[headers->count] && headers->values[headers->count]) {
    headers->count++;
  } else {
    free(headers->keys[headers->count]);
    free(headers->values[headers->count]);
    headers->keys[headers->count] = NULL;
    headers->values[headers->count] = NULL;
  }
}

void fetch_headers_set(fetch_headers_t *headers, const char *name,
                       const char *value) {
  if (!headers || !name || !value)
    return;

  for (size_t i = 0; i < headers->count; i++) {
    if (fetch_strcasecmp(headers->keys[i], name) == 0) {
      free(headers->values[i]);
      headers->values[i] = strdup(value);
      return;
    }
  }

  fetch_headers_append(headers, name, value);
}

void fetch_headers_delete(fetch_headers_t *headers, const char *name) {
  if (!headers || !name)
    return;

  for (size_t i = 0; i < headers->count; i++) {
    if (fetch_strcasecmp(headers->keys[i], name) == 0) {
      free(headers->keys[i]);
      free(headers->values[i]);

      memmove(&headers->keys[i], &headers->keys[i + 1],
              (headers->count - i - 1) * sizeof(char *));
      memmove(&headers->values[i], &headers->values[i + 1],
              (headers->count - i - 1) * sizeof(char *));

      headers->count--;
      headers->keys[headers->count] = NULL;
      headers->values[headers->count] = NULL;
      return;
    }
  }
}

const char *fetch_headers_get(const fetch_headers_t *headers,
                              const char *name) {
  if (!headers || !name)
    return NULL;

  for (size_t i = 0; i < headers->count; i++) {
    if (fetch_strcasecmp(headers->keys[i], name) == 0) {
      return headers->values[i];
    }
  }

  return NULL;
}

bool fetch_headers_has(const fetch_headers_t *headers, const char *name) {
  return fetch_headers_get(headers, name) != NULL;
}

fetch_headers_iterator_t fetch_headers_entries(const fetch_headers_t *headers) {
  const fetch_headers_iterator_t iter = {.headers = headers, .index = 0};
  return iter;
}

bool fetch_headers_next(fetch_headers_iterator_t *iter, const char **key,
                        const char **value) {
  if (!iter || !iter->headers || iter->index >= iter->headers->count) {
    return false;
  }

  if (key)
    *key = iter->headers->keys[iter->index];
  if (value)
    *value = iter->headers->values[iter->index];

  iter->index++;
  return true;
}

fetch_body_t *fetch_body_text(const char *text) {
  if (!text)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body)
    return NULL;

  body->type = FETCH_BODY_TEXT;
  body->data.memory.data = strdup(text);
  body->data.memory.size = strlen(text);
  body->content_type = "text/plain; charset=utf-8";

  if (!body->data.memory.data) {
    free(body);
    return NULL;
  }

  return body;
}

fetch_body_t *fetch_body_json(const char *json) {
  if (!json)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body)
    return NULL;

  body->type = FETCH_BODY_JSON;
  body->data.memory.data = strdup(json);
  body->data.memory.size = strlen(json);
  body->content_type = "application/json; charset=utf-8";

  if (!body->data.memory.data) {
    free(body);
    return NULL;
  }

  return body;
}

fetch_body_t *fetch_body_binary(const void *data, size_t size,
                                const char *content_type) {
  if (!data || size == 0)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body)
    return NULL;

  void *data_copy = malloc(size);
  if (!data_copy) {
    free(body);
    return NULL;
  }

  memcpy(data_copy, data, size);

  body->type = FETCH_BODY_BINARY;
  body->data.memory.data = data_copy;
  body->data.memory.size = size;
  body->content_type = content_type ? content_type : "application/octet-stream";

  return body;
}

fetch_body_t *fetch_body_form_data(const char *form_data) {
  if (!form_data)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body)
    return NULL;

  body->type = FETCH_BODY_FORM_DATA;
  body->data.memory.data = strdup(form_data);
  body->data.memory.size = strlen(form_data);
  body->content_type = "application/x-www-form-urlencoded";

  if (!body->data.memory.data) {
    free(body);
    return NULL;
  }

  return body;
}

void fetch_body_free(fetch_body_t *body) {
  if (!body)
    return;

  switch (body->type) {
  case FETCH_BODY_FILE:

    if (body->data.file.close_on_free &&
        body->data.file.handle != FETCH_INVALID_FILE_HANDLE) {
#if defined(_WIN32) || defined(_WIN64)
      CloseHandle(body->data.file.handle);
#else
      fclose(body->data.file.handle);
#endif
    }
    break;

  case FETCH_BODY_TEXT:
  case FETCH_BODY_JSON:
  case FETCH_BODY_BINARY:
  case FETCH_BODY_FORM_DATA:

    free((void *)body->data.memory.data);
    break;

  case FETCH_BODY_NONE:
  default:

    break;
  }

  free(body);
}

const char *fetch_response_text(fetch_response_t *response) {
  if (!response || !response->body)
    return NULL;

  if (response->body_type == FETCH_BODY_TEXT ||
      response->body_type == FETCH_BODY_JSON) {
    return (const char *)response->body;
  }

  return NULL;
}

const void *fetch_response_array_buffer(fetch_response_t *response,
                                        size_t *size) {
  if (!response || !size)
    return NULL;

  *size = response->body_size;
  return response->body;
}

const char *fetch_response_json(fetch_response_t *response) {
  if (!response || !response->body)
    return NULL;

  if (response->body_type == FETCH_BODY_JSON) {
    return (const char *)response->body;
  }

  if (response->headers) {
    const char *content_type =
        fetch_headers_get(response->headers, "Content-Type");
    if (content_type && strstr(content_type, "application/json")) {
      return (const char *)response->body;
    }
  }

  return NULL;
}

bool fetch_response_ok(const fetch_response_t *response) {
  return response ? response->ok : false;
}

uint16_t fetch_response_status(const fetch_response_t *response) {
  return response ? response->status : 0;
}

const char *fetch_response_status_text(const fetch_response_t *response) {
  return response ? response->status_text : NULL;
}

const char *fetch_response_url(const fetch_response_t *response) {
  return response ? response->url : NULL;
}

fetch_headers_t *fetch_response_headers(const fetch_response_t *response) {
  return response ? response->headers : NULL;
}

void fetch_response_free(fetch_response_t *response) {
  if (!response)
    return;

  free((void *)response->status_text);
  free((void *)response->url);
  fetch_headers_free(response->headers);
  free((void *)response->body);
  free((void *)response->error_message);
  free(response);
}

void fetch_promise_free(fetch_promise_t *promise) {
  if (!promise)
    return;

  promise->detached = true;

  if (promise->state == FETCH_PROMISE_PENDING) {
    fetch_promise_cancel(promise, "Promise destroyed");
  }

  fetch_connection_t *conn = (fetch_connection_t *)promise->internal_state;
  if (conn) {
    bool conn_valid = false;

    fetch_connection_t *check = g_event_loop.active_connections;
    while (check && !conn_valid) {
      if (check == conn) {
        conn_valid = true;
        break;
      }
      check = check->next;
    }

    if (!conn_valid) {
      check = g_event_loop.completed_connections;
      while (check && !conn_valid) {
        if (check == conn) {
          conn_valid = true;
          break;
        }
        check = check->next;
      }
    }

    if (conn_valid && conn->promise == promise) {
      conn->promise = NULL;
    }

    promise->internal_state = NULL;
  }

  if (promise->response) {
    fetch_response_free(promise->response);
    promise->response = NULL;
  }

  free((void *)promise->error_message);
  promise->error_message = NULL;

  free(promise);
}

bool percent_encode(const char *input, const uint8_t character_set[],
                    char *output, bool append) {
  if (!input || !character_set || !output) {
    return false;
  }

  const char *src = input;
  const char *first_encode_pos = NULL;

  while (*src) {
    if (bit_at(character_set, (uint8_t)*src)) {
      first_encode_pos = src;
      break;
    }
    src++;
  }

  if (!first_encode_pos) {
    if (!append) {
      strcpy(output, input);
    } else {
      strcat(output, input);
    }
    return false;
  }

  if (!append) {
    output[0] = '\0';
  }

  size_t prefix_len = first_encode_pos - input;
  strncat(output, input, prefix_len);

  char *dst = output + strlen(output);
  src = first_encode_pos;

  while (*src) {
    if (bit_at(character_set, (uint8_t)*src)) {
      const char *hex_entry = hex + (uint8_t)*src * 4;
      *dst++ = hex_entry[0];
      *dst++ = hex_entry[1];
      *dst++ = hex_entry[2];
    } else {
      *dst++ = *src;
    }
    src++;
  }

  *dst = '\0';
  return true;
}

fetch_url_search_params_t *fetch_url_search_params_new(void) {
  fetch_url_search_params_t *params = NULL;
  bool success = false;

  params = calloc(1, sizeof(fetch_url_search_params_t));
  if (!params) {
    goto cleanup;
  }

  params->capacity = 8;
  params->keys = calloc(params->capacity, sizeof(char *));
  if (!params->keys) {
    goto cleanup;
  }

  params->values = calloc(params->capacity, sizeof(char *));
  if (!params->values) {
    goto cleanup;
  }

  success = true;

cleanup:
  if (!success && params) {
    free(params->keys);
    free(params->values);
    free(params);
    params = NULL;
  }

  return params;
}

void fetch_url_search_params_free(fetch_url_search_params_t *params) {
  if (!params)
    return;

  for (size_t i = 0; i < params->count; i++) {
    free(params->keys[i]);
    free(params->values[i]);
  }

  free(params->keys);
  free(params->values);
  free(params);
}

static bool fetch_url_search_params_resize(fetch_url_search_params_t *params) {
  if (!params)
    return false;

  const size_t new_capacity = params->capacity * 2;
  char **new_keys = realloc(params->keys, new_capacity * sizeof(char *));
  char **new_values = realloc(params->values, new_capacity * sizeof(char *));

  if (!new_keys || !new_values) {
    free(new_keys);
    free(new_values);
    return false;
  }

  params->keys = new_keys;
  params->values = new_values;
  params->capacity = new_capacity;

  memset(params->keys + params->count, 0,
         (new_capacity - params->count) * sizeof(char *));
  memset(params->values + params->count, 0,
         (new_capacity - params->count) * sizeof(char *));

  return true;
}

void fetch_url_search_params_append(fetch_url_search_params_t *params,
                                    const char *name, const char *value) {
  if (!params || !name || !value)
    return;

  if (params->count >= params->capacity) {
    if (!fetch_url_search_params_resize(params))
      return;
  }

  params->keys[params->count] = strdup(name);
  params->values[params->count] = strdup(value);

  if (params->keys[params->count] && params->values[params->count]) {
    params->count++;
  } else {
    free(params->keys[params->count]);
    free(params->values[params->count]);
    params->keys[params->count] = NULL;
    params->values[params->count] = NULL;
  }
}

void fetch_url_search_params_set(fetch_url_search_params_t *params,
                                 const char *name, const char *value) {
  if (!params || !name || !value)
    return;

  for (size_t i = 0; i < params->count; i++) {
    if (fetch_strcasecmp(params->keys[i], name) == 0) {
      free(params->values[i]);
      params->values[i] = strdup(value);
      return;
    }
  }

  fetch_url_search_params_append(params, name, value);
}

void fetch_url_search_params_delete(fetch_url_search_params_t *params,
                                    const char *name) {
  if (!params || !name)
    return;

  for (size_t i = 0; i < params->count;) {
    if (fetch_strcasecmp(params->keys[i], name) == 0) {
      free(params->keys[i]);
      free(params->values[i]);

      memmove(&params->keys[i], &params->keys[i + 1],
              (params->count - i - 1) * sizeof(char *));
      memmove(&params->values[i], &params->values[i + 1],
              (params->count - i - 1) * sizeof(char *));

      params->count--;
      params->keys[params->count] = NULL;
      params->values[params->count] = NULL;
    } else {
      i++;
    }
  }
}

const char *fetch_url_search_params_get(const fetch_url_search_params_t *params,
                                        const char *name) {
  if (!params || !name)
    return NULL;

  for (size_t i = 0; i < params->count; i++) {
    if (fetch_strcasecmp(params->keys[i], name) == 0) {
      return params->values[i];
    }
  }

  return NULL;
}

bool fetch_url_search_params_has(const fetch_url_search_params_t *params,
                                 const char *name) {
  return fetch_url_search_params_get(params, name) != NULL;
}

char *
fetch_url_search_params_to_string(const fetch_url_search_params_t *params) {
  char *result = NULL;
  char *encoded_key = NULL;
  char *encoded_value = NULL;
  bool success = false;

  if (!params) {
    goto cleanup;
  }

  if (params->count == 0) {
    result = malloc(1);
    if (!result) {
      goto cleanup;
    }
    result[0] = '\0';
    success = true;
    goto cleanup;
  }

  size_t estimated_size = 0;
  size_t valid_count = 0;

  for (size_t i = 0; i < params->count; i++) {
    if (!params->keys[i] || !params->values[i]) {
      continue;
    }
    estimated_size += strlen(params->keys[i]) * 3;
    estimated_size += strlen(params->values[i]) * 3;
    estimated_size += 2;
    valid_count++;
  }

  if (valid_count == 0) {
    result = malloc(1);
    if (!result) {
      goto cleanup;
    }
    result[0] = '\0';
    success = true;
    goto cleanup;
  }

  estimated_size += 1;

  result = malloc(estimated_size);
  if (!result) {
    goto cleanup;
  }

  result[0] = '\0';
  bool first = true;

  for (size_t i = 0; i < params->count; i++) {
    if (!params->keys[i] || !params->values[i]) {
      continue;
    }

    const size_t key_buf_size = strlen(params->keys[i]) * 3 + 1;
    const size_t value_buf_size = strlen(params->values[i]) * 3 + 1;

    encoded_key = malloc(key_buf_size);
    if (!encoded_key) {
      goto cleanup;
    }

    encoded_value = malloc(value_buf_size);
    if (!encoded_value) {
      goto cleanup;
    }

    percent_encode(params->keys[i], WWW_FORM_URLENCODED_PERCENT_ENCODE,
                   encoded_key, false);
    percent_encode(params->values[i], WWW_FORM_URLENCODED_PERCENT_ENCODE,
                   encoded_value, false);

    if (!first) {
      strcat(result, "&");
    }
    strcat(result, encoded_key);
    strcat(result, "=");
    strcat(result, encoded_value);

    first = false;

    free(encoded_key);
    encoded_key = NULL;
    free(encoded_value);
    encoded_value = NULL;
  }

  success = true;

cleanup:
  free(encoded_key);
  free(encoded_value);

  if (!success) {
    free(result);
    result = NULL;
  }

  return result;
}

fetch_body_t *fetch_body_url_search_params(fetch_url_search_params_t *params) {
  if (!params)
    return NULL;

  char *form_data = fetch_url_search_params_to_string(params);
  if (!form_data)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body) {
    free(form_data);
    return NULL;
  }

  body->type = FETCH_BODY_FORM_DATA;
  body->data.memory.data = form_data;
  body->data.memory.size = strlen(form_data);
  body->content_type = "application/x-www-form-urlencoded";

  return body;
}

fetch_body_t *fetch_body_file(FETCH_FILE_HANDLE file_handle, size_t size,
                              const char *content_type, bool close_on_free,
                              fetch_file_continue_cb continue_cb,
                              void *userdata) {
  if (file_handle == FETCH_INVALID_FILE_HANDLE)
    return NULL;

  fetch_body_t *body = malloc(sizeof(fetch_body_t));
  if (!body)
    return NULL;

  body->type = FETCH_BODY_FILE;
  body->data.file.handle = file_handle;
  body->data.file.size = size;
  body->data.file.offset = 0;
  body->data.file.close_on_free = close_on_free;
  body->data.file.continue_cb = continue_cb;
  body->data.file.userdata = userdata;
  body->content_type = content_type ? content_type : "application/octet-stream";

  return body;
}

fetch_url_search_params_iterator_t
fetch_url_search_params_entries(const fetch_url_search_params_t *params) {
  const fetch_url_search_params_iterator_t iter = {.params = params,
                                                   .index = 0};
  return iter;
}

bool fetch_url_search_params_next(fetch_url_search_params_iterator_t *iter,
                                  const char **key, const char **value) {
  if (!iter || !iter->params || iter->index >= iter->params->count) {
    return false;
  }

  if (key)
    *key = iter->params->keys[iter->index];
  if (value)
    *value = iter->params->values[iter->index];

  iter->index++;
  return true;
}

fetch_abort_controller_t *fetch_abort_controller_new(void) {
  fetch_abort_controller_t *controller =
      calloc(1, sizeof(fetch_abort_controller_t));
  return controller;
}

void fetch_abort_controller_abort(fetch_abort_controller_t *controller,
                                  const char *reason) {
  if (!controller)
    return;

  controller->aborted = true;
  controller->reason = reason ? reason : "Operation aborted";

  if (controller->on_abort) {
    controller->on_abort(controller->userdata);
  }
}

bool fetch_abort_controller_aborted(
    const fetch_abort_controller_t *controller) {
  return controller ? controller->aborted : false;
}

void fetch_abort_controller_free(fetch_abort_controller_t *controller) {
  free(controller);
}

fetch_init_t *fetch_init_new(void) {
  fetch_init_t *init = calloc(1, sizeof(fetch_init_t));
  if (!init)
    return NULL;

  init->method = HTTP_METHOD_GET;
  init->mode = FETCH_MODE_NO_CORS;
  init->credentials = FETCH_CREDENTIALS_INCLUDE;
  init->cache = FETCH_CACHE_DEFAULT;
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->referrer_policy = "strict-origin-when-cross-origin";

  init->keepalive = fetch_config_get_flag(g_fetch_config.flags,
                                          FETCH_FLAG_KEEP_ALIVE_DEFAULT);
  init->timeout_ms = g_fetch_config.default_timeout_ms;
  init->max_redirects = 20;

  return init;
}

void fetch_init_free(fetch_init_t *init) {
  if (!init)
    return;

  fetch_headers_free(init->headers);
  fetch_body_free(init->body);
  fetch_abort_controller_free(init->signal);
  free(init);
}

fetch_init_t *fetch_init_method(fetch_init_t *init, http_method_t method) {
  if (init)
    init->method = method;
  return init;
}

fetch_init_t *fetch_init_headers(fetch_init_t *init, fetch_headers_t *headers) {
  if (init) {
    fetch_headers_free(init->headers);
    init->headers = headers;
  }
  return init;
}

fetch_init_t *fetch_init_body(fetch_init_t *init, fetch_body_t *body) {
  if (init) {
    fetch_body_free(init->body);
    init->body = body;
  }
  return init;
}

fetch_init_t *fetch_init_timeout(fetch_init_t *init, uint32_t timeout_ms) {
  if (init)
    init->timeout_ms = timeout_ms;
  return init;
}

fetch_init_t *fetch_init_signal(fetch_init_t *init,
                                fetch_abort_controller_t *signal) {
  if (init)
    init->signal = signal;
  return init;
}

cookie_jar_t *fetch_get_cookie_jar(void) {
  if (!fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES)) {
    return NULL;
  }
  return g_fetch_config.cookie_jar;
}

size_t fetch_cookie_jar_count(const char *domain_filter) {
  if (!fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES) ||
      !g_fetch_config.cookie_jar)
    return 0;

  if (!domain_filter || strlen(domain_filter) == 0) {
    return cookie_jar_count(g_fetch_config.cookie_jar);
  }
  return cookie_jar_count_for_domain(g_fetch_config.cookie_jar, domain_filter);
}

void fetch_cookie_jar_clear(void) {
  if (fetch_config_get_flag(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES) &&
      g_fetch_config.cookie_jar) {
    cookie_jar_clear(g_fetch_config.cookie_jar);
  }
}

void fetch_disable_cookies(void) {
  g_fetch_config.cookie_jar = NULL;
  g_fetch_config.flags =
      FETCH_FLAG_CLEAR(g_fetch_config.flags, FETCH_FLAG_ENABLE_COOKIES);

  if (g_fetch_config.origin) {
    free((void *)g_fetch_config.origin);
    g_fetch_config.origin = NULL;
  }
}

cookie_jar_t *fetch_create_cookie_jar(const char *persistent_file) {
  cookie_jar_config_t config = {
      .max_cookies_total = COOKIE_DEFAULT_MAX_COOKIES,
      .max_cookies_per_domain = COOKIE_DEFAULT_MAX_PER_DOMAIN,
      .max_cookie_size = 4096,
      .accept_session_cookies = true,
      .accept_persistent_cookies = true,
      .accept_third_party = true,
      .max_age_seconds = COOKIE_DEFAULT_MAX_AGE_SECONDS,
      .persistent_file = persistent_file};

  cookie_jar_t *jar = cookie_jar_new_with_config(&config);

  if (!jar) {
    return NULL;
  }

  return jar;
}

void fetch_cookie_jar_free(cookie_jar_t *jar) { cookie_jar_free(jar); }

bool fetch_save_cookies(const char *filename, cookie_jar_t *jar) {
  if (!filename || !jar)
    return false;

  return cookie_jar_save_binary(jar, filename);
}

bool fetch_load_cookies(const char *filename, cookie_jar_t *jar) {
  if (!filename || !jar)
    return false;

  return cookie_jar_load_binary(jar, filename);
}

void fetch_cookie_jar_print(cookie_jar_t *jar, const char *domain_filter) {
  if (!jar) {

    return;
  }

  size_t total_count = cookie_jar_count(jar);
  if (total_count == 0) {

    return;
  }

  if (domain_filter) {
    printf("Cookie jar (%zu total, filtering for domain: %s):\n", total_count,
           domain_filter);
  } else {
    printf("Cookie jar (%zu cookies):\n", total_count);
  }

  cookie_iterator_t iter = domain_filter
                               ? cookie_jar_iterator_domain(jar, domain_filter)
                               : cookie_jar_iterator(jar);

  int printed = 0;
  cookie_t *cookie;
  while ((cookie = cookie_iterator_next(&iter)) != NULL) {
    printf("  %s=%s (domain=%s, path=%s", cookie->name ? cookie->name : "NULL",
           cookie->value ? cookie->value : "NULL",
           cookie->domain ? cookie->domain : "NULL",
           cookie->path ? cookie->path : "NULL");

    if (cookie_is_session(cookie)) {
      printf(", session");
    } else {
      printf(", expires=%lld", (long long)cookie->expires);
    }

    if (cookie_is_secure(cookie)) {
      printf(", secure");
    }

    if (cookie_is_http_only(cookie)) {
      printf(", httponly");
    }

    printf(")\n");
    printed++;
  }

  if (domain_filter && printed == 0) {
    printf("  No cookies found for domain: %s\n", domain_filter);
  }
}

const char *fetch_method_to_string(http_method_t method) {
  switch (method) {
  case HTTP_METHOD_GET:
    return "GET";
  case HTTP_METHOD_HEAD:
    return "HEAD";
  case HTTP_METHOD_POST:
    return "POST";
  case HTTP_METHOD_PUT:
    return "PUT";
  case HTTP_METHOD_DELETE:
    return "DELETE";
  case HTTP_METHOD_CONNECT:
    return "CONNECT";
  case HTTP_METHOD_OPTIONS:
    return "OPTIONS";
  case HTTP_METHOD_TRACE:
    return "TRACE";
  case HTTP_METHOD_PATCH:
    return "PATCH";
  default:
    return "GET";
  }
}

http_method_t fetch_method_from_string(const char *method_str) {
  if (!method_str)
    return HTTP_METHOD_GET;

  if (fetch_strcasecmp(method_str, "GET") == 0)
    return HTTP_METHOD_GET;
  if (fetch_strcasecmp(method_str, "HEAD") == 0)
    return HTTP_METHOD_HEAD;
  if (fetch_strcasecmp(method_str, "POST") == 0)
    return HTTP_METHOD_POST;
  if (fetch_strcasecmp(method_str, "PUT") == 0)
    return HTTP_METHOD_PUT;
  if (fetch_strcasecmp(method_str, "DELETE") == 0)
    return HTTP_METHOD_DELETE;
  if (fetch_strcasecmp(method_str, "CONNECT") == 0)
    return HTTP_METHOD_CONNECT;
  if (fetch_strcasecmp(method_str, "OPTIONS") == 0)
    return HTTP_METHOD_OPTIONS;
  if (fetch_strcasecmp(method_str, "TRACE") == 0)
    return HTTP_METHOD_TRACE;
  if (fetch_strcasecmp(method_str, "PATCH") == 0)
    return HTTP_METHOD_PATCH;

  return HTTP_METHOD_GET;
}

bool fetch_is_valid_url(const char *url) {
  if (!url)
    return false;

  const size_t url_len = strnlen(url, FETCH_MAX_URL_LENGTH);
  const ada_url parsed = ada_parse(url, url_len);
  const bool valid = ada_is_valid(parsed);
  ada_free(parsed);
  return valid;
}

const char *fetch_error_to_string(fetch_error_t error) {
  switch (error) {
  case FETCH_ERROR_NONE:
    return "No error";
  case FETCH_ERROR_NETWORK:
    return "Network error";
  case FETCH_ERROR_TIMEOUT:
    return "Request timeout";
  case FETCH_ERROR_INVALID_URL:
    return "Invalid URL";
  case FETCH_ERROR_INVALID_METHOD:
    return "Invalid HTTP method";
  case FETCH_ERROR_INVALID_HEADERS:
    return "Invalid headers";
  case FETCH_ERROR_MEMORY:
    return "Out of memory";
  case FETCH_ERROR_ABORTED:
    return "Request aborted";
  case FETCH_ERROR_TOO_MANY_REDIRECTS:
    return "Too many redirects";
  case FETCH_ERROR_CONNECTION_REFUSED:
    return "Connection refused";
  case FETCH_ERROR_DNS_RESOLUTION:
    return "DNS resolution failed";
  case FETCH_ERROR_PROTOCOL_ERROR:
    return "HTTP protocol error";
  default:
    return "Unknown error";
  }
}