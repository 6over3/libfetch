/**
 * @file dns.h
 * @brief Asynchronous DNS resolver library
 *
 * This library provides a high-performance asynchronous DNS resolver with
 * support for both IPv4 and IPv6 addresses. It allows for concurrent DNS
 * queries with configurable timeouts and preferences.
 */

#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle for DNS resolver instance
 *
 * This structure contains the internal state of the DNS resolver.
 * Users should not access its members directly.
 */
typedef struct dns_resolver dns_resolver_t;

/**
 * @brief Opaque handle for individual DNS request
 *
 * This structure represents a single DNS resolution request.
 * It can be used to cancel pending requests.
 */
typedef struct dns_request dns_request_t;

/**
 * @brief Structure representing a resolved network address
 *
 * Contains the resolved address information including the address string,
 * address family, socket type, and protocol information.
 */
typedef struct {
  char address[46]; /**< IP address string (max IPv6 length) */
  int family;       /**< Address family (AF_INET or AF_INET6) */
  int socktype;     /**< Socket type (SOCK_STREAM, SOCK_DGRAM, etc.) */
  int protocol;     /**< Protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) */
} dns_address_t;

/**
 * @brief Structure containing DNS resolution results
 *
 * This structure is passed to the callback function and contains
 * all resolved addresses for a hostname, along with error information.
 */
typedef struct {
  dns_address_t *addresses; /**< Array of resolved addresses */
  size_t count;             /**< Number of addresses in the array */
  int error_code;           /**< Error code (0 on success) */
  char *hostname;           /**< Copy of the resolved hostname */
} dns_result_t;

/**
 * @brief Callback function type for asynchronous DNS resolution
 *
 * This function is called when a DNS resolution completes (either successfully
 * or with an error). The result structure contains the resolution results.
 *
 * @param result Pointer to the DNS resolution result
 * @param user_data User-provided data passed to the callback
 *
 * @note The result structure must be freed using dns_result_free()
 * @note This callback may be called from a different thread
 */
typedef void (*dns_callback_t)(dns_result_t *result, void *user_data);

/**
 * @brief Configuration structure for DNS resolver
 *
 * Contains various configuration options to customize the behavior
 * of the DNS resolver.
 */
typedef struct {
  int timeout_ms;     /**< Timeout in milliseconds (0 = no timeout) */
  int max_concurrent; /**< Maximum concurrent requests (0 = unlimited) */
  bool prefer_ipv4;   /**< Prefer IPv4 addresses in results */
  bool prefer_ipv6;   /**< Prefer IPv6 addresses in results */
} dns_config_t;

/**
 * @brief Create a new DNS resolver instance
 *
 * Creates and initializes a new DNS resolver with the specified configuration.
 * The resolver must be destroyed with dns_resolver_destroy() when no longer
 * needed.
 *
 * @param config Pointer to configuration structure (NULL for default config)
 * @return Pointer to new resolver instance, or NULL on failure
 *
 * @see dns_resolver_destroy()
 * @see dns_config_default()
 */
dns_resolver_t *dns_resolver_create(const dns_config_t *config);

/**
 * @brief Destroy a DNS resolver instance
 *
 * Destroys the resolver and frees all associated resources. Any pending
 * requests will be cancelled automatically.
 *
 * @param resolver Pointer to resolver instance (may be NULL)
 *
 * @warning Do not use the resolver pointer after calling this function
 * @see dns_resolver_create()
 */
void dns_resolver_destroy(dns_resolver_t *resolver);

/**
 * @brief Start asynchronous DNS resolution
 *
 * Initiates an asynchronous DNS resolution for the specified hostname.
 * The callback function will be called when the resolution completes.
 *
 * @param resolver DNS resolver instance
 * @param hostname Hostname to resolve (null-terminated string)
 * @param service Service name or port number (may be NULL)
 * @param callback Callback function to call when resolution completes
 * @param user_data User data to pass to the callback function
 * @return Pointer to request handle, or NULL on failure
 *
 * @note The returned request handle can be used to cancel the request
 * @see dns_request_cancel()
 * @see dns_callback_t
 */
dns_request_t *dns_resolve_async(dns_resolver_t *resolver, const char *hostname,
                                 const char *service, dns_callback_t callback,
                                 void *user_data);

/**
 * @brief Cancel a pending DNS request
 *
 * Attempts to cancel a pending DNS resolution request. If successful,
 * the callback will not be called for this request.
 *
 * @param request Pointer to request handle
 * @return true if the request was successfully cancelled, false otherwise
 *
 * @note This function may fail if the request has already completed
 * @warning Do not use the request pointer after calling this function
 */
bool dns_request_cancel(dns_request_t *request);

/**
 * @brief Process pending DNS operations
 *
 * This function must be called regularly (typically in your main event loop)
 * to process completed DNS operations and invoke callbacks. It is non-blocking
 * and will return immediately if no operations are ready.
 *
 * @param resolver DNS resolver instance
 *
 * @note This function should be called frequently for timely callback execution
 * @note Thread-safe: can be called from multiple threads
 */
void dns_resolver_process(dns_resolver_t *resolver);

/**
 * @brief Free DNS result structure
 *
 * Frees all memory associated with a DNS result structure, including
 * the addresses array and hostname string.
 *
 * @param result Pointer to result structure (may be NULL)
 *
 * @note This function must be called for each result passed to callbacks
 * @warning Do not use the result pointer after calling this function
 */
void dns_result_free(dns_result_t *result);

/**
 * @brief Get human-readable error message
 *
 * Returns a string description of the specified error code.
 *
 * @param error_code Error code from dns_result_t
 * @return Pointer to error message string (never NULL)
 *
 * @note The returned string is statically allocated and should not be freed
 */
const char *dns_error_string(int error_code);

/**
 * @brief Get default configuration
 *
 * Returns a configuration structure initialized with default values.
 * This can be used as a starting point for custom configurations.
 *
 * @return Default configuration structure
 *
 * @see dns_resolver_create()
 */
dns_config_t dns_config_default(void);

#ifdef __cplusplus
}
#endif

#endif /* DNS_RESOLVER_H */
