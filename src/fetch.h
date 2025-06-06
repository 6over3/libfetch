/**
 * @file fetch.h
 * @brief A lightweight asynchronous HTTP/1.1 client library for C with
 * fetch-like API
 *
 * This library provides a JavaScript fetch-like API for making HTTP requests in
 * C. It supports both synchronous and asynchronous operations, connection
 * pooling, cookie management, redirects, file streaming, and various HTTP
 * methods.
 *
 * @section threading Threading Model
 * This library is NOT thread-safe. All operations must be performed from a
 * single thread. The event loop and all fetch operations should be called
 * from the same thread.
 *
 * @section memory Memory Management
 * The library uses clear ownership semantics:
 * - Objects returned by "new" functions must be freed by the caller
 * - Objects passed to functions are either borrowed (temporary) or owned
 * (transferred)
 * - Check function documentation for specific ownership semantics
 *
 * @section file_streaming File Streaming
 * The library supports efficient file streaming for uploads without loading
 * entire files into memory:
 * - Regular files: Known size, standard Content-Length header
 * - Streaming files: Unknown size, uses chunked transfer encoding
 * - Live streams: Continuous data with user-controlled completion
 */

#ifndef FETCH_H
#define FETCH_H

/* Include generated version information */
#include "cookie.h"
#include "version.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @defgroup file_handles File Handle Support
 * @brief Platform-specific file handle types for streaming
 * @{
 */

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
/** @brief File handle type for streaming file content */
typedef HANDLE FETCH_FILE_HANDLE;
/** @brief Invalid file handle value */
#define FETCH_INVALID_FILE_HANDLE INVALID_HANDLE_VALUE
#else
#include <stdio.h>
/** @brief File handle type for streaming file content */
typedef FILE *FETCH_FILE_HANDLE;
/** @brief Invalid file handle value */
#define FETCH_INVALID_FILE_HANDLE NULL
#endif

/** @} */

/**
 * @defgroup file_streaming File Streaming Support
 * @brief Support for streaming files with user-controlled completion
 * @{
 */

/**
 * @brief Return codes for file streaming continue callback
 */
typedef enum {
  FETCH_STREAM_READ = 0, /**< More data available to read */
  FETCH_STREAM_DONE = 1, /**< No more data, end stream */
  FETCH_STREAM_SKIP = 2  /**< No data currently, but not done */
} fetch_stream_result_t;

/**
 * @brief Callback function for controlling file streaming continuation
 *
 * This callback is called when the library needs to determine if there's
 * more data to read from a streaming file. Use this for files of unknown
 * length like continuously written logs or live streams.
 *
 * The callback should return:
 * - FETCH_STREAM_READ: More data is available, continue reading
 * - FETCH_STREAM_DONE: No more data will be available, finalize the stream
 * - FETCH_STREAM_SKIP: No data currently available, but more may come later
 *
 * @param userdata User-provided data passed to fetch_body_file()
 * @return fetch_stream_result_t indicating the stream state
 *
 * @note This callback enables chunked transfer encoding automatically
 * @note The callback may be called multiple times during the upload
 *
 * @code
 * // Example: Streaming a log file that's being written to
 * fetch_stream_result_t continue_log_stream(void *userdata) {
 *     LogStreamContext *ctx = (LogStreamContext*)userdata;
 *
 *     if (ctx->should_stop) {
 *         return FETCH_STREAM_DONE;
 *     }
 *
 *     // Check if new data has been written to the file
 *     if (has_new_log_data(ctx)) {
 *         return FETCH_STREAM_READ;
 *     }
 *
 *     return FETCH_STREAM_SKIP; // No new data yet, but keep trying
 * }
 * @endcode
 */
typedef fetch_stream_result_t (*fetch_file_continue_cb)(void *userdata);

/** @} */

/**
 * @brief Default user agent string
 *
 * This macro generates the default user agent string used by the library.
 * Format: "libfetch/VERSION"
 */
#define FETCH_USER_AGENT "libfetch/" FETCH_VERSION_STRING

/**
 * @defgroup version_api Version Information
 * @brief Functions to query library version at runtime
 * @{
 */

/**
 * @brief Get version information at runtime
 * @return Full version string with Git information
 */
static inline const char *fetch_version(void) { return FETCH_VERSION; }

/**
 * @brief Get clean semantic version at runtime
 * @return Semantic version string (e.g., "1.2.3")
 */
static inline const char *fetch_version_string(void) {
  return FETCH_VERSION_STRING;
}

/**
 * @brief Get major version number at runtime
 * @return Major version number
 */
static inline int fetch_version_major(void) { return FETCH_VERSION_MAJOR; }

/**
 * @brief Get minor version number at runtime
 * @return Minor version number
 */
static inline int fetch_version_minor(void) { return FETCH_VERSION_MINOR; }

/**
 * @brief Get patch version number at runtime
 * @return Patch version number
 */
static inline int fetch_version_patch(void) { return FETCH_VERSION_PATCH; }

/**
 * @brief Compare version against another version
 * @param major Major version to compare against
 * @param minor Minor version to compare against
 * @param patch Patch version to compare against
 * @return Positive if current version is newer, negative if older, 0 if equal
 */
static inline int fetch_version_compare(int major, int minor, int patch) {
  int current = FETCH_VERSION_NUMBER;
  int compare = (major * 10000) + (minor * 100) + patch;
  return current - compare;
}

/**
 * @brief Check if current version is at least the specified version
 * @param major Minimum major version
 * @param minor Minimum minor version
 * @param patch Minimum patch version
 * @return true if current version is >= specified version
 */
static inline bool fetch_version_at_least(int major, int minor, int patch) {
  return fetch_version_compare(major, minor, patch) >= 0;
}

/** @} */

/**
 * @defgroup fetch_flags Configuration Flags
 * @brief Bitfield flags for controlling fetch behavior
 * @{
 */

/**
 * @brief Configuration flags for the fetch library
 */
typedef enum {
  FETCH_FLAG_KEEP_ALIVE_DEFAULT = 0,   /**< Enable HTTP keep-alive by default */
  FETCH_FLAG_ACCEPT_INVALID_CERTS = 1, /**< Accept invalid SSL certificates */
  FETCH_FLAG_FOLLOW_REDIRECTS = 2,   /**< Automatically follow HTTP redirects */
  FETCH_FLAG_ENABLE_COMPRESSION = 3, /**< Enable gzip/deflate compression */
  FETCH_FLAG_ENABLE_COOKIES = 4,     /**< Enable cookie handling */
  FETCH_FLAG_DEBUG_LOGGING = 5,      /**< Enable debug logging */
} fetch_flag_bit_t;

/** @brief Get a flag value from a flags bitfield */
#define FETCH_FLAG_GET(flags, bit) (((flags) >> (bit)) & 1U)
/** @brief Set a flag in a flags bitfield */
#define FETCH_FLAG_SET(flags, bit) ((flags) | (1U << (bit)))
/** @brief Clear a flag in a flags bitfield */
#define FETCH_FLAG_CLEAR(flags, bit) ((flags) & ~(1U << (bit)))
/** @brief Toggle a flag in a flags bitfield */
#define FETCH_FLAG_TOGGLE(flags, bit) ((flags) ^ (1U << (bit)))

/** @} */

/**
 * @defgroup http_methods HTTP Methods
 * @brief Standard HTTP request methods
 * @{
 */

/**
 * @brief HTTP request methods
 */
typedef enum {
  HTTP_METHOD_GET,     /**< GET method for retrieving data */
  HTTP_METHOD_HEAD,    /**< HEAD method for headers only */
  HTTP_METHOD_POST,    /**< POST method for sending data */
  HTTP_METHOD_PUT,     /**< PUT method for updating resources */
  HTTP_METHOD_DELETE,  /**< DELETE method for removing resources */
  HTTP_METHOD_CONNECT, /**< CONNECT method for tunneling */
  HTTP_METHOD_OPTIONS, /**< OPTIONS method for checking capabilities */
  HTTP_METHOD_TRACE,   /**< TRACE method for diagnostics */
  HTTP_METHOD_PATCH    /**< PATCH method for partial updates */
} http_method_t;

/** @} */

/**
 * @defgroup fetch_modes Request Modes
 * @brief Control how requests interact with CORS
 * @{
 */

/**
 * @brief Request modes for CORS handling
 */
typedef enum {
  FETCH_MODE_CORS,        /**< Use CORS for cross-origin requests */
  FETCH_MODE_NO_CORS,     /**< No CORS restrictions */
  FETCH_MODE_SAME_ORIGIN, /**< Only allow same-origin requests */
  FETCH_MODE_NAVIGATE     /**< Navigation mode */
} fetch_mode_t;

/** @} */

/**
 * @defgroup credentials Credential Modes
 * @brief Control when credentials are sent with requests
 * @{
 */

/**
 * @brief Credential handling modes
 */
typedef enum {
  FETCH_CREDENTIALS_OMIT,        /**< Never send credentials */
  FETCH_CREDENTIALS_SAME_ORIGIN, /**< Send credentials for same-origin only */
  FETCH_CREDENTIALS_INCLUDE      /**< Always send credentials */
} fetch_credentials_t;

/** @} */

/**
 * @defgroup cache_modes Cache Control
 * @brief Control how requests interact with HTTP cache
 * @{
 */

/**
 * @brief Cache control modes
 */
typedef enum {
  FETCH_CACHE_DEFAULT,       /**< Use default cache behavior */
  FETCH_CACHE_NO_STORE,      /**< Don't use cache at all */
  FETCH_CACHE_RELOAD,        /**< Bypass cache, update it */
  FETCH_CACHE_NO_CACHE,      /**< Use cache but validate first */
  FETCH_CACHE_FORCE_CACHE,   /**< Use cache, ignore validation */
  FETCH_CACHE_ONLY_IF_CACHED /**< Only use cache, fail if not cached */
} fetch_cache_t;

/** @} */

/**
 * @defgroup redirect_modes Redirect Control
 * @brief Control how redirects are handled
 * @{
 */

/**
 * @brief Redirect handling modes
 */
typedef enum {
  FETCH_REDIRECT_FOLLOW, /**< Automatically follow redirects */
  FETCH_REDIRECT_ERROR,  /**< Treat redirects as errors */
  FETCH_REDIRECT_MANUAL  /**< Return redirect responses to caller */
} fetch_redirect_t;

/** @} */

/**
 * @defgroup promise_states Promise States
 * @brief States of asynchronous fetch promises
 * @{
 */

/**
 * @brief Promise states for asynchronous operations
 */
typedef enum {
  FETCH_PROMISE_PENDING,   /**< Operation is still in progress */
  FETCH_PROMISE_FULFILLED, /**< Operation completed successfully */
  FETCH_PROMISE_REJECTED   /**< Operation failed or was cancelled */
} fetch_promise_state_t;

/** @} */

/**
 * @defgroup error_codes Error Codes
 * @brief Error codes returned by fetch operations
 * @{
 */

/**
 * @brief Error codes for fetch operations
 */
typedef enum {
  FETCH_ERROR_NONE = 0,           /**< No error occurred */
  FETCH_ERROR_NETWORK,            /**< Network-related error */
  FETCH_ERROR_TIMEOUT,            /**< Request timed out */
  FETCH_ERROR_INVALID_URL,        /**< Invalid or malformed URL */
  FETCH_ERROR_INVALID_METHOD,     /**< Invalid HTTP method for request */
  FETCH_ERROR_INVALID_HEADERS,    /**< Invalid header values */
  FETCH_ERROR_MEMORY,             /**< Memory allocation failed */
  FETCH_ERROR_ABORTED,            /**< Request was cancelled */
  FETCH_ERROR_TOO_MANY_REDIRECTS, /**< Exceeded maximum redirect limit */
  FETCH_ERROR_CONNECTION_REFUSED, /**< Server refused connection */
  FETCH_ERROR_DNS_RESOLUTION,     /**< DNS lookup failed */
  FETCH_ERROR_PROTOCOL_ERROR      /**< HTTP protocol error */
} fetch_error_t;

/** @} */

/**
 * @defgroup abort_controller Abort Controller
 * @brief Control and cancel ongoing requests
 * @{
 */

/**
 * @brief Abort controller for cancelling requests
 *
 * Used to signal cancellation of ongoing fetch operations.
 *
 * @note Memory: libfetch owns the controller once passed
 */
typedef struct fetch_abort_controller {
  bool aborted;                     /**< Whether the operation was aborted */
  const char *reason;               /**< Reason for abortion */
  void (*on_abort)(void *userdata); /**< Callback when aborted */
  void *userdata;                   /**< User data for callback */
} fetch_abort_controller_t;

/** @} */

/**
 * @defgroup headers HTTP Headers
 * @brief Manage HTTP request and response headers
 * @{
 */

/**
 * @brief HTTP headers container
 *
 * Stores key-value pairs of HTTP headers with case-insensitive keys.
 *
 * @note Memory: Caller owns the headers and must call fetch_headers_free()
 */
typedef struct fetch_headers {
  char **keys;     /**< Header names */
  char **values;   /**< Header values */
  size_t count;    /**< Number of headers */
  size_t capacity; /**< Allocated capacity */
} fetch_headers_t;

/**
 * @brief Iterator for traversing headers
 */
typedef struct {
  const fetch_headers_t *headers; /**< Headers being iterated */
  size_t index;                   /**< Current iteration index */
} fetch_headers_iterator_t;

/** @} */

/**
 * @defgroup body Request/Response Body
 * @brief Handle different types of request and response bodies
 * @{
 */

/**
 * @brief Types of request/response bodies
 */
typedef enum {
  FETCH_BODY_NONE,      /**< No body content */
  FETCH_BODY_TEXT,      /**< Plain text content */
  FETCH_BODY_BINARY,    /**< Binary data */
  FETCH_BODY_FORM_DATA, /**< Form-encoded data */
  FETCH_BODY_JSON,      /**< JSON data */
  FETCH_BODY_FILE       /**< File content to be streamed */
} fetch_body_type_t;

/**
 * @brief Request or response body
 *
 * Contains the data payload along with its type and content type.
 * Supports both in-memory data and file streaming using a tagged union.
 *
 * For file streaming, the library supports:
 * - Regular files: Known size, uses Content-Length header
 * - Streaming files: Unknown/dynamic size, uses chunked transfer encoding
 * - Live streams: Continuous data with user-controlled completion via callback
 *
 * @note Memory: Caller owns the body and must call fetch_body_free()
 */
typedef struct {
  fetch_body_type_t type; /**< Type of body content (union tag) */

  union {
    // Memory-based body data (for TEXT, JSON, BINARY, FORM_DATA)
    struct {
      const void *data; /**< Pointer to body data */
      size_t size;      /**< Size of body in bytes */
    } memory;

    // File streaming data (for FILE type)
    struct {
      FETCH_FILE_HANDLE handle; /**< File handle for streaming */
      size_t size;              /**< File size in bytes (0 if unknown) */
      size_t offset;            /**< Current read offset in file */
      bool close_on_free; /**< Whether to close handle when body is freed */
      fetch_file_continue_cb
          continue_cb; /**< NULL = regular file, non-NULL = streaming */
      void *userdata;  /**< User data for callback */
    } file;
  } data;

  const char *content_type; /**< MIME content type */
} fetch_body_t;

/** @} */

/**
 * @defgroup request_init Request Initialization
 * @brief Configure HTTP requests
 * @{
 */

/**
 * @brief Request configuration options
 *
 * Similar to JavaScript's RequestInit, this structure contains
 * all options for configuring an HTTP request.
 *
 * @note Memory: Caller owns the init and must call fetch_init_free()
 */
typedef struct fetch_init {
  http_method_t method;     /**< HTTP method */
  fetch_headers_t *headers; /**< Request headers (ownership transferred) */
  fetch_body_t *body;       /**< Request body (ownership transferred) */
  fetch_mode_t mode;        /**< CORS mode */
  fetch_credentials_t credentials; /**< Credential handling */
  fetch_cache_t cache;             /**< Cache control */
  fetch_redirect_t redirect;       /**< Redirect handling */
  const char *referrer;            /**< Referrer URL */
  const char *referrer_policy;     /**< Referrer policy */
  const char *integrity;           /**< Subresource integrity */
  bool keepalive;                  /**< Keep connection alive */
  fetch_abort_controller_t
      *signal;            /**< Abort controller (borrowed reference) */
  uint32_t timeout_ms;    /**< Request timeout in milliseconds */
  uint32_t max_redirects; /**< Maximum number of redirects */
} fetch_init_t;

/** @} */

/**
 * @defgroup response HTTP Response
 * @brief Handle HTTP responses
 * @{
 */

/**
 * @brief HTTP response object
 *
 * Contains the complete response including status, headers, and body.
 *
 * @note Memory: Caller owns the response and must call fetch_response_free()
 */
typedef struct fetch_response {
  uint16_t status;             /**< HTTP status code */
  const char *status_text;     /**< HTTP status message */
  bool ok;                     /**< True if status is 200-299 */
  bool redirected;             /**< True if response was redirected */
  const char *url;             /**< Final URL after redirects */
  fetch_headers_t *headers;    /**< Response headers (owned by response) */
  void *body;                  /**< Response body data */
  size_t body_size;            /**< Size of response body */
  fetch_body_type_t body_type; /**< Type of response body */
  fetch_error_t error;         /**< Error code if request failed */
  const char *error_message;   /**< Error message if request failed */
} fetch_response_t;

/** @} */

/**
 * @defgroup promises Async Promises
 * @brief Handle asynchronous fetch operations
 * @{
 */

/**
 * @brief Callback for successful promise completion
 * @param response The HTTP response (borrowed reference, do not free)
 * @param userdata User-provided data
 */
typedef void (*fetch_on_fulfilled_cb)(fetch_response_t *response,
                                      void *userdata);

/**
 * @brief Callback for promise rejection/failure
 * @param error The error code
 * @param message Error message
 * @param userdata User-provided data
 */
typedef void (*fetch_on_rejected_cb)(fetch_error_t error, const char *message,
                                     void *userdata);

/**
 * @brief Promise for asynchronous fetch operations
 *
 * Represents an ongoing or completed asynchronous HTTP request.
 *
 * @note Memory: Caller owns the promise and must call fetch_promise_free()
 * @note Threading: Promises are not thread-safe and must be used from the same
 * thread
 */
typedef struct fetch_promise {
  uint64_t promise_id;         /**< Unique promise identifier */
  fetch_promise_state_t state; /**< Current promise state */
  fetch_response_t *response;  /**< Response (if fulfilled) */
  fetch_error_t error;         /**< Error code (if rejected) */
  const char *error_message;   /**< Error message (if rejected) */

  fetch_on_fulfilled_cb on_fulfilled; /**< Success callback */
  fetch_on_rejected_cb on_rejected;   /**< Failure callback */
  void *userdata;                     /**< User data for callbacks */

  void *internal_state;   /**< Internal implementation state */
  volatile bool detached; /**< True if promise was freed */
} fetch_promise_t;

/** @} */

/**
 * @defgroup url_params URL Search Parameters
 * @brief Build and manipulate URL query parameters
 * @{
 */

/**
 * @brief URL search parameters container
 *
 * Manages key-value pairs for URL query strings with automatic encoding.
 *
 * @note Memory: Caller owns the params and must call
 * fetch_url_search_params_free()
 */
typedef struct fetch_url_search_params {
  char **keys;     /**< Parameter names */
  char **values;   /**< Parameter values */
  size_t count;    /**< Number of parameters */
  size_t capacity; /**< Allocated capacity */
} fetch_url_search_params_t;

/**
 * @brief Iterator for URL search parameters
 */
typedef struct {
  const fetch_url_search_params_t *params; /**< Parameters being iterated */
  size_t index;                            /**< Current iteration index */
} fetch_url_search_params_iterator_t;

/** @} */

/**
 * @defgroup event_loop Event Loop
 * @brief Manage the event loop for asynchronous operations
 * @{
 */

/**
 * @brief Opaque event loop structure
 */
typedef struct fetch_event_loop fetch_event_loop_t;

/** @} */

/**
 * @defgroup core_api Core Fetch API
 * @brief Main functions for making HTTP requests
 * @{
 */

/**
 * @brief Make a synchronous HTTP request (BLOCKING)
 *
 * This function blocks the calling thread until the request completes or fails.
 * The event loop runs internally during this call.
 *
 * @param url The URL to fetch
 * @param init Request configuration options (can be NULL for defaults, borrowed
 * reference)
 * @return Response object (caller owns, must call fetch_response_free()), or
 * NULL on memory allocation failure
 *
 * @warning This function BLOCKS the calling thread until completion
 *
 * @note Memory: Returns owned response object that must be freed
 * @note Threading: Must be called from the same thread as the event loop
 *
 * @code
 * // Simple blocking GET request
 * fetch_response_t *response = fetch("https://httpbin.org/get", NULL);
 * if (response) {
 *     if (fetch_response_ok(response)) {
 *         printf("Status: %d\n", fetch_response_status(response));
 *         const char *text = fetch_response_text(response);
 *         if (text) {
 *             printf("Body: %s\n", text);
 *         }
 *     } else {
 *         printf("Request failed: %d %s\n", fetch_response_status(response),
 *                fetch_response_status_text(response));
 *     }
 *     fetch_response_free(response); // Required: free the response
 * }
 * @endcode
 */
fetch_response_t *fetch(const char *url, fetch_init_t *init);

/**
 * @brief Make an asynchronous HTTP request (NON-BLOCKING)
 *
 * Returns immediately with a promise. The request proceeds in the background
 * and must be driven by calling fetch_event_loop_process() regularly.
 *
 * @param url The URL to fetch
 * @param init Request configuration options (can be NULL for defaults, borrowed
 * reference)
 * @return Promise object (caller owns, must call fetch_promise_free()), or NULL
 * on memory allocation failure
 *
 * @note This function returns immediately and does NOT block
 * @note Memory: Returns owned promise object that must be freed
 * @note Event Loop: Requires fetch_event_loop_process() to be called regularly
 * for progress
 *
 * @code
 * // CORRECT: Non-blocking usage with event loop driving
 * if (!fetch_event_loop_start()) {
 *     fprintf(stderr, "Failed to start event loop\n");
 *     return -1;
 * }
 *
 * fetch_promise_t *promise = fetch_async("https://httpbin.org/get", NULL);
 * if (!promise) {
 *     fetch_event_loop_stop();
 *     return -1;
 * }
 *
 * // Drive the event loop until completion (non-blocking approach)
 * while (fetch_promise_pending(promise)) {
 *     int events = fetch_event_loop_process(100); // 100ms timeout
 *     if (events < 0) {
 *         printf("Event loop error\n");
 *         break;
 *     }
 *
 *     // Do other work here while request is in progress
 *     printf("Request in progress...\n");
 * }
 *
 * // Check result
 * if (fetch_promise_fulfilled(promise)) {
 *     fetch_response_t *response = fetch_promise_response(promise);
 *     if (response && fetch_response_ok(response)) {
 *         printf("Success: %s\n", fetch_response_text(response));
 *     }
 *     // Note: response is owned by promise, don't free it separately
 * } else if (fetch_promise_rejected(promise)) {
 *     printf("Failed: %s\n", fetch_promise_error_message(promise));
 * }
 *
 * fetch_promise_free(promise); // Required: free the promise
 * fetch_event_loop_stop();
 * @endcode
 */
fetch_promise_t *fetch_async(const char *url, fetch_init_t *init);

/** @} */

/**
 * @defgroup promise_api Promise Management
 * @brief Functions for working with fetch promises
 * @{
 */

/**
 * @brief Check if a promise has completed (NON-BLOCKING)
 *
 * @param promise The promise to check
 * @return true if promise is completed (fulfilled or rejected), false if still
 * pending
 *
 * @note This function does NOT block and does NOT drive the event loop
 * @note You must call fetch_event_loop_process() separately to make progress
 *
 * @code
 * // CORRECT: Non-blocking polling
 * fetch_promise_t *promise = fetch_async("https://httpbin.org/get", NULL);
 *
 * while (!fetch_promise_poll(promise)) {
 *     // Drive the event loop to make progress
 *     fetch_event_loop_process(10); // Small timeout for responsiveness
 *
 *     // Do other work while waiting
 *     handle_other_tasks();
 * }
 *
 * // Promise is now complete
 * @endcode
 */
bool fetch_promise_poll(fetch_promise_t *promise);

/**
 * @brief Wait for a promise to complete (BLOCKING)
 *
 * This function blocks the calling thread and drives the event loop internally
 * until the promise completes or times out.
 *
 * @param promise The promise to wait for
 * @param timeout_ms Maximum time to wait in milliseconds (0 for infinite)
 * @return true if promise completed within timeout, false if timed out
 *
 * @warning This function BLOCKS the calling thread
 * @note Event Loop: Drives the event loop internally while waiting
 *
 * @code
 * // BLOCKING approach (simpler but blocks thread)
 * fetch_promise_t *promise = fetch_async("https://httpbin.org/get", NULL);
 *
 * if (fetch_promise_await(promise, 5000)) { // Blocks for up to 5 seconds
 *     if (fetch_promise_fulfilled(promise)) {
 *         printf("Request completed successfully\n");
 *     } else {
 *         printf("Request failed\n");
 *     }
 * } else {
 *     printf("Request timed out\n");
 * }
 *
 * fetch_promise_free(promise);
 * @endcode
 */
bool fetch_promise_await(fetch_promise_t *promise, uint32_t timeout_ms);

/**
 * @brief Cancel a pending promise
 *
 * @param promise The promise to cancel
 * @param reason Optional reason for cancellation
 * @return true if promise was cancelled, false if already completed
 *
 * @code
 * fetch_promise_t *promise = fetch_async("https://httpbin.org/delay/10", NULL);
 *
 * // Cancel after 2 seconds in a separate thread or timer
 * if (fetch_promise_cancel(promise, "User cancelled")) {
 *     printf("Request was cancelled\n");
 * }
 *
 * fetch_promise_free(promise);
 * @endcode
 */
bool fetch_promise_cancel(fetch_promise_t *promise, const char *reason);

/**
 * @brief Check if a promise was cancelled
 *
 * @param promise The promise to check
 * @return true if promise was cancelled
 */
bool fetch_promise_cancelled(const fetch_promise_t *promise);

/** @} */

/**
 * @defgroup promise_accessors Promise State Accessors
 * @brief Functions to inspect promise state and results
 * @{
 */

/**
 * @brief Get the response from a fulfilled promise
 * @param promise The promise
 * @return Response object (owned by promise, do NOT free), or NULL if not
 * fulfilled
 *
 * @note Memory: Response is owned by the promise, do not call
 * fetch_response_free() on it
 */
fetch_response_t *fetch_promise_response(const fetch_promise_t *promise);

/**
 * @brief Get the current state of a promise
 * @param promise The promise
 * @return Promise state
 */
fetch_promise_state_t fetch_promise_state(const fetch_promise_t *promise);

/**
 * @brief Get the error code from a rejected promise
 * @param promise The promise
 * @return Error code
 */
fetch_error_t fetch_promise_error(const fetch_promise_t *promise);

/**
 * @brief Get the error message from a rejected promise
 * @param promise The promise
 * @return Error message string (owned by promise), or NULL
 */
const char *fetch_promise_error_message(const fetch_promise_t *promise);

/**
 * @brief Check if promise is still pending
 * @param promise The promise
 * @return true if pending
 */
bool fetch_promise_pending(const fetch_promise_t *promise);

/**
 * @brief Check if promise was fulfilled successfully
 * @param promise The promise
 * @return true if fulfilled
 */
bool fetch_promise_fulfilled(const fetch_promise_t *promise);

/**
 * @brief Check if promise was rejected
 * @param promise The promise
 * @return true if rejected
 */
bool fetch_promise_rejected(const fetch_promise_t *promise);

/** @} */

/**
 * @defgroup event_loop_api Event Loop Management
 * @brief Control the event loop for asynchronous operations
 * @{
 */

/**
 * @brief Start the event loop
 *
 * Must be called before making asynchronous requests.
 * The event loop runs in the calling thread and must be driven by
 * calling fetch_event_loop_process() regularly.
 *
 * @return true if event loop started successfully
 *
 * @note Threading: Event loop runs in the calling thread
 * @note Memory: No cleanup required for starting, but call
 * fetch_event_loop_stop() to clean up
 *
 * @code
 * if (!fetch_event_loop_start()) {
 *     fprintf(stderr, "Failed to start event loop\n");
 *     return -1;
 * }
 *
 * // Event loop is now ready for async requests
 * // You must call fetch_event_loop_process() to drive it
 * @endcode
 */
bool fetch_event_loop_start(void);

/**
 * @brief Stop the event loop
 *
 * Cancels all pending requests and shuts down the event loop.
 * Call this during cleanup to free event loop resources.
 *
 * @note Memory: Frees all event loop resources and cancels pending requests
 */
void fetch_event_loop_stop(void);

/**
 * @brief Process events in the event loop (NON-BLOCKING with timeout)
 *
 * Call this regularly to make progress on asynchronous requests.
 * This function will return after processing available events or
 * when the timeout expires.
 *
 * @param timeout_ms Maximum time to wait for events (0 for non-blocking)
 * @return Number of events processed, or -1 if event loop not running
 *
 * @note This function may block up to timeout_ms milliseconds
 * @note Call this regularly (e.g., in your main loop) to drive async requests
 *
 * @code
 * // Main application loop
 * while (application_running) {
 *     // Process fetch events (non-blocking)
 *     int events = fetch_event_loop_process(0);
 *     if (events < 0) {
 *         printf("Event loop stopped unexpectedly\n");
 *         break;
 *     }
 *
 *     // Handle application events
 *     handle_ui_events();
 *     handle_other_work();
 *
 *     // Small delay to prevent busy waiting
 *     usleep(1000); // 1ms
 * }
 *
 * // Alternative: blocking approach with timeout
 * while (has_pending_requests) {
 *     int events = fetch_event_loop_process(100); // Wait up to 100ms
 *     if (events < 0) break; // Event loop stopped
 *
 *     // Check if requests completed
 *     check_promise_states();
 * }
 * @endcode
 */
int fetch_event_loop_process(uint32_t timeout_ms);

/**
 * @brief Check if the event loop is running
 * @return true if event loop is active
 */
bool fetch_event_loop_is_running(void);

/** @} */

/**
 * @defgroup headers_api Headers Management
 * @brief Functions for managing HTTP headers
 * @{
 */

/**
 * @brief Create a new headers container
 * @return New headers object (caller owns, must call fetch_headers_free()), or
 * NULL on memory allocation failure
 *
 * @note Memory: Returns owned object that must be freed
 *
 * @code
 * fetch_headers_t *headers = fetch_headers_new();
 * if (!headers) {
 *     fprintf(stderr, "Failed to create headers\n");
 *     return -1;
 * }
 *
 * fetch_headers_set(headers, "Content-Type", "application/json");
 * fetch_headers_set(headers, "Authorization", "Bearer token123");
 *
 * // Use headers with request...
 *
 * fetch_headers_free(headers); // Required: free the headers
 * @endcode
 */
fetch_headers_t *fetch_headers_new(void);

/**
 * @brief Free a headers container and all its contents
 * @param headers Headers to free (can be NULL)
 *
 * @note Memory: Frees the headers object and all contained strings
 */
void fetch_headers_free(fetch_headers_t *headers);

/**
 * @brief Add a header (allows duplicates)
 * @param headers Headers container
 * @param name Header name
 * @param value Header value
 *
 * @note Memory: Makes copies of name and value strings
 *
 * @code
 * fetch_headers_append(headers, "Accept", "text/html");
 * fetch_headers_append(headers, "Accept", "application/json"); // Both values
 * kept
 * @endcode
 */
void fetch_headers_append(fetch_headers_t *headers, const char *name,
                          const char *value);

/**
 * @brief Set a header (replaces existing)
 * @param headers Headers container
 * @param name Header name (case-insensitive)
 * @param value Header value
 *
 * @note Memory: Makes copies of name and value strings
 *
 * @code
 * fetch_headers_set(headers, "User-Agent", "MyApp/1.0");
 * fetch_headers_set(headers, "user-agent", "MyApp/2.0"); // Replaces previous
 * @endcode
 */
void fetch_headers_set(fetch_headers_t *headers, const char *name,
                       const char *value);

/**
 * @brief Remove all headers with the given name
 * @param headers Headers container
 * @param name Header name to remove (case-insensitive)
 */
void fetch_headers_delete(fetch_headers_t *headers, const char *name);

/**
 * @brief Get the first header value with the given name
 * @param headers Headers container
 * @param name Header name (case-insensitive)
 * @return Header value (owned by headers, do not free), or NULL if not found
 *
 * @note Memory: Returned string is owned by the headers object
 *
 * @code
 * const char *content_type = fetch_headers_get(headers, "Content-Type");
 * if (content_type) {
 *     printf("Content-Type: %s\n", content_type);
 *     // Do NOT free content_type, it's owned by headers
 * }
 * @endcode
 */
const char *fetch_headers_get(const fetch_headers_t *headers, const char *name);

/**
 * @brief Check if a header exists
 * @param headers Headers container
 * @param name Header name (case-insensitive)
 * @return true if header exists
 */
bool fetch_headers_has(const fetch_headers_t *headers, const char *name);

/**
 * @brief Create an iterator for headers
 * @param headers Headers to iterate
 * @return Iterator object (no cleanup required)
 */
fetch_headers_iterator_t fetch_headers_entries(const fetch_headers_t *headers);

/**
 * @brief Get the next header from an iterator
 * @param iter Iterator object
 * @param key Output pointer for header name (owned by headers, do not free)
 * @param value Output pointer for header value (owned by headers, do not free)
 * @return true if a header was returned, false if iteration complete
 *
 * @note Memory: Returned strings are owned by the headers object
 *
 * @code
 * fetch_headers_iterator_t iter = fetch_headers_entries(headers);
 * const char *key, *value;
 * while (fetch_headers_next(&iter, &key, &value)) {
 *     printf("%s: %s\n", key, value);
 *     // Do NOT free key or value
 * }
 * @endcode
 */
bool fetch_headers_next(fetch_headers_iterator_t *iter, const char **key,
                        const char **value);

/** @} */

/**
 * @defgroup body_api Body Management
 * @brief Functions for creating request/response bodies
 * @{
 */

/**
 * @brief Create a text body
 * @param text Text content (will be copied)
 * @return Body object (caller owns, must call fetch_body_free()), or NULL on
 * failure
 *
 * @note Memory: Makes a copy of the text, returns owned object
 *
 * @code
 * fetch_body_t *body = fetch_body_text("Hello, World!");
 * if (!body) {
 *     fprintf(stderr, "Failed to create body\n");
 *     return -1;
 * }
 *
 * // Use with request...
 * fetch_body_free(body); // Required: free the body
 * @endcode
 */
fetch_body_t *fetch_body_text(const char *text);

/**
 * @brief Create a JSON body
 * @param json JSON content (will be copied)
 * @return Body object (caller owns, must call fetch_body_free()), or NULL on
 * failure
 *
 * @note Memory: Makes a copy of the JSON string, returns owned object
 *
 * @code
 * fetch_body_t *body = fetch_body_json("{\"name\": \"John\", \"age\": 30}");
 * if (body) {
 *     // Use with request...
 *     fetch_body_free(body); // Required
 * }
 * @endcode
 */
fetch_body_t *fetch_body_json(const char *json);

/**
 * @brief Create a binary body
 * @param data Binary data (will be copied)
 * @param size Size of data in bytes
 * @param content_type MIME type (optional, defaults to
 * "application/octet-stream")
 * @return Body object (caller owns, must call fetch_body_free()), or NULL on
 * failure
 *
 * @note Memory: Makes a copy of the binary data, returns owned object
 *
 * @code
 * uint8_t image_data[] = {0x89, 0x50, 0x4E, 0x47, ...};
 * fetch_body_t *body = fetch_body_binary(image_data, sizeof(image_data),
 * "image/png"); if (body) {
 *     // Use with request...
 *     fetch_body_free(body); // Required
 * }
 * @endcode
 */
fetch_body_t *fetch_body_binary(const void *data, size_t size,
                                const char *content_type);

/**
 * @brief Create a form data body
 * @param form_data URL-encoded form data (will be copied)
 * @return Body object (caller owns, must call fetch_body_free()), or NULL on
 * failure
 *
 * @note Memory: Makes a copy of the form data, returns owned object
 *
 * @code
 * fetch_body_t *body = fetch_body_form_data("name=John&age=30&city=New+York");
 * if (body) {
 *     // Use with request...
 *     fetch_body_free(body); // Required
 * }
 * @endcode
 */
fetch_body_t *fetch_body_form_data(const char *form_data);

/**
 * @brief Create a body from URL search parameters
 * @param params URL search parameters object
 * @return Body object formatted as form data (caller owns, must call
 * fetch_body_free()), or NULL on failure
 *
 * @note Memory: Creates new body object, original params unchanged
 *
 * @code
 * fetch_url_search_params_t *params = fetch_url_search_params_new();
 * fetch_url_search_params_append(params, "name", "John");
 * fetch_url_search_params_append(params, "age", "30");
 *
 * fetch_body_t *body = fetch_body_url_search_params(params);
 *
 * // Both body and params need to be freed
 * fetch_body_free(body); // Required
 * fetch_url_search_params_free(params); // Required
 * @endcode
 */
fetch_body_t *fetch_body_url_search_params(fetch_url_search_params_t *params);

/**
 * @brief Create a body from a file handle for streaming
 *
 * Creates a request body that streams data directly from a file handle,
 * avoiding the need to load large files into memory. Supports three modes:
 *
 * 1. **Regular files** (continue_cb = NULL, size > 0):
 *    - Uses Content-Length header with known file size
 *    - Most efficient for static files
 *
 * 2. **Unknown-size files** (continue_cb = NULL, size = 0):
 *    - Uses chunked transfer encoding
 *    - For files where size cannot be determined
 *
 * 3. **Live streaming** (continue_cb != NULL):
 *    - Uses chunked transfer encoding with user-controlled completion
 *    - For continuously written files, logs, or live data streams
 *    - The callback determines when more data is available
 *
 * @param file_handle File handle to stream from (platform-specific)
 * @param size File size in bytes (0 if unknown, enables chunked encoding)
 * @param content_type MIME type (optional, defaults to
 * "application/octet-stream")
 * @param close_on_free Whether to close the file handle when body is freed
 * @param continue_cb Callback for streaming control (NULL for regular files)
 * @param userdata User data passed to continue_cb
 * @return Body object (caller owns, must call fetch_body_free()), or NULL on
 * failure
 *
 * @note Memory: Body object manages file handle according to close_on_free flag
 * @note File Handle: If close_on_free is false, caller must keep handle open
 * until request completes
 * @note Threading: File operations will be performed on the same thread as the
 * event loop
 * @note Streaming: If continue_cb is non-NULL, uses chunked transfer encoding
 * for unknown-length streams
 *
 * @code
 * // Example 1: Regular file with known size (most efficient)
 * FILE *file = fopen("upload.dat", "rb");
 * if (file) {
 *     fseek(file, 0, SEEK_END);
 *     size_t size = ftell(file);
 *     fseek(file, 0, SEEK_SET);
 *
 *     // Library will close the file automatically
 *     fetch_body_t *body = fetch_body_file(file, size,
 * "application/octet-stream", true, NULL, NULL);
 *
 *     // Use body with request...
 *     fetch_body_free(body); // This will close the file handle
 * }
 *
 * // Example 2: Streaming a log file that's being written to
 * typedef struct {
 *     bool should_stop;
 *     FILE *log_file;
 * } LogStreamContext;
 *
 * fetch_stream_result_t continue_log_stream(void *userdata) {
 *     LogStreamContext *ctx = (LogStreamContext*)userdata;
 *
 *     if (ctx->should_stop) {
 *         return FETCH_STREAM_DONE;
 *     }
 *
 *     // Check if new data has been written
 *     long current_pos = ftell(ctx->log_file);
 *     fseek(ctx->log_file, 0, SEEK_END);
 *     long end_pos = ftell(ctx->log_file);
 *     fseek(ctx->log_file, current_pos, SEEK_SET);
 *
 *     if (end_pos > current_pos) {
 *         return FETCH_STREAM_READ;  // More data available
 *     }
 *
 *     return FETCH_STREAM_SKIP;  // No new data yet, but keep trying
 * }
 *
 * FILE *log_file = fopen("live.log", "rb");
 * LogStreamContext ctx = { .should_stop = false, .log_file = log_file };
 *
 * // Stream with unknown size and continuous monitoring
 * fetch_body_t *body = fetch_body_file(log_file, 0, "text/plain", false,
 *                                      continue_log_stream, &ctx);
 *
 * // Start upload...
 * // Later, to stop streaming: ctx.should_stop = true;
 *
 * fetch_body_free(body);
 * fclose(log_file); // Manual cleanup since close_on_free was false
 *
 * // Example 3: Windows file with automatic cleanup
 * #ifdef _WIN32
 * HANDLE file = CreateFile(L"upload.dat", GENERIC_READ, FILE_SHARE_READ,
 *                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
 * if (file != INVALID_HANDLE_VALUE) {
 *     LARGE_INTEGER size;
 *     GetFileSizeEx(file, &size);
 *
 *     // Body will close the file handle automatically
 *     fetch_body_t *body = fetch_body_file(file, size.QuadPart,
 *                                          "application/octet-stream", true,
 *                                          NULL, NULL);
 *
 *     // Use body with request...
 *
 *     fetch_body_free(body); // This will close the file handle
 * }
 * #endif
 * @endcode
 */
fetch_body_t *fetch_body_file(FETCH_FILE_HANDLE file_handle, size_t size,
                              const char *content_type, bool close_on_free,
                              fetch_file_continue_cb continue_cb,
                              void *userdata);

/**
 * @brief Free a body object
 * @param body Body to free (can be NULL)
 *
 * @note Memory: Frees the body and all contained data
 * @note File Handles: If body is FETCH_BODY_FILE and close_on_free is true,
 *       closes the file handle automatically
 */
void fetch_body_free(fetch_body_t *body);

/** @} */

/**
 * @defgroup url_params_api URL Search Parameters
 * @brief Functions for building query strings
 * @{
 */

/**
 * @brief Create a new URL search parameters container
 * @return New parameters object (caller owns, must call
 * fetch_url_search_params_free()), or NULL on failure
 *
 * @note Memory: Returns owned object that must be freed
 */
fetch_url_search_params_t *fetch_url_search_params_new(void);

/**
 * @brief Free a URL search parameters container
 * @param params Parameters to free (can be NULL)
 *
 * @note Memory: Frees the parameters and all contained strings
 */
void fetch_url_search_params_free(fetch_url_search_params_t *params);

/**
 * @brief Add a parameter (allows duplicates)
 * @param params Parameters container
 * @param name Parameter name
 * @param value Parameter value
 *
 * @note Memory: Makes copies of name and value strings
 */
void fetch_url_search_params_append(fetch_url_search_params_t *params,
                                    const char *name, const char *value);

/**
 * @brief Set a parameter (replaces existing)
 * @param params Parameters container
 * @param name Parameter name
 * @param value Parameter value
 *
 * @note Memory: Makes copies of name and value strings
 */
void fetch_url_search_params_set(fetch_url_search_params_t *params,
                                 const char *name, const char *value);

/**
 * @brief Remove all parameters with the given name
 * @param params Parameters container
 * @param name Parameter name to remove
 */
void fetch_url_search_params_delete(fetch_url_search_params_t *params,
                                    const char *name);

/**
 * @brief Get the first parameter value with the given name
 * @param params Parameters container
 * @param name Parameter name
 * @return Parameter value (owned by params, do not free), or NULL if not found
 *
 * @note Memory: Returned string is owned by the parameters object
 */
const char *fetch_url_search_params_get(const fetch_url_search_params_t *params,
                                        const char *name);

/**
 * @brief Check if a parameter exists
 * @param params Parameters container
 * @param name Parameter name
 * @return true if parameter exists
 */
bool fetch_url_search_params_has(const fetch_url_search_params_t *params,
                                 const char *name);

/**
 * @brief Convert parameters to URL-encoded string
 * @param params Parameters container
 * @return URL-encoded string (caller owns, must call free()), or NULL on
 * failure
 *
 * @note Memory: Returns owned string that must be freed with free()
 *
 * @code
 * fetch_url_search_params_t *params = fetch_url_search_params_new();
 * fetch_url_search_params_append(params, "q", "hello world");
 * fetch_url_search_params_append(params, "lang", "en");
 *
 * char *query_string = fetch_url_search_params_to_string(params);
 * if (query_string) {
 *     printf("Query: %s\n", query_string); // "q=hello%20world&lang=en"
 *     free(query_string); // Required: free the string
 * }
 *
 * fetch_url_search_params_free(params); // Required: free the params
 * @endcode
 */
char *
fetch_url_search_params_to_string(const fetch_url_search_params_t *params);

/**
 * @brief Create an iterator for URL search parameters
 * @param params Parameters to iterate
 * @return Iterator object (no cleanup required)
 */
fetch_url_search_params_iterator_t
fetch_url_search_params_entries(const fetch_url_search_params_t *params);

/**
 * @brief Get the next parameter from an iterator
 * @param iter Iterator object
 * @param key Output pointer for parameter name (owned by params, do not free)
 * @param value Output pointer for parameter value (owned by params, do not
 * free)
 * @return true if a parameter was returned, false if iteration complete
 *
 * @note Memory: Returned strings are owned by the parameters object
 */
bool fetch_url_search_params_next(fetch_url_search_params_iterator_t *iter,
                                  const char **key, const char **value);

/** @} */

/**
 * @defgroup response_api Response Access
 * @brief Functions for reading HTTP responses
 * @{
 */

/**
 * @brief Get response body as text
 * @param response The response
 * @return Text content (owned by response, do not free), or NULL if not text or
 * no body
 *
 * @note Memory: Returned string is owned by the response object
 *
 * @code
 * fetch_response_t *response = fetch("https://httpbin.org/get", NULL);
 * if (response) {
 *     const char *text = fetch_response_text(response);
 *     if (text) {
 *         printf("Response: %s\n", text);
 *         // Do NOT free text, it's owned by response
 *     }
 *     fetch_response_free(response); // Required: free the response
 * }
 * @endcode
 */
const char *fetch_response_text(fetch_response_t *response);

/**
 * @brief Get response body as binary data
 * @param response The response
 * @param size Output pointer for data size
 * @return Pointer to binary data (owned by response, do not free), or NULL if
 * no body
 *
 * @note Memory: Returned data is owned by the response object
 *
 * @code
 * size_t size;
 * const uint8_t *data = fetch_response_array_buffer(response, &size);
 * if (data) {
 *     printf("Received %zu bytes of binary data\n", size);
 *     // Process data...
 *     // Do NOT free data, it's owned by response
 * }
 * @endcode
 */
const void *fetch_response_array_buffer(fetch_response_t *response,
                                        size_t *size);

/**
 * @brief Get response body as JSON text
 * @param response The response
 * @return JSON text (owned by response, do not free), or NULL if not JSON or no
 * body
 *
 * @note Memory: Returned string is owned by the response object
 */
const char *fetch_response_json(fetch_response_t *response);

/**
 * @brief Check if response is successful (2xx status)
 * @param response The response
 * @return true if status is 200-299
 */
bool fetch_response_ok(const fetch_response_t *response);

/**
 * @brief Get HTTP status code
 * @param response The response
 * @return HTTP status code (e.g., 200, 404, 500)
 */
uint16_t fetch_response_status(const fetch_response_t *response);

/**
 * @brief Get HTTP status text
 * @param response The response
 * @return Status text (owned by response, do not free)
 *
 * @note Memory: Returned string is owned by the response object
 */
const char *fetch_response_status_text(const fetch_response_t *response);

/**
 * @brief Get final URL (after redirects)
 * @param response The response
 * @return Final URL string (owned by response, do not free)
 *
 * @note Memory: Returned string is owned by the response object
 */
const char *fetch_response_url(const fetch_response_t *response);

/**
 * @brief Get response headers
 * @param response The response
 * @return Headers object (owned by response, do not free)
 *
 * @note Memory: Returned headers are owned by the response object
 */
fetch_headers_t *fetch_response_headers(const fetch_response_t *response);

/**
 * @brief Clone a response object
 * @param response The response to clone
 * @return New response object (caller owns, must call fetch_response_free()),
 * or NULL on failure
 *
 * @note Memory: Creates a deep copy, caller owns the new response
 */
fetch_response_t *fetch_response_clone(const fetch_response_t *response);

/**
 * @brief Free a response object
 * @param response Response to free (can be NULL)
 *
 * @note Memory: Frees the response and all contained data
 */
void fetch_response_free(fetch_response_t *response);

/** @} */

/**
 * @defgroup abort_api Abort Controller
 * @brief Functions for request cancellation
 * @{
 */

/**
 * @brief Create a new abort controller
 * @return New abort controller (caller owns, must call
 * fetch_abort_controller_free() if not passed to fetch_init), or NULL on
 * failure
 *
 * @note Memory: Returns owned object that must be freed
 *
 * @code
 * fetch_abort_controller_t *controller = fetch_abort_controller_new();
 * if (!controller) {
 *     fprintf(stderr, "Failed to create abort controller\n");
 *     return -1;
 * }
 *
 * fetch_init_t *init = fetch_init_new();
 * fetch_init_signal(init, controller); // Controller is borrowed by init
 *
 * fetch_promise_t *promise = fetch_async("https://httpbin.org/delay/10", init);
 *
 * // Cancel after 5 seconds
 * sleep(5);
 * fetch_abort_controller_abort(controller, "Took too long");
 *
 * // Cleanup (order matters)
 * fetch_promise_free(promise);
 * fetch_init_free(init); // This frees the controller
 * @endcode
 */
fetch_abort_controller_t *fetch_abort_controller_new(void);

/**
 * @brief Abort operations using this controller
 * @param controller The abort controller
 * @param reason Optional reason for abortion
 */
void fetch_abort_controller_abort(fetch_abort_controller_t *controller,
                                  const char *reason);

/**
 * @brief Check if controller has been aborted
 * @param controller The abort controller
 * @return true if aborted
 */
bool fetch_abort_controller_aborted(const fetch_abort_controller_t *controller);

/**
 * @brief Free an abort controller
 * @param controller Controller to free (can be NULL)
 *
 * @note Memory: Frees the controller
 */
void fetch_abort_controller_free(fetch_abort_controller_t *controller);

/** @} */

/**
 * @defgroup init_api Request Initialization
 * @brief Functions for configuring requests
 * @{
 */

/**
 * @brief Create a new request configuration
 * @return New init object with default values (caller owns, must call
 * fetch_init_free()), or NULL on failure
 *
 * @note Memory: Returns owned object that must be freed
 *
 * @code
 * fetch_init_t *init = fetch_init_new();
 * if (!init) {
 *     fprintf(stderr, "Failed to create init\n");
 *     return -1;
 * }
 *
 * // Configure request (these functions transfer ownership)
 * fetch_init_method(init, HTTP_METHOD_POST);
 * fetch_init_timeout(init, 10000); // 10 seconds
 *
 * fetch_headers_t *headers = fetch_headers_new();
 * fetch_headers_set(headers, "Content-Type", "application/json");
 * fetch_init_headers(init, headers); // Ownership of headers transferred to
 * init
 *
 * fetch_body_t *body = fetch_body_json("{\"test\": true}");
 * fetch_init_body(init, body); // Ownership of body transferred to init
 *
 * // Use init with request...
 *
 * fetch_init_free(init); // Required: frees init, headers, and body
 * @endcode
 */
fetch_init_t *fetch_init_new(void);

/**
 * @brief Free a request configuration
 * @param init Init object to free (can be NULL)
 *
 * @note Memory: Frees the init object and all owned resources (headers, body,
 * etc.)
 */
void fetch_init_free(fetch_init_t *init);

/**
 * @brief Set HTTP method (fluent interface)
 * @param init Init object
 * @param method HTTP method
 * @return Same init object for chaining
 */
fetch_init_t *fetch_init_method(fetch_init_t *init, http_method_t method);

/**
 * @brief Set request headers (fluent interface)
 * @param init Init object
 * @param headers Headers object (ownership transferred to init)
 * @return Same init object for chaining
 *
 * @note Memory: Ownership of headers is transferred to init
 */
fetch_init_t *fetch_init_headers(fetch_init_t *init, fetch_headers_t *headers);

/**
 * @brief Set request body (fluent interface)
 * @param init Init object
 * @param body Body object (ownership transferred to init)
 * @return Same init object for chaining
 *
 * @note Memory: Ownership of body is transferred to init
 */
fetch_init_t *fetch_init_body(fetch_init_t *init, fetch_body_t *body);

/**
 * @brief Set request timeout (fluent interface)
 * @param init Init object
 * @param timeout_ms Timeout in milliseconds
 * @return Same init object for chaining
 */
fetch_init_t *fetch_init_timeout(fetch_init_t *init, uint32_t timeout_ms);

/**
 * @brief Set abort signal (fluent interface)
 * @param init Init object
 * @param signal Abort controller (borrowed reference, init does not own)
 * @return Same init object for chaining
 *
 * @note Memory: Controller is borrowed, caller must keep it alive and free it
 */
fetch_init_t *fetch_init_signal(fetch_init_t *init,
                                fetch_abort_controller_t *signal);

/** @} */

/**
 * @defgroup utility_api Utility Functions
 * @brief Helper functions for common operations
 * @{
 */

/**
 * @brief Convert HTTP method enum to string
 * @param method HTTP method
 * @return Method name string (static, do not free)
 *
 * @note Memory: Returned string is static, do not free
 *
 * @code
 * printf("Method: %s\n", fetch_method_to_string(HTTP_METHOD_POST)); // "POST"
 * @endcode
 */
const char *fetch_method_to_string(http_method_t method);

/**
 * @brief Convert string to HTTP method enum
 * @param method_str Method name string (case-insensitive)
 * @return HTTP method enum (defaults to GET for invalid input)
 *
 * @code
 * http_method_t method = fetch_method_from_string("post"); // HTTP_METHOD_POST
 * @endcode
 */
http_method_t fetch_method_from_string(const char *method_str);

/**
 * @brief Check if a URL is valid
 * @param url URL string to validate
 * @return true if URL is valid
 *
 * @code
 * if (fetch_is_valid_url("https://example.com/api")) {
 *     // Safe to use this URL
 * }
 * @endcode
 */
bool fetch_is_valid_url(const char *url);

/**
 * @brief Convert error code to human-readable string
 * @param error Error code
 * @return Error description string (static, do not free)
 *
 * @note Memory: Returned string is static, do not free
 *
 * @code
 * if (fetch_promise_rejected(promise)) {
 *     fetch_error_t error = fetch_promise_error(promise);
 *     printf("Error: %s\n", fetch_error_to_string(error));
 * }
 * @endcode
 */
const char *fetch_error_to_string(fetch_error_t error);

/** @} */

/**
 * @defgroup config_api Global Configuration
 * @brief Configure library-wide settings
 * @{
 */

/**
 * @brief Global configuration for the fetch library
 */
typedef struct fetch_config {
  const char *user_agent; /**< Default User-Agent header */
  const char *origin;     /**< Origin for CORS and cookie handling */
  cookie_jar_t
      *cookie_jar; /**< Cookie storage (optional, borrowed reference) */

  uint32_t default_timeout_ms;       /**< Default request timeout */
  uint32_t max_connections;          /**< Maximum concurrent connections */
  uint32_t max_connections_per_host; /**< Max connections per hostname */
  uint32_t keep_alive_timeout_ms;    /**< Keep-alive timeout */
  uint32_t pool_cleanup_interval_ms; /**< Connection pool cleanup interval */
  uint32_t max_pooled_connections;   /**< Maximum pooled connections */

  uint32_t flags; /**< Configuration flags bitfield */
} fetch_config_t;

/**
 * @brief Get a configuration flag value
 * @param flags Flags bitfield
 * @param bit Flag to check
 * @return true if flag is set
 */
static inline bool fetch_config_get_flag(uint32_t flags, fetch_flag_bit_t bit) {
  return FETCH_FLAG_GET(flags, bit) != 0;
}

/**
 * @brief Set or clear a configuration flag
 * @param config Configuration object
 * @param flag Flag to modify
 * @param value true to set, false to clear
 */
static inline void fetch_config_set_flag(fetch_config_t *config,
                                         fetch_flag_bit_t flag, bool value) {
  if (!config)
    return;

  if (value) {
    config->flags = FETCH_FLAG_SET(config->flags, flag);
  } else {
    config->flags = FETCH_FLAG_CLEAR(config->flags, flag);
  }
}

/**
 * @brief Get default configuration
 * @return Default configuration struct
 *
 * @code
 * // Configure library with custom settings
 * fetch_config_t config = fetch_config_default();
 * config.default_timeout_ms = 5000; // 5 seconds
 * config.user_agent = "MyApp/1.0";
 *
 * // Create cookie jar if needed
 * cookie_jar_t *jar = fetch_create_cookie_jar(NULL); // Memory-only
 * config.cookie_jar = jar; // Borrowed reference
 *
 * fetch_global_init(&config);
 *
 * // Library is now configured...
 *
 * // Cleanup
 * fetch_global_dispose(); // This doesn't free the cookie jar
 * fetch_cookie_jar_free(jar); // Required: free cookie jar separately
 * @endcode
 */
static inline fetch_config_t fetch_config_default(void) {
  fetch_config_t config = {.user_agent = FETCH_USER_AGENT,
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
  return config;
}

/**
 * @brief Initialize the fetch library with configuration
 * @param config Configuration options (NULL for defaults, borrowed reference)
 *
 * @note Memory: Configuration is copied, original can be freed
 * @note Threading: Must be called before any fetch operations, not thread-safe
 *
 * @code
 * // Initialize with defaults
 * fetch_global_init(NULL);
 *
 * // Or with custom config
 * fetch_config_t config = fetch_config_default();
 * config.default_timeout_ms = 10000;
 * config.user_agent = "MyCustomApp/1.0";
 * fetch_global_init(&config);
 * // config can now be freed/go out of scope
 * @endcode
 */
void fetch_global_init(const fetch_config_t *config);

/**
 * @brief Clean up the fetch library
 *
 * Stops the event loop and frees all resources.
 * Call this during application shutdown.
 *
 * @note Memory: Frees all library resources
 * @note Threading: Must be called from the same thread that initialized the
 * library
 */
void fetch_global_dispose(void);

/** @} */

/**
 * @defgroup cookie_api Cookie Management
 * @brief Functions for HTTP cookie handling
 * @{
 */

/**
 * @brief Get the current cookie jar
 * @return Cookie jar (owned by library, do not free), or NULL if cookies
 * disabled
 *
 * @note Memory: Cookie jar is owned by the library
 */
cookie_jar_t *fetch_get_cookie_jar(void);

/**
 * @brief Count cookies in the jar
 * @param domain_filter Optional domain filter (NULL for all cookies)
 * @return Number of cookies
 *
 * @code
 * size_t total = fetch_cookie_jar_count(NULL);
 * size_t google = fetch_cookie_jar_count("google.com");
 * printf("Total cookies: %zu, Google cookies: %zu\n", total, google);
 * @endcode
 */
size_t fetch_cookie_jar_count(const char *domain_filter);

/**
 * @brief Clear all cookies from the jar
 */
void fetch_cookie_jar_clear(void);

/**
 * @brief Disable cookie handling
 *
 * Removes the cookie jar and disables cookie processing.
 */
void fetch_disable_cookies(void);

/**
 * @brief Create a new cookie jar
 * @param persistent_file Optional file for persistent storage (NULL for
 * memory-only)
 * @return New cookie jar (caller owns, must call fetch_cookie_jar_free()), or
 * NULL on failure
 *
 * @note Memory: Returns owned cookie jar that must be freed
 *
 * @code
 * // Memory-only cookie jar
 * cookie_jar_t *jar = fetch_create_cookie_jar(NULL);
 * if (!jar) {
 *     fprintf(stderr, "Failed to create cookie jar\n");
 *     return -1;
 * }
 *
 * // Persistent cookie jar
 * cookie_jar_t *persistent_jar = fetch_create_cookie_jar("cookies.dat");
 * if (persistent_jar) {
 *     // Use jar...
 *     fetch_cookie_jar_free(persistent_jar); // Required
 * }
 *
 * fetch_cookie_jar_free(jar); // Required
 * @endcode
 */
cookie_jar_t *fetch_create_cookie_jar(const char *persistent_file);

/**
 * @brief Free a cookie jar
 * @param jar Cookie jar to free
 *
 * @note Memory: Frees the cookie jar and all contained cookies
 */
void fetch_cookie_jar_free(cookie_jar_t *jar);

/**
 * @brief Save cookies to a file
 * @param filename File path to save to
 * @param jar Cookie jar to save
 * @return true if successful
 */
bool fetch_save_cookies(const char *filename, cookie_jar_t *jar);

/**
 * @brief Load cookies from a file
 * @param filename File path to load from
 * @param jar Cookie jar to load into
 * @return true if successful
 */
bool fetch_load_cookies(const char *filename, cookie_jar_t *jar);

/**
 * @brief Print cookies to stdout (for debugging)
 * @param jar Cookie jar to print
 * @param domain_filter Optional domain filter (NULL for all)
 */
void fetch_cookie_jar_print(cookie_jar_t *jar, const char *domain_filter);

/** @} */

/**
 * @defgroup memory_api Memory Management
 * @brief Functions for cleaning up objects
 * @{
 */

/**
 * @brief Free a promise object
 * @param promise Promise to free (can be NULL)
 *
 * Always call this when done with a promise to prevent memory leaks.
 *
 * @note Memory: Frees the promise and associated response (if any)
 * @note Threading: Must be called from the same thread that created the promise
 */
void fetch_promise_free(fetch_promise_t *promise);

/** @} */

/**
 * @defgroup convenience_macros Convenience Macros
 * @brief Shortcuts for common operations
 * @{
 */

/** @brief Make a simple GET request (BLOCKING) */
#define FETCH_GET(url) fetch(url, NULL)

/** @brief Make a simple async GET request (NON-BLOCKING) */
#define FETCH_ASYNC_GET(url) fetch_async(url, NULL)

/** @brief Check if response is successful */
#define FETCH_IS_OK(response)                                                  \
  ((response) != NULL && fetch_response_ok(response))

/** @brief Check if promise is done (fulfilled or rejected) */
#define FETCH_PROMISE_IS_DONE(promise)                                         \
  ((promise) != NULL && fetch_promise_poll(promise))

/** @} */

/**
 * @defgroup timeout_constants Timeout Constants
 * @brief Predefined timeout values
 * @{
 */

#define FETCH_TIMEOUT_INFINITE 0    /**< Infinite timeout */
#define FETCH_TIMEOUT_DEFAULT 30000 /**< 30 second default timeout */
#define FETCH_TIMEOUT_SHORT 5000    /**< 5 second short timeout */
#define FETCH_TIMEOUT_LONG 60000    /**< 60 second long timeout */

/** @} */

/**
 * @defgroup examples Usage Examples
 * @brief Complete examples showing proper library usage
 * @{
 */

/**
 * @brief Example: Simple synchronous request (BLOCKING)
 *
 * This example shows the simplest way to make an HTTP request.
 * The thread will block until the request completes.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 *
 * int main() {
 *     // Initialize library (optional, will auto-initialize)
 *     fetch_global_init(NULL);
 *
 *     // Make blocking request
 *     fetch_response_t *response = fetch("https://httpbin.org/get", NULL);
 *     if (!response) {
 *         fprintf(stderr, "Failed to make request\n");
 *         fetch_global_dispose();
 *         return 1;
 *     }
 *
 *     // Check response
 *     if (fetch_response_ok(response)) {
 *         printf("Success! Status: %d\n", fetch_response_status(response));
 *         const char *text = fetch_response_text(response);
 *         if (text) {
 *             printf("Response: %s\n", text);
 *         }
 *     } else {
 *         printf("Request failed: %d %s\n",
 *                fetch_response_status(response),
 *                fetch_response_status_text(response));
 *     }
 *
 *     // Cleanup
 *     fetch_response_free(response); // Required
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: Asynchronous request with event loop (NON-BLOCKING)
 *
 * This example shows how to make non-blocking requests and drive
 * the event loop manually. This approach allows you to handle multiple
 * requests concurrently and do other work while requests are in progress.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <unistd.h>
 *
 * int main() {
 *     // Initialize library and start event loop
 *     fetch_global_init(NULL);
 *     if (!fetch_event_loop_start()) {
 *         fprintf(stderr, "Failed to start event loop\n");
 *         fetch_global_dispose();
 *         return 1;
 *     }
 *
 *     // Start multiple async requests
 *     fetch_promise_t *promise1 = fetch_async("https://httpbin.org/get", NULL);
 *     fetch_promise_t *promise2 = fetch_async("https://httpbin.org/user-agent",
 * NULL);
 *
 *     if (!promise1 || !promise2) {
 *         fprintf(stderr, "Failed to create promises\n");
 *         goto cleanup;
 *     }
 *
 *     printf("Requests started, processing...\n");
 *
 *     // Drive event loop until both requests complete
 *     while (fetch_promise_pending(promise1) ||
 * fetch_promise_pending(promise2)) {
 *         // Process events (non-blocking with 50ms timeout)
 *         int events = fetch_event_loop_process(50);
 *         if (events < 0) {
 *             fprintf(stderr, "Event loop error\n");
 *             break;
 *         }
 *
 *         // Do other work while waiting
 *         printf("Doing other work...\n");
 *         usleep(100000); // 100ms
 *     }
 *
 *     // Check results
 *     if (fetch_promise_fulfilled(promise1)) {
 *         fetch_response_t *response = fetch_promise_response(promise1);
 *         printf("Request 1 completed: %d\n", fetch_response_status(response));
 *         // Note: don't free response, it's owned by the promise
 *     } else {
 *         printf("Request 1 failed: %s\n",
 * fetch_promise_error_message(promise1));
 *     }
 *
 *     if (fetch_promise_fulfilled(promise2)) {
 *         fetch_response_t *response = fetch_promise_response(promise2);
 *         printf("Request 2 completed: %d\n", fetch_response_status(response));
 *     } else {
 *         printf("Request 2 failed: %s\n",
 * fetch_promise_error_message(promise2));
 *     }
 *
 * cleanup:
 *     // Cleanup (promises own their responses)
 *     fetch_promise_free(promise1); // Required
 *     fetch_promise_free(promise2); // Required
 *     fetch_event_loop_stop();
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: POST request with custom headers and body
 *
 * This example shows how to create a POST request with custom headers
 * and a JSON body, demonstrating proper memory management.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 *
 * int main() {
 *     fetch_global_init(NULL);
 *
 *     // Create request configuration
 *     fetch_init_t *init = fetch_init_new();
 *     if (!init) {
 *         fprintf(stderr, "Failed to create init\n");
 *         goto cleanup;
 *     }
 *
 *     // Set method
 *     fetch_init_method(init, HTTP_METHOD_POST);
 *
 *     // Create headers
 *     fetch_headers_t *headers = fetch_headers_new();
 *     if (!headers) {
 *         fprintf(stderr, "Failed to create headers\n");
 *         goto cleanup;
 *     }
 *     fetch_headers_set(headers, "Content-Type", "application/json");
 *     fetch_headers_set(headers, "Authorization", "Bearer token123");
 *     fetch_headers_set(headers, "X-Custom-Header", "MyValue");
 *
 *     // Transfer ownership of headers to init
 *     fetch_init_headers(init, headers);
 *     // headers is now owned by init, don't free it separately
 *
 *     // Create JSON body
 *     fetch_body_t *body = fetch_body_json(
 *         "{"
 *         "\"name\": \"John Doe\","
 *         "\"email\": \"john@example.com\","
 *         "\"age\": 30"
 *         "}"
 *     );
 *     if (!body) {
 *         fprintf(stderr, "Failed to create body\n");
 *         goto cleanup;
 *     }
 *
 *     // Transfer ownership of body to init
 *     fetch_init_body(init, body);
 *     // body is now owned by init, don't free it separately
 *
 *     // Set timeout
 *     fetch_init_timeout(init, 10000); // 10 seconds
 *
 *     // Make request (blocking)
 *     fetch_response_t *response = fetch("https://httpbin.org/post", init);
 *     if (!response) {
 *         fprintf(stderr, "Failed to make request\n");
 *         goto cleanup;
 *     }
 *
 *     // Process response
 *     printf("Response status: %d %s\n",
 *            fetch_response_status(response),
 *            fetch_response_status_text(response));
 *
 *     if (fetch_response_ok(response)) {
 *         const char *response_text = fetch_response_text(response);
 *         if (response_text) {
 *             printf("Response body: %s\n", response_text);
 *         }
 *
 *         // Access response headers
 *         fetch_headers_t *resp_headers = fetch_response_headers(response);
 *         const char *content_type = fetch_headers_get(resp_headers,
 * "Content-Type"); if (content_type) { printf("Response Content-Type: %s\n",
 * content_type);
 *         }
 *     }
 *
 *     // Cleanup
 *     fetch_response_free(response); // Required
 *
 * cleanup:
 *     fetch_init_free(init); // This frees headers and body too
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: Request cancellation with abort controller
 *
 * This example shows how to cancel requests using an abort controller.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <signal.h>
 * #include <unistd.h>
 *
 * // Global abort controller for signal handling
 * fetch_abort_controller_t *g_abort_controller = NULL;
 *
 * void signal_handler(int sig) {
 *     printf("\nReceived signal %d, cancelling request...\n", sig);
 *     if (g_abort_controller) {
 *         fetch_abort_controller_abort(g_abort_controller, "Interrupted by
 * user");
 *     }
 * }
 *
 * int main() {
 *     fetch_global_init(NULL);
 *
 *     if (!fetch_event_loop_start()) {
 *         fprintf(stderr, "Failed to start event loop\n");
 *         return 1;
 *     }
 *
 *     // Create abort controller
 *     g_abort_controller = fetch_abort_controller_new();
 *     if (!g_abort_controller) {
 *         fprintf(stderr, "Failed to create abort controller\n");
 *         goto cleanup;
 *     }
 *
 *     // Set up signal handler for Ctrl+C
 *     signal(SIGINT, signal_handler);
 *
 *     // Create request with abort controller
 *     fetch_init_t *init = fetch_init_new();
 *     fetch_init_signal(init, g_abort_controller); // Borrowed reference
 *
 *     // Start a long request
 *     printf("Starting request to delayed endpoint (press Ctrl+C to
 * cancel)...\n"); fetch_promise_t *promise =
 * fetch_async("https://httpbin.org/delay/10", init);
 *
 *     if (!promise) {
 *         fprintf(stderr, "Failed to create promise\n");
 *         goto cleanup;
 *     }
 *
 *     // Drive event loop
 *     while (fetch_promise_pending(promise)) {
 *         int events = fetch_event_loop_process(100);
 *         if (events < 0) break;
 *
 *         // Check if cancelled
 *         if (fetch_promise_cancelled(promise)) {
 *             printf("Request was cancelled\n");
 *             break;
 *         }
 *     }
 *
 *     // Check final result
 *     if (fetch_promise_fulfilled(promise)) {
 *         printf("Request completed successfully\n");
 *     } else if (fetch_promise_cancelled(promise)) {
 *         printf("Request was cancelled: %s\n",
 * fetch_promise_error_message(promise)); } else { printf("Request failed:
 * %s\n", fetch_promise_error_message(promise));
 *     }
 *
 * cleanup:
 *     fetch_promise_free(promise);
 *     fetch_init_free(init); // This frees the abort controller
 *     g_abort_controller = NULL;
 *     fetch_event_loop_stop();
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: Cookie management
 *
 * This example shows how to use cookies with the fetch library.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 *
 * int main() {
 *     // Create cookie jar
 *     cookie_jar_t *jar = fetch_create_cookie_jar("cookies.dat"); // Persistent
 *     if (!jar) {
 *         fprintf(stderr, "Failed to create cookie jar\n");
 *         return 1;
 *     }
 *
 *     // Configure library with cookies
 *     fetch_config_t config = fetch_config_default();
 *     config.cookie_jar = jar; // Borrowed reference
 *     config.origin = "https://httpbin.org"; // For same-origin cookie policy
 *     fetch_global_init(&config);
 *
 *     printf("Making request to set cookies...\n");
 *
 *     // Make request that sets cookies
 *     fetch_response_t *response1 =
 * fetch("https://httpbin.org/cookies/set/test/value123", NULL); if (response1)
 * { printf("First request status: %d\n", fetch_response_status(response1));
 *         fetch_response_free(response1);
 *     }
 *
 *     // Check cookies
 *     printf("Cookies after first request:\n");
 *     fetch_cookie_jar_print(jar, NULL);
 *
 *     printf("\nMaking second request (should include cookies)...\n");
 *
 *     // Make another request - cookies should be sent automatically
 *     fetch_response_t *response2 = fetch("https://httpbin.org/cookies", NULL);
 *     if (response2) {
 *         printf("Second request status: %d\n",
 * fetch_response_status(response2)); const char *text =
 * fetch_response_text(response2); if (text) { printf("Response shows cookies:
 * %s\n", text);
 *         }
 *         fetch_response_free(response2);
 *     }
 *
 *     // Save cookies to file
 *     if (fetch_save_cookies("my_cookies.dat", jar)) {
 *         printf("Cookies saved to file\n");
 *     }
 *
 *     // Cleanup
 *     fetch_global_dispose(); // This doesn't free the cookie jar
 *     fetch_cookie_jar_free(jar); // Required: free separately
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: File streaming upload
 *
 * This example shows how to upload a large file using file streaming
 * to avoid loading the entire file into memory.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 *
 * int main() {
 *     fetch_global_init(NULL);
 *
 * #ifdef _WIN32
 *     // Windows file handling
 *     HANDLE file = CreateFile(L"large_file.bin", GENERIC_READ,
 * FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); if (file
 * == INVALID_HANDLE_VALUE) { fprintf(stderr, "Failed to open file\n"); return
 * 1;
 *     }
 *
 *     // Get file size
 *     LARGE_INTEGER file_size;
 *     if (!GetFileSizeEx(file, &file_size)) {
 *         fprintf(stderr, "Failed to get file size\n");
 *         CloseHandle(file);
 *         return 1;
 *     }
 *
 *     // Create file body for streaming (automatic cleanup)
 *     fetch_body_t *body = fetch_body_file(file, file_size.QuadPart,
 * "application/octet-stream", true, NULL, NULL); #else
 *     // Unix/Linux file handling
 *     FILE *file = fopen("large_file.bin", "rb");
 *     if (!file) {
 *         fprintf(stderr, "Failed to open file\n");
 *         return 1;
 *     }
 *
 *     // Get file size
 *     fseek(file, 0, SEEK_END);
 *     size_t file_size = ftell(file);
 *     fseek(file, 0, SEEK_SET);
 *
 *     // Create file body for streaming (automatic cleanup)
 *     fetch_body_t *body = fetch_body_file(file, file_size,
 * "application/octet-stream", true, NULL, NULL); #endif
 *
 *     if (!body) {
 *         fprintf(stderr, "Failed to create file body\n");
 *         goto cleanup_file;
 *     }
 *
 *     // Create request with file body
 *     fetch_init_t *init = fetch_init_new();
 *     fetch_init_method(init, HTTP_METHOD_POST);
 *     fetch_init_body(init, body); // Ownership transferred to init
 *
 *     // Add headers
 *     fetch_headers_t *headers = fetch_headers_new();
 *     fetch_headers_set(headers, "Content-Type", "application/octet-stream");
 *     fetch_headers_set(headers, "X-Upload-Type", "file-stream");
 *     fetch_init_headers(init, headers); // Ownership transferred to init
 *
 *     printf("Starting file upload...\n");
 *
 *     // Make the request (file will be streamed asynchronously)
 *     fetch_response_t *response = fetch("https://httpbin.org/post", init);
 *
 *     if (response) {
 *         if (fetch_response_ok(response)) {
 *             printf("Upload successful! Status: %d\n",
 * fetch_response_status(response)); printf("Server response: %s\n",
 * fetch_response_text(response)); } else { printf("Upload failed: %d %s\n",
 *                    fetch_response_status(response),
 *                    fetch_response_status_text(response));
 *         }
 *         fetch_response_free(response);
 *     } else {
 *         printf("Failed to make request\n");
 *     }
 *
 *     // Cleanup
 *     fetch_init_free(init); // This frees the body and closes the file handle
 *
 * cleanup_file:
 *     // File handle is automatically closed by fetch_body_free (called by
 * fetch_init_free)
 *     // No manual cleanup needed when close_on_free is true
 *
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/**
 * @brief Example: Live streaming upload with callback
 *
 * This example shows how to upload a continuously written file (like a log)
 * using the streaming callback to control when the upload should complete.
 *
 * @code
 * #include "fetch.h"
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <unistd.h>
 *
 * typedef struct {
 *     bool should_stop;
 *     FILE *log_file;
 *     size_t max_lines;
 *     size_t lines_sent;
 * } LogStreamContext;
 *
 * // Callback to control when streaming should continue or stop
 * fetch_stream_result_t continue_log_stream(void *userdata) {
 *     LogStreamContext *ctx = (LogStreamContext*)userdata;
 *
 *     // Stop if requested or reached max lines
 *     if (ctx->should_stop || ctx->lines_sent >= ctx->max_lines) {
 *         return FETCH_STREAM_DONE;
 *     }
 *
 *     // Check if new data has been written to the file
 *     long current_pos = ftell(ctx->log_file);
 *     fseek(ctx->log_file, 0, SEEK_END);
 *     long end_pos = ftell(ctx->log_file);
 *     fseek(ctx->log_file, current_pos, SEEK_SET);
 *
 *     if (end_pos > current_pos) {
 *         return FETCH_STREAM_READ;  // More data available
 *     }
 *
 *     return FETCH_STREAM_SKIP;  // No new data yet, but keep trying
 * }
 *
 * int main() {
 *     fetch_global_init(NULL);
 *
 *     if (!fetch_event_loop_start()) {
 *         fprintf(stderr, "Failed to start event loop\n");
 *         return 1;
 *     }
 *
 *     // Open log file for streaming
 *     FILE *log_file = fopen("live.log", "rb");
 *     if (!log_file) {
 *         fprintf(stderr, "Failed to open log file\n");
 *         fetch_event_loop_stop();
 *         return 1;
 *     }
 *
 *     LogStreamContext ctx = {
 *         .should_stop = false,
 *         .log_file = log_file,
 *         .max_lines = 1000,
 *         .lines_sent = 0
 *     };
 *
 *     printf("Starting live log stream upload...\n");
 *
 *     // Create streaming body with callback (unknown size, chunked encoding)
 *     fetch_body_t *body = fetch_body_file(log_file, 0, "text/plain", false,
 *                                          continue_log_stream, &ctx);
 *
 *     fetch_init_t *init = fetch_init_new();
 *     fetch_init_method(init, HTTP_METHOD_POST);
 *     fetch_init_body(init, body);
 *
 *     // Start async upload
 *     fetch_promise_t *promise = fetch_async("https://httpbin.org/post", init);
 *     if (!promise) {
 *         fprintf(stderr, "Failed to start upload\n");
 *         goto cleanup;
 *     }
 *
 *     // Monitor upload progress while writing more data to the log
 *     int iteration = 0;
 *     while (fetch_promise_pending(promise)) {
 *         fetch_event_loop_process(100); // Process events
 *
 *         // Simulate writing to log file (in real app, this would be done
 * elsewhere) if (iteration % 10 == 0) { // Every 1 second FILE *write_file =
 * fopen("live.log", "a"); if (write_file) { fprintf(write_file, "Log entry %d
 * at %lu\n", iteration, time(NULL)); fclose(write_file); ctx.lines_sent++;
 *             }
 *         }
 *
 *         // Stop after some time or condition
 *         if (iteration > 50) { // After ~5 seconds
 *             ctx.should_stop = true;
 *         }
 *
 *         iteration++;
 *         usleep(100000); // 100ms
 *     }
 *
 *     // Check result
 *     if (fetch_promise_fulfilled(promise)) {
 *         fetch_response_t *response = fetch_promise_response(promise);
 *         printf("Live stream upload completed! Status: %d\n",
 *                fetch_response_status(response));
 *         printf("Sent %zu lines\n", ctx.lines_sent);
 *     } else {
 *         printf("Upload failed: %s\n", fetch_promise_error_message(promise));
 *     }
 *
 * cleanup:
 *     fetch_promise_free(promise);
 *     fetch_init_free(init);
 *     fclose(log_file); // Manual cleanup since close_on_free was false
 *     fetch_event_loop_stop();
 *     fetch_global_dispose();
 *     return 0;
 * }
 * @endcode
 */

/** @} */

#endif /* FETCH_H */
