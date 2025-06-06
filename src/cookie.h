/**
 * @file cookie.h
 * @brief HTTP Cookie management library for C
 *
 * This library provides comprehensive HTTP cookie handling including parsing,
 * storage, matching, and persistence. It supports all modern cookie attributes
 * including Secure, HttpOnly, SameSite, and Priority flags.
 */

#ifndef COOKIE_H
#define COOKIE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/**
 * @defgroup cookie_types Forward Declarations
 * @brief Opaque types for cookie structures
 * @{
 */

/** @brief Individual HTTP cookie */
typedef struct cookie cookie_t;

/** @brief Container for multiple cookies */
typedef struct cookie_jar cookie_jar_t;

/** @brief Iterator for traversing cookies */
typedef struct cookie_iterator cookie_iterator_t;

/** @} */

/**
 * @defgroup cookie_flags Cookie Flags
 * @brief Bitfield flags for cookie attributes
 * @{
 */

/**
 * @brief Cookie attribute flags
 *
 * These flags control cookie behavior and security attributes.
 */
typedef enum {
  COOKIE_FLAG_SECURE = 1 << 0,    /**< Cookie only sent over HTTPS */
  COOKIE_FLAG_HTTP_ONLY = 1 << 1, /**< Cookie not accessible via JavaScript */
  COOKIE_FLAG_HOST_ONLY = 1 << 2, /**< Cookie only sent to exact host */
  COOKIE_FLAG_SESSION = 1 << 3,   /**< Session cookie (no expiry) */
  COOKIE_FLAG_PERSISTENT = 1 << 4 /**< Persistent cookie (has expiry) */
} cookie_flags_t;

/** @} */

/**
 * @defgroup cookie_samesite SameSite Attribute
 * @brief Control cross-site cookie behavior
 * @{
 */

/**
 * @brief SameSite attribute values
 *
 * Controls when cookies are sent in cross-site requests.
 */
typedef enum {
  COOKIE_SAMESITE_NONE = 0, /**< Cookie sent in all requests */
  COOKIE_SAMESITE_LAX,      /**< Cookie sent in top-level navigation */
  COOKIE_SAMESITE_STRICT    /**< Cookie only sent in same-site requests */
} cookie_samesite_t;

/** @} */

/**
 * @defgroup cookie_priority Cookie Priority
 * @brief Control cookie eviction priority
 * @{
 */

/**
 * @brief Cookie priority levels
 *
 * Used to determine which cookies to evict when limits are reached.
 */
typedef enum {
  COOKIE_PRIORITY_LOW = 0, /**< Low priority, evicted first */
  COOKIE_PRIORITY_MEDIUM,  /**< Medium priority (default) */
  COOKIE_PRIORITY_HIGH     /**< High priority, evicted last */
} cookie_priority_t;

/** @} */

/**
 * @defgroup cookie_struct Cookie Structure
 * @brief Internal cookie data structure
 * @{
 */

/**
 * @brief HTTP cookie structure
 *
 * Contains all cookie data and metadata including attributes and timestamps.
 */
typedef struct cookie {
  /** @brief Cookie name */
  char *name;
  /** @brief Cookie value */
  char *value;
  /** @brief Domain attribute */
  char *domain;
  /** @brief Path attribute */
  char *path;

  /** @brief Expiration time (0 for session cookies) */
  time_t expires;
  /** @brief When cookie was created */
  time_t creation_time;
  /** @brief When cookie was last accessed */
  time_t last_access_time;

  /** @brief Cookie attribute flags */
  cookie_flags_t flags;
  /** @brief SameSite attribute */
  cookie_samesite_t samesite;
  /** @brief Priority level */
  cookie_priority_t priority;

  /** @brief Next cookie in linked list */
  struct cookie *next;
  /** @brief Previous cookie in linked list */
  struct cookie *prev;
} cookie_t;

/** @} */

/**
 * @defgroup cookie_config Cookie Jar Configuration
 * @brief Configuration options for cookie storage
 * @{
 */

/**
 * @brief Cookie jar configuration
 *
 * Controls cookie jar behavior, limits, and storage options.
 */
typedef struct {
  size_t max_cookies_total;       /**< Maximum total cookies */
  size_t max_cookies_per_domain;  /**< Maximum cookies per domain */
  size_t max_cookie_size;         /**< Maximum cookie size in bytes */
  bool accept_session_cookies;    /**< Accept session cookies */
  bool accept_persistent_cookies; /**< Accept persistent cookies */
  bool accept_third_party;        /**< Accept third-party cookies */
  time_t max_age_seconds;         /**< Maximum cookie age */
  const char *persistent_file;    /**< File for persistent storage */
} cookie_jar_config_t;

/** @} */

/**
 * @defgroup cookie_internal Internal Structures
 * @brief Internal implementation structures
 * @{
 */

/**
 * @brief Domain bucket for cookie storage
 *
 * Internal structure for organizing cookies by domain.
 */
typedef struct cookie_domain_bucket {
  char *domain;                      /**< Domain name */
  cookie_t *cookies;                 /**< Cookies for this domain */
  size_t count;                      /**< Number of cookies */
  struct cookie_domain_bucket *next; /**< Next bucket in hash table */
} cookie_domain_bucket_t;

/**
 * @brief Cookie jar implementation
 *
 * Main container for cookie storage and management.
 */
typedef struct cookie_jar {
  cookie_jar_config_t config;              /**< Configuration options */
  cookie_domain_bucket_t **domain_buckets; /**< Hash table of domain buckets */
  size_t bucket_count;                     /**< Number of hash buckets */
  size_t total_cookies;                    /**< Total cookies stored */
  bool dirty;                              /**< True if changes need saving */
  time_t last_cleanup;                     /**< Last cleanup timestamp */
} cookie_jar_t;

/** @} */

/**
 * @defgroup cookie_parsing Cookie Parsing
 * @brief Parse Set-Cookie headers
 * @{
 */

/**
 * @brief Cookie parsing result codes
 */
typedef enum {
  COOKIE_PARSE_SUCCESS = 0,           /**< Cookie parsed successfully */
  COOKIE_PARSE_ERROR_INVALID_FORMAT,  /**< Invalid Set-Cookie format */
  COOKIE_PARSE_ERROR_INVALID_NAME,    /**< Invalid cookie name */
  COOKIE_PARSE_ERROR_INVALID_VALUE,   /**< Invalid cookie value */
  COOKIE_PARSE_ERROR_INVALID_DOMAIN,  /**< Invalid domain attribute */
  COOKIE_PARSE_ERROR_INVALID_PATH,    /**< Invalid path attribute */
  COOKIE_PARSE_ERROR_INVALID_EXPIRES, /**< Invalid expires attribute */
  COOKIE_PARSE_ERROR_MEMORY           /**< Memory allocation failed */
} cookie_parse_result_t;

/** @} */

/**
 * @defgroup cookie_matching Cookie Matching
 * @brief Match cookies to requests
 * @{
 */

/**
 * @brief Cookie match result
 *
 * Linked list of cookies that match a request.
 */
typedef struct cookie_match {
  cookie_t *cookie;          /**< Matching cookie */
  struct cookie_match *next; /**< Next match in list */
} cookie_match_t;

/** @} */

/**
 * @defgroup cookie_iterator Cookie Iterator
 * @brief Iterate through cookies
 * @{
 */

/**
 * @brief Cookie iterator implementation
 *
 * Used to traverse all cookies or cookies for a specific domain.
 */
typedef struct cookie_iterator {
  cookie_jar_t *jar;                      /**< Cookie jar being iterated */
  size_t bucket_index;                    /**< Current bucket index */
  cookie_domain_bucket_t *current_bucket; /**< Current bucket */
  cookie_t *current_cookie;               /**< Current cookie */
  const char *domain_filter;              /**< Domain filter (NULL for all) */
  bool include_http_only;                 /**< Include HttpOnly cookies */
} cookie_iterator_t;

/** @} */

/**
 * @defgroup cookie_jar_api Cookie Jar Management
 * @brief Create and manage cookie jars
 * @{
 */

/**
 * @brief Create a new cookie jar with default configuration
 * @return New cookie jar, or NULL on failure
 *
 * @code
 * cookie_jar_t *jar = cookie_jar_new();
 * if (jar) {
 *     // Use cookie jar...
 *     cookie_jar_free(jar);
 * }
 * @endcode
 */
cookie_jar_t *cookie_jar_new(void);

/**
 * @brief Create a new cookie jar with custom configuration
 * @param config Configuration options
 * @return New cookie jar, or NULL on failure
 *
 * @code
 * cookie_jar_config_t config = cookie_jar_default_config();
 * config.max_cookies_total = 1000;
 * config.persistent_file = "cookies.dat";
 *
 * cookie_jar_t *jar = cookie_jar_new_with_config(&config);
 * @endcode
 */
cookie_jar_t *cookie_jar_new_with_config(const cookie_jar_config_t *config);

/**
 * @brief Free a cookie jar and all its cookies
 * @param jar Cookie jar to free (can be NULL)
 */
void cookie_jar_free(cookie_jar_t *jar);

/**
 * @brief Get default cookie jar configuration
 * @return Default configuration structure
 *
 * @code
 * cookie_jar_config_t config = cookie_jar_default_config();
 * config.max_cookies_total = 500; // Customize as needed
 * @endcode
 */
cookie_jar_config_t cookie_jar_default_config(void);

/**
 * @brief Clear all cookies from a jar
 * @param jar Cookie jar to clear
 */
void cookie_jar_clear(cookie_jar_t *jar);

/**
 * @brief Get total number of cookies in jar
 * @param jar Cookie jar
 * @return Number of cookies, or 0 if jar is NULL
 */
size_t cookie_jar_count(const cookie_jar_t *jar);

/**
 * @brief Get number of cookies for a specific domain
 * @param jar Cookie jar
 * @param domain Domain name
 * @return Number of cookies for domain, or 0 if not found
 *
 * @code
 * size_t google_cookies = cookie_jar_count_for_domain(jar, "google.com");
 * printf("Google has %zu cookies\n", google_cookies);
 * @endcode
 */
size_t cookie_jar_count_for_domain(const cookie_jar_t *jar, const char *domain);

/** @} */

/**
 * @defgroup cookie_creation Cookie Creation
 * @brief Create and manipulate individual cookies
 * @{
 */

/**
 * @brief Create a new cookie
 * @param name Cookie name (required)
 * @param value Cookie value (required)
 * @param domain Domain attribute (optional, can be NULL)
 * @param path Path attribute (optional, defaults to "/")
 * @return New cookie, or NULL on failure
 *
 * @code
 * cookie_t *cookie = cookie_new("session_id", "abc123", "example.com", "/");
 * if (cookie) {
 *     cookie_set_secure(cookie, true);
 *     cookie_set_http_only(cookie, true);
 *     // Use cookie...
 *     cookie_free(cookie);
 * }
 * @endcode
 */
cookie_t *cookie_new(const char *name, const char *value, const char *domain,
                     const char *path);

/**
 * @brief Parse a Set-Cookie header
 * @param header_value Set-Cookie header value
 * @param request_url URL of the request (for domain/path defaults)
 * @param cookie Output pointer for parsed cookie
 * @return Parse result code
 *
 * @code
 * cookie_t *cookie = NULL;
 * cookie_parse_result_t result = cookie_parse_set_cookie(
 *     "sessionid=abc123; Domain=example.com; Path=/; Secure; HttpOnly",
 *     "https://example.com/login",
 *     &cookie
 * );
 *
 * if (result == COOKIE_PARSE_SUCCESS) {
 *     // Use parsed cookie...
 *     cookie_free(cookie);
 * } else {
 *     printf("Parse error: %s\n", cookie_parse_error_string(result));
 * }
 * @endcode
 */
cookie_parse_result_t cookie_parse_set_cookie(const char *header_value,
                                              const char *request_url,
                                              cookie_t **cookie);

/**
 * @brief Parse multiple Set-Cookie headers
 * @param header_values Array of Set-Cookie header values
 * @param count Number of headers
 * @param request_url URL of the request
 * @param cookies Output array of parsed cookies
 * @param cookie_count Output number of successfully parsed cookies
 * @return Parse result code
 */
cookie_parse_result_t
cookie_parse_set_cookie_headers(const char **header_values, size_t count,
                                const char *request_url, cookie_t ***cookies,
                                size_t *cookie_count);

/**
 * @brief Clone a cookie
 * @param cookie Cookie to clone
 * @return New cookie copy, or NULL on failure
 */
cookie_t *cookie_clone(const cookie_t *cookie);

/**
 * @brief Free a cookie
 * @param cookie Cookie to free (can be NULL)
 */
void cookie_free(cookie_t *cookie);

/** @} */

/**
 * @defgroup cookie_attributes Cookie Attributes
 * @brief Set and get cookie attributes
 * @{
 */

/**
 * @brief Set cookie expiration time
 * @param cookie Cookie to modify
 * @param expires Expiration timestamp (0 for session cookie)
 *
 * @code
 * time_t one_hour = time(NULL) + 3600;
 * cookie_set_expires(cookie, one_hour);
 * @endcode
 */
void cookie_set_expires(cookie_t *cookie, time_t expires);

/**
 * @brief Set cookie max-age
 * @param cookie Cookie to modify
 * @param max_age_seconds Max age in seconds (negative to delete immediately)
 *
 * @code
 * // Set cookie to expire in 1 hour
 * cookie_set_max_age(cookie, 3600);
 *
 * // Delete cookie immediately
 * cookie_set_max_age(cookie, -1);
 * @endcode
 */
void cookie_set_max_age(cookie_t *cookie, int64_t max_age_seconds);

/**
 * @brief Set Secure flag
 * @param cookie Cookie to modify
 * @param secure True to require HTTPS
 */
void cookie_set_secure(cookie_t *cookie, bool secure);

/**
 * @brief Set HttpOnly flag
 * @param cookie Cookie to modify
 * @param http_only True to prevent JavaScript access
 */
void cookie_set_http_only(cookie_t *cookie, bool http_only);

/**
 * @brief Set SameSite attribute
 * @param cookie Cookie to modify
 * @param samesite SameSite value
 *
 * @code
 * cookie_set_samesite(cookie, COOKIE_SAMESITE_STRICT);
 * @endcode
 */
void cookie_set_samesite(cookie_t *cookie, cookie_samesite_t samesite);

/**
 * @brief Set Priority attribute
 * @param cookie Cookie to modify
 * @param priority Priority level
 */
void cookie_set_priority(cookie_t *cookie, cookie_priority_t priority);

/** @} */

/**
 * @defgroup cookie_inspection Cookie Inspection
 * @brief Check cookie properties and states
 * @{
 */

/**
 * @brief Check if cookie has Secure flag
 * @param cookie Cookie to check
 * @return True if cookie is secure
 */
bool cookie_is_secure(const cookie_t *cookie);

/**
 * @brief Check if cookie has HttpOnly flag
 * @param cookie Cookie to check
 * @return True if cookie is HTTP-only
 */
bool cookie_is_http_only(const cookie_t *cookie);

/**
 * @brief Check if cookie is a session cookie
 * @param cookie Cookie to check
 * @return True if cookie has no expiry time
 */
bool cookie_is_session(const cookie_t *cookie);

/**
 * @brief Check if cookie is expired
 * @param cookie Cookie to check
 * @param current_time Current timestamp for comparison
 * @return True if cookie is expired
 *
 * @code
 * if (cookie_is_expired(cookie, time(NULL))) {
 *     printf("Cookie has expired\n");
 * }
 * @endcode
 */
bool cookie_is_expired(const cookie_t *cookie, time_t current_time);

/**
 * @brief Check if cookie is host-only
 * @param cookie Cookie to check
 * @return True if cookie is restricted to exact host
 */
bool cookie_is_host_only(const cookie_t *cookie);

/**
 * @brief Get cookie's SameSite attribute
 * @param cookie Cookie to check
 * @return SameSite value
 */
cookie_samesite_t cookie_get_samesite(const cookie_t *cookie);

/**
 * @brief Get cookie's priority
 * @param cookie Cookie to check
 * @return Priority level
 */
cookie_priority_t cookie_get_priority(const cookie_t *cookie);

/**
 * @brief Update cookie's last access time
 * @param cookie Cookie to touch
 *
 * Call this when a cookie is used to track access patterns.
 */
void cookie_touch(cookie_t *cookie);

/** @} */

/**
 * @defgroup cookie_storage Cookie Storage
 * @brief Add, remove, and manage cookies in jars
 * @{
 */

/**
 * @brief Add a cookie to a jar
 * @param jar Cookie jar
 * @param cookie Cookie to add (ownership transferred to jar)
 * @return True if cookie was added successfully
 *
 * @code
 * cookie_t *cookie = cookie_new("test", "value", "example.com", "/");
 * if (cookie_jar_add(jar, cookie)) {
 *     printf("Cookie added successfully\n");
 * } else {
 *     // Cookie not added, we still own it
 *     cookie_free(cookie);
 * }
 * @endcode
 */
bool cookie_jar_add(cookie_jar_t *jar, cookie_t *cookie);

/**
 * @brief Remove a specific cookie from jar
 * @param jar Cookie jar
 * @param name Cookie name
 * @param domain Cookie domain
 * @param path Cookie path
 * @return True if cookie was found and removed
 */
bool cookie_jar_remove(cookie_jar_t *jar, const char *name, const char *domain,
                       const char *path);

/**
 * @brief Remove all cookies for a domain
 * @param jar Cookie jar
 * @param domain Domain name
 * @return Number of cookies removed
 *
 * @code
 * size_t removed = cookie_jar_remove_domain(jar, "old-site.com");
 * printf("Removed %zu cookies for old-site.com\n", removed);
 * @endcode
 */
size_t cookie_jar_remove_domain(cookie_jar_t *jar, const char *domain);

/**
 * @brief Remove expired cookies from jar
 * @param jar Cookie jar
 * @return Number of cookies removed
 *
 * Call this periodically to clean up expired cookies.
 */
size_t cookie_jar_cleanup_expired(cookie_jar_t *jar);

/**
 * @brief Remove all session cookies from jar
 * @param jar Cookie jar
 * @return Number of cookies removed
 *
 * Useful when user logs out or closes browser.
 */
size_t cookie_jar_remove_session(cookie_jar_t *jar);

/** @} */

/**
 * @defgroup cookie_retrieval Cookie Retrieval
 * @brief Find cookies matching requests
 * @{
 */

/**
 * @brief Get cookies that match a URL
 * @param jar Cookie jar
 * @param url Request URL
 * @param include_http_only Include HttpOnly cookies
 * @return Linked list of matching cookies (caller must free with
 * cookie_match_free)
 *
 * @code
 * cookie_match_t *matches = cookie_jar_get_cookies_for_url(jar,
 *     "https://example.com/api", true);
 *
 * char *header = cookie_match_to_header(matches);
 * if (header) {
 *     printf("Cookie: %s\n", header);
 *     free(header);
 * }
 * cookie_match_free(matches);
 * @endcode
 */
cookie_match_t *cookie_jar_get_cookies_for_url(cookie_jar_t *jar,
                                               const char *url,
                                               bool include_http_only);

/**
 * @brief Get cookies matching domain and path
 * @param jar Cookie jar
 * @param domain Request domain
 * @param path Request path
 * @param secure_only Only include cookies that work over HTTPS
 * @param include_http_only Include HttpOnly cookies
 * @return Linked list of matching cookies
 */
cookie_match_t *cookie_jar_get_cookies(cookie_jar_t *jar, const char *domain,
                                       const char *path, bool secure_only,
                                       bool include_http_only);

/**
 * @brief Free a list of cookie matches
 * @param matches Cookie match list to free
 */
void cookie_match_free(cookie_match_t *matches);

/**
 * @brief Convert cookie matches to HTTP Cookie header
 * @param matches Cookie match list
 * @return Cookie header string (caller must free), or NULL if no matches
 *
 * @code
 * cookie_match_t *matches = cookie_jar_get_cookies_for_url(jar, url, false);
 * char *cookie_header = cookie_match_to_header(matches);
 * if (cookie_header) {
 *     // Add to HTTP request: "Cookie: sessionid=abc123; csrf=xyz789"
 *     free(cookie_header);
 * }
 * cookie_match_free(matches);
 * @endcode
 */
char *cookie_match_to_header(const cookie_match_t *matches);

/** @} */

/**
 * @defgroup cookie_iteration Cookie Iteration
 * @brief Iterate through stored cookies
 * @{
 */

/**
 * @brief Create iterator for all cookies in jar
 * @param jar Cookie jar
 * @return Iterator object
 *
 * @code
 * cookie_iterator_t iter = cookie_jar_iterator(jar);
 * cookie_t *cookie;
 * while ((cookie = cookie_iterator_next(&iter)) != NULL) {
 *     printf("Cookie: %s=%s\n", cookie->name, cookie->value);
 * }
 * @endcode
 */
cookie_iterator_t cookie_jar_iterator(cookie_jar_t *jar);

/**
 * @brief Create iterator for cookies in specific domain
 * @param jar Cookie jar
 * @param domain Domain to filter by
 * @return Iterator object
 */
cookie_iterator_t cookie_jar_iterator_domain(cookie_jar_t *jar,
                                             const char *domain);

/**
 * @brief Get next cookie from iterator
 * @param iter Iterator object
 * @return Next cookie, or NULL if iteration complete
 */
cookie_t *cookie_iterator_next(cookie_iterator_t *iter);

/**
 * @brief Check if iterator has more cookies
 * @param iter Iterator object
 * @return True if more cookies available
 */
bool cookie_iterator_has_next(const cookie_iterator_t *iter);

/**
 * @brief Reset iterator to beginning
 * @param iter Iterator object
 */
void cookie_iterator_reset(cookie_iterator_t *iter);

/** @} */

/**
 * @defgroup cookie_persistence Cookie Persistence
 * @brief Save and load cookies to/from files
 * @{
 */

/**
 * @brief Load cookies from binary file
 * @param jar Cookie jar to load into
 * @param filename File path
 * @return True if successful
 *
 * @code
 * cookie_jar_t *jar = cookie_jar_new();
 * if (cookie_jar_load_binary(jar, "cookies.dat")) {
 *     printf("Loaded cookies successfully\n");
 * }
 * @endcode
 */
bool cookie_jar_load_binary(cookie_jar_t *jar, const char *filename);

/**
 * @brief Save cookies to binary file
 * @param jar Cookie jar to save
 * @param filename File path
 * @return True if successful
 */
bool cookie_jar_save_binary(const cookie_jar_t *jar, const char *filename);

/**
 * @brief Save cookies to memory buffer
 * @param jar Cookie jar to save
 * @param buffer_size Output size of buffer
 * @return Buffer containing serialized cookies (caller must free), or NULL on
 * error
 */
char *cookie_jar_save_binary_buffer(const cookie_jar_t *jar,
                                    size_t *buffer_size);

/**
 * @brief Load cookies from memory buffer
 * @param jar Cookie jar to load into
 * @param buffer Buffer containing serialized cookies
 * @param buffer_size Size of buffer
 * @return True if successful
 */
bool cookie_jar_load_binary_buffer(cookie_jar_t *jar, const char *buffer,
                                   size_t buffer_size);

/** @} */

/**
 * @defgroup cookie_matching_utils Cookie Matching Utilities
 * @brief Low-level domain and path matching functions
 * @{
 */

/**
 * @brief Check if cookie domain matches request domain
 * @param cookie_domain Cookie's domain attribute
 * @param request_domain Request's domain
 * @return True if domain matches
 *
 * @code
 * // These all return true:
 * cookie_domain_matches("example.com", "example.com");      // exact match
 * cookie_domain_matches(".example.com", "sub.example.com"); // subdomain match
 * cookie_domain_matches(".example.com", "example.com");     // parent match
 * @endcode
 */
bool cookie_domain_matches(const char *cookie_domain,
                           const char *request_domain);

/**
 * @brief Check if cookie path matches request path
 * @param cookie_path Cookie's path attribute
 * @param request_path Request's path
 * @return True if path matches
 *
 * @code
 * // These return true:
 * cookie_path_matches("/", "/anything");          // root matches all
 * cookie_path_matches("/api", "/api/users");      // prefix match
 * cookie_path_matches("/api/", "/api/users");     // prefix with slash
 *
 * // This returns false:
 * cookie_path_matches("/api", "/application");    // not a prefix
 * @endcode
 */
bool cookie_path_matches(const char *cookie_path, const char *request_path);

/**
 * @brief Convert domain to canonical lowercase form
 * @param domain Domain name
 * @return Canonicalized domain (caller must free), or NULL on error
 */
char *cookie_canonicalize_domain(const char *domain);

/**
 * @brief Extract default path from URL
 * @param url Request URL
 * @return Default path for cookies (caller must free)
 *
 * @code
 * char *path = cookie_default_path("https://example.com/api/users/123");
 * // Returns "/api/users" (removes filename and trailing slash)
 * free(path);
 * @endcode
 */
char *cookie_default_path(const char *url);

/**
 * @brief Check if domain is a public suffix
 * @param domain Domain name
 * @return True if domain is a public suffix (like .com, .co.uk)
 *
 * Prevents cookies from being set on top-level domains.
 */
bool cookie_is_public_suffix(const char *domain);

/** @} */

/**
 * @defgroup cookie_validation Cookie Validation
 * @brief Validate cookie names and values
 * @{
 */

/**
 * @brief Check if cookie name is valid
 * @param name Cookie name to validate
 * @return True if name is valid
 *
 * Cookie names cannot contain control characters or certain special characters.
 */
bool cookie_is_valid_name(const char *name);

/**
 * @brief Check if cookie value is valid
 * @param value Cookie value to validate
 * @return True if value is valid
 *
 * Cookie values cannot contain control characters, quotes, or semicolons.
 */
bool cookie_is_valid_value(const char *value);

/** @} */

/**
 * @defgroup cookie_encoding Cookie Encoding
 * @brief URL encoding/decoding for cookie values
 * @{
 */

/**
 * @brief URL-decode a string
 * @param encoded URL-encoded string
 * @return Decoded string (caller must free), or NULL on error
 */
char *cookie_url_decode(const char *encoded);

/**
 * @brief URL-encode a string
 * @param decoded Plain string
 * @return URL-encoded string (caller must free), or NULL on error
 */
char *cookie_url_encode(const char *decoded);

/** @} */

/**
 * @defgroup cookie_string_utils String Conversion Utilities
 * @brief Convert enums to/from strings
 * @{
 */

/**
 * @brief Convert SameSite enum to string
 * @param samesite SameSite value
 * @return String representation ("Strict", "Lax", "None")
 */
const char *cookie_samesite_to_string(cookie_samesite_t samesite);

/**
 * @brief Convert string to SameSite enum
 * @param str String representation (case-insensitive)
 * @return SameSite value (defaults to Lax for invalid input)
 */
cookie_samesite_t cookie_samesite_from_string(const char *str);

/**
 * @brief Convert Priority enum to string
 * @param priority Priority value
 * @return String representation ("Low", "Medium", "High")
 */
const char *cookie_priority_to_string(cookie_priority_t priority);

/**
 * @brief Convert string to Priority enum
 * @param str String representation (case-insensitive)
 * @return Priority value (defaults to Medium for invalid input)
 */
cookie_priority_t cookie_priority_from_string(const char *str);

/**
 * @brief Get error message for parse result
 * @param result Parse result code
 * @return Human-readable error message
 *
 * @code
 * cookie_parse_result_t result = cookie_parse_set_cookie(header, url, &cookie);
 * if (result != COOKIE_PARSE_SUCCESS) {
 *     fprintf(stderr, "Cookie parse error: %s\n",
 *             cookie_parse_error_string(result));
 * }
 * @endcode
 */
const char *cookie_parse_error_string(cookie_parse_result_t result);

/** @} */

/**
 * @defgroup cookie_constants Constants and Limits
 * @brief Size limits and default values
 * @{
 */

/** @brief Maximum cookie name length */
#define COOKIE_MAX_NAME_LENGTH 256

/** @brief Maximum cookie value length */
#define COOKIE_MAX_VALUE_LENGTH 4096

/** @brief Maximum domain length */
#define COOKIE_MAX_DOMAIN_LENGTH 253

/** @brief Maximum path length */
#define COOKIE_MAX_PATH_LENGTH 1024

/** @brief Default maximum total cookies */
#define COOKIE_DEFAULT_MAX_COOKIES 3000

/** @brief Default maximum cookies per domain */
#define COOKIE_DEFAULT_MAX_PER_DOMAIN 50

/** @brief Default maximum cookie age (1 year) */
#define COOKIE_DEFAULT_MAX_AGE_SECONDS (365 * 24 * 60 * 60)

/** @} */

/**
 * @defgroup cookie_macros Convenience Macros
 * @brief Shortcuts for common cookie operations
 * @{
 */

/**
 * @brief Check if cookie is valid for HTTP requests
 * @param cookie Cookie to check
 * @return True if cookie is valid and not expired
 */
#define COOKIE_IS_VALID_FOR_HTTP(cookie)                                       \
  ((cookie) != NULL && !cookie_is_expired((cookie), time(NULL)))

/**
 * @brief Check if cookie is valid for HTTPS requests
 * @param cookie Cookie to check
 * @return True if cookie is valid for HTTPS
 *
 * Note: Secure cookies can only be sent over HTTPS, but non-secure
 * cookies can be sent over both HTTP and HTTPS.
 */
#define COOKIE_IS_VALID_FOR_HTTPS(cookie)                                      \
  (COOKIE_IS_VALID_FOR_HTTP(cookie) && (!cookie_is_secure(cookie) || true))

/** @} */

#endif /* COOKIE_H */
