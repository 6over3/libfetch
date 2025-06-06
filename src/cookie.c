#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cookie.h"
#include "ada_c.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma region Platform-Specific Includes and Compatibility

#if defined(_WIN32) || defined(_WIN64)
#include "win32/str_win32.h"
#include "win32/strptime.h"
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define timegm _mkgmtime
#define strtok_r strtok_s
#else
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#pragma endregion

#pragma region Constants and Configuration

#define COOKIE_HASH_TABLE_SIZE 256
#define COOKIE_NETSCAPE_HEADER                                                 \
  "# Netscape HTTP Cookie File\n# This is a generated file! Do not edit.\n\n"
#define COOKIE_MAX_LINE_LENGTH 8192
#define COOKIE_CLEANUP_INTERVAL 3600

/** @brief Standard date formats for cookie expiration parsing */
#define RFC1123_DATE_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define RFC850_DATE_FORMAT "%A, %d-%b-%y %H:%M:%S GMT"
#define ASCTIME_DATE_FORMAT "%a %b %d %H:%M:%S %Y"

/** @brief Binary file format constants */
#define COOKIE_BINARY_MAGIC 0x52414A43 // "CJAR" in little-endian
#define COOKIE_BINARY_VERSION 1

#pragma endregion

#pragma region Binary Serialization Structures

/**
 * @brief Binary format header for individual cookies
 *
 * Used for efficient serialization of cookie data to disk.
 */
typedef struct {
  uint16_t name_length;      /**< Length of cookie name */
  uint16_t value_length;     /**< Length of cookie value */
  uint16_t domain_length;    /**< Length of domain string */
  uint16_t path_length;      /**< Length of path string */
  uint32_t flags;            /**< Cookie flags (secure, httponly, etc.) */
  uint8_t samesite;          /**< SameSite attribute */
  uint8_t priority;          /**< Cookie priority */
  uint16_t reserved;         /**< Reserved for future use */
  uint64_t creation_time;    /**< Creation timestamp */
  uint64_t last_access_time; /**< Last access timestamp */
  uint64_t expires_time;     /**< Expiration timestamp */
} cookie_binary_header_t;

/**
 * @brief Binary format header for cookie jar files
 *
 * Contains metadata about the cookie jar and validation information.
 */
typedef struct {
  uint32_t magic;                  /**< Magic number for format validation */
  uint16_t version;                /**< File format version */
  uint16_t flags;                  /**< Jar flags (reserved) */
  uint32_t cookie_count;           /**< Number of cookies in file */
  uint64_t creation_timestamp;     /**< Jar creation time */
  uint64_t last_cleanup_timestamp; /**< Last cleanup time */
  uint64_t reserved;               /**< Reserved for future use */
} cookie_jar_binary_header_t;

#pragma endregion

#pragma region Platform-Specific Utility Functions

#if defined(_WIN32) || defined(_WIN64)
/**
 * @brief Windows-compatible dirname implementation
 *
 * @param path Path string to extract directory from
 * @return Directory portion of path, or "." if no directory
 */
static char *dirname(char *path) {
  if (!path || *path == '\0')
    return ".";

  char *last_slash = strrchr(path, '/');
  char *last_backslash = strrchr(path, '\\');
  char *last_separator =
      (last_slash > last_backslash) ? last_slash : last_backslash;

  if (!last_separator)
    return ".";
  if (last_separator == path)
    return "/";

  *last_separator = '\0';
  return path;
}
#endif

#pragma endregion

#pragma region General Utility Functions

/**
 * @brief Remove leading and trailing whitespace from a string
 *
 * Modifies the string in place by moving content and null-terminating.
 *
 * @param str String to trim (modified in place)
 * @return Pointer to the trimmed string (same as input)
 */
static char *trim_whitespace(char *str) {
  if (!str)
    return NULL;

  // Skip leading whitespace
  char *start = str;
  while (isspace((unsigned char)*start))
    start++;

  if (*start == '\0') {
    *str = '\0';
    return str;
  }

  // Trim trailing whitespace
  char *end = start + strlen(start) - 1;
  while (end > start && isspace((unsigned char)*end))
    end--;
  *(end + 1) = '\0';

  // Move content to beginning if needed
  if (start != str) {
    memmove(str, start, strlen(start) + 1);
  }

  return str;
}

/**
 * @brief Calculate FNV-1a hash for domain strings
 *
 * Uses the FNV-1a hash algorithm for consistent domain hashing.
 * Converts to lowercase for case-insensitive domain matching.
 *
 * @param domain Domain string to hash
 * @return 32-bit hash value
 */
static uint32_t hash_domain(const char *domain) {
  if (!domain)
    return 0;

  const uint32_t FNV_PRIME = 0x01000193;
  const uint32_t FNV_OFFSET_BASIS = 0x811c9dc5;

  uint32_t hash = FNV_OFFSET_BASIS;
  for (const char *p = domain; *p; p++) {
    hash ^= (uint32_t)tolower((unsigned char)*p);
    hash *= FNV_PRIME;
  }

  return hash;
}

/**
 * @brief Parse cookie expiration date from various formats
 *
 * Supports RFC 1123, RFC 850, and asctime date formats as specified
 * in RFC 6265. Handles Y2K issues in RFC 850 format.
 *
 * @param date_str Date string to parse
 * @return Unix timestamp, or 0 if parsing failed
 */
static time_t parse_cookie_date(const char *date_str) {
  if (!date_str)
    return 0;

  struct tm tm_time = {0};

  // Try RFC 1123 format first
  if (strptime(date_str, RFC1123_DATE_FORMAT, &tm_time)) {
    return timegm(&tm_time);
  }

  // Try RFC 850 format with Y2K handling
  memset(&tm_time, 0, sizeof(tm_time));
  if (strptime(date_str, RFC850_DATE_FORMAT, &tm_time)) {
    // Handle Y2K issue: years 00-69 are 2000-2069, 70-99 are 1970-1999
    if (tm_time.tm_year < 70) {
      tm_time.tm_year += 100;
    }
    return timegm(&tm_time);
  }

  // Try asctime format
  memset(&tm_time, 0, sizeof(tm_time));
  if (strptime(date_str, ASCTIME_DATE_FORMAT, &tm_time)) {
    return timegm(&tm_time);
  }

  return 0;
}

#pragma endregion

#pragma region Domain Bucket Management

/**
 * @brief Find domain bucket in hash table
 *
 * @param jar Cookie jar to search
 * @param domain Domain to find bucket for
 * @return Pointer to domain bucket, or NULL if not found
 */
static cookie_domain_bucket_t *find_domain_bucket(const cookie_jar_t *jar,
                                                  const char *domain) {
  if (!jar || !domain)
    return NULL;

  const uint32_t hash = hash_domain(domain);
  const size_t bucket_index = hash % jar->bucket_count;

  cookie_domain_bucket_t *bucket = jar->domain_buckets[bucket_index];
  while (bucket) {
    if (strcasecmp(bucket->domain, domain) == 0) {
      return bucket;
    }
    bucket = bucket->next;
  }

  return NULL;
}

/**
 * @brief Create new domain bucket and add to hash table
 *
 * @param jar Cookie jar to add bucket to
 * @param domain Domain for the new bucket
 * @return Pointer to new bucket, or NULL on memory error
 */
static cookie_domain_bucket_t *create_domain_bucket(cookie_jar_t *jar,
                                                    const char *domain) {
  if (!jar || !domain)
    return NULL;

  cookie_domain_bucket_t *bucket = calloc(1, sizeof(*bucket));
  if (!bucket)
    return NULL;

  bucket->domain = strdup(domain);
  if (!bucket->domain) {
    free(bucket);
    return NULL;
  }

  // Add to hash table
  const uint32_t hash = hash_domain(domain);
  const size_t bucket_index = hash % jar->bucket_count;

  bucket->next = jar->domain_buckets[bucket_index];
  jar->domain_buckets[bucket_index] = bucket;

  return bucket;
}

/**
 * @brief Remove cookie from its domain bucket
 *
 * @param bucket Domain bucket containing the cookie
 * @param cookie Cookie to remove
 * @return true if cookie was found and removed
 */
static bool remove_cookie_from_bucket(cookie_domain_bucket_t *bucket,
                                      cookie_t *cookie) {
  if (!bucket || !cookie)
    return false;

  // Update linked list pointers
  if (cookie->prev) {
    cookie->prev->next = cookie->next;
  } else {
    bucket->cookies = cookie->next;
  }

  if (cookie->next) {
    cookie->next->prev = cookie->prev;
  }

  bucket->count--;
  return true;
}

/**
 * @brief Add cookie to domain bucket
 *
 * @param bucket Domain bucket to add cookie to
 * @param cookie Cookie to add
 * @return true on success
 */
static bool add_cookie_to_bucket(cookie_domain_bucket_t *bucket,
                                 cookie_t *cookie) {
  if (!bucket || !cookie)
    return false;

  // Add to front of list
  cookie->next = bucket->cookies;
  cookie->prev = NULL;

  if (bucket->cookies) {
    bucket->cookies->prev = cookie;
  }
  bucket->cookies = cookie;
  bucket->count++;

  return true;
}

#pragma endregion

#pragma region Cookie Validation

/**
 * @brief Validate cookie domain against request host
 *
 * Implements domain validation rules from RFC 6265, including:
 * - ASCII-only domains
 * - No percent-encoding
 * - Proper subdomain matching for dot-prefixed domains
 *
 * @param cookie_domain Domain attribute from cookie
 * @param request_host Host from request URL
 * @return true if domain is valid for the request host
 */
static bool validate_cookie_domain(const char *cookie_domain,
                                   const char *request_host) {
  if (!cookie_domain || !request_host)
    return false;

  // Check for ASCII-only characters
  for (const char *p = cookie_domain; *p; p++) {
    if (!isascii((unsigned char)*p))
      return false;
  }

  // No percent-encoding allowed
  if (strchr(cookie_domain, '%'))
    return false;

  // Empty domain is valid (defaults to host-only)
  if (*cookie_domain == '\0')
    return true;

  char *lower_domain = cookie_canonicalize_domain(cookie_domain);
  char *lower_host = cookie_canonicalize_domain(request_host);

  if (!lower_domain || !lower_host) {
    free(lower_domain);
    free(lower_host);
    return false;
  }

  bool result = false;

  if (cookie_domain[0] == '.') {
    // Domain cookie: check if request host matches domain suffix
    const char *domain_suffix = lower_domain + 1;
    size_t host_len = strlen(lower_host);
    size_t suffix_len = strlen(domain_suffix);

    if (host_len >= suffix_len) {
      const char *host_suffix = lower_host + (host_len - suffix_len);
      if (strcmp(host_suffix, domain_suffix) == 0) {
        // Ensure it's a proper subdomain or exact match
        if (host_len == suffix_len ||
            lower_host[host_len - suffix_len - 1] == '.') {
          result = true;
        }
      }
    }
  } else {
    // Host-only cookie: exact match required
    result = (strcmp(lower_domain, lower_host) == 0);
  }

  free(lower_domain);
  free(lower_host);
  return result;
}

/**
 * @brief Validate cookie name prefix security attributes
 *
 * Implements __Secure- and __Host- prefix validation from RFC 6265bis.
 *
 * @param name Cookie name to validate
 * @param cookie Cookie with security attributes
 * @param is_secure_request Whether the request was made over HTTPS
 * @return true if prefix requirements are met
 */
static bool validate_cookie_prefix(const char *name, const cookie_t *cookie,
                                   bool is_secure_request) {
  if (!name || !cookie)
    return true;

  if (strncasecmp(name, "__Secure-", 9) == 0) {
    // __Secure- prefix requires Secure attribute and HTTPS
    return cookie_is_secure(cookie) && is_secure_request;
  }

  if (strncasecmp(name, "__Host-", 7) == 0) {
    // __Host- prefix requires Secure, HTTPS, no Domain, and Path="/"
    return cookie_is_secure(cookie) && is_secure_request &&
           (cookie->domain == NULL) && (strcmp(cookie->path, "/") == 0);
  }

  return true;
}

#pragma endregion

#pragma region Binary Serialization Helpers

/**
 * @brief Calculate total size needed for binary serialization
 *
 * @param jar Cookie jar to serialize
 * @param cookie_count Output parameter for number of cookies to save
 * @return Total buffer size needed
 */
static size_t calculate_binary_size(const cookie_jar_t *jar,
                                    uint32_t *cookie_count) {
  size_t total_size = sizeof(cookie_jar_binary_header_t);
  *cookie_count = 0;

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        bool should_save = false;
        if (cookie_is_session(cookie)) {
          should_save = jar->config.accept_session_cookies;
        } else if (!cookie_is_expired(cookie, time(NULL))) {
          should_save = jar->config.accept_persistent_cookies;
        }

        if (should_save) {
          (*cookie_count)++;
          total_size += sizeof(cookie_binary_header_t);
          total_size += cookie->name ? strlen(cookie->name) : 0;
          total_size += cookie->value ? strlen(cookie->value) : 0;
          total_size += cookie->domain ? strlen(cookie->domain) : 0;
          total_size += cookie->path ? strlen(cookie->path) : 0;
        }
        cookie = cookie->next;
      }
      bucket = bucket->next;
    }
  }
  return total_size;
}

/**
 * @brief Serialize cookie jar to binary buffer
 *
 * @param jar Cookie jar to serialize
 * @param buffer Pre-allocated buffer to write to
 * @param buffer_size Size of the buffer
 * @return true on successful serialization
 */
static bool serialize_to_buffer(const cookie_jar_t *jar, char *buffer,
                                size_t buffer_size) {
  uint32_t saved_cookies;
  size_t expected_size = calculate_binary_size(jar, &saved_cookies);

  if (buffer_size < expected_size)
    return false;

  char *write_ptr = buffer;

  // Write jar header
  cookie_jar_binary_header_t header = {
      .magic = COOKIE_BINARY_MAGIC,
      .version = COOKIE_BINARY_VERSION,
      .flags = 0,
      .cookie_count = saved_cookies,
      .creation_timestamp = (uint64_t)time(NULL),
      .last_cleanup_timestamp = (uint64_t)jar->last_cleanup,
      .reserved = 0};

  memcpy(write_ptr, &header, sizeof(header));
  write_ptr += sizeof(header);

  // Write each cookie
  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        bool should_save = false;
        if (cookie_is_session(cookie)) {
          should_save = jar->config.accept_session_cookies;
        } else if (!cookie_is_expired(cookie, time(NULL))) {
          should_save = jar->config.accept_persistent_cookies;
        }

        if (should_save) {
          const char *name = cookie->name ? cookie->name : "";
          const char *value = cookie->value ? cookie->value : "";
          const char *domain = cookie->domain ? cookie->domain : "";
          const char *path = cookie->path ? cookie->path : "";

          uint16_t name_len = (uint16_t)strlen(name);
          uint16_t value_len = (uint16_t)strlen(value);
          uint16_t domain_len = (uint16_t)strlen(domain);
          uint16_t path_len = (uint16_t)strlen(path);

          cookie_binary_header_t cookie_header = {
              .name_length = name_len,
              .value_length = value_len,
              .domain_length = domain_len,
              .path_length = path_len,
              .flags = cookie->flags,
              .samesite = (uint8_t)cookie->samesite,
              .priority = (uint8_t)cookie->priority,
              .reserved = 0,
              .creation_time = (uint64_t)cookie->creation_time,
              .last_access_time = (uint64_t)cookie->last_access_time,
              .expires_time = (uint64_t)cookie->expires};

          memcpy(write_ptr, &cookie_header, sizeof(cookie_header));
          write_ptr += sizeof(cookie_header);

          if (name_len > 0) {
            memcpy(write_ptr, name, name_len);
            write_ptr += name_len;
          }
          if (value_len > 0) {
            memcpy(write_ptr, value, value_len);
            write_ptr += value_len;
          }
          if (domain_len > 0) {
            memcpy(write_ptr, domain, domain_len);
            write_ptr += domain_len;
          }
          if (path_len > 0) {
            memcpy(write_ptr, path, path_len);
            write_ptr += path_len;
          }
        }
        cookie = cookie->next;
      }
      bucket = bucket->next;
    }
  }

  return true;
}

/**
 * @brief Deserialize cookie jar from binary buffer
 *
 * @param jar Cookie jar to populate
 * @param buffer Buffer containing serialized data
 * @param buffer_size Size of the buffer
 * @return true on successful deserialization
 */
static bool deserialize_from_buffer(cookie_jar_t *jar, const char *buffer,
                                    size_t buffer_size) {
  if (!jar || !buffer || buffer_size < sizeof(cookie_jar_binary_header_t)) {
    return false;
  }

  const char *read_ptr = buffer;
  const char *buffer_end = buffer + buffer_size;

  // Use memcpy to avoid alignment issues
  cookie_jar_binary_header_t header;
  memcpy(&header, read_ptr, sizeof(cookie_jar_binary_header_t));
  read_ptr += sizeof(cookie_jar_binary_header_t);

  if (header.magic != COOKIE_BINARY_MAGIC ||
      header.version != COOKIE_BINARY_VERSION) {
    return false;
  }

  jar->last_cleanup = (time_t)header.last_cleanup_timestamp;

  for (uint32_t i = 0; i < header.cookie_count; i++) {
    // Validate buffer bounds
    if (read_ptr + sizeof(cookie_binary_header_t) > buffer_end) {
      return false;
    }

    // Use memcpy to avoid alignment issues
    cookie_binary_header_t cookie_header;
    memcpy(&cookie_header, read_ptr, sizeof(cookie_binary_header_t));
    read_ptr += sizeof(cookie_binary_header_t);

    // Validate string lengths
    if (cookie_header.name_length > COOKIE_MAX_NAME_LENGTH ||
        cookie_header.value_length > COOKIE_MAX_VALUE_LENGTH ||
        cookie_header.domain_length > COOKIE_MAX_DOMAIN_LENGTH ||
        cookie_header.path_length > COOKIE_MAX_PATH_LENGTH) {
      return false;
    }

    size_t total_string_length =
        cookie_header.name_length + cookie_header.value_length +
        cookie_header.domain_length + cookie_header.path_length;

    if (read_ptr + total_string_length > buffer_end) {
      return false;
    }

    // Extract strings
    char *name = NULL, *value = NULL, *domain = NULL, *path = NULL;

    if (cookie_header.name_length > 0) {
      name = strndup(read_ptr, cookie_header.name_length);
      read_ptr += cookie_header.name_length;
    } else {
      name = strdup("");
    }

    if (cookie_header.value_length > 0) {
      value = strndup(read_ptr, cookie_header.value_length);
      read_ptr += cookie_header.value_length;
    } else {
      value = strdup("");
    }

    if (cookie_header.domain_length > 0) {
      domain = strndup(read_ptr, cookie_header.domain_length);
      read_ptr += cookie_header.domain_length;
    }

    if (cookie_header.path_length > 0) {
      path = strndup(read_ptr, cookie_header.path_length);
      read_ptr += cookie_header.path_length;
    }

    if (!name || !value) {
      free(name);
      free(value);
      free(domain);
      free(path);
      return false;
    }

    // Create and restore cookie
    cookie_t *cookie = cookie_new(name, value, domain, path);
    if (cookie) {
      cookie->flags = cookie_header.flags;
      cookie->samesite = (cookie_samesite_t)cookie_header.samesite;
      cookie->priority = (cookie_priority_t)cookie_header.priority;
      cookie->creation_time = (time_t)cookie_header.creation_time;
      cookie->last_access_time = (time_t)cookie_header.last_access_time;
      cookie->expires = (time_t)cookie_header.expires_time;

      if (!cookie_jar_add(jar, cookie)) {
        cookie_free(cookie);
      }
    }

    free(name);
    free(value);
    free(domain);
    free(path);
  }

  jar->dirty = false;
  return true;
}

#pragma endregion

#pragma region Public API - Cookie Validation

bool cookie_is_valid_name(const char *name) {
  if (!name || *name == '\0')
    return false;

  const char *invalid_chars = "()<>@,;:\\\"/[]?={} \t";

  for (const char *p = name; *p; p++) {
    if (iscntrl((unsigned char)*p) || strchr(invalid_chars, *p)) {
      return false;
    }
  }

  return true;
}

bool cookie_is_valid_value(const char *value) {
  if (!value)
    return false;
  if (*value == '\0')
    return true;

  for (const char *p = value; *p; p++) {
    unsigned char c = (unsigned char)*p;

    if (iscntrl(c))
      return false;

    if (c == ' ' || c == '"' || c == ',' || c == ';' || c == '\\') {
      return false;
    }
  }

  return true;
}

#pragma endregion

#pragma region Public API - Cookie Jar Configuration

cookie_jar_config_t cookie_jar_default_config(void) {
  cookie_jar_config_t config = {
      .max_cookies_total = COOKIE_DEFAULT_MAX_COOKIES,
      .max_cookies_per_domain = COOKIE_DEFAULT_MAX_PER_DOMAIN,
      .max_cookie_size = 4096,
      .accept_session_cookies = true,
      .accept_persistent_cookies = true,
      .accept_third_party = true,
      .max_age_seconds = COOKIE_DEFAULT_MAX_AGE_SECONDS,
      .persistent_file = NULL};
  return config;
}

#pragma endregion

#pragma region Public API - Cookie Jar Management

cookie_jar_t *cookie_jar_new(void) {
  const cookie_jar_config_t default_config = cookie_jar_default_config();
  return cookie_jar_new_with_config(&default_config);
}

cookie_jar_t *cookie_jar_new_with_config(const cookie_jar_config_t *config) {
  if (!config)
    return NULL;

  cookie_jar_t *jar = calloc(1, sizeof(cookie_jar_t));
  if (!jar)
    return NULL;

  jar->config = *config;
  if (config->persistent_file) {
    jar->config.persistent_file = strdup(config->persistent_file);
    if (!jar->config.persistent_file) {
      free(jar);
      return NULL;
    }
  }

  jar->bucket_count = COOKIE_HASH_TABLE_SIZE;
  jar->domain_buckets = calloc(jar->bucket_count, sizeof(*jar->domain_buckets));
  if (!jar->domain_buckets) {
    free((char *)jar->config.persistent_file);
    free(jar);
    return NULL;
  }

  jar->last_cleanup = time(NULL);
  jar->dirty = false;

  if (jar->config.persistent_file) {
    cookie_jar_load_binary(jar, jar->config.persistent_file);
  }

  return jar;
}

void cookie_jar_free(cookie_jar_t *jar) {
  if (!jar)
    return;

  if (jar->dirty && jar->config.persistent_file) {
    cookie_jar_save_binary(jar, jar->config.persistent_file);
  }

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_domain_bucket_t *next_bucket = bucket->next;

      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        cookie_t *next_cookie = cookie->next;
        cookie_free(cookie);
        cookie = next_cookie;
      }

      free(bucket->domain);
      free(bucket);
      bucket = next_bucket;
    }
  }

  free(jar->domain_buckets);
  free((char *)jar->config.persistent_file);
  free(jar);
}

void cookie_jar_clear(cookie_jar_t *jar) {
  if (!jar)
    return;

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_domain_bucket_t *next_bucket = bucket->next;

      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        cookie_t *next_cookie = cookie->next;
        cookie_free(cookie);
        cookie = next_cookie;
      }

      free(bucket->domain);
      free(bucket);
      bucket = next_bucket;
    }
    jar->domain_buckets[i] = NULL;
  }

  jar->total_cookies = 0;
  jar->dirty = true;
}

size_t cookie_jar_count(const cookie_jar_t *jar) {
  return jar ? jar->total_cookies : 0;
}

size_t cookie_jar_count_for_domain(const cookie_jar_t *jar,
                                   const char *domain) {
  if (!jar || !domain)
    return 0;

  cookie_domain_bucket_t *bucket = find_domain_bucket(jar, domain);
  return bucket ? bucket->count : 0;
}

#pragma endregion

#pragma region Public API - Cookie Management

cookie_t *cookie_new(const char *name, const char *value, const char *domain,
                     const char *path) {
  if (!name || !value || !cookie_is_valid_name(name) ||
      !cookie_is_valid_value(value)) {
    return NULL;
  }

  cookie_t *cookie = calloc(1, sizeof(cookie_t));
  if (!cookie)
    return NULL;

  cookie->name = strndup(name, COOKIE_MAX_NAME_LENGTH);
  cookie->value = strndup(value, COOKIE_MAX_VALUE_LENGTH);

  if (domain) {
    size_t domain_len = strlen(domain);
    if (domain_len > COOKIE_MAX_DOMAIN_LENGTH) {
      cookie_free(cookie);
      return NULL;
    }
    cookie->domain = strndup(domain, domain_len);
  } else {
    cookie->domain = NULL;
  }

  cookie->path = path ? strndup(path, COOKIE_MAX_PATH_LENGTH) : strdup("/");

  if (!cookie->name || !cookie->value || !cookie->path) {
    cookie_free(cookie);
    return NULL;
  }

  cookie->creation_time = time(NULL);
  cookie->last_access_time = cookie->creation_time;
  cookie->flags = COOKIE_FLAG_SESSION;
  cookie->samesite = COOKIE_SAMESITE_LAX;
  cookie->priority = COOKIE_PRIORITY_MEDIUM;

  return cookie;
}

cookie_t *cookie_clone(const cookie_t *cookie) {
  if (!cookie)
    return NULL;

  cookie_t *clone = calloc(1, sizeof(cookie_t));
  if (!clone)
    return NULL;

  clone->name = cookie->name ? strdup(cookie->name) : NULL;
  clone->value = cookie->value ? strdup(cookie->value) : NULL;
  clone->domain = cookie->domain ? strdup(cookie->domain) : NULL;
  clone->path = cookie->path ? strdup(cookie->path) : NULL;

  if ((cookie->name && !clone->name) || (cookie->value && !clone->value) ||
      (cookie->domain && !clone->domain) || (cookie->path && !clone->path)) {
    cookie_free(clone);
    return NULL;
  }

  clone->expires = cookie->expires;
  clone->creation_time = cookie->creation_time;
  clone->last_access_time = cookie->last_access_time;
  clone->flags = cookie->flags;
  clone->samesite = cookie->samesite;
  clone->priority = cookie->priority;

  return clone;
}

void cookie_free(cookie_t *cookie) {
  if (!cookie)
    return;

  free(cookie->name);
  free(cookie->value);
  free(cookie->domain);
  free(cookie->path);
  free(cookie);
}

#pragma endregion

#pragma region Public API - Cookie Property Setters

void cookie_set_expires(cookie_t *cookie, time_t expires) {
  if (!cookie)
    return;

  cookie->expires = expires;
  if (expires > 0) {
    cookie->flags &= ~(unsigned int)COOKIE_FLAG_SESSION;
    cookie->flags |= COOKIE_FLAG_PERSISTENT;
  } else {
    cookie->flags &= ~(unsigned int)COOKIE_FLAG_PERSISTENT;
    cookie->flags |= COOKIE_FLAG_SESSION;
  }
}

void cookie_set_max_age(cookie_t *cookie, int64_t max_age_seconds) {
  if (!cookie)
    return;

  if (max_age_seconds < 0) {
    cookie_set_expires(cookie, 1);
  } else if (max_age_seconds == 0) {
    cookie_set_expires(cookie, 0);
  } else {
    cookie_set_expires(cookie, time(NULL) + max_age_seconds);
  }
}

void cookie_set_secure(cookie_t *cookie, bool secure) {
  if (!cookie)
    return;

  if (secure) {
    cookie->flags |= COOKIE_FLAG_SECURE;
  } else {
    cookie->flags &= ~(unsigned int)COOKIE_FLAG_SECURE;
  }
}

void cookie_set_http_only(cookie_t *cookie, bool http_only) {
  if (!cookie)
    return;

  if (http_only) {
    cookie->flags |= COOKIE_FLAG_HTTP_ONLY;
  } else {
    cookie->flags &= ~(unsigned int)COOKIE_FLAG_HTTP_ONLY;
  }
}

void cookie_set_samesite(cookie_t *cookie, cookie_samesite_t samesite) {
  if (cookie) {
    cookie->samesite = samesite;
  }
}

void cookie_set_priority(cookie_t *cookie, cookie_priority_t priority) {
  if (cookie) {
    cookie->priority = priority;
  }
}

#pragma endregion

#pragma region Public API - Cookie Property Getters

bool cookie_is_secure(const cookie_t *cookie) {
  return cookie && (cookie->flags & COOKIE_FLAG_SECURE);
}

bool cookie_is_http_only(const cookie_t *cookie) {
  return cookie && (cookie->flags & COOKIE_FLAG_HTTP_ONLY);
}

bool cookie_is_session(const cookie_t *cookie) {
  return cookie && (cookie->flags & COOKIE_FLAG_SESSION);
}

bool cookie_is_expired(const cookie_t *cookie, time_t current_time) {
  if (!cookie)
    return true;
  if (cookie->flags & COOKIE_FLAG_SESSION)
    return false;
  return cookie->expires > 0 && cookie->expires <= current_time;
}

bool cookie_is_host_only(const cookie_t *cookie) {
  return cookie && (cookie->flags & COOKIE_FLAG_HOST_ONLY);
}

cookie_samesite_t cookie_get_samesite(const cookie_t *cookie) {
  return cookie ? cookie->samesite : COOKIE_SAMESITE_LAX;
}

cookie_priority_t cookie_get_priority(const cookie_t *cookie) {
  return cookie ? cookie->priority : COOKIE_PRIORITY_MEDIUM;
}

void cookie_touch(cookie_t *cookie) {
  if (cookie) {
    cookie->last_access_time = time(NULL);
  }
}

#pragma endregion

#pragma region Public API - Cookie Matching

bool cookie_domain_matches(const char *cookie_domain,
                           const char *request_domain) {
  if (!cookie_domain || !request_domain)
    return false;

  if (strcasecmp(cookie_domain, request_domain) == 0) {
    return true;
  }

  if (cookie_domain[0] == '.') {
    const char *domain_suffix = cookie_domain + 1;
    const size_t request_len = strlen(request_domain);
    const size_t suffix_len = strlen(domain_suffix);

    if (request_len >= suffix_len) {
      const char *request_suffix = request_domain + (request_len - suffix_len);
      if (strcasecmp(request_suffix, domain_suffix) == 0) {
        // Ensure it's a proper subdomain or exact match
        if (request_len == suffix_len ||
            request_domain[request_len - suffix_len - 1] == '.') {
          return true;
        }
      }
    }
  }

  return false;
}

bool cookie_path_matches(const char *cookie_path, const char *request_path) {
  if (!cookie_path || !request_path)
    return false;

  const size_t cookie_len = strlen(cookie_path);
  const size_t request_len = strlen(request_path);

  if (request_len < cookie_len)
    return false;

  if (strncmp(cookie_path, request_path, cookie_len) != 0)
    return false;

  if (request_len == cookie_len || cookie_path[cookie_len - 1] == '/' ||
      request_path[cookie_len] == '/') {
    return true;
  }

  return false;
}

#pragma endregion

#pragma region Public API - URL and Domain Utilities

char *cookie_canonicalize_domain(const char *domain) {
  if (!domain)
    return NULL;

  char *canonical = strdup(domain);
  if (!canonical)
    return NULL;

  for (char *p = canonical; *p; p++) {
    *p = (char)tolower((unsigned char)*p);
  }

  return canonical;
}

char *cookie_default_path(const char *url) {
  if (!url)
    return strdup("/");

  const ada_url parsed = ada_parse(url, strlen(url));
  if (!ada_is_valid(parsed)) {
    ada_free(parsed);
    return strdup("/");
  }

  const ada_string pathname = ada_get_pathname(parsed);
  char *path = NULL;

  if (pathname.length > 0) {
    path = strndup(pathname.data, pathname.length);

    if (path && strlen(path) > 1) {
      char *last_slash = strrchr(path, '/');
      if (last_slash && last_slash != path) {
        *last_slash = '\0';
      } else if (last_slash == path) {
        // Root path
        free(path);
        path = strdup("/");
      }
    } else {
      // Empty or single char path
      free(path);
      path = strdup("/");
    }
  }

  ada_free(parsed);
  return path ? path : strdup("/");
}

bool cookie_is_public_suffix(const char *domain) {
  if (!domain)
    return false;

  const char *public_suffixes[] = {
      "com",    "org",    "net",    "edu",       "gov",    "mil",
      "int",    "biz",    "info",   "name",      "co.uk",  "org.uk",
      "ac.uk",  "gov.uk", "ltd.uk", "plc.uk",    "net.uk", "sch.uk",
      "mod.uk", "me.uk",  "nhs.uk", "police.uk", "co.jp",  "ne.jp",
      "or.jp",  "go.jp",  "ac.jp",  "ad.jp",     "ed.jp",  "gr.jp",
      "lg.jp",  "co.kr",  "ne.kr",  "or.kr",     "go.kr",  NULL};

  for (const char **suffix = public_suffixes; *suffix; suffix++) {
    if (strcasecmp(domain, *suffix) == 0) {
      return true;
    }
  }

  return false;
}

#pragma endregion

#pragma region Public API - Cookie Parsing

cookie_parse_result_t cookie_parse_set_cookie(const char *header_value,
                                              const char *request_url,
                                              cookie_t **cookie) {
  if (!header_value || !request_url || !cookie) {
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  *cookie = NULL;

  const ada_url parsed_url = ada_parse(request_url, strlen(request_url));
  if (!ada_is_valid(parsed_url)) {
    ada_free(parsed_url);
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  if (ada_get_host_type(parsed_url) != 0) {
    ada_free(parsed_url);
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  const ada_string hostname = ada_get_hostname(parsed_url);
  const ada_string pathname = ada_get_pathname(parsed_url);
  const ada_string protocol = ada_get_protocol(parsed_url);

  char *default_domain = NULL;
  char *default_path = NULL;
  bool is_secure_request = false;

  if (hostname.length > 0) {
    default_domain = strndup(hostname.data, hostname.length);
  }

  if (pathname.length > 0) {
    default_path = strndup(pathname.data, pathname.length);
    if (default_path && strlen(default_path) > 1) {
      char *last_slash = strrchr(default_path, '/');
      if (last_slash && last_slash != default_path) {
        *last_slash = '\0';
      } else {
        free(default_path);
        default_path = strdup("/");
      }
    } else {
      free(default_path);
      default_path = strdup("/");
    }
  } else {
    default_path = strdup("/");
  }

  is_secure_request =
      (protocol.length >= 5 && strncmp(protocol.data, "https", 5) == 0);

  ada_free(parsed_url);

  if (!default_domain || !default_path) {
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_MEMORY;
  }

  char *header_copy = strdup(header_value);
  if (!header_copy) {
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_MEMORY;
  }

  char *semicolon = strchr(header_copy, ';');
  if (semicolon)
    *semicolon = '\0';

  char *equals = strchr(header_copy, '=');
  if (!equals) {
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  *equals = '\0';
  char *name = trim_whitespace(header_copy);
  char *value = trim_whitespace(equals + 1);

  if (!cookie_is_valid_name(name) || !cookie_is_valid_value(value)) {
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_NAME;
  }

  cookie_t *new_cookie = cookie_new(name, value, default_domain, default_path);
  if (!new_cookie) {
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_MEMORY;
  }

  new_cookie->flags |= COOKIE_FLAG_HOST_ONLY;

  bool max_age_set = false;

  if (semicolon) {
    const char *attr_start = header_value + (semicolon - header_copy) + 1;
    char *attr_copy = strdup(attr_start);
    if (attr_copy) {
      char *saveptr;
      char *token = strtok_r(attr_copy, ";", &saveptr);
      while (token) {
        token = trim_whitespace(token);

        if (strcasecmp(token, "Secure") == 0) {
          cookie_set_secure(new_cookie, true);
        } else if (strcasecmp(token, "HttpOnly") == 0) {
          cookie_set_http_only(new_cookie, true);
        } else if (strncasecmp(token, "Domain=", 7) == 0) {
          char *domain_value = trim_whitespace(token + 7);
          if (*domain_value != '\0') {
            free(new_cookie->domain);
            new_cookie->domain = strdup(domain_value);

            if (domain_value[0] == '.') {
              new_cookie->flags &= ~(unsigned int)COOKIE_FLAG_HOST_ONLY;
            } else {
              new_cookie->flags |= COOKIE_FLAG_HOST_ONLY;
            }
          }
        } else if (strncasecmp(token, "Path=", 5) == 0) {
          char *path_value = trim_whitespace(token + 5);
          if (*path_value != '\0' && path_value[0] == '/') {
            free(new_cookie->path);
            new_cookie->path = strdup(path_value);
          }
        } else if (strncasecmp(token, "Max-Age=", 8) == 0) {
          int64_t max_age = strtoll(token + 8, NULL, 10);
          cookie_set_max_age(new_cookie, max_age);
          max_age_set = true;
        } else if (strncasecmp(token, "Expires=", 8) == 0 && !max_age_set) {
          time_t expires = parse_cookie_date(token + 8);
          if (expires > 0) {
            cookie_set_expires(new_cookie, expires);
          }
        } else if (strncasecmp(token, "SameSite=", 9) == 0) {
          char *samesite_value = trim_whitespace(token + 9);
          if (strcasecmp(samesite_value, "Strict") == 0) {
            cookie_set_samesite(new_cookie, COOKIE_SAMESITE_STRICT);
          } else if (strcasecmp(samesite_value, "Lax") == 0) {
            cookie_set_samesite(new_cookie, COOKIE_SAMESITE_LAX);
          } else if (strcasecmp(samesite_value, "None") == 0) {
            cookie_set_samesite(new_cookie, COOKIE_SAMESITE_NONE);
          }
        } else if (strncasecmp(token, "Priority=", 9) == 0) {
          char *priority_value = trim_whitespace(token + 9);
          cookie_set_priority(new_cookie,
                              cookie_priority_from_string(priority_value));
        }

        token = strtok_r(NULL, ";", &saveptr);
      }
      free(attr_copy);
    }
  }

  if (!validate_cookie_prefix(name, new_cookie, is_secure_request)) {
    cookie_free(new_cookie);
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  if (cookie_is_secure(new_cookie) && !is_secure_request) {
    cookie_free(new_cookie);
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_FORMAT;
  }

  if (new_cookie->domain &&
      !validate_cookie_domain(new_cookie->domain, default_domain)) {
    cookie_free(new_cookie);
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_DOMAIN;
  }

  if (new_cookie->domain && cookie_is_public_suffix(new_cookie->domain)) {
    cookie_free(new_cookie);
    free(header_copy);
    free(default_domain);
    free(default_path);
    return COOKIE_PARSE_ERROR_INVALID_DOMAIN;
  }

  *cookie = new_cookie;

  free(header_copy);
  free(default_domain);
  free(default_path);
  return COOKIE_PARSE_SUCCESS;
}

#pragma endregion

#pragma region Public API - String Conversion Utilities

const char *cookie_samesite_to_string(cookie_samesite_t samesite) {
  switch (samesite) {
  case COOKIE_SAMESITE_STRICT:
    return "Strict";
  case COOKIE_SAMESITE_LAX:
    return "Lax";
  case COOKIE_SAMESITE_NONE:
    return "None";
  default:
    return "Lax";
  }
}

cookie_samesite_t cookie_samesite_from_string(const char *str) {
  if (!str)
    return COOKIE_SAMESITE_LAX;

  if (strcasecmp(str, "Strict") == 0)
    return COOKIE_SAMESITE_STRICT;
  if (strcasecmp(str, "Lax") == 0)
    return COOKIE_SAMESITE_LAX;
  if (strcasecmp(str, "None") == 0)
    return COOKIE_SAMESITE_NONE;

  return COOKIE_SAMESITE_LAX;
}

const char *cookie_priority_to_string(cookie_priority_t priority) {
  switch (priority) {
  case COOKIE_PRIORITY_LOW:
    return "Low";
  case COOKIE_PRIORITY_MEDIUM:
    return "Medium";
  case COOKIE_PRIORITY_HIGH:
    return "High";
  default:
    return "Medium";
  }
}

cookie_priority_t cookie_priority_from_string(const char *str) {
  if (!str)
    return COOKIE_PRIORITY_MEDIUM;

  if (strcasecmp(str, "Low") == 0)
    return COOKIE_PRIORITY_LOW;
  if (strcasecmp(str, "Medium") == 0)
    return COOKIE_PRIORITY_MEDIUM;
  if (strcasecmp(str, "High") == 0)
    return COOKIE_PRIORITY_HIGH;

  return COOKIE_PRIORITY_MEDIUM;
}

const char *cookie_parse_error_string(cookie_parse_result_t result) {
  switch (result) {
  case COOKIE_PARSE_SUCCESS:
    return "Success";
  case COOKIE_PARSE_ERROR_INVALID_FORMAT:
    return "Invalid format";
  case COOKIE_PARSE_ERROR_INVALID_NAME:
    return "Invalid name";
  case COOKIE_PARSE_ERROR_INVALID_VALUE:
    return "Invalid value";
  case COOKIE_PARSE_ERROR_INVALID_DOMAIN:
    return "Invalid domain";
  case COOKIE_PARSE_ERROR_INVALID_PATH:
    return "Invalid path";
  case COOKIE_PARSE_ERROR_INVALID_EXPIRES:
    return "Invalid expires";
  case COOKIE_PARSE_ERROR_MEMORY:
    return "Out of memory";
  default:
    return "Unknown error";
  }
}

#pragma endregion

#pragma region Public API - Cookie Jar Operations

bool cookie_jar_add(cookie_jar_t *jar, cookie_t *cookie) {
  if (!jar || !cookie)
    return false;

  if (jar->total_cookies >= jar->config.max_cookies_total) {
    return false;
  }

  cookie_domain_bucket_t *bucket = find_domain_bucket(jar, cookie->domain);
  if (!bucket) {
    bucket = create_domain_bucket(jar, cookie->domain);
    if (!bucket) {
      return false;
    }
  }

  if (bucket->count >= jar->config.max_cookies_per_domain) {
    return false;
  }

  // Replace existing cookie with same name and path
  cookie_t *existing = bucket->cookies;
  while (existing) {
    if (strcmp(existing->name, cookie->name) == 0 &&
        strcmp(existing->path, cookie->path) == 0) {
      remove_cookie_from_bucket(bucket, existing);
      jar->total_cookies--;
      cookie_free(existing);
      break;
    }
    existing = existing->next;
  }

  add_cookie_to_bucket(bucket, cookie);
  jar->total_cookies++;
  jar->dirty = true;

  return true;
}

bool cookie_jar_remove(cookie_jar_t *jar, const char *name, const char *domain,
                       const char *path) {
  if (!jar || !name || !domain || !path)
    return false;

  cookie_domain_bucket_t *bucket = find_domain_bucket(jar, domain);
  if (!bucket) {
    return false;
  }

  cookie_t *cookie = bucket->cookies;
  while (cookie) {
    if (strcmp(cookie->name, name) == 0 && strcmp(cookie->path, path) == 0) {
      remove_cookie_from_bucket(bucket, cookie);
      jar->total_cookies--;
      jar->dirty = true;
      cookie_free(cookie);
      return true;
    }
    cookie = cookie->next;
  }

  return false;
}

size_t cookie_jar_remove_domain(cookie_jar_t *jar, const char *domain) {
  if (!jar || !domain)
    return 0;

  cookie_domain_bucket_t *bucket = find_domain_bucket(jar, domain);
  if (!bucket) {
    return 0;
  }

  size_t removed = 0;
  cookie_t *cookie = bucket->cookies;
  while (cookie) {
    cookie_t *next = cookie->next;
    cookie_free(cookie);
    removed++;
    cookie = next;
  }

  bucket->cookies = NULL;
  bucket->count = 0;
  jar->total_cookies -= removed;
  jar->dirty = true;

  return removed;
}

size_t cookie_jar_cleanup_expired(cookie_jar_t *jar) {
  if (!jar)
    return 0;

  size_t removed = 0;
  time_t current_time = time(NULL);

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        cookie_t *next = cookie->next;
        if (cookie_is_expired(cookie, current_time)) {
          remove_cookie_from_bucket(bucket, cookie);
          jar->total_cookies--;
          cookie_free(cookie);
          removed++;
        }
        cookie = next;
      }
      bucket = bucket->next;
    }
  }

  if (removed > 0) {
    jar->dirty = true;
  }
  jar->last_cleanup = current_time;

  return removed;
}

size_t cookie_jar_remove_session(cookie_jar_t *jar) {
  if (!jar)
    return 0;

  size_t removed = 0;

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];
    while (bucket) {
      cookie_t *cookie = bucket->cookies;
      while (cookie) {
        cookie_t *next = cookie->next;
        if (cookie_is_session(cookie)) {
          remove_cookie_from_bucket(bucket, cookie);
          jar->total_cookies--;
          cookie_free(cookie);
          removed++;
        }
        cookie = next;
      }
      bucket = bucket->next;
    }
  }

  if (removed > 0) {
    jar->dirty = true;
  }

  return removed;
}

#pragma endregion

#pragma region Public API - Cookie Retrieval

cookie_match_t *cookie_jar_get_cookies_for_url(cookie_jar_t *jar,
                                               const char *url,
                                               bool include_http_only) {
  if (!jar || !url)
    return NULL;

  const ada_url parsed = ada_parse(url, strlen(url));
  if (!ada_is_valid(parsed)) {
    ada_free(parsed);
    return NULL;
  }

  const ada_string hostname = ada_get_hostname(parsed);
  const ada_string pathname = ada_get_pathname(parsed);
  const ada_string protocol = ada_get_protocol(parsed);

  char *domain = NULL;
  char *path = NULL;
  bool is_secure = false;

  if (hostname.length > 0) {
    domain = strndup(hostname.data, hostname.length);
  }
  if (pathname.length > 0) {
    path = strndup(pathname.data, pathname.length);
  } else {
    path = strdup("/");
  }
  is_secure = (protocol.length >= 5 && strncmp(protocol.data, "https", 5) == 0);

  ada_free(parsed);

  if (!domain || !path) {
    free(domain);
    free(path);
    return NULL;
  }

  cookie_match_t *matches =
      cookie_jar_get_cookies(jar, domain, path, is_secure, include_http_only);

  free(domain);
  free(path);
  return matches;
}

cookie_match_t *cookie_jar_get_cookies(cookie_jar_t *jar, const char *domain,
                                       const char *path, bool secure_only,
                                       bool include_http_only) {
  if (!jar || !domain || !path)
    return NULL;

  cookie_match_t *matches = NULL;
  cookie_match_t *last_match = NULL;

  for (size_t i = 0; i < jar->bucket_count; i++) {
    cookie_domain_bucket_t *bucket = jar->domain_buckets[i];

    while (bucket) {
      // Check if bucket domain matches request domain
      if (cookie_domain_matches(bucket->domain, domain)) {
        cookie_t *cookie = bucket->cookies;

        while (cookie) {
          bool path_matches = cookie_path_matches(cookie->path, path);
          bool not_expired = !cookie_is_expired(cookie, time(NULL));
          bool secure_ok = !cookie_is_secure(cookie) || secure_only;
          bool http_only_ok = include_http_only || !cookie_is_http_only(cookie);

          if (path_matches && not_expired && secure_ok && http_only_ok) {
            // Create match entry
            cookie_match_t *match = malloc(sizeof(cookie_match_t));
            if (match) {
              match->cookie = cookie;
              match->next = NULL;

              if (!matches) {
                matches = match;
              } else {
                last_match->next = match;
              }
              last_match = match;

              cookie_touch(cookie);
            }
          }
          cookie = cookie->next;
        }
      }
      bucket = bucket->next;
    }
  }

  return matches;
}

void cookie_match_free(cookie_match_t *matches) {
  while (matches) {
    cookie_match_t *next = matches->next;
    free(matches);
    matches = next;
  }
}

char *cookie_match_to_header(const cookie_match_t *matches) {
  if (!matches)
    return NULL;

  size_t total_size = 0;
  const cookie_match_t *current = matches;
  while (current) {
    total_size +=
        strlen(current->cookie->name) + 1 + strlen(current->cookie->value);
    if (current->next) {
      total_size += 2; // "; "
    }
    current = current->next;
  }
  total_size++; // null terminator

  char *header = malloc(total_size);
  if (!header)
    return NULL;

  header[0] = '\0';
  current = matches;
  bool first = true;

  while (current) {
    if (!first) {
      strcat(header, "; ");
    }
    strcat(header, current->cookie->name);
    strcat(header, "=");
    strcat(header, current->cookie->value);
    first = false;
    current = current->next;
  }

  return header;
}

#pragma endregion

#pragma region Public API - Cookie Iteration

cookie_iterator_t cookie_jar_iterator(cookie_jar_t *jar) {
  cookie_iterator_t iter = {0};

  if (!jar) {
    return iter;
  }

  iter.jar = jar;
  iter.bucket_index = 0;
  iter.current_bucket = NULL;
  iter.current_cookie = NULL;
  iter.domain_filter = NULL;
  iter.include_http_only = true;

  while (iter.bucket_index < jar->bucket_count) {
    if (jar->domain_buckets[iter.bucket_index] != NULL) {
      iter.current_bucket = jar->domain_buckets[iter.bucket_index];
      iter.current_cookie = iter.current_bucket->cookies;
      break;
    }
    iter.bucket_index++;
  }

  return iter;
}

cookie_iterator_t cookie_jar_iterator_domain(cookie_jar_t *jar,
                                             const char *domain) {
  cookie_iterator_t iter = {0};

  if (!jar || !domain) {
    return iter;
  }

  iter.jar = jar;
  iter.domain_filter = domain;
  iter.include_http_only = true;

  cookie_domain_bucket_t *bucket = find_domain_bucket(jar, domain);
  if (bucket) {
    iter.current_bucket = bucket;
    iter.current_cookie = bucket->cookies;
    iter.bucket_index = 0;
  }

  return iter;
}

cookie_t *cookie_iterator_next(cookie_iterator_t *iter) {
  if (!iter || !iter->jar) {
    return NULL;
  }

  cookie_t *result = NULL;

  if (iter->domain_filter) {
    // Domain-specific iteration
    if (iter->current_cookie) {
      result = iter->current_cookie;
      iter->current_cookie = iter->current_cookie->next;
    }
  } else {
    // Full jar iteration
    while (iter->bucket_index < iter->jar->bucket_count) {
      if (iter->current_cookie) {
        result = iter->current_cookie;
        iter->current_cookie = iter->current_cookie->next;
        break;
      }

      if (iter->current_bucket && iter->current_bucket->next) {
        iter->current_bucket = iter->current_bucket->next;
        iter->current_cookie = iter->current_bucket->cookies;
        continue;
      }

      iter->bucket_index++;
      iter->current_bucket = NULL;

      while (iter->bucket_index < iter->jar->bucket_count) {
        if (iter->jar->domain_buckets[iter->bucket_index] != NULL) {
          iter->current_bucket = iter->jar->domain_buckets[iter->bucket_index];
          iter->current_cookie = iter->current_bucket->cookies;
          break;
        }
        iter->bucket_index++;
      }
    }
  }

  return result;
}

bool cookie_iterator_has_next(const cookie_iterator_t *iter) {
  if (!iter || !iter->jar) {
    return false;
  }

  bool has_next = false;

  if (iter->domain_filter) {
    // Domain-specific iteration
    has_next = (iter->current_cookie != NULL);
  } else {
    // Full jar iteration
    if (iter->current_cookie) {
      has_next = true;
    } else {
      // Check if there are more buckets or cookies in current bucket chain
      cookie_domain_bucket_t *bucket = iter->current_bucket;
      size_t bucket_idx = iter->bucket_index;

      if (bucket && bucket->next) {
        has_next = true;
      } else {
        // Check remaining buckets
        for (size_t i = bucket_idx + 1; i < iter->jar->bucket_count; i++) {
          if (iter->jar->domain_buckets[i] != NULL) {
            has_next = true;
            break;
          }
        }
      }
    }
  }

  return has_next;
}

void cookie_iterator_reset(cookie_iterator_t *iter) {
  if (!iter || !iter->jar) {
    return;
  }

  if (iter->domain_filter) {
    // Reset domain-specific iterator
    cookie_domain_bucket_t *bucket =
        find_domain_bucket(iter->jar, iter->domain_filter);
    if (bucket) {
      iter->current_bucket = bucket;
      iter->current_cookie = bucket->cookies;
    } else {
      iter->current_bucket = NULL;
      iter->current_cookie = NULL;
    }
  } else {
    // Reset full jar iterator
    iter->bucket_index = 0;
    iter->current_bucket = NULL;
    iter->current_cookie = NULL;

    while (iter->bucket_index < iter->jar->bucket_count) {
      if (iter->jar->domain_buckets[iter->bucket_index] != NULL) {
        iter->current_bucket = iter->jar->domain_buckets[iter->bucket_index];
        iter->current_cookie = iter->current_bucket->cookies;
        break;
      }
      iter->bucket_index++;
    }
  }
}

#pragma endregion

#pragma region Public API - Binary Serialization

bool cookie_jar_save_binary(const cookie_jar_t *jar, const char *filename) {
  if (!jar || !filename)
    return false;

  uint32_t cookie_count;
  size_t buffer_size = calculate_binary_size(jar, &cookie_count);

  char *buffer = malloc(buffer_size);
  if (!buffer)
    return false;

  if (!serialize_to_buffer(jar, buffer, buffer_size)) {
    free(buffer);
    return false;
  }

  FILE *file = fopen(filename, "wb");
  if (!file) {
    free(buffer);
    return false;
  }

  bool success = (fwrite(buffer, 1, buffer_size, file) == buffer_size);
  success = success && (fflush(file) == 0);
  success = success && (fclose(file) == 0);

  free(buffer);

  if (!success) {
    unlink(filename);
    return false;
  }

  return true;
}

bool cookie_jar_load_binary(cookie_jar_t *jar, const char *filename) {
  if (!jar || !filename)
    return false;

  FILE *file = fopen(filename, "rb");
  if (!file) {
    // File not found is not an error for loading
    return true;
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size <= 0) {
    fclose(file);
    return false;
  }

  char *buffer = malloc((size_t)file_size);
  if (!buffer) {
    fclose(file);
    return false;
  }

  bool success =
      (fread(buffer, 1, (size_t)file_size, file) == (size_t)file_size);
  fclose(file);

  if (success) {
    success = deserialize_from_buffer(jar, buffer, (size_t)file_size);
  }

  free(buffer);
  return success;
}

char *cookie_jar_save_binary_buffer(const cookie_jar_t *jar,
                                    size_t *buffer_size) {
  if (!jar || !buffer_size)
    return NULL;

  uint32_t cookie_count;
  *buffer_size = calculate_binary_size(jar, &cookie_count);

  char *buffer = malloc(*buffer_size);
  if (!buffer)
    return NULL;

  if (!serialize_to_buffer(jar, buffer, *buffer_size)) {
    free(buffer);
    return NULL;
  }

  return buffer;
}

bool cookie_jar_load_binary_buffer(cookie_jar_t *jar, const char *buffer,
                                   size_t buffer_size) {
  return deserialize_from_buffer(jar, buffer, buffer_size);
}

#pragma endregion
