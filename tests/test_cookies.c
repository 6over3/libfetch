#include "../src/cookie.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Platform-specific includes
#if defined(_WIN32) || defined(_WIN64)
#include <io.h>
#include <process.h>
#define sleep(x) Sleep((x) * 1000)
#define unlink _unlink
#else
#include <unistd.h>
#endif

static cookie_jar_t *test_jar = NULL;

void setUp(void)
{
  test_jar = cookie_jar_new();
}

void tearDown(void)
{
  cookie_jar_free(test_jar);
  test_jar = NULL;
}

void test_cookie_new_and_free(void)
{
  cookie_t *cookie = cookie_new("test_name", "test_value", "example.com", "/");
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_EQUAL_STRING("test_name", cookie->name);
  TEST_ASSERT_EQUAL_STRING("test_value", cookie->value);
  TEST_ASSERT_EQUAL_STRING("example.com", cookie->domain);
  TEST_ASSERT_EQUAL_STRING("/", cookie->path);
  TEST_ASSERT_TRUE(cookie_is_session(cookie));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_get_samesite(cookie));
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM, cookie_get_priority(cookie));
  cookie_free(cookie);

  cookie = cookie_new("name", "value", NULL, NULL);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_NULL(cookie->domain);
  TEST_ASSERT_EQUAL_STRING("/", cookie->path);
  cookie_free(cookie);

  TEST_ASSERT_NULL(cookie_new(NULL, "value", "domain", "/"));
  TEST_ASSERT_NULL(cookie_new("name", NULL, "domain", "/"));
  TEST_ASSERT_NULL(cookie_new("", "value", "domain", "/"));
  TEST_ASSERT_NULL(cookie_new("invalid()name", "value", "domain", "/"));
  TEST_ASSERT_NULL(cookie_new("name", "invalid\x01value", "domain", "/"));

  cookie_free(NULL);
}

void test_cookie_clone(void)
{
  cookie_t *original =
      cookie_new("session_id", "abc123", "example.com", "/app");
  TEST_ASSERT_NOT_NULL(original);

  cookie_set_secure(original, true);
  cookie_set_http_only(original, true);
  cookie_set_samesite(original, COOKIE_SAMESITE_STRICT);
  cookie_set_priority(original, COOKIE_PRIORITY_HIGH);
  cookie_set_expires(original, time(NULL) + 3600);

  cookie_t *clone = cookie_clone(original);
  TEST_ASSERT_NOT_NULL(clone);

  TEST_ASSERT_EQUAL_STRING(original->name, clone->name);
  TEST_ASSERT_EQUAL_STRING(original->value, clone->value);
  TEST_ASSERT_EQUAL_STRING(original->domain, clone->domain);
  TEST_ASSERT_EQUAL_STRING(original->path, clone->path);
  TEST_ASSERT_EQUAL(original->expires, clone->expires);
  TEST_ASSERT_EQUAL(original->flags, clone->flags);
  TEST_ASSERT_EQUAL(original->samesite, clone->samesite);
  TEST_ASSERT_EQUAL(original->priority, clone->priority);

  TEST_ASSERT_NOT_EQUAL(original, clone);
  TEST_ASSERT_NOT_EQUAL(original->name, clone->name);

  TEST_ASSERT_NULL(cookie_clone(NULL));

  cookie_free(original);
  cookie_free(clone);
}

void test_cookie_attributes(void)
{
  cookie_t *cookie = cookie_new("test", "value", "example.com", "/");
  TEST_ASSERT_NOT_NULL(cookie);

  TEST_ASSERT_FALSE(cookie_is_secure(cookie));
  cookie_set_secure(cookie, true);
  TEST_ASSERT_TRUE(cookie_is_secure(cookie));
  cookie_set_secure(cookie, false);
  TEST_ASSERT_FALSE(cookie_is_secure(cookie));

  TEST_ASSERT_FALSE(cookie_is_http_only(cookie));
  cookie_set_http_only(cookie, true);
  TEST_ASSERT_TRUE(cookie_is_http_only(cookie));
  cookie_set_http_only(cookie, false);
  TEST_ASSERT_FALSE(cookie_is_http_only(cookie));

  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_get_samesite(cookie));
  cookie_set_samesite(cookie, COOKIE_SAMESITE_STRICT);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT, cookie_get_samesite(cookie));
  cookie_set_samesite(cookie, COOKIE_SAMESITE_NONE);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_NONE, cookie_get_samesite(cookie));

  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM, cookie_get_priority(cookie));
  cookie_set_priority(cookie, COOKIE_PRIORITY_HIGH);
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_HIGH, cookie_get_priority(cookie));
  cookie_set_priority(cookie, COOKIE_PRIORITY_LOW);
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_LOW, cookie_get_priority(cookie));

  TEST_ASSERT_TRUE(cookie_is_session(cookie));
  time_t future = time(NULL) + 3600;
  cookie_set_expires(cookie, future);
  TEST_ASSERT_FALSE(cookie_is_session(cookie));
  TEST_ASSERT_EQUAL(future, cookie->expires);
  TEST_ASSERT_FALSE(cookie_is_expired(cookie, time(NULL)));
  TEST_ASSERT_TRUE(cookie_is_expired(cookie, future + 1));

  cookie_set_max_age(cookie, 7200);
  TEST_ASSERT_FALSE(cookie_is_session(cookie));
  TEST_ASSERT_GREATER_OR_EQUAL(time(NULL) + 7200 - 1, cookie->expires);

  cookie_set_max_age(cookie, 0);
  TEST_ASSERT_TRUE(cookie_is_session(cookie));

  cookie_set_max_age(cookie, -1);
  TEST_ASSERT_TRUE(cookie_is_expired(cookie, time(NULL)));

  time_t before_touch = cookie->last_access_time;

  cookie_touch(cookie);

  TEST_ASSERT_FALSE(cookie_is_secure(NULL));
  TEST_ASSERT_FALSE(cookie_is_http_only(NULL));
  TEST_ASSERT_TRUE(cookie_is_expired(NULL, time(NULL)));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_get_samesite(NULL));

  cookie_free(cookie);
}

void test_cookie_validation(void)
{
  TEST_ASSERT_TRUE(cookie_is_valid_name("simple"));
  TEST_ASSERT_TRUE(cookie_is_valid_name("with-dashes"));
  TEST_ASSERT_TRUE(cookie_is_valid_name("with_underscores"));
  TEST_ASSERT_TRUE(cookie_is_valid_name("with123numbers"));
  TEST_ASSERT_TRUE(cookie_is_valid_name("MixedCase"));

  TEST_ASSERT_FALSE(cookie_is_valid_name(NULL));
  TEST_ASSERT_FALSE(cookie_is_valid_name(""));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with spaces"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with(parens)"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with<brackets>"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with@at"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with,comma"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with;semicolon"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with:colon"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with\\backslash"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with\"quote"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with/slash"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with[square]"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with?question"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with=equals"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with{braces}"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with\ttab"));
  TEST_ASSERT_FALSE(cookie_is_valid_name("with\x01control"));

  TEST_ASSERT_TRUE(cookie_is_valid_value(""));
  TEST_ASSERT_TRUE(cookie_is_valid_value("simple"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("with-dashes"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("with_underscores"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("with123numbers"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("MixedCase"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("with.dots"));
  TEST_ASSERT_TRUE(cookie_is_valid_value("with+plus"));

  TEST_ASSERT_FALSE(cookie_is_valid_value(NULL));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with spaces"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with\"quote"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with,comma"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with;semicolon"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with\\backslash"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with\ttab"));
  TEST_ASSERT_FALSE(cookie_is_valid_value("with\x01control"));
}

void test_cookie_jar_creation_and_config(void)
{
  cookie_jar_config_t default_config = cookie_jar_default_config();
  TEST_ASSERT_EQUAL(3000, default_config.max_cookies_total);
  TEST_ASSERT_EQUAL(50, default_config.max_cookies_per_domain);
  TEST_ASSERT_EQUAL(4096, default_config.max_cookie_size);
  TEST_ASSERT_TRUE(default_config.accept_session_cookies);
  TEST_ASSERT_TRUE(default_config.accept_persistent_cookies);
  TEST_ASSERT_TRUE(default_config.accept_third_party);
  TEST_ASSERT_NULL(default_config.persistent_file);

  cookie_jar_t *jar1 = cookie_jar_new();
  TEST_ASSERT_NOT_NULL(jar1);
  TEST_ASSERT_EQUAL(0, cookie_jar_count(jar1));
  TEST_ASSERT_EQUAL(3000, jar1->config.max_cookies_total);
  cookie_jar_free(jar1);

  cookie_jar_config_t custom_config = {.max_cookies_total = 1000,
                                       .max_cookies_per_domain = 25,
                                       .max_cookie_size = 2048,
                                       .accept_session_cookies = false,
                                       .accept_persistent_cookies = true,
                                       .accept_third_party = false,
                                       .max_age_seconds = 86400,
                                       .persistent_file =
#ifdef _WIN32
                                           "C:\\temp\\test_cookies.txt"};
#else
                                           "/tmp/test_cookies.txt"};
#endif

  cookie_jar_t *jar2 = cookie_jar_new_with_config(&custom_config);
  TEST_ASSERT_NOT_NULL(jar2);
  TEST_ASSERT_EQUAL(1000, jar2->config.max_cookies_total);
  TEST_ASSERT_EQUAL(25, jar2->config.max_cookies_per_domain);
  TEST_ASSERT_FALSE(jar2->config.accept_session_cookies);
#ifdef _WIN32
  TEST_ASSERT_EQUAL_STRING("C:\\temp\\test_cookies.txt",
                           jar2->config.persistent_file);
#else
  TEST_ASSERT_EQUAL_STRING("/tmp/test_cookies.txt",
                           jar2->config.persistent_file);
#endif
  cookie_jar_free(jar2);

  TEST_ASSERT_NULL(cookie_jar_new_with_config(NULL));

  cookie_jar_free(NULL);
}

void test_cookie_jar_add_and_count(void)
{
  TEST_ASSERT_EQUAL(0, cookie_jar_count(test_jar));

  cookie_t *cookie1 = cookie_new("session", "abc123", "example.com", "/");
  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, cookie1));
  TEST_ASSERT_EQUAL(1, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(1, cookie_jar_count_for_domain(test_jar, "example.com"));
  TEST_ASSERT_EQUAL(0, cookie_jar_count_for_domain(test_jar, "other.com"));

  cookie_t *cookie2 = cookie_new("prefs", "dark_mode", "example.com", "/app");
  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, cookie2));
  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(2, cookie_jar_count_for_domain(test_jar, "example.com"));

  cookie_t *cookie3 = cookie_new("user", "john", "other.com", "/");
  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, cookie3));
  TEST_ASSERT_EQUAL(3, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(2, cookie_jar_count_for_domain(test_jar, "example.com"));
  TEST_ASSERT_EQUAL(1, cookie_jar_count_for_domain(test_jar, "other.com"));

  cookie_t *cookie4 = cookie_new("session", "def456", "example.com", "/");
  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, cookie4));
  TEST_ASSERT_EQUAL(3, cookie_jar_count(test_jar));

  TEST_ASSERT_FALSE(cookie_jar_add(NULL, cookie1));
  TEST_ASSERT_FALSE(cookie_jar_add(test_jar, NULL));
  TEST_ASSERT_EQUAL(0, cookie_jar_count(NULL));
  TEST_ASSERT_EQUAL(0, cookie_jar_count_for_domain(NULL, "example.com"));
  TEST_ASSERT_EQUAL(0, cookie_jar_count_for_domain(test_jar, NULL));
}

void test_cookie_jar_remove(void)
{
  cookie_jar_add(test_jar, cookie_new("cookie1", "value1", "example.com", "/"));
  cookie_jar_add(test_jar,
                 cookie_new("cookie2", "value2", "example.com", "/app"));
  cookie_jar_add(test_jar, cookie_new("cookie3", "value3", "other.com", "/"));
  TEST_ASSERT_EQUAL(3, cookie_jar_count(test_jar));

  TEST_ASSERT_TRUE(cookie_jar_remove(test_jar, "cookie1", "example.com", "/"));
  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(1, cookie_jar_count_for_domain(test_jar, "example.com"));

  TEST_ASSERT_FALSE(
      cookie_jar_remove(test_jar, "nonexistent", "example.com", "/"));
  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));

  cookie_jar_add(test_jar,
                 cookie_new("cookie4", "value4", "example.com", "/admin"));
  TEST_ASSERT_EQUAL(3, cookie_jar_count(test_jar));

  size_t removed = cookie_jar_remove_domain(test_jar, "example.com");
  TEST_ASSERT_EQUAL(2, removed);
  TEST_ASSERT_EQUAL(1, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(0, cookie_jar_count_for_domain(test_jar, "example.com"));
  TEST_ASSERT_EQUAL(1, cookie_jar_count_for_domain(test_jar, "other.com"));

  TEST_ASSERT_FALSE(cookie_jar_remove(NULL, "name", "domain", "/"));
  TEST_ASSERT_FALSE(cookie_jar_remove(test_jar, NULL, "domain", "/"));
  TEST_ASSERT_EQUAL(0, cookie_jar_remove_domain(NULL, "domain"));
  TEST_ASSERT_EQUAL(0, cookie_jar_remove_domain(test_jar, NULL));
}

void test_cookie_jar_clear(void)
{
  cookie_jar_add(test_jar, cookie_new("cookie1", "value1", "example.com", "/"));
  cookie_jar_add(test_jar, cookie_new("cookie2", "value2", "other.com", "/"));
  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));

  cookie_jar_clear(test_jar);
  TEST_ASSERT_EQUAL(0, cookie_jar_count(test_jar));
  TEST_ASSERT_EQUAL(0, cookie_jar_count_for_domain(test_jar, "example.com"));

  cookie_jar_clear(NULL);
}

void test_cookie_jar_cleanup_expired(void)
{
  time_t now = time(NULL);

  cookie_jar_add(test_jar, cookie_new("session", "value", "example.com", "/"));

  cookie_t *future_cookie = cookie_new("future", "value", "example.com", "/");
  cookie_set_expires(future_cookie, now + 3600);
  cookie_jar_add(test_jar, future_cookie);

  cookie_t *expired_cookie = cookie_new("expired", "value", "example.com", "/");
  cookie_set_expires(expired_cookie, now - 3600);
  cookie_jar_add(test_jar, expired_cookie);

  TEST_ASSERT_EQUAL(3, cookie_jar_count(test_jar));

  size_t removed = cookie_jar_cleanup_expired(test_jar);
  TEST_ASSERT_EQUAL(1, removed);
  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));

  TEST_ASSERT_EQUAL(0, cookie_jar_cleanup_expired(NULL));
}

void test_cookie_jar_remove_session(void)
{
  cookie_jar_add(test_jar, cookie_new("session", "value", "example.com", "/"));

  cookie_t *persistent = cookie_new("persistent", "value", "example.com", "/");
  cookie_set_expires(persistent, time(NULL) + 3600);
  cookie_jar_add(test_jar, persistent);

  TEST_ASSERT_EQUAL(2, cookie_jar_count(test_jar));

  size_t removed = cookie_jar_remove_session(test_jar);
  TEST_ASSERT_EQUAL(1, removed);
  TEST_ASSERT_EQUAL(1, cookie_jar_count(test_jar));

  TEST_ASSERT_EQUAL(0, cookie_jar_remove_session(NULL));
}

void test_cookie_domain_matching(void)
{
  TEST_ASSERT_TRUE(cookie_domain_matches("example.com", "example.com"));
  TEST_ASSERT_TRUE(cookie_domain_matches("EXAMPLE.COM", "example.com"));
  TEST_ASSERT_TRUE(cookie_domain_matches("example.com", "EXAMPLE.COM"));

  TEST_ASSERT_TRUE(cookie_domain_matches(".example.com", "www.example.com"));
  TEST_ASSERT_TRUE(cookie_domain_matches(".example.com", "api.example.com"));
  TEST_ASSERT_TRUE(
      cookie_domain_matches(".example.com", "sub.domain.example.com"));
  TEST_ASSERT_TRUE(cookie_domain_matches(".example.com", "example.com"));

  TEST_ASSERT_FALSE(cookie_domain_matches("example.com", "other.com"));
  TEST_ASSERT_FALSE(cookie_domain_matches("example.com", "notexample.com"));
  TEST_ASSERT_FALSE(cookie_domain_matches(".example.com", "badexample.com"));
  TEST_ASSERT_FALSE(cookie_domain_matches("sub.example.com", "example.com"));

  TEST_ASSERT_FALSE(cookie_domain_matches(NULL, "example.com"));
  TEST_ASSERT_FALSE(cookie_domain_matches("example.com", NULL));
  TEST_ASSERT_FALSE(cookie_domain_matches(NULL, NULL));
}

void test_cookie_path_matching(void)
{
  TEST_ASSERT_TRUE(cookie_path_matches("/", "/"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app", "/app"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app/", "/app/"));

  TEST_ASSERT_TRUE(cookie_path_matches("/", "/app"));
  TEST_ASSERT_TRUE(cookie_path_matches("/", "/anything"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app", "/app/page"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app/", "/app/page"));

  TEST_ASSERT_FALSE(cookie_path_matches("/app", "/other"));
  TEST_ASSERT_FALSE(cookie_path_matches("/app", "/ap"));
  TEST_ASSERT_FALSE(cookie_path_matches("/app", "/application"));
  TEST_ASSERT_FALSE(cookie_path_matches("/app/page", "/app"));

  TEST_ASSERT_FALSE(cookie_path_matches(NULL, "/"));
  TEST_ASSERT_FALSE(cookie_path_matches("/", NULL));
  TEST_ASSERT_FALSE(cookie_path_matches(NULL, NULL));
}

void test_cookie_default_path(void)
{
  char *path = cookie_default_path("http://example.com/");
  TEST_ASSERT_EQUAL_STRING("/", path);
  free(path);

  path = cookie_default_path("http://example.com/app");
  TEST_ASSERT_EQUAL_STRING("/", path);
  free(path);

  path = cookie_default_path("http://example.com/app/");
  TEST_ASSERT_EQUAL_STRING("/app", path);
  free(path);

  path = cookie_default_path("http://example.com/app/page");
  TEST_ASSERT_EQUAL_STRING("/app", path);
  free(path);

  path = cookie_default_path("http://example.com/app/sub/page");
  TEST_ASSERT_EQUAL_STRING("/app/sub", path);
  free(path);

  path = cookie_default_path(NULL);
  TEST_ASSERT_EQUAL_STRING("/", path);
  free(path);

  path = cookie_default_path("not-a-url");
  TEST_ASSERT_EQUAL_STRING("/", path);
  free(path);
}

void test_cookie_canonicalize_domain(void)
{
  char *canonical = cookie_canonicalize_domain("EXAMPLE.COM");
  TEST_ASSERT_EQUAL_STRING("example.com", canonical);
  free(canonical);

  canonical = cookie_canonicalize_domain("MiXeD.CaSe.CoM");
  TEST_ASSERT_EQUAL_STRING("mixed.case.com", canonical);
  free(canonical);

  canonical = cookie_canonicalize_domain("already.lowercase.com");
  TEST_ASSERT_EQUAL_STRING("already.lowercase.com", canonical);
  free(canonical);

  canonical = cookie_canonicalize_domain(NULL);
  TEST_ASSERT_NULL(canonical);
}

void test_cookie_public_suffix(void)
{
  TEST_ASSERT_TRUE(cookie_is_public_suffix("com"));
  TEST_ASSERT_TRUE(cookie_is_public_suffix("org"));
  TEST_ASSERT_TRUE(cookie_is_public_suffix("net"));
  TEST_ASSERT_TRUE(cookie_is_public_suffix("co.uk"));
  TEST_ASSERT_TRUE(cookie_is_public_suffix("org.uk"));

  TEST_ASSERT_FALSE(cookie_is_public_suffix("example.com"));
  TEST_ASSERT_FALSE(cookie_is_public_suffix("google.com"));
  TEST_ASSERT_FALSE(cookie_is_public_suffix("unknown.tld"));

  TEST_ASSERT_FALSE(cookie_is_public_suffix(NULL));
}

void test_cookie_parse_basic(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result = cookie_parse_set_cookie(
      "session=abc123", "http://example.com/app", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_EQUAL_STRING("session", cookie->name);
  TEST_ASSERT_EQUAL_STRING("abc123", cookie->value);
  TEST_ASSERT_EQUAL_STRING("example.com", cookie->domain);
  TEST_ASSERT_EQUAL_STRING("/", cookie->path);
  TEST_ASSERT_TRUE(cookie_is_session(cookie));
  TEST_ASSERT_FALSE(cookie_is_secure(cookie));
  TEST_ASSERT_FALSE(cookie_is_http_only(cookie));
  cookie_free(cookie);
}

void test_cookie_parse_with_attributes(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result = cookie_parse_set_cookie(
      "prefs=dark_mode; Domain=.example.com; Path=/app; Secure; HttpOnly; "
      "SameSite=Strict; Max-Age=3600",
      "https://www.example.com/app/settings", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_EQUAL_STRING("prefs", cookie->name);
  TEST_ASSERT_EQUAL_STRING("dark_mode", cookie->value);
  TEST_ASSERT_EQUAL_STRING(".example.com", cookie->domain);
  TEST_ASSERT_EQUAL_STRING("/app", cookie->path);
  TEST_ASSERT_TRUE(cookie_is_secure(cookie));
  TEST_ASSERT_TRUE(cookie_is_http_only(cookie));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT, cookie_get_samesite(cookie));
  TEST_ASSERT_FALSE(cookie_is_session(cookie));
  TEST_ASSERT_FALSE(cookie_is_host_only(cookie));
  cookie_free(cookie);
}

void test_cookie_parse_expires_date(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result = cookie_parse_set_cookie(
      "persistent=value; Expires=Wed, 09 Jun 2030 10:18:14 GMT",
      "http://example.com/", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_FALSE(cookie_is_session(cookie));
  TEST_ASSERT_GREATER_THAN(0, cookie->expires);
  TEST_ASSERT_GREATER_THAN(time(NULL), cookie->expires);
  cookie_free(cookie);
}

void test_cookie_parse_max_age_priority(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result = cookie_parse_set_cookie(
      "test=value; Max-Age=7200; Expires=Wed, 09 Jun 2021 10:18:14 GMT",
      "http://example.com/", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_FALSE(cookie_is_session(cookie));
  TEST_ASSERT_GREATER_OR_EQUAL(time(NULL) + 7200 - 5, cookie->expires);
  TEST_ASSERT_LESS_OR_EQUAL(time(NULL) + 7200 + 5, cookie->expires);
  cookie_free(cookie);
}

void test_cookie_parse_samesite_variations(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_set_cookie("test1=value; SameSite=Strict", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT, cookie_get_samesite(cookie));
  cookie_free(cookie);

  cookie_parse_set_cookie("test2=value; SameSite=Lax", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_get_samesite(cookie));
  cookie_free(cookie);

  cookie_parse_set_cookie("test3=value; SameSite=None", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_NONE, cookie_get_samesite(cookie));
  cookie_free(cookie);

  cookie_parse_set_cookie("test4=value; SameSite=Invalid",
                          "http://example.com/", &cookie);
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_get_samesite(cookie));
  cookie_free(cookie);
}

void test_cookie_parse_priority_attribute(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_set_cookie("test1=value; Priority=High", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_HIGH, cookie_get_priority(cookie));
  cookie_free(cookie);

  cookie_parse_set_cookie("test2=value; Priority=Low", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_LOW, cookie_get_priority(cookie));
  cookie_free(cookie);

  cookie_parse_set_cookie("test3=value; Priority=Medium", "http://example.com/",
                          &cookie);
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM, cookie_get_priority(cookie));
  cookie_free(cookie);
}

void test_cookie_parse_security_validation(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result =
      cookie_parse_set_cookie("secure_cookie=value; Secure",
                              "http://example.com/",
                              &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_FORMAT, result);
  TEST_ASSERT_NULL(cookie);

  result = cookie_parse_set_cookie("secure_cookie=value; Secure",
                                   "https://example.com/",
                                   &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  TEST_ASSERT_TRUE(cookie_is_secure(cookie));
  cookie_free(cookie);
}

void test_cookie_parse_domain_validation(void)
{
  cookie_t *cookie = NULL;

  cookie_parse_result_t result = cookie_parse_set_cookie(
      "test=value; Domain=other.com", "http://example.com/", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_DOMAIN, result);
  TEST_ASSERT_NULL(cookie);

  result = cookie_parse_set_cookie("test=value; Domain=example.com",
                                   "http://example.com/", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  cookie_free(cookie);

  result = cookie_parse_set_cookie("test=value; Domain=.example.com",
                                   "http://www.example.com/", &cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(cookie);
  cookie_free(cookie);
}

void test_cookie_parse_error_cases(void)
{
  cookie_t *cookie = NULL;

  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_FORMAT,
                    cookie_parse_set_cookie("invalid_format",
                                            "http://example.com/", &cookie));
  TEST_ASSERT_NULL(cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_NAME,
                    cookie_parse_set_cookie("invalid()name=value",
                                            "http://example.com/", &cookie));
  TEST_ASSERT_NULL(cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_NAME,
                    cookie_parse_set_cookie("name=invalid\x01value",
                                            "http://example.com/", &cookie));
  TEST_ASSERT_NULL(cookie);

  TEST_ASSERT_EQUAL(
      COOKIE_PARSE_ERROR_INVALID_FORMAT,
      cookie_parse_set_cookie(NULL, "http://example.com/", &cookie));
  TEST_ASSERT_EQUAL(COOKIE_PARSE_ERROR_INVALID_FORMAT,
                    cookie_parse_set_cookie("name=value", NULL, &cookie));
  TEST_ASSERT_EQUAL(
      COOKIE_PARSE_ERROR_INVALID_FORMAT,
      cookie_parse_set_cookie("name=value", "http://example.com/", NULL));

  TEST_ASSERT_EQUAL(
      COOKIE_PARSE_ERROR_INVALID_FORMAT,
      cookie_parse_set_cookie("name=value", "not-a-url", &cookie));
}

void test_cookie_jar_get_cookies_for_url(void)
{
  cookie_jar_add(test_jar, cookie_new("session", "abc123", "example.com", "/"));
  cookie_jar_add(test_jar, cookie_new("prefs", "dark", "example.com", "/app"));

  cookie_t *secure_cookie = cookie_new("secure", "value", "example.com", "/");
  cookie_set_secure(secure_cookie, true);
  cookie_jar_add(test_jar, secure_cookie);

  cookie_t *httponly_cookie =
      cookie_new("httponly", "value", "example.com", "/");
  cookie_set_http_only(httponly_cookie, true);
  cookie_jar_add(test_jar, httponly_cookie);

  cookie_jar_add(test_jar, cookie_new("other", "value", "other.com", "/"));

  cookie_match_t *matches =
      cookie_jar_get_cookies_for_url(test_jar, "http://example.com/", true);
  TEST_ASSERT_NOT_NULL(matches);

  int count = 0;
  bool found_session = false, found_httponly = false, found_secure = false;

  cookie_match_t *current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "session") == 0)
      found_session = true;
    if (strcmp(current->cookie->name, "httponly") == 0)
      found_httponly = true;
    if (strcmp(current->cookie->name, "secure") == 0)
      found_secure = true;
    current = current->next;
  }

  TEST_ASSERT_EQUAL(2, count);
  TEST_ASSERT_TRUE(found_session);
  TEST_ASSERT_TRUE(found_httponly);
  TEST_ASSERT_FALSE(found_secure);

  cookie_match_free(matches);

  matches =
      cookie_jar_get_cookies_for_url(test_jar, "https://example.com/", true);
  count = 0;
  found_secure = false;

  current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "secure") == 0)
      found_secure = true;
    current = current->next;
  }

  TEST_ASSERT_EQUAL(3, count);
  TEST_ASSERT_TRUE(found_secure);

  cookie_match_free(matches);

  matches = cookie_jar_get_cookies_for_url(
      test_jar, "http://example.com/app/page", false);
  count = 0;
  bool found_prefs = false;

  current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "prefs") == 0)
      found_prefs = true;
    current = current->next;
  }

  TEST_ASSERT_GREATER_OR_EQUAL(2, count);
  TEST_ASSERT_TRUE(found_prefs);

  cookie_match_free(matches);

  TEST_ASSERT_NULL(
      cookie_jar_get_cookies_for_url(NULL, "http://example.com/", false));
  TEST_ASSERT_NULL(cookie_jar_get_cookies_for_url(test_jar, NULL, false));
}

void test_cookie_match_to_header(void)
{
  cookie_jar_add(test_jar, cookie_new("session", "abc123", "example.com", "/"));
  cookie_jar_add(test_jar,
                 cookie_new("prefs", "dark_mode", "example.com", "/"));
  cookie_jar_add(test_jar, cookie_new("lang", "en", "example.com", "/"));

  cookie_match_t *matches =
      cookie_jar_get_cookies_for_url(test_jar, "http://example.com/", false);
  TEST_ASSERT_NOT_NULL(matches);

  char *header = cookie_match_to_header(matches);
  TEST_ASSERT_NOT_NULL(header);

  TEST_ASSERT_NOT_NULL(strstr(header, "session=abc123"));
  TEST_ASSERT_NOT_NULL(strstr(header, "prefs=dark_mode"));
  TEST_ASSERT_NOT_NULL(strstr(header, "lang=en"));

  free(header);
  cookie_match_free(matches);

  TEST_ASSERT_NULL(cookie_match_to_header(NULL));

  cookie_match_free(NULL);
}

void test_cookie_string_utilities(void)
{
  TEST_ASSERT_EQUAL_STRING("Strict",
                           cookie_samesite_to_string(COOKIE_SAMESITE_STRICT));
  TEST_ASSERT_EQUAL_STRING("Lax",
                           cookie_samesite_to_string(COOKIE_SAMESITE_LAX));
  TEST_ASSERT_EQUAL_STRING("None",
                           cookie_samesite_to_string(COOKIE_SAMESITE_NONE));
  TEST_ASSERT_EQUAL_STRING(
      "Lax", cookie_samesite_to_string(999));

  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT,
                    cookie_samesite_from_string("Strict"));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT,
                    cookie_samesite_from_string("strict"));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_samesite_from_string("Lax"));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_NONE, cookie_samesite_from_string("None"));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX,
                    cookie_samesite_from_string("Invalid"));
  TEST_ASSERT_EQUAL(COOKIE_SAMESITE_LAX, cookie_samesite_from_string(NULL));

  TEST_ASSERT_EQUAL_STRING("High",
                           cookie_priority_to_string(COOKIE_PRIORITY_HIGH));
  TEST_ASSERT_EQUAL_STRING("Medium",
                           cookie_priority_to_string(COOKIE_PRIORITY_MEDIUM));
  TEST_ASSERT_EQUAL_STRING("Low",
                           cookie_priority_to_string(COOKIE_PRIORITY_LOW));

  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_HIGH, cookie_priority_from_string("High"));
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM,
                    cookie_priority_from_string("Medium"));
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_LOW, cookie_priority_from_string("Low"));
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM,
                    cookie_priority_from_string("Invalid"));
  TEST_ASSERT_EQUAL(COOKIE_PRIORITY_MEDIUM, cookie_priority_from_string(NULL));

  TEST_ASSERT_EQUAL_STRING("Success",
                           cookie_parse_error_string(COOKIE_PARSE_SUCCESS));
  TEST_ASSERT_EQUAL_STRING(
      "Invalid format",
      cookie_parse_error_string(COOKIE_PARSE_ERROR_INVALID_FORMAT));
  TEST_ASSERT_EQUAL_STRING(
      "Invalid name",
      cookie_parse_error_string(COOKIE_PARSE_ERROR_INVALID_NAME));
  TEST_ASSERT_EQUAL_STRING(
      "Out of memory", cookie_parse_error_string(COOKIE_PARSE_ERROR_MEMORY));
  TEST_ASSERT_EQUAL_STRING("Unknown error", cookie_parse_error_string(999));
}

void test_cookie_jar_binary_format(void)
{
  const char *test_file = "test_cookies_binary.dat";

  cookie_jar_add(test_jar, cookie_new("session", "abc123", "example.com", "/"));

  cookie_t *persistent =
      cookie_new("persistent", "value", ".example.com", "/app");
  cookie_set_expires(persistent, time(NULL) + 3600);
  cookie_set_secure(persistent, true);
  cookie_set_http_only(persistent, true);
  cookie_jar_add(test_jar, persistent);

  bool save_result = cookie_jar_save_binary(test_jar, test_file);
  if (!save_result)
  {
    return;
  }
  TEST_ASSERT_TRUE(save_result);

  cookie_jar_t *loaded_jar = cookie_jar_new();
  TEST_ASSERT_TRUE(cookie_jar_load_binary(loaded_jar, test_file));

  TEST_ASSERT_EQUAL(2, cookie_jar_count(loaded_jar));

  cookie_match_t *matches = cookie_jar_get_cookies_for_url(
      loaded_jar, "https://example.com/app", true);
  TEST_ASSERT_NOT_NULL(matches);

  bool found_persistent = false;
  cookie_match_t *current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "persistent") == 0)
    {
      found_persistent = true;
      TEST_ASSERT_EQUAL_STRING("value", current->cookie->value);
      TEST_ASSERT_EQUAL_STRING(".example.com", current->cookie->domain);
      TEST_ASSERT_EQUAL_STRING("/app", current->cookie->path);
      TEST_ASSERT_TRUE(cookie_is_secure(current->cookie));
      TEST_ASSERT_TRUE(cookie_is_http_only(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_persistent);

  cookie_match_free(matches);
  cookie_jar_free(loaded_jar);

  unlink(test_file);

  TEST_ASSERT_FALSE(cookie_jar_save_binary(NULL, test_file));
  TEST_ASSERT_FALSE(cookie_jar_save_binary(test_jar, NULL));
  TEST_ASSERT_FALSE(cookie_jar_load_binary(NULL, test_file));
  TEST_ASSERT_FALSE(cookie_jar_load_binary(test_jar, NULL));
}

void test_cookie_jar_binary_buffer(void)
{
  cookie_jar_add(test_jar, cookie_new("test", "value", "example.com", "/"));

  cookie_t *complex_cookie =
      cookie_new("complex", "data", ".example.com", "/api");
  cookie_set_expires(complex_cookie, time(NULL) + 7200);
  cookie_set_secure(complex_cookie, true);
  cookie_set_http_only(complex_cookie, true);
  cookie_set_samesite(complex_cookie, COOKIE_SAMESITE_STRICT);
  cookie_set_priority(complex_cookie, COOKIE_PRIORITY_HIGH);
  cookie_jar_add(test_jar, complex_cookie);

  size_t buffer_size;
  char *buffer = cookie_jar_save_binary_buffer(test_jar, &buffer_size);
  TEST_ASSERT_NOT_NULL(buffer);
  TEST_ASSERT_GREATER_THAN(0, buffer_size);

  uint32_t magic_value;
  memcpy(&magic_value, buffer, sizeof(magic_value));
  TEST_ASSERT_EQUAL_HEX32(0x52414A43, magic_value);

  cookie_jar_t *loaded_jar = cookie_jar_new();
  TEST_ASSERT_TRUE(
      cookie_jar_load_binary_buffer(loaded_jar, buffer, buffer_size));
  TEST_ASSERT_EQUAL(2, cookie_jar_count(loaded_jar));

  cookie_match_t *matches = cookie_jar_get_cookies_for_url(
      loaded_jar, "https://example.com/api", true);
  TEST_ASSERT_NOT_NULL(matches);

  bool found_complex = false;
  cookie_match_t *current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "complex") == 0)
    {
      found_complex = true;
      TEST_ASSERT_EQUAL_STRING("data", current->cookie->value);
      TEST_ASSERT_EQUAL_STRING(".example.com", current->cookie->domain);
      TEST_ASSERT_EQUAL_STRING("/api", current->cookie->path);
      TEST_ASSERT_TRUE(cookie_is_secure(current->cookie));
      TEST_ASSERT_TRUE(cookie_is_http_only(current->cookie));
      TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT,
                        cookie_get_samesite(current->cookie));
      TEST_ASSERT_EQUAL(COOKIE_PRIORITY_HIGH,
                        cookie_get_priority(current->cookie));
      TEST_ASSERT_FALSE(cookie_is_session(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_complex);

  cookie_match_free(matches);
  free(buffer);
  cookie_jar_free(loaded_jar);

  TEST_ASSERT_NULL(cookie_jar_save_binary_buffer(NULL, &buffer_size));
  TEST_ASSERT_NULL(cookie_jar_save_binary_buffer(test_jar, NULL));
  TEST_ASSERT_FALSE(cookie_jar_load_binary_buffer(NULL, "data", 4));
  TEST_ASSERT_FALSE(cookie_jar_load_binary_buffer(test_jar, NULL, 0));
}

void test_cookie_jar_binary_error_handling(void)
{
  const char invalid_data[] = "invalid binary data";
  TEST_ASSERT_FALSE(cookie_jar_load_binary_buffer(test_jar, invalid_data,
                                                  sizeof(invalid_data)));

  char truncated_header[10] = {0};
  TEST_ASSERT_FALSE(cookie_jar_load_binary_buffer(test_jar, truncated_header,
                                                  sizeof(truncated_header)));

  char wrong_magic[40] = {0};
  uint32_t magic = 0x12345678;
  memcpy(wrong_magic, &magic, sizeof(magic));
  TEST_ASSERT_FALSE(cookie_jar_load_binary_buffer(test_jar, wrong_magic,
                                                  sizeof(wrong_magic)));

  TEST_ASSERT_TRUE(
      cookie_jar_load_binary(test_jar, "/nonexistent/path/cookies.dat"));
}

void test_cookie_jar_binary_roundtrip(void)
{
  cookie_t *cookies[] = {
      cookie_new("session", "sess123", "example.com", "/"),
      cookie_new("persistent", "persist456", ".example.com", "/app"),
      cookie_new("secure_only", "secure789", "secure.example.com", "/"),
      cookie_new("httponly", "http012", "example.com", "/api")};

  cookie_set_expires(cookies[1], time(NULL) + 86400);
  cookie_set_secure(cookies[2], true);
  cookie_set_http_only(cookies[3], true);
  cookie_set_samesite(cookies[1], COOKIE_SAMESITE_STRICT);
  cookie_set_priority(cookies[2], COOKIE_PRIORITY_LOW);

  for (int i = 0; i < 4; i++)
  {
    TEST_ASSERT_TRUE(cookie_jar_add(test_jar, cookies[i]));
  }

  TEST_ASSERT_EQUAL(4, cookie_jar_count(test_jar));

  size_t buffer_size;
  char *buffer = cookie_jar_save_binary_buffer(test_jar, &buffer_size);
  TEST_ASSERT_NOT_NULL(buffer);

  cookie_jar_t *new_jar = cookie_jar_new();
  TEST_ASSERT_TRUE(cookie_jar_load_binary_buffer(new_jar, buffer, buffer_size));

  TEST_ASSERT_EQUAL(4, cookie_jar_count(new_jar));

  cookie_match_t *matches;

  matches =
      cookie_jar_get_cookies_for_url(new_jar, "http://example.com/", false);
  TEST_ASSERT_NOT_NULL(matches);
  bool found_session = false;
  cookie_match_t *current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "session") == 0)
    {
      found_session = true;
      TEST_ASSERT_TRUE(cookie_is_session(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_session);
  cookie_match_free(matches);

  matches = cookie_jar_get_cookies_for_url(new_jar,
                                           "http://www.example.com/app", false);
  TEST_ASSERT_NOT_NULL(matches);
  bool found_persistent = false;
  current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "persistent") == 0)
    {
      found_persistent = true;
      TEST_ASSERT_FALSE(cookie_is_session(current->cookie));
      TEST_ASSERT_EQUAL(COOKIE_SAMESITE_STRICT,
                        cookie_get_samesite(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_persistent);
  cookie_match_free(matches);

  matches = cookie_jar_get_cookies_for_url(
      new_jar, "https://secure.example.com/", false);
  TEST_ASSERT_NOT_NULL(matches);
  bool found_secure = false;
  current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "secure_only") == 0)
    {
      found_secure = true;
      TEST_ASSERT_TRUE(cookie_is_secure(current->cookie));
      TEST_ASSERT_EQUAL(COOKIE_PRIORITY_LOW,
                        cookie_get_priority(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_secure);
  cookie_match_free(matches);

  matches =
      cookie_jar_get_cookies_for_url(new_jar, "http://example.com/api", true);
  TEST_ASSERT_NOT_NULL(matches);
  bool found_httponly = false;
  current = matches;
  while (current)
  {
    if (strcmp(current->cookie->name, "httponly") == 0)
    {
      found_httponly = true;
      TEST_ASSERT_TRUE(cookie_is_http_only(current->cookie));
      break;
    }
    current = current->next;
  }
  TEST_ASSERT_TRUE(found_httponly);
  cookie_match_free(matches);

  free(buffer);
  cookie_jar_free(new_jar);
}

void test_cookie_full_workflow(void)
{
  cookie_t *session_cookie = NULL;
  cookie_parse_result_t result =
      cookie_parse_set_cookie("SESSIONID=xyz789; Path=/; HttpOnly; Secure; "
                              "SameSite=Strict; Max-Age=3600",
                              "https://example.com/login", &session_cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(session_cookie);

  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, session_cookie));

  cookie_t *pref_cookie = NULL;
  result = cookie_parse_set_cookie(
      "theme=dark; Domain=.example.com; Path=/; Max-Age=2592000",
      "https://www.example.com/settings", &pref_cookie);

  TEST_ASSERT_EQUAL(COOKIE_PARSE_SUCCESS, result);
  TEST_ASSERT_NOT_NULL(pref_cookie);
  TEST_ASSERT_TRUE(cookie_jar_add(test_jar, pref_cookie));

  cookie_match_t *matches = cookie_jar_get_cookies_for_url(
      test_jar, "https://example.com/dashboard", true);
  TEST_ASSERT_NOT_NULL(matches);

  char *cookie_header = cookie_match_to_header(matches);
  TEST_ASSERT_NOT_NULL(cookie_header);
  TEST_ASSERT_NOT_NULL(strstr(cookie_header, "SESSIONID=xyz789"));
  TEST_ASSERT_NOT_NULL(strstr(cookie_header, "theme=dark"));

  free(cookie_header);
  cookie_match_free(matches);

  TEST_ASSERT_TRUE(
      cookie_jar_remove(test_jar, "SESSIONID", "example.com", "/"));
  TEST_ASSERT_EQUAL(1, cookie_jar_count(test_jar));

  matches = cookie_jar_get_cookies_for_url(
      test_jar, "https://example.com/dashboard", false);
  if (matches)
  {
    cookie_header = cookie_match_to_header(matches);
    if (cookie_header)
    {
      TEST_ASSERT_NULL(strstr(cookie_header, "SESSIONID"));
      TEST_ASSERT_NOT_NULL(strstr(cookie_header, "theme=dark"));
      free(cookie_header);
    }
    cookie_match_free(matches);
  }
}

void test_cookie_complex_domain_scenarios(void)
{
  cookie_jar_add(test_jar,
                 cookie_new("host_only", "value1", "www.example.com", "/"));
  cookie_jar_add(test_jar,
                 cookie_new("domain_wide", "value2", ".example.com", "/"));
  cookie_jar_add(test_jar,
                 cookie_new("subdomain", "value3", "api.example.com", "/"));

  cookie_match_t *matches = cookie_jar_get_cookies_for_url(
      test_jar, "http://www.example.com/", false);
  TEST_ASSERT_NOT_NULL(matches);

  int count = 0;
  bool found_host_only = false, found_domain_wide = false,
       found_subdomain = false;

  cookie_match_t *current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "host_only") == 0)
      found_host_only = true;
    if (strcmp(current->cookie->name, "domain_wide") == 0)
      found_domain_wide = true;
    if (strcmp(current->cookie->name, "subdomain") == 0)
      found_subdomain = true;
    current = current->next;
  }

  TEST_ASSERT_EQUAL(2, count);
  TEST_ASSERT_TRUE(found_host_only);
  TEST_ASSERT_TRUE(found_domain_wide);
  TEST_ASSERT_FALSE(found_subdomain);

  cookie_match_free(matches);

  matches = cookie_jar_get_cookies_for_url(test_jar, "http://api.example.com/",
                                           false);
  count = 0;
  found_host_only = false;
  found_domain_wide = false;
  found_subdomain = false;

  current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "host_only") == 0)
      found_host_only = true;
    if (strcmp(current->cookie->name, "domain_wide") == 0)
      found_domain_wide = true;
    if (strcmp(current->cookie->name, "subdomain") == 0)
      found_subdomain = true;
    current = current->next;
  }

  TEST_ASSERT_EQUAL(2, count);
  TEST_ASSERT_FALSE(found_host_only);
  TEST_ASSERT_TRUE(found_domain_wide);
  TEST_ASSERT_TRUE(found_subdomain);

  cookie_match_free(matches);

  matches =
      cookie_jar_get_cookies_for_url(test_jar, "http://example.com/", false);
  count = 0;
  found_domain_wide = false;

  current = matches;
  while (current)
  {
    count++;
    if (strcmp(current->cookie->name, "domain_wide") == 0)
      found_domain_wide = true;
    current = current->next;
  }

  TEST_ASSERT_EQUAL(1, count);
  TEST_ASSERT_TRUE(found_domain_wide);

  cookie_match_free(matches);
}

void test_cookie_edge_cases(void)
{
  cookie_t *empty_value = cookie_new("empty", "", "example.com", "/");
  TEST_ASSERT_NOT_NULL(empty_value);
  TEST_ASSERT_EQUAL_STRING("", empty_value->value);
  cookie_free(empty_value);

  char long_value[4000];
  memset(long_value, 'A', sizeof(long_value) - 1);
  long_value[sizeof(long_value) - 1] = '\0';

  cookie_t *long_cookie = cookie_new("long", long_value, "example.com", "/");
  TEST_ASSERT_NOT_NULL(long_cookie);
  TEST_ASSERT_EQUAL_STRING(long_value, long_cookie->value);
  cookie_free(long_cookie);

  TEST_ASSERT_TRUE(cookie_path_matches("/", "/"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app", "/app"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app", "/app/"));
  TEST_ASSERT_TRUE(cookie_path_matches("/app/", "/app/sub"));
  TEST_ASSERT_FALSE(cookie_path_matches("/app", "/application"));

  cookie_t *expired = cookie_new("expired", "value", "example.com", "/");
  cookie_set_expires(expired, time(NULL) - 1);
  TEST_ASSERT_TRUE(cookie_is_expired(expired, time(NULL)));
  cookie_jar_add(test_jar, expired);
  TEST_ASSERT_EQUAL(1, cookie_jar_count(test_jar));

  size_t removed = cookie_jar_cleanup_expired(test_jar);
  TEST_ASSERT_EQUAL(1, removed);
  TEST_ASSERT_EQUAL(0, cookie_jar_count(test_jar));
}

int main(void)
{
  UNITY_BEGIN();

  RUN_TEST(test_cookie_new_and_free);
  RUN_TEST(test_cookie_clone);
  RUN_TEST(test_cookie_attributes);

  RUN_TEST(test_cookie_validation);

  RUN_TEST(test_cookie_jar_creation_and_config);
  RUN_TEST(test_cookie_jar_add_and_count);
  RUN_TEST(test_cookie_jar_remove);
  RUN_TEST(test_cookie_jar_clear);
  RUN_TEST(test_cookie_jar_cleanup_expired);
  RUN_TEST(test_cookie_jar_remove_session);

  RUN_TEST(test_cookie_domain_matching);
  RUN_TEST(test_cookie_path_matching);
  RUN_TEST(test_cookie_default_path);
  RUN_TEST(test_cookie_canonicalize_domain);
  RUN_TEST(test_cookie_public_suffix);

  RUN_TEST(test_cookie_parse_basic);
  RUN_TEST(test_cookie_parse_with_attributes);
  RUN_TEST(test_cookie_parse_expires_date);
  RUN_TEST(test_cookie_parse_max_age_priority);
  RUN_TEST(test_cookie_parse_samesite_variations);
  RUN_TEST(test_cookie_parse_priority_attribute);
  RUN_TEST(test_cookie_parse_security_validation);
  RUN_TEST(test_cookie_parse_domain_validation);
  RUN_TEST(test_cookie_parse_error_cases);

  RUN_TEST(test_cookie_jar_get_cookies_for_url);
  RUN_TEST(test_cookie_match_to_header);

  RUN_TEST(test_cookie_string_utilities);

  RUN_TEST(test_cookie_jar_binary_format);
  RUN_TEST(test_cookie_jar_binary_buffer);
  RUN_TEST(test_cookie_jar_binary_error_handling);
  RUN_TEST(test_cookie_jar_binary_roundtrip);

  RUN_TEST(test_cookie_full_workflow);
  RUN_TEST(test_cookie_complex_domain_scenarios);

  RUN_TEST(test_cookie_edge_cases);

  return UNITY_END();
}