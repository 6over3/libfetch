#include "../src/fetch.h"
#include "unity.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Platform-specific includes and definitions
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <process.h>
#include <io.h>

// Windows threading types and functions
typedef HANDLE pthread_t;
typedef struct
{
  HANDLE handle;
} pthread_mutex_t;

static int pthread_create(pthread_t *thread, void *attr, void *(*start_routine)(void *), void *arg)
{
  *thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start_routine, arg, 0, NULL);
  return (*thread == NULL) ? -1 : 0;
}

static int pthread_join(pthread_t thread, void **retval)
{
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  return 0;
}

static void usleep(int microseconds)
{
  Sleep(microseconds / 1000);
}

#define sleep(x) Sleep((x) * 1000)

#else
#include <pthread.h>
#include <unistd.h>
#endif

#if defined(LIBFETCH_TLS_ENABLED)
#define TARGET_URL "https://go-httpbin-production-9ac2.up.railway.app"
#else
#define TARGET_URL "http://localhost:8080"
#endif

#define BUILD_URL(route) TARGET_URL route
#define BUILD_URL_FMT(buffer, size, route, ...) \
  snprintf(buffer, size, TARGET_URL route __VA_OPT__(, ) __VA_ARGS__)

// ==================================================
// Simple test resource cleanup with ownership tracking
// ==================================================

typedef struct test_resource
{
  void *ptr;
  void (*free_func)(void *);
  struct test_resource *next;
} test_resource_t;

static test_resource_t *g_test_resources = NULL;

// Add resource to cleanup list
static void *track_resource(void *ptr, void (*free_func)(void *))
{
  if (!ptr)
    return NULL;

  test_resource_t *resource = malloc(sizeof(test_resource_t));
  resource->ptr = ptr;
  resource->free_func = free_func;
  resource->next = g_test_resources;
  g_test_resources = resource;

  return ptr;
}

// Remove resource from tracking (when ownership is transferred)
static void untrack_resource(void *ptr)
{
  test_resource_t **current = &g_test_resources;
  while (*current)
  {
    if ((*current)->ptr == ptr)
    {
      test_resource_t *to_remove = *current;
      *current = (*current)->next;
      free(to_remove);
      return;
    }
    current = &(*current)->next;
  }
}

// Clean up all tracked resources
static void cleanup_tracked_resources(void)
{
  while (g_test_resources)
  {
    test_resource_t *current = g_test_resources;
    g_test_resources = current->next;

    if (current->free_func && current->ptr)
    {
      current->free_func(current->ptr);
    }
    free(current);
  }
}

// Convenience macros for tracking resources
#define TRACK(ptr, free_func) track_resource(ptr, (void (*)(void *))free_func)
#define UNTRACK(ptr) untrack_resource(ptr)

// ==================================================
// Background thread management
// ==================================================

static pthread_t event_thread;
static volatile bool thread_running = false;
static volatile bool thread_should_stop = false;

static void *event_loop_thread(void *_)
{
  if (!fetch_event_loop_start())
  {
    return NULL;
  }

  thread_running = true;

  while (!thread_should_stop)
  {
    fetch_event_loop_process(100);
  }

  fetch_event_loop_stop();
  thread_running = false;
  return NULL;
}

static bool start_background_event_loop(void)
{
  if (thread_running)
    return true;

  thread_should_stop = false;
  if (pthread_create(&event_thread, NULL, event_loop_thread, NULL) != 0)
  {
    return false;
  }

  while (!thread_running)
  {
    usleep(10000);
  }

  return true;
}

static void stop_background_event_loop(void)
{
  if (!thread_running)
    return;

  thread_should_stop = true;
  pthread_join(event_thread, NULL);
}

// ==================================================
// Unity setUp/tearDown
// ==================================================

void setUp(void)
{
  fetch_global_init(NULL);
}

void tearDown(void)
{
  cleanup_tracked_resources();
  if (thread_running)
  {
    stop_background_event_loop();
  }
  fetch_disable_cookies();
  fetch_global_dispose();
}

// ==================================================
// Tests with automatic resource cleanup
// ==================================================

void test_fetch_method_to_string(void)
{
  TEST_ASSERT_EQUAL_STRING("GET", fetch_method_to_string(HTTP_METHOD_GET));
  TEST_ASSERT_EQUAL_STRING("POST", fetch_method_to_string(HTTP_METHOD_POST));
  TEST_ASSERT_EQUAL_STRING("PUT", fetch_method_to_string(HTTP_METHOD_PUT));
  TEST_ASSERT_EQUAL_STRING("DELETE", fetch_method_to_string(HTTP_METHOD_DELETE));
  TEST_ASSERT_EQUAL_STRING("PATCH", fetch_method_to_string(HTTP_METHOD_PATCH));
  TEST_ASSERT_EQUAL_STRING("HEAD", fetch_method_to_string(HTTP_METHOD_HEAD));
  TEST_ASSERT_EQUAL_STRING("OPTIONS", fetch_method_to_string(HTTP_METHOD_OPTIONS));
  TEST_ASSERT_EQUAL_STRING("TRACE", fetch_method_to_string(HTTP_METHOD_TRACE));
  TEST_ASSERT_EQUAL_STRING("CONNECT", fetch_method_to_string(HTTP_METHOD_CONNECT));
  TEST_ASSERT_EQUAL_STRING("GET", fetch_method_to_string(999));
}

void test_fetch_method_from_string(void)
{
  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, fetch_method_from_string("GET"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_POST, fetch_method_from_string("POST"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_PUT, fetch_method_from_string("PUT"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_DELETE, fetch_method_from_string("DELETE"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_PATCH, fetch_method_from_string("PATCH"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_HEAD, fetch_method_from_string("HEAD"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_OPTIONS, fetch_method_from_string("OPTIONS"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_TRACE, fetch_method_from_string("TRACE"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_CONNECT, fetch_method_from_string("CONNECT"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, fetch_method_from_string("get"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_POST, fetch_method_from_string("post"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_PUT, fetch_method_from_string("Put"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, fetch_method_from_string("INVALID"));
  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, fetch_method_from_string(NULL));
  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, fetch_method_from_string(""));
}

void test_fetch_is_valid_url(void)
{
  TEST_ASSERT_TRUE(fetch_is_valid_url("http://example.com"));
  TEST_ASSERT_TRUE(fetch_is_valid_url("http://api.example.com/data"));
  TEST_ASSERT_TRUE(fetch_is_valid_url(TARGET_URL));
  TEST_ASSERT_TRUE(fetch_is_valid_url("http://192.168.1.1:3000/api"));
  TEST_ASSERT_TRUE(fetch_is_valid_url("http://example.com/path?query=value"));
  TEST_ASSERT_TRUE(fetch_is_valid_url("http://example.com:80/path#fragment"));
  TEST_ASSERT_TRUE(fetch_is_valid_url("https://example.com"));
  TEST_ASSERT_TRUE(fetch_is_valid_url("ftp://example.com"));
  TEST_ASSERT_FALSE(fetch_is_valid_url("not-a-url"));
  TEST_ASSERT_FALSE(fetch_is_valid_url(""));
  TEST_ASSERT_FALSE(fetch_is_valid_url(NULL));
  TEST_ASSERT_FALSE(fetch_is_valid_url("://missing-protocol"));
  TEST_ASSERT_FALSE(fetch_is_valid_url("http://"));
}

void test_fetch_error_to_string(void)
{
  TEST_ASSERT_EQUAL_STRING("No error", fetch_error_to_string(FETCH_ERROR_NONE));
  TEST_ASSERT_EQUAL_STRING("Network error", fetch_error_to_string(FETCH_ERROR_NETWORK));
  TEST_ASSERT_EQUAL_STRING("Request timeout", fetch_error_to_string(FETCH_ERROR_TIMEOUT));
  TEST_ASSERT_EQUAL_STRING("Invalid URL", fetch_error_to_string(FETCH_ERROR_INVALID_URL));
  TEST_ASSERT_EQUAL_STRING("Invalid HTTP method", fetch_error_to_string(FETCH_ERROR_INVALID_METHOD));
  TEST_ASSERT_EQUAL_STRING("Invalid headers", fetch_error_to_string(FETCH_ERROR_INVALID_HEADERS));
  TEST_ASSERT_EQUAL_STRING("Out of memory", fetch_error_to_string(FETCH_ERROR_MEMORY));
  TEST_ASSERT_EQUAL_STRING("Request aborted", fetch_error_to_string(FETCH_ERROR_ABORTED));
  TEST_ASSERT_EQUAL_STRING("Too many redirects", fetch_error_to_string(FETCH_ERROR_TOO_MANY_REDIRECTS));
  TEST_ASSERT_EQUAL_STRING("Connection refused", fetch_error_to_string(FETCH_ERROR_CONNECTION_REFUSED));
  TEST_ASSERT_EQUAL_STRING("DNS resolution failed", fetch_error_to_string(FETCH_ERROR_DNS_RESOLUTION));
  TEST_ASSERT_EQUAL_STRING("HTTP protocol error", fetch_error_to_string(FETCH_ERROR_PROTOCOL_ERROR));
  TEST_ASSERT_EQUAL_STRING("Unknown error", fetch_error_to_string(999));
}

void test_fetch_headers_basic_operations(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  TEST_ASSERT_NOT_NULL(headers);
  TEST_ASSERT_EQUAL(0, headers->count);

  fetch_headers_append(headers, "Content-Type", "application/json");
  fetch_headers_append(headers, "User-Agent", "TestAgent/1.0");
  fetch_headers_append(headers, "Authorization", "Bearer token123");
  TEST_ASSERT_EQUAL(3, headers->count);

  const char *content_type = fetch_headers_get(headers, "Content-Type");
  TEST_ASSERT_NOT_NULL(content_type);
  TEST_ASSERT_EQUAL_STRING("application/json", content_type);

  const char *user_agent = fetch_headers_get(headers, "user-agent");
  TEST_ASSERT_NOT_NULL(user_agent);
  TEST_ASSERT_EQUAL_STRING("TestAgent/1.0", user_agent);

  const char *auth = fetch_headers_get(headers, "AUTHORIZATION");
  TEST_ASSERT_NOT_NULL(auth);
  TEST_ASSERT_EQUAL_STRING("Bearer token123", auth);

  TEST_ASSERT_TRUE(fetch_headers_has(headers, "Content-Type"));
  TEST_ASSERT_TRUE(fetch_headers_has(headers, "USER-AGENT"));
  TEST_ASSERT_TRUE(fetch_headers_has(headers, "authorization"));
  TEST_ASSERT_FALSE(fetch_headers_has(headers, "X-Custom-Header"));

  fetch_headers_set(headers, "Content-Type", "text/plain");
  const char *new_content_type = fetch_headers_get(headers, "Content-Type");
  TEST_ASSERT_EQUAL_STRING("text/plain", new_content_type);
  TEST_ASSERT_EQUAL(3, headers->count);

  fetch_headers_set(headers, "X-Custom", "custom-value");
  TEST_ASSERT_EQUAL(4, headers->count);
  TEST_ASSERT_EQUAL_STRING("custom-value", fetch_headers_get(headers, "X-Custom"));

  fetch_headers_delete(headers, "User-Agent");
  TEST_ASSERT_FALSE(fetch_headers_has(headers, "User-Agent"));
  TEST_ASSERT_EQUAL(3, headers->count);

  fetch_headers_delete(headers, "Non-Existent");
  TEST_ASSERT_EQUAL(3, headers->count);
}

void test_fetch_headers_iteration(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);

  fetch_headers_iterator_t empty_iter = fetch_headers_entries(headers);
  const char *key, *value;
  TEST_ASSERT_FALSE(fetch_headers_next(&empty_iter, &key, &value));

  fetch_headers_append(headers, "Header1", "Value1");
  fetch_headers_append(headers, "Header2", "Value2");
  fetch_headers_append(headers, "Header3", "Value3");

  fetch_headers_iterator_t iter = fetch_headers_entries(headers);
  int count = 0;
  bool found_header1 = false, found_header2 = false, found_header3 = false;

  while (fetch_headers_next(&iter, &key, &value))
  {
    TEST_ASSERT_NOT_NULL(key);
    TEST_ASSERT_NOT_NULL(value);

    if (strcmp(key, "Header1") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("Value1", value);
      found_header1 = true;
    }
    else if (strcmp(key, "Header2") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("Value2", value);
      found_header2 = true;
    }
    else if (strcmp(key, "Header3") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("Value3", value);
      found_header3 = true;
    }
    count++;
  }

  TEST_ASSERT_EQUAL(3, count);
  TEST_ASSERT_TRUE(found_header1);
  TEST_ASSERT_TRUE(found_header2);
  TEST_ASSERT_TRUE(found_header3);
}

void test_fetch_headers_null_safety(void)
{
  fetch_headers_append(NULL, "Key", "Value");
  fetch_headers_set(NULL, "Key", "Value");
  fetch_headers_delete(NULL, "Key");

  TEST_ASSERT_NULL(fetch_headers_get(NULL, "Key"));
  TEST_ASSERT_FALSE(fetch_headers_has(NULL, "Key"));

  fetch_headers_free(NULL);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_append(headers, NULL, "Value");
  fetch_headers_append(headers, "Key", NULL);
  fetch_headers_append(headers, NULL, NULL);
  TEST_ASSERT_EQUAL(0, headers->count);

  fetch_headers_set(headers, NULL, "Value");
  fetch_headers_set(headers, "Key", NULL);
  TEST_ASSERT_EQUAL(0, headers->count);

  fetch_headers_delete(headers, NULL);

  TEST_ASSERT_NULL(fetch_headers_get(headers, NULL));
  TEST_ASSERT_FALSE(fetch_headers_has(headers, NULL));
}

void test_fetch_headers_case_sensitivity(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);

  fetch_headers_set(headers, "Content-Type", "application/json");

  TEST_ASSERT_EQUAL_STRING("application/json", fetch_headers_get(headers, "Content-Type"));
  TEST_ASSERT_EQUAL_STRING("application/json", fetch_headers_get(headers, "content-type"));
  TEST_ASSERT_EQUAL_STRING("application/json", fetch_headers_get(headers, "CONTENT-TYPE"));
  TEST_ASSERT_EQUAL_STRING("application/json", fetch_headers_get(headers, "Content-type"));

  fetch_headers_set(headers, "CONTENT-TYPE", "text/plain");
  TEST_ASSERT_EQUAL_STRING("text/plain", fetch_headers_get(headers, "content-type"));
  TEST_ASSERT_EQUAL(1, headers->count);
}

void test_fetch_body_text(void)
{
  const char *text = "Hello, World!";
  fetch_body_t *body = TRACK(fetch_body_text(text), fetch_body_free);

  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_TEXT, body->type);
  TEST_ASSERT_EQUAL(strlen(text), body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("text/plain; charset=utf-8", body->content_type);
  TEST_ASSERT_EQUAL_STRING(text, (const char *)body->data.memory.data);

  body = TRACK(fetch_body_text(""), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(0, body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("", (const char *)body->data.memory.data);
}

void test_fetch_body_json(void)
{
  const char *json = "{\"message\": \"Hello, World!\", \"number\": 42}";
  fetch_body_t *body = TRACK(fetch_body_json(json), fetch_body_free);

  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_JSON, body->type);
  TEST_ASSERT_EQUAL(strlen(json), body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("application/json; charset=utf-8", body->content_type);
  TEST_ASSERT_EQUAL_STRING(json, (const char *)body->data.memory.data);
}

void test_fetch_body_binary(void)
{
  const uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0xFF, 0x42};
  fetch_body_t *body = TRACK(fetch_body_binary(data, sizeof(data), "application/octet-stream"), fetch_body_free);

  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_BINARY, body->type);
  TEST_ASSERT_EQUAL(sizeof(data), body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("application/octet-stream", body->content_type);
  TEST_ASSERT_EQUAL_MEMORY(data, body->data.memory.data, sizeof(data));

  body = TRACK(fetch_body_binary(data, sizeof(data), "image/png"), fetch_body_free);
  TEST_ASSERT_EQUAL_STRING("image/png", body->content_type);

  body = TRACK(fetch_body_binary(data, sizeof(data), NULL), fetch_body_free);
  TEST_ASSERT_EQUAL_STRING("application/octet-stream", body->content_type);
}

void test_fetch_body_form_data(void)
{
  const char *form = "name=John+Doe&age=30&city=New+York&email=john%40example.com";
  fetch_body_t *body = TRACK(fetch_body_form_data(form), fetch_body_free);

  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FORM_DATA, body->type);
  TEST_ASSERT_EQUAL(strlen(form), body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", body->content_type);
  TEST_ASSERT_EQUAL_STRING(form, (const char *)body->data.memory.data);
}

void test_fetch_body_null_safety(void)
{
  TEST_ASSERT_NULL(fetch_body_text(NULL));
  TEST_ASSERT_NULL(fetch_body_json(NULL));
  TEST_ASSERT_NULL(fetch_body_binary(NULL, 10, "type"));
  TEST_ASSERT_NULL(fetch_body_binary("data", 0, "type"));
  TEST_ASSERT_NULL(fetch_body_form_data(NULL));

  fetch_body_free(NULL);
}

void test_fetch_init_new_and_free(void)
{
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  TEST_ASSERT_NOT_NULL(init);

  TEST_ASSERT_EQUAL(HTTP_METHOD_GET, init->method);
  TEST_ASSERT_EQUAL(FETCH_MODE_NO_CORS, init->mode);
  TEST_ASSERT_EQUAL(FETCH_CREDENTIALS_INCLUDE, init->credentials);
  TEST_ASSERT_EQUAL(FETCH_CACHE_DEFAULT, init->cache);
  TEST_ASSERT_EQUAL(FETCH_REDIRECT_FOLLOW, init->redirect);
  TEST_ASSERT_TRUE(init->keepalive);
  TEST_ASSERT_EQUAL(30000, init->timeout_ms);
  TEST_ASSERT_EQUAL(20, init->max_redirects);
  TEST_ASSERT_NULL(init->headers);
  TEST_ASSERT_NULL(init->body);
  TEST_ASSERT_NULL(init->signal);

  fetch_init_free(NULL);
}

void test_fetch_init_fluent_interface(void)
{
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Authorization", "Bearer token");
  fetch_body_t *body = TRACK(fetch_body_json("{\"test\": true}"), fetch_body_free);
  fetch_abort_controller_t *controller = TRACK(fetch_abort_controller_new(), fetch_abort_controller_free);

  TEST_ASSERT_EQUAL(init, fetch_init_method(init, HTTP_METHOD_POST));
  TEST_ASSERT_EQUAL(HTTP_METHOD_POST, init->method);

  TEST_ASSERT_EQUAL(init, fetch_init_headers(init, headers));
  TEST_ASSERT_EQUAL(headers, init->headers);
  UNTRACK(headers); // init now owns headers

  TEST_ASSERT_EQUAL(init, fetch_init_body(init, body));
  TEST_ASSERT_EQUAL(body, init->body);
  UNTRACK(body); // init now owns body

  TEST_ASSERT_EQUAL(init, fetch_init_timeout(init, 5000));
  TEST_ASSERT_EQUAL(5000, init->timeout_ms);

  TEST_ASSERT_EQUAL(init, fetch_init_signal(init, controller));
  TEST_ASSERT_EQUAL(controller, init->signal);
  UNTRACK(controller); // init now owns controller

  fetch_init_t *init2 = TRACK(fetch_init_new(), fetch_init_free);
  fetch_headers_t *headers2 = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_body_t *body2 = TRACK(fetch_body_text("test"), fetch_body_free);

  fetch_init_t *result = fetch_init_method(
      fetch_init_timeout(
          fetch_init_headers(fetch_init_body(init2, body2), headers2), 10000),
      HTTP_METHOD_PUT);

  TEST_ASSERT_EQUAL(init2, result);
  TEST_ASSERT_EQUAL(HTTP_METHOD_PUT, init2->method);
  TEST_ASSERT_EQUAL(10000, init2->timeout_ms);
  TEST_ASSERT_EQUAL(headers2, init2->headers);
  TEST_ASSERT_EQUAL(body2, init2->body);

  // Untrack resources that init2 now owns
  UNTRACK(headers2);
  UNTRACK(body2);
}

void test_fetch_init_null_safety(void)
{
  TEST_ASSERT_NULL(fetch_init_method(NULL, HTTP_METHOD_POST));
  TEST_ASSERT_NULL(fetch_init_headers(NULL, NULL));
  TEST_ASSERT_NULL(fetch_init_body(NULL, NULL));
  TEST_ASSERT_NULL(fetch_init_timeout(NULL, 1000));
  TEST_ASSERT_NULL(fetch_init_signal(NULL, NULL));
}

static bool abort_callback_called = false;
static void *abort_callback_userdata = NULL;

static void test_abort_callback(void *userdata)
{
  abort_callback_called = true;
  abort_callback_userdata = userdata;
}

void test_fetch_abort_controller(void)
{
  abort_callback_called = false;
  abort_callback_userdata = NULL;

  fetch_abort_controller_t *controller = TRACK(fetch_abort_controller_new(), fetch_abort_controller_free);
  TEST_ASSERT_NOT_NULL(controller);
  TEST_ASSERT_FALSE(fetch_abort_controller_aborted(controller));
  TEST_ASSERT_FALSE(controller->aborted);
  TEST_ASSERT_NULL(controller->reason);

  controller->on_abort = test_abort_callback;
  controller->userdata = "test_data";

  fetch_abort_controller_abort(controller, "Test abort reason");
  TEST_ASSERT_TRUE(fetch_abort_controller_aborted(controller));
  TEST_ASSERT_TRUE(controller->aborted);
  TEST_ASSERT_EQUAL_STRING("Test abort reason", controller->reason);
  TEST_ASSERT_TRUE(abort_callback_called);
  TEST_ASSERT_EQUAL_STRING("test_data", (const char *)abort_callback_userdata);

  abort_callback_called = false;
  controller = TRACK(fetch_abort_controller_new(), fetch_abort_controller_free);
  controller->on_abort = test_abort_callback;

  fetch_abort_controller_abort(controller, NULL);
  TEST_ASSERT_TRUE(fetch_abort_controller_aborted(controller));
  TEST_ASSERT_EQUAL_STRING("Operation aborted", controller->reason);
  TEST_ASSERT_TRUE(abort_callback_called);

  fetch_abort_controller_free(NULL);
}

void test_fetch_abort_controller_null_safety(void)
{
  TEST_ASSERT_FALSE(fetch_abort_controller_aborted(NULL));
  fetch_abort_controller_abort(NULL, "test");
  fetch_abort_controller_free(NULL);
}

void test_fetch_event_loop_control(void)
{
  bool started = fetch_event_loop_start();
  TEST_ASSERT_TRUE(started);
  TEST_ASSERT_TRUE(fetch_event_loop_is_running());

  bool started_again = fetch_event_loop_start();
  TEST_ASSERT_TRUE(started_again);
  TEST_ASSERT_TRUE(fetch_event_loop_is_running());

  int events = fetch_event_loop_process(0);
  TEST_ASSERT_GREATER_OR_EQUAL(0, events);

  fetch_event_loop_stop();
  TEST_ASSERT_FALSE(fetch_event_loop_is_running());

  fetch_event_loop_stop();
  TEST_ASSERT_FALSE(fetch_event_loop_is_running());

  events = fetch_event_loop_process(0);
  TEST_ASSERT_EQUAL(-1, events);
}

void test_fetch_invalid_parameters(void)
{
  fetch_response_t *response = TRACK(fetch(NULL, NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_URL, response->error);
  TEST_ASSERT_FALSE(fetch_response_ok(response));

  response = TRACK(fetch("", NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_URL, response->error);

  response = TRACK(fetch("not-a-valid-url", NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_URL, response->error);

  response = TRACK(fetch("ftp://example.com", NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_URL, response->error);
}

void test_fetch_method_validation(void)
{
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);

  init->method = HTTP_METHOD_GET;
  fetch_body_t *body = TRACK(fetch_body_text("test body"), fetch_body_free);
  init->body = body;
  UNTRACK(body); // init now owns the body

  fetch_response_t *response = TRACK(fetch("http://example.com", init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_METHOD, response->error);

  // Create new init for second test since the first one consumed the body
  init = TRACK(fetch_init_new(), fetch_init_free);
  init->method = HTTP_METHOD_HEAD;
  body = TRACK(fetch_body_text("test body"), fetch_body_free);
  init->body = body;
  UNTRACK(body); // init now owns the body

  response = TRACK(fetch("http://example.com", init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_METHOD, response->error);
}

void test_fetch_timeout_configuration(void)
{
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);

  fetch_init_timeout(init, 1000);
  TEST_ASSERT_EQUAL(1000, init->timeout_ms);

  fetch_init_timeout(init, 0);
  TEST_ASSERT_EQUAL(0, init->timeout_ms);
}

void test_fetch_async_basic_lifecycle(void)
{
  #if defined(LIBFETCH_TLS_ENABLED)
  #define GOOGLE_URL "https://google.com"
  #else
  #define GOOGLE_URL "http://google.com"
  #endif
  fetch_promise_t *promise = TRACK(fetch_async(GOOGLE_URL, NULL), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  TEST_ASSERT_EQUAL(FETCH_PROMISE_PENDING, fetch_promise_state(promise));
  TEST_ASSERT_TRUE(fetch_promise_pending(promise));
  TEST_ASSERT_FALSE(fetch_promise_fulfilled(promise));
  TEST_ASSERT_FALSE(fetch_promise_rejected(promise));
  TEST_ASSERT_FALSE(fetch_promise_cancelled(promise));

  fetch_event_loop_process(1000);

  bool immediate_result = fetch_promise_poll(promise);
  TEST_ASSERT_FALSE(immediate_result);

  bool completed = fetch_promise_await(promise, 10000);
  TEST_ASSERT_TRUE(completed);

  TEST_ASSERT_NOT_EQUAL(FETCH_PROMISE_PENDING, fetch_promise_state(promise));
  TEST_ASSERT_FALSE(fetch_promise_pending(promise));
  TEST_ASSERT_TRUE(fetch_promise_poll(promise));


  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));
  TEST_ASSERT_EQUAL(FETCH_ERROR_NONE, fetch_promise_error(promise));
  TEST_ASSERT_NULL(fetch_promise_error_message(promise));

  fetch_response_t *response = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));
  TEST_ASSERT_TRUE(fetch_response_ok(response));

  printf("Response URL: %s\n", fetch_response_url(response));
  printf("Response Status: %d %s\n", fetch_response_status(response), fetch_response_status_text(response));
  printf("Response Headers:\n");
  fetch_headers_t *headers = fetch_response_headers(response);
  fetch_headers_iterator_t iter = fetch_headers_entries(headers);
  const char *key, *value;
  while (fetch_headers_next(&iter, &key, &value))
  {
    printf("  %s: %s\n", key, value);
  }
  #undef GOOGLE_URL
}

void test_fetch_async_invalid_url(void)
{
  fetch_promise_t *promise = TRACK(fetch_async("invalid-url", NULL), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);
  TEST_ASSERT_EQUAL(FETCH_PROMISE_REJECTED, fetch_promise_state(promise));
  TEST_ASSERT_EQUAL(FETCH_ERROR_INVALID_URL, fetch_promise_error(promise));
  TEST_ASSERT_NOT_NULL(fetch_promise_error_message(promise));
  TEST_ASSERT_TRUE(fetch_promise_rejected(promise));
  TEST_ASSERT_FALSE(fetch_promise_pending(promise));
  TEST_ASSERT_FALSE(fetch_promise_fulfilled(promise));
}

void test_fetch_async_cancellation(void)
{
  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/delay/5"), NULL), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  bool cancelled = fetch_promise_cancel(promise, "Test cancellation");

  if (cancelled)
  {
    TEST_ASSERT_TRUE(fetch_promise_cancelled(promise));
    TEST_ASSERT_EQUAL(FETCH_PROMISE_REJECTED, fetch_promise_state(promise));
    TEST_ASSERT_EQUAL(FETCH_ERROR_ABORTED, fetch_promise_error(promise));
    TEST_ASSERT_NOT_NULL(fetch_promise_error_message(promise));
  }

  bool cancelled_again = fetch_promise_cancel(promise, "Second cancel");
  TEST_ASSERT_FALSE(cancelled_again);
}

void test_fetch_async_null_safety(void)
{
  TEST_ASSERT_NULL(fetch_promise_response(NULL));
  TEST_ASSERT_EQUAL(FETCH_PROMISE_REJECTED, fetch_promise_state(NULL));
  TEST_ASSERT_EQUAL(FETCH_ERROR_NONE, fetch_promise_error(NULL));
  TEST_ASSERT_NULL(fetch_promise_error_message(NULL));
  TEST_ASSERT_FALSE(fetch_promise_pending(NULL));
  TEST_ASSERT_FALSE(fetch_promise_fulfilled(NULL));
  TEST_ASSERT_FALSE(fetch_promise_rejected(NULL));
  TEST_ASSERT_FALSE(fetch_promise_cancelled(NULL));
  TEST_ASSERT_FALSE(fetch_promise_poll(NULL));
  TEST_ASSERT_FALSE(fetch_promise_await(NULL, 1000));
  TEST_ASSERT_FALSE(fetch_promise_cancel(NULL, "test"));

  fetch_promise_free(NULL);
}

void test_response_accessor_null_safety(void)
{
  TEST_ASSERT_FALSE(fetch_response_ok(NULL));
  TEST_ASSERT_EQUAL(0, fetch_response_status(NULL));
  TEST_ASSERT_NULL(fetch_response_status_text(NULL));
  TEST_ASSERT_NULL(fetch_response_url(NULL));
  TEST_ASSERT_NULL(fetch_response_headers(NULL));
  TEST_ASSERT_NULL(fetch_response_text(NULL));
  TEST_ASSERT_NULL(fetch_response_json(NULL));

  size_t size;
  TEST_ASSERT_NULL(fetch_response_array_buffer(NULL, &size));
  TEST_ASSERT_NULL(fetch_response_array_buffer(NULL, NULL));

  fetch_response_free(NULL);
}

void test_fetch_global_configuration(void)
{
  fetch_config_t config = {.default_timeout_ms = 5000,
                           .max_connections = 500,
                           .user_agent = "TestAgent/2.0"};

  fetch_config_set_flag(&config, FETCH_FLAG_KEEP_ALIVE_DEFAULT, true);
  fetch_global_dispose();
  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  TEST_ASSERT_EQUAL(5000, init->timeout_ms);
  TEST_ASSERT_TRUE(init->keepalive);

  fetch_global_dispose();
  fetch_global_init(NULL);

  init = TRACK(fetch_init_new(), fetch_init_free);
  TEST_ASSERT_EQUAL(30000, init->timeout_ms);
  TEST_ASSERT_TRUE(init->keepalive);
}

void test_complete_post_request_flow(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/json");
  fetch_headers_set(headers, "User-Agent", "FetchLibrary/2.0 Test");
  fetch_headers_set(headers, "Accept", "application/json");

  fetch_body_t *body = TRACK(fetch_body_json("{\"name\": \"test\", \"value\": 42, \"active\": true}"), fetch_body_free);
  fetch_abort_controller_t *controller = TRACK(fetch_abort_controller_new(), fetch_abort_controller_free);
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);

  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 10000);
  fetch_init_signal(init, controller);
  UNTRACK(controller); // init now owns controller

  TEST_ASSERT_EQUAL(HTTP_METHOD_POST, init->method);
  TEST_ASSERT_EQUAL(headers, init->headers);
  TEST_ASSERT_EQUAL(body, init->body);
  TEST_ASSERT_EQUAL(10000, init->timeout_ms);
  TEST_ASSERT_EQUAL(controller, init->signal);

  TEST_ASSERT_EQUAL_STRING("application/json", fetch_headers_get(init->headers, "Content-Type"));
  TEST_ASSERT_EQUAL_STRING("FetchLibrary/2.0 Test", fetch_headers_get(init->headers, "User-Agent"));

  TEST_ASSERT_EQUAL(FETCH_BODY_JSON, init->body->type);
  TEST_ASSERT_GREATER_THAN(0, init->body->data.memory.size);
}

void test_convenience_macros(void)
{
#ifdef FETCH_GET
  TEST_ASSERT_TRUE(true);
#endif

#ifdef FETCH_ASYNC_GET
  TEST_ASSERT_TRUE(true);
#endif

  TEST_ASSERT_EQUAL(0, FETCH_TIMEOUT_INFINITE);
  TEST_ASSERT_EQUAL(30000, FETCH_TIMEOUT_DEFAULT);
  TEST_ASSERT_EQUAL(5000, FETCH_TIMEOUT_SHORT);
  TEST_ASSERT_EQUAL(60000, FETCH_TIMEOUT_LONG);
}

void test_multiple_headers_same_name(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);

  fetch_headers_append(headers, "X-Custom", "value1");
  fetch_headers_append(headers, "X-Custom", "value2");
  fetch_headers_append(headers, "X-Custom", "value3");

  TEST_ASSERT_EQUAL(3, headers->count);

  const char *value = fetch_headers_get(headers, "X-Custom");
  TEST_ASSERT_EQUAL_STRING("value1", value);

  fetch_headers_set(headers, "X-Custom", "new_value");
  value = fetch_headers_get(headers, "X-Custom");
  TEST_ASSERT_EQUAL_STRING("new_value", value);
  TEST_ASSERT_EQUAL(3, headers->count);
}

void test_large_headers_and_body(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  for (int i = 0; i < 100; i++)
  {
    char key[32], value[64];
    snprintf(key, sizeof(key), "Header-%d", i);
    snprintf(value, sizeof(value), "Value-%d-with-some-longer-content", i);
    fetch_headers_append(headers, key, value);
  }

  TEST_ASSERT_EQUAL(100, headers->count);

  TEST_ASSERT_EQUAL_STRING("Value-50-with-some-longer-content", fetch_headers_get(headers, "Header-50"));
  TEST_ASSERT_EQUAL_STRING("Value-99-with-some-longer-content", fetch_headers_get(headers, "Header-99"));

  size_t body_size = 100 * 1024;
  char *large_body = TRACK(malloc(body_size), free);
  memset(large_body, 'A', body_size - 1);
  large_body[body_size - 1] = '\0';

  fetch_body_t *body = TRACK(fetch_body_text(large_body), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(body_size - 1, body->data.memory.size);
}

void test_empty_and_whitespace_headers(void)
{
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);

  fetch_headers_set(headers, "  Spaced-Header  ", "  spaced value  ");
  fetch_headers_set(headers, "Normal-Header", "normal value");

  TEST_ASSERT_GREATER_OR_EQUAL(1, headers->count);
}

void test_concurrent_async_requests(void)
{
#define NUM_REQUESTS 4
  fetch_promise_t *promises[NUM_REQUESTS];
  bool request_completed[NUM_REQUESTS];

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    request_completed[i] = false;
  }

  const char *urls[4] = {
      BUILD_URL("/get"),
      BUILD_URL("/uuid"),
      BUILD_URL("/base64/aGVsbG8gd29ybGQ%3D"),
      BUILD_URL("/user-agent")};

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
    fetch_init_timeout(init, 15000);
    promises[i] = TRACK(fetch_async(urls[i], init), fetch_promise_free);
    TEST_ASSERT_NOT_NULL(promises[i]);
  }

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    TEST_ASSERT_EQUAL(FETCH_PROMISE_PENDING, fetch_promise_state(promises[i]));
  }

  int completed = 0;
  int successful = 0;
  int failed = 0;
  time_t start = time(NULL);
  const int timeout_seconds = 20;

  while (completed < NUM_REQUESTS && (time(NULL) - start) < timeout_seconds)
  {
    fetch_event_loop_process(10);

    for (int i = 0; i < NUM_REQUESTS; i++)
    {
      if (request_completed[i])
        continue;

      fetch_promise_state_t state = fetch_promise_state(promises[i]);

      if (state != FETCH_PROMISE_PENDING)
      {
        request_completed[i] = true;
        completed++;

        if (state == FETCH_PROMISE_FULFILLED)
        {
          successful++;
          fetch_response_t *response = fetch_promise_response(promises[i]);
          TEST_ASSERT_NOT_NULL(response);

          if (fetch_response_ok(response))
          {
            printf("Request %d to %s completed successfully\n", i, urls[i]);
          }
          else
          {
            printf("Request %d to %s completed but response not OK (status: %d)\n",
                   i, urls[i], fetch_response_status(response));
            successful--;
            failed++;
          }
        }
        else if (state == FETCH_PROMISE_REJECTED)
        {
          failed++;
          printf("Request %d to %s failed/rejected\n", i, urls[i]);
          printf("Error: %s\n",
                 fetch_promise_error_message(promises[i]) ? fetch_promise_error_message(promises[i]) : "Unknown error");
        }
      }
    }

    usleep(1000);
  }

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    if (!request_completed[i] && fetch_promise_state(promises[i]) == FETCH_PROMISE_PENDING)
    {
      fetch_promise_cancel(promises[i], "Test cleanup - timeout");
      printf("Request %d to %s timed out and was cancelled\n", i, urls[i]);
    }
  }

  printf("Completed: %d, Successful: %d, Failed: %d, Total: %d\n",
         completed, successful, failed, NUM_REQUESTS);

  TEST_ASSERT_EQUAL_MESSAGE(NUM_REQUESTS, completed, "Not all requests completed within timeout");
  TEST_ASSERT_EQUAL_MESSAGE(NUM_REQUESTS, successful, "Not all requests completed successfully");

#undef NUM_REQUESTS
}

void test_fetch_url_search_params_basic_operations(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);
  TEST_ASSERT_NOT_NULL(params);
  TEST_ASSERT_EQUAL(0, params->count);

  fetch_url_search_params_append(params, "name", "John Doe");
  fetch_url_search_params_append(params, "age", "30");
  fetch_url_search_params_append(params, "city", "New York");
  TEST_ASSERT_EQUAL(3, params->count);

  const char *name = fetch_url_search_params_get(params, "name");
  TEST_ASSERT_NOT_NULL(name);
  TEST_ASSERT_EQUAL_STRING("John Doe", name);

  const char *age = fetch_url_search_params_get(params, "age");
  TEST_ASSERT_NOT_NULL(age);
  TEST_ASSERT_EQUAL_STRING("30", age);

  TEST_ASSERT_TRUE(fetch_url_search_params_has(params, "name"));
  TEST_ASSERT_TRUE(fetch_url_search_params_has(params, "age"));
  TEST_ASSERT_TRUE(fetch_url_search_params_has(params, "city"));
  TEST_ASSERT_FALSE(fetch_url_search_params_has(params, "email"));

  fetch_url_search_params_set(params, "age", "31");
  const char *new_age = fetch_url_search_params_get(params, "age");
  TEST_ASSERT_EQUAL_STRING("31", new_age);
  TEST_ASSERT_EQUAL(3, params->count);

  fetch_url_search_params_set(params, "email", "john@example.com");
  TEST_ASSERT_EQUAL(4, params->count);
  TEST_ASSERT_EQUAL_STRING("john@example.com", fetch_url_search_params_get(params, "email"));

  fetch_url_search_params_delete(params, "city");
  TEST_ASSERT_FALSE(fetch_url_search_params_has(params, "city"));
  TEST_ASSERT_EQUAL(3, params->count);

  fetch_url_search_params_delete(params, "non-existent");
  TEST_ASSERT_EQUAL(3, params->count);
}

void test_fetch_url_search_params_duplicate_keys(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  fetch_url_search_params_append(params, "hobby", "reading");
  fetch_url_search_params_append(params, "hobby", "swimming");
  fetch_url_search_params_append(params, "hobby", "coding");
  TEST_ASSERT_EQUAL(3, params->count);

  const char *hobby = fetch_url_search_params_get(params, "hobby");
  TEST_ASSERT_EQUAL_STRING("reading", hobby);

  fetch_url_search_params_set(params, "hobby", "gaming");
  hobby = fetch_url_search_params_get(params, "hobby");
  TEST_ASSERT_EQUAL_STRING("gaming", hobby);
  TEST_ASSERT_EQUAL(3, params->count);

  fetch_url_search_params_delete(params, "hobby");
  TEST_ASSERT_FALSE(fetch_url_search_params_has(params, "hobby"));
  TEST_ASSERT_EQUAL(0, params->count);
}

void test_fetch_url_search_params_to_string(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  char *empty_string = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(empty_string);
  TEST_ASSERT_EQUAL_STRING("", empty_string);
  TRACK(empty_string, free);

  fetch_url_search_params_append(params, "name", "John");
  char *single_string = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(single_string);
  TEST_ASSERT_EQUAL_STRING("name=John", single_string);
  TRACK(single_string, free);

  fetch_url_search_params_append(params, "age", "30");
  fetch_url_search_params_append(params, "city", "New York");
  char *multi_string = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(multi_string);
  TEST_ASSERT_EQUAL_STRING("name=John&age=30&city=New%20York", multi_string);
  TRACK(multi_string, free);
}

void test_fetch_url_search_params_url_encoding(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  fetch_url_search_params_append(params, "message", "Hello World!");
  fetch_url_search_params_append(params, "email", "user@example.com");
  fetch_url_search_params_append(params, "symbols", "100% & more");
  fetch_url_search_params_append(params, "unicode", "café");

  char *encoded_string = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(encoded_string);

  TEST_ASSERT_NOT_NULL(strstr(encoded_string, "message=Hello%20World%21"));
  TEST_ASSERT_NOT_NULL(strstr(encoded_string, "email=user%40example.com"));
  TEST_ASSERT_NOT_NULL(strstr(encoded_string, "symbols=100%25%20%26%20more"));

  TRACK(encoded_string, free);
}

void test_fetch_url_search_params_iteration(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  fetch_url_search_params_iterator_t empty_iter = fetch_url_search_params_entries(params);
  const char *key, *value;
  TEST_ASSERT_FALSE(fetch_url_search_params_next(&empty_iter, &key, &value));

  fetch_url_search_params_append(params, "param1", "value1");
  fetch_url_search_params_append(params, "param2", "value2");
  fetch_url_search_params_append(params, "param3", "value3");

  fetch_url_search_params_iterator_t iter = fetch_url_search_params_entries(params);
  int count = 0;
  bool found_param1 = false, found_param2 = false, found_param3 = false;

  while (fetch_url_search_params_next(&iter, &key, &value))
  {
    TEST_ASSERT_NOT_NULL(key);
    TEST_ASSERT_NOT_NULL(value);

    if (strcmp(key, "param1") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("value1", value);
      found_param1 = true;
    }
    else if (strcmp(key, "param2") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("value2", value);
      found_param2 = true;
    }
    else if (strcmp(key, "param3") == 0)
    {
      TEST_ASSERT_EQUAL_STRING("value3", value);
      found_param3 = true;
    }
    count++;
  }

  TEST_ASSERT_EQUAL(3, count);
  TEST_ASSERT_TRUE(found_param1);
  TEST_ASSERT_TRUE(found_param2);
  TEST_ASSERT_TRUE(found_param3);
}

void test_fetch_url_search_params_null_safety(void)
{
  char *result = fetch_url_search_params_to_string(NULL);
  TEST_ASSERT_NULL(result);

  fetch_url_search_params_append(NULL, "key", "value");
  fetch_url_search_params_set(NULL, "key", "value");
  fetch_url_search_params_delete(NULL, "key");

  TEST_ASSERT_NULL(fetch_url_search_params_get(NULL, "key"));
  TEST_ASSERT_FALSE(fetch_url_search_params_has(NULL, "key"));
  TEST_ASSERT_NULL(fetch_body_url_search_params(NULL));

  fetch_url_search_params_free(NULL);

  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);
  fetch_url_search_params_append(params, NULL, "value");
  fetch_url_search_params_append(params, "key", NULL);
  fetch_url_search_params_append(params, NULL, NULL);
  TEST_ASSERT_EQUAL(0, params->count);

  fetch_url_search_params_set(params, NULL, "value");
  fetch_url_search_params_set(params, "key", NULL);
  TEST_ASSERT_EQUAL(0, params->count);

  fetch_url_search_params_delete(params, NULL);

  TEST_ASSERT_NULL(fetch_url_search_params_get(params, NULL));
  TEST_ASSERT_FALSE(fetch_url_search_params_has(params, NULL));

  char *empty_result = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(empty_result);
  TEST_ASSERT_EQUAL_STRING("", empty_result);
  TRACK(empty_result, free);
}

void test_fetch_body_url_search_params(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  fetch_url_search_params_append(params, "name", "John Doe");
  fetch_url_search_params_append(params, "age", "30");
  fetch_url_search_params_append(params, "city", "New York");

  fetch_body_t *body = TRACK(fetch_body_url_search_params(params), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FORM_DATA, body->type);
  TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", body->content_type);
  TEST_ASSERT_GREATER_THAN(0, body->data.memory.size);

  const char *body_str = (const char *)body->data.memory.data;
  TEST_ASSERT_NOT_NULL(strstr(body_str, "name=John%20Doe"));
  TEST_ASSERT_NOT_NULL(strstr(body_str, "age=30"));
  TEST_ASSERT_NOT_NULL(strstr(body_str, "city=New%20York"));
}

void test_fetch_url_search_params_edge_cases(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);

  fetch_url_search_params_append(params, "", "=");
  fetch_url_search_params_append(params, "empty", "");
  fetch_url_search_params_append(params, "", "value");
  TEST_ASSERT_EQUAL(3, params->count);

  char *string_result = fetch_url_search_params_to_string(params);
  TEST_ASSERT_NOT_NULL(string_result);
  TEST_ASSERT_EQUAL_STRING("=%3D&empty=&=value", string_result);
  TRACK(string_result, free);

  char long_value[1000];
  memset(long_value, 'A', 999);
  long_value[999] = '\0';

  fetch_url_search_params_set(params, "long", long_value);
  TEST_ASSERT_EQUAL_STRING(long_value, fetch_url_search_params_get(params, "long"));
}

void test_url_search_params_integration(void)
{
  fetch_url_search_params_t *params = TRACK(fetch_url_search_params_new(), fetch_url_search_params_free);
  TEST_ASSERT_NOT_NULL(params);

  fetch_url_search_params_append(params, "a", "1");
  fetch_url_search_params_append(params, "b", "test value");
  fetch_url_search_params_append(params, "c", "special & chars");

  fetch_body_t *body = TRACK(fetch_body_url_search_params(params), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  TEST_ASSERT_NOT_NULL(headers);
  fetch_headers_set(headers, "User-Agent", "FetchLibrary/2.0 Test");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  TEST_ASSERT_NOT_NULL(init);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 10000);

  TEST_ASSERT_EQUAL(HTTP_METHOD_POST, init->method);
  TEST_ASSERT_EQUAL(FETCH_BODY_FORM_DATA, init->body->type);
  TEST_ASSERT_EQUAL_STRING("application/x-www-form-urlencoded", init->body->content_type);

  const char *form_data = (const char *)init->body->data.memory.data;
  TEST_ASSERT_NOT_NULL(strstr(form_data, "a=1"));
  TEST_ASSERT_NOT_NULL(strstr(form_data, "b=test%20value"));
  TEST_ASSERT_NOT_NULL(strstr(form_data, "c=special%20%26%20chars"));

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));
}

void test_async_fetch_stress_test(void)
{
#define NUM_REQUESTS 8

  fetch_promise_t *promises[NUM_REQUESTS];
  bool request_completed[NUM_REQUESTS];

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    request_completed[i] = false;
  }

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    char url[256];
    int delay = i % 4;
    BUILD_URL_FMT(url, sizeof(url), "/delay/%d", delay);

    fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
    fetch_init_timeout(init, 10000);

    promises[i] = TRACK(fetch_async(url, init), fetch_promise_free);
    TEST_ASSERT_NOT_NULL(promises[i]);
    TEST_ASSERT_EQUAL(FETCH_PROMISE_PENDING, fetch_promise_state(promises[i]));
  }

  int completed = 0;
  time_t start = time(NULL);

  while (completed < NUM_REQUESTS)
  {
    fetch_event_loop_process(100);

    for (int i = 0; i < NUM_REQUESTS; i++)
    {
      if (request_completed[i])
      {
        continue;
      }

      if (fetch_promise_poll(promises[i]) && !fetch_promise_pending(promises[i]))
      {
        request_completed[i] = true;
        completed++;

        if (fetch_promise_fulfilled(promises[i]))
        {
          fetch_response_t *response = fetch_promise_response(promises[i]);
          TEST_ASSERT_NOT_NULL(response);
          TEST_ASSERT_TRUE(fetch_response_ok(response));
        }
      }
    }
  }

  int successful = 0;
  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    if (fetch_promise_fulfilled(promises[i]))
    {
      successful++;
    }
  }
  TEST_ASSERT_EQUAL(NUM_REQUESTS, successful);
#undef NUM_REQUESTS
}

void test_fetch_async_with_background_thread(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());

  fetch_promise_t *promise1 = TRACK(fetch_async(BUILD_URL("/get"), NULL), fetch_promise_free);
  fetch_promise_t *promise2 = TRACK(fetch_async(BUILD_URL("/uuid"), NULL), fetch_promise_free);
  fetch_promise_t *promise3 = TRACK(fetch_async(BUILD_URL("/user-agent"), NULL), fetch_promise_free);

  TEST_ASSERT_NOT_NULL(promise1);
  TEST_ASSERT_NOT_NULL(promise2);
  TEST_ASSERT_NOT_NULL(promise3);

  int completed = 0;
  int successful = 0;

  for (int i = 0; i < 200 && completed < 3; i++)
  {
    usleep(100000);

    completed = 0;
    if (!fetch_promise_pending(promise1))
      completed++;
    if (!fetch_promise_pending(promise2))
      completed++;
    if (!fetch_promise_pending(promise3))
      completed++;
  }

  if (fetch_promise_fulfilled(promise1))
  {
    fetch_response_t *resp = fetch_promise_response(promise1);
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT_TRUE(fetch_response_ok(resp));
    TEST_ASSERT_EQUAL(200, fetch_response_status(resp));
    TEST_ASSERT_NOT_NULL(fetch_response_text(resp));
    successful++;
  }

  if (fetch_promise_fulfilled(promise2))
  {
    fetch_response_t *resp = fetch_promise_response(promise2);
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT_TRUE(fetch_response_ok(resp));
    TEST_ASSERT_EQUAL(200, fetch_response_status(resp));
    TEST_ASSERT_NOT_NULL(fetch_response_text(resp));
    successful++;
  }

  if (fetch_promise_fulfilled(promise3))
  {
    fetch_response_t *resp = fetch_promise_response(promise3);
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT_TRUE(fetch_response_ok(resp));
    TEST_ASSERT_EQUAL(200, fetch_response_status(resp));
    TEST_ASSERT_NOT_NULL(fetch_response_text(resp));
    successful++;
  }

  TEST_ASSERT_EQUAL(3, successful);
  TEST_ASSERT_GREATER_THAN(0, successful);
}

void test_rapid_fire_async_requests(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());
#define NUM_REQUESTS 10

  fetch_promise_t *promises[NUM_REQUESTS];

  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    char url[256];
    BUILD_URL_FMT(url, sizeof(url), "/get?request=%d", i);

    promises[i] = TRACK(fetch_async(url, NULL), fetch_promise_free);
    TEST_ASSERT_NOT_NULL(promises[i]);
  }

  // --- START: CORRECTED WAITING LOGIC ---
  int all_completed = 0;
  // Poll for completion with a 20-second timeout
  for (int i = 0; i < 200; i++)
  {
    int completed_count = 0;
    for (int j = 0; j < NUM_REQUESTS; j++)
    {
      if (!fetch_promise_pending(promises[j]))
      {
        completed_count++;
      }
    }

    if (completed_count == NUM_REQUESTS)
    {
      all_completed = 1;
      break;
    }
    usleep(100000); // Wait 100ms before polling again
  }

  TEST_ASSERT_EQUAL_MESSAGE(1, all_completed, "Not all rapid-fire requests completed in time.");
  // --- END: CORRECTED WAITING LOGIC ---

  int successful = 0;
  for (int i = 0; i < NUM_REQUESTS; i++)
  {
    if (fetch_promise_fulfilled(promises[i]))
    {
      fetch_response_t *resp = fetch_promise_response(promises[i]);
      TEST_ASSERT_NOT_NULL(resp);
      TEST_ASSERT_TRUE(fetch_response_ok(resp));
      TEST_ASSERT_EQUAL(200, fetch_response_status(resp));

      const char *response_text = fetch_response_text(resp);
      TEST_ASSERT_NOT_NULL(response_text);

      char expected_param[64];
      snprintf(expected_param, sizeof(expected_param),
               "\"request\": [\n      \"%d\"\n    ]", i);
      TEST_ASSERT_NOT_NULL(strstr(response_text, expected_param));

      successful++;
    }
  }

  TEST_ASSERT_EQUAL(NUM_REQUESTS, successful);
#undef NUM_REQUESTS
}

void test_cancellation_with_background_thread(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());

  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/delay/10"), NULL), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);
  TEST_ASSERT_TRUE(fetch_promise_pending(promise));

  // Give the request a moment to get started
  usleep(100000);

  // --- START: CORRECTED CANCELLATION LOGIC ---
  bool cancelled = fetch_promise_cancel(promise, "Background thread test cancellation");

  // It's possible the request finished/errored in the tiny gap before cancellation.
  // The important part is to check the final state.
  if (!cancelled)
  {
    // If cancellation failed, it means the promise was already resolved.
    // We should check that it's not pending.
    TEST_ASSERT_FALSE(fetch_promise_pending(promise));
  }

  // Wait for the final state to be fully processed by the event loop.
  for (int i = 0; i < 50; i++)
  { // 5 second wait
    if (fetch_promise_rejected(promise))
    {
      break;
    }
    usleep(100000);
  }

  // Now, definitively check the outcome.
  TEST_ASSERT_TRUE(fetch_promise_rejected(promise));
  TEST_ASSERT_TRUE(fetch_promise_cancelled(promise));
  TEST_ASSERT_EQUAL(FETCH_ERROR_ABORTED, fetch_promise_error(promise));
  TEST_ASSERT_EQUAL_STRING("Background thread test cancellation", fetch_promise_error_message(promise));
  TEST_ASSERT_NULL(fetch_promise_response(promise));
  // --- END: CORRECTED CANCELLATION LOGIC ---
}

void test_post_request_with_background_thread(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/json");
  fetch_headers_set(headers, "X-Test-Thread", "background");

  fetch_body_t *body = TRACK(fetch_body_json("{\"test\": \"background_post\", \"timestamp\": 1234567890}"), fetch_body_free);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 15000);

  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/post"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  // --- START: MODIFIED CODE ---
  // Replace fetch_promise_await with a polling loop.
  // This allows the background thread to do its work without interference.
  int completed = 0;
  for (int i = 0; i < 200 && completed < 1; i++) // 20-second timeout
  {
    usleep(100000); // Wait 100ms
    if (!fetch_promise_pending(promise))
    {
      completed++;
    }
  }

  TEST_ASSERT_EQUAL_MESSAGE(1, completed, "Promise did not complete in time.");
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));
  // --- END: MODIFIED CODE ---

  fetch_response_t *resp = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(resp);
  TEST_ASSERT_TRUE(fetch_response_ok(resp));
  TEST_ASSERT_EQUAL(200, fetch_response_status(resp));

  const char *response_text = fetch_response_text(resp);
  TEST_ASSERT_NOT_NULL(response_text);

  TEST_ASSERT_NOT_NULL(strstr(response_text, "background_post"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "1234567890"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Test-Thread"));
}

void test_mixed_requests_with_background_thread(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());

  fetch_promise_t *get_promise = TRACK(fetch_async(BUILD_URL("/get?test=mixed"), NULL), fetch_promise_free);

  fetch_init_t *post_init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(post_init, HTTP_METHOD_POST);
  fetch_body_t *post_body = TRACK(fetch_body_json("{\"mixed_test\": true}"), fetch_body_free);
  fetch_init_body(post_init, post_body);
  UNTRACK(post_body);

  fetch_promise_t *post_promise = TRACK(fetch_async(BUILD_URL("/post"), post_init), fetch_promise_free);

  TEST_ASSERT_NOT_NULL(get_promise);
  TEST_ASSERT_NOT_NULL(post_promise);

  int completed = 0;
  // The waiting loop is already correct, using a timeout and usleep.
  for (int i = 0; i < 200 && completed < 2; i++)
  {
    usleep(100000);

    completed = 0;
    if (!fetch_promise_pending(get_promise))
      completed++;
    if (!fetch_promise_pending(post_promise))
      completed++;
  }

  // --- START: ADDED ROBUSTNESS CHECK ---
  TEST_ASSERT_EQUAL_MESSAGE(2, completed, "Not all mixed requests completed in time.");
  // --- END: ADDED ROBUSTNESS CHECK ---

  int successful = 0;

  if (fetch_promise_fulfilled(get_promise))
  {
    // ... (rest of the assertions are correct) ...
    fetch_response_t *resp = fetch_promise_response(get_promise);
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT_TRUE(fetch_response_ok(resp));
    TEST_ASSERT_EQUAL(200, fetch_response_status(resp));

    const char *response_text = fetch_response_text(resp);
    TEST_ASSERT_NOT_NULL(response_text);
    TEST_ASSERT_NOT_NULL(strstr(response_text, "test=mixed"));
    successful++;
  }

  if (fetch_promise_fulfilled(post_promise))
  {
    // ... (rest of the assertions are correct) ...
    fetch_response_t *resp = fetch_promise_response(post_promise);
    TEST_ASSERT_NOT_NULL(resp);
    TEST_ASSERT_TRUE(fetch_response_ok(resp));
    TEST_ASSERT_EQUAL(200, fetch_response_status(resp));

    const char *response_text = fetch_response_text(resp);
    TEST_ASSERT_NOT_NULL(response_text);
    TEST_ASSERT_NOT_NULL(strstr(response_text, "mixed_test"));
    successful++;
  }
  TEST_ASSERT_EQUAL(2, successful);
}

void test_fetch_binary_data_basic_post(void)
{
  const uint8_t test_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                               0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                               0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF};
  const size_t data_size = sizeof(test_data);

  fetch_body_t *body = TRACK(fetch_body_binary(test_data, data_size, "application/octet-stream"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_BINARY, body->type);
  TEST_ASSERT_EQUAL(data_size, body->data.memory.size);
  TEST_ASSERT_EQUAL_STRING("application/octet-stream", body->content_type);
  TEST_ASSERT_EQUAL_MEMORY(test_data, body->data.memory.data, data_size);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/octet-stream");
  fetch_headers_set(headers, "X-Test-Type", "binary-basic");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 15000);

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);

  TEST_ASSERT_NOT_NULL(strstr(response_text, "application/octet-stream"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Test-Type"));
}

void test_fetch_binary_data_image_simulation(void)
{
  const uint8_t png_like_data[] = {
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x20,
      0x00, 0x00, 0x00, 0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0xFC, 0x18, 0xED,
      0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0xFF,
      0x00, 0xFF, 0x00, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
      0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
  const size_t data_size = sizeof(png_like_data);

  fetch_body_t *body = TRACK(fetch_body_binary(png_like_data, data_size, "image/png"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING("image/png", body->content_type);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "image/png");
  fetch_headers_set(headers, "X-Image-Type", "test-png");
  fetch_headers_set(headers, "Content-Length", "56");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "image/png"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Image-Type"));
}

void test_fetch_binary_data_async_post(void)
{
  const size_t data_size = 1024;
  uint8_t *test_data = TRACK(malloc(data_size), free);
  TEST_ASSERT_NOT_NULL(test_data);

  for (size_t i = 0; i < data_size; i++)
  {
    test_data[i] = (uint8_t)(i % 256);
  }

  fetch_body_t *body = TRACK(fetch_body_binary(test_data, data_size, "application/octet-stream"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/octet-stream");
  fetch_headers_set(headers, "X-Test-Size", "1024");
  fetch_headers_set(headers, "X-Async-Test", "binary");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 20000);

  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/post"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  bool completed = fetch_promise_await(promise, 25000);
  TEST_ASSERT_TRUE(completed);
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));

  fetch_response_t *response = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Test-Size"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Async-Test"));
}

void test_fetch_binary_data_receive_bytes(void)
{
  const size_t requested_bytes = 512;
  char url[256];
  BUILD_URL_FMT(url, sizeof(url), "/bytes/%zu", requested_bytes);

  fetch_response_t *response = TRACK(fetch(url, NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  size_t received_size;
  const uint8_t *binary_data = fetch_response_array_buffer(response, &received_size);
  TEST_ASSERT_NOT_NULL(binary_data);
  TEST_ASSERT_EQUAL(requested_bytes, received_size);

  bool has_null_bytes = false;
  bool has_high_bytes = false;

  for (size_t i = 0; i < received_size; i++)
  {
    if (binary_data[i] == 0x00)
    {
      has_null_bytes = true;
    }
    if (binary_data[i] > 0x7F)
    {
      has_high_bytes = true;
    }
  }

  TEST_ASSERT_TRUE(has_null_bytes || has_high_bytes);
}

void test_fetch_binary_data_async_receive_bytes(void)
{
  const size_t requested_bytes = 1024;
  char url[256];
  BUILD_URL_FMT(url, sizeof(url), "/bytes/%zu", requested_bytes);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_timeout(init, 15000);

  fetch_promise_t *promise = TRACK(fetch_async(url, init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  bool completed = fetch_promise_await(promise, 20000);
  TEST_ASSERT_TRUE(completed);
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));

  fetch_response_t *response = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));

  size_t received_size;
  const uint8_t *binary_data = fetch_response_array_buffer(response, &received_size);
  TEST_ASSERT_NOT_NULL(binary_data);
  TEST_ASSERT_EQUAL(requested_bytes, received_size);

  int byte_counts[256] = {0};
  for (size_t i = 0; i < received_size; i++)
  {
    byte_counts[binary_data[i]]++;
  }

  int unique_bytes = 0;
  for (int i = 0; i < 256; i++)
  {
    if (byte_counts[i] > 0)
    {
      unique_bytes++;
    }
  }

  TEST_ASSERT_GREATER_THAN(50, unique_bytes);
}

void test_fetch_binary_data_large_payload(void)
{
  const size_t data_size = 16 * 1024;
  uint8_t *large_data = TRACK(malloc(data_size), free);
  TEST_ASSERT_NOT_NULL(large_data);

  for (size_t i = 0; i < data_size; i++)
  {
    large_data[i] = (uint8_t)((i * 17 + i / 256) % 256);
  }

  fetch_body_t *body = TRACK(fetch_body_binary(large_data, data_size, "application/octet-stream"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/octet-stream");
  fetch_headers_set(headers, "X-Data-Size", "16384");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 30000);

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Data-Size"));
}

void test_fetch_binary_data_with_background_thread(void)
{
  TEST_ASSERT_TRUE(start_background_event_loop());

  const uint8_t binary_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
                                 0xBA, 0xBE, 0x00, 0x01, 0x02, 0x03,
                                 0xFF, 0xFE, 0xFD, 0xFC};
  const size_t data_size = sizeof(binary_data);
  fetch_body_t *body = TRACK(fetch_body_binary(binary_data, data_size, "application/octet-stream"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/octet-stream");
  fetch_headers_set(headers, "X-Background-Binary", "true");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body

  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/post"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  // --- START: CORRECTED WAITING LOGIC ---
  // DO NOT call fetch_promise_await. Poll the promise state instead.
  int is_done = 0;
  for (int i = 0; i < 150; i++)
  { // 15-second timeout
    if (!fetch_promise_pending(promise))
    {
      is_done = 1;
      break;
    }
    usleep(100000); // sleep for 100ms
  }

  TEST_ASSERT_EQUAL_MESSAGE(1, is_done, "Promise did not complete in time.");
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));
  // --- END: CORRECTED WAITING LOGIC ---

  fetch_response_t *response = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Background-Binary"));

  // This cleanup loop at the end is also problematic and should be removed.
  // The background thread handles all event processing.
  /*
  int cleanup_iterations = 0;
  int events_processed;
  do
  {
    events_processed = fetch_event_loop_process(100);
    cleanup_iterations++;

    if (cleanup_iterations > 50)
    {
      break;
    }
  } while (events_processed > 0);
  */
}

void test_fetch_binary_data_null_bytes_handling(void)
{
  const size_t data_size = 256;
  uint8_t *null_heavy_data = TRACK(calloc(data_size, 1), free);
  TEST_ASSERT_NOT_NULL(null_heavy_data);

  null_heavy_data[0] = 0xFF;
  null_heavy_data[63] = 0xAA;
  null_heavy_data[127] = 0x55;
  null_heavy_data[191] = 0xCC;
  null_heavy_data[255] = 0x33;

  fetch_body_t *body = TRACK(fetch_body_binary(null_heavy_data, data_size, "application/octet-stream"), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(data_size, body->data.memory.size);

  const uint8_t *body_data = (const uint8_t *)body->data.memory.data;
  TEST_ASSERT_EQUAL(0xFF, body_data[0]);
  TEST_ASSERT_EQUAL(0x00, body_data[1]);
  TEST_ASSERT_EQUAL(0xAA, body_data[63]);
  TEST_ASSERT_EQUAL(0x00, body_data[64]);
  TEST_ASSERT_EQUAL(0x33, body_data[255]);

  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "application/octet-stream");
  fetch_headers_set(headers, "X-Null-Heavy", "true");

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Null-Heavy"));
}

void test_fetch_binary_data_response_validation(void)
{
  const size_t requested_size = 128;
  char url[256];
  BUILD_URL_FMT(url, sizeof(url), "/bytes/%zu", requested_size);

  fetch_response_t *response = TRACK(fetch(url, NULL), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));

  size_t binary_size;
  const uint8_t *binary_data = fetch_response_array_buffer(response, &binary_size);
  TEST_ASSERT_NOT_NULL(binary_data);
  TEST_ASSERT_EQUAL(requested_size, binary_size);

  fetch_headers_t *response_headers = fetch_response_headers(response);
  TEST_ASSERT_NOT_NULL(response_headers);

  const char *content_length = fetch_headers_get(response_headers, "Content-Length");
  if (content_length)
  {
    int reported_length = atoi(content_length);
    TEST_ASSERT_EQUAL(requested_size, (size_t)reported_length);
  }
}

void test_fetch_body_file_basic(void)
{
  const char *test_filename = "test_file_body.tmp";
  const char *test_content = "This is test file content for libfetch file streaming test.\n"
                            "It contains multiple lines to test file reading.\n"
                            "Binary data: \x00\x01\x02\x03\xFF\xFE\xFD\xFC\n"
                            "End of test content.";
  const size_t content_size = strlen(test_content);

  // Create test file
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  DWORD bytes_written;
  BOOL write_result = WriteFile(file_handle, test_content, (DWORD)content_size, &bytes_written, NULL);
  TEST_ASSERT_TRUE(write_result);
  TEST_ASSERT_EQUAL(content_size, bytes_written);
  CloseHandle(file_handle);

  // Open for reading
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  
  size_t bytes_written = fwrite(test_content, 1, content_size, temp_file);
  TEST_ASSERT_EQUAL(content_size, bytes_written);
  fclose(temp_file);

  // Open for reading
  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
#endif

  // Test fetch_body_file with close_on_free=true
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, content_size, "text/plain", true, NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  
  // Verify body structure
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);
  TEST_ASSERT_EQUAL_STRING("text/plain", body->content_type);
  TEST_ASSERT_EQUAL(file_handle, body->data.file.handle);
  TEST_ASSERT_EQUAL(content_size, body->data.file.size);
  TEST_ASSERT_EQUAL(0, body->data.file.offset);
  TEST_ASSERT_TRUE(body->data.file.close_on_free);

  // Clean up (fetch_body_free should close the file automatically)
  UNTRACK(body);
  fetch_body_free(body);
  
  // Clean up test file
  unlink(test_filename);
}

void test_fetch_body_file_manual_close(void)
{
  const char *test_filename = "test_file_manual.tmp";
  const char *test_content = "Manual close test content";
  const size_t content_size = strlen(test_content);

  // Create test file
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  DWORD bytes_written;
  WriteFile(file_handle, test_content, (DWORD)content_size, &bytes_written, NULL);
  CloseHandle(file_handle);

  // Open for reading
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  fwrite(test_content, 1, content_size, temp_file);
  fclose(temp_file);

  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
#endif

  // Test fetch_body_file with close_on_free=false
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, content_size, "application/octet-stream", false, NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  
  // Verify body structure
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);
  TEST_ASSERT_EQUAL_STRING("application/octet-stream", body->content_type);
  TEST_ASSERT_EQUAL(file_handle, body->data.file.handle);
  TEST_ASSERT_EQUAL(content_size, body->data.file.size);
  TEST_ASSERT_EQUAL(0, body->data.file.offset);
  TEST_ASSERT_FALSE(body->data.file.close_on_free);

  // Free body (should NOT close the file)
  UNTRACK(body);
  fetch_body_free(body);
  
  // Manually close the file
#if defined(_WIN32) || defined(_WIN64)
  CloseHandle(file_handle);
#else
  fclose(file_handle);
#endif
  
  // Clean up test file
  unlink(test_filename);
}

void test_fetch_body_file_null_safety(void)
{
  // Test with invalid parameters
#if defined(_WIN32) || defined(_WIN64)
  TEST_ASSERT_NULL(fetch_body_file(INVALID_HANDLE_VALUE, 100, "text/plain", true, NULL, NULL));
#else
  TEST_ASSERT_NULL(fetch_body_file(NULL, 100, "text/plain", true, NULL, NULL));
#endif
  
  // Test with zero size (should still work)
  const char *test_filename = "test_empty.tmp";
  
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, 0, "text/plain", true, NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);
  TEST_ASSERT_EQUAL(0, body->data.file.size);
#else
  FILE *file_handle = fopen(test_filename, "w+b");
  TEST_ASSERT_NOT_NULL(file_handle);
  
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, 0, "text/plain", true,NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);
  TEST_ASSERT_EQUAL(0, body->data.file.size);
#endif

  // Clean up
  unlink(test_filename);
}

void test_fetch_body_file_content_types(void)
{
  const char *test_filename = "test_content_types.tmp";
  const char *test_content = "Content type test";
  
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  DWORD bytes_written;
  WriteFile(file_handle, test_content, (DWORD)strlen(test_content), &bytes_written, NULL);
  CloseHandle(file_handle);

  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  fwrite(test_content, 1, strlen(test_content), temp_file);
  fclose(temp_file);

  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
#endif

  // Test with NULL content type (should default to application/octet-stream)
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, strlen(test_content), NULL, false,NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING("application/octet-stream", body->content_type);
  
  UNTRACK(body);
  fetch_body_free(body);

  // Test with custom content type
#if defined(_WIN32) || defined(_WIN64)
  CloseHandle(file_handle);
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
  fclose(file_handle);
  file_handle = fopen(test_filename, "rb");
#endif

  body = TRACK(fetch_body_file(file_handle, strlen(test_content), "image/jpeg", true,NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL_STRING("image/jpeg", body->content_type);
  
  // Clean up
  unlink(test_filename);
}

void test_fetch_body_file_network_post(void)
{
  const char *test_filename = "test_file_network.tmp";
  const char *test_content = "This is a network test file for libfetch file streaming.\n"
                            "Line 2: Testing file upload functionality.\n" 
                            "Line 3: Binary data follows: \x01\x02\x03\xFF\xFE\xFD\xFC\n"
                            "Line 4: End of file content for network test.";
  const size_t content_size = strlen(test_content);

  // Create test file
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  DWORD bytes_written;
  BOOL write_result = WriteFile(file_handle, test_content, (DWORD)content_size, &bytes_written, NULL);
  TEST_ASSERT_TRUE(write_result);
  TEST_ASSERT_EQUAL(content_size, bytes_written);
  CloseHandle(file_handle);

  // Open for reading
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  
  size_t bytes_written = fwrite(test_content, 1, content_size, temp_file);
  TEST_ASSERT_EQUAL(content_size, bytes_written);
  fclose(temp_file);

  // Open for reading
  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
#endif

  // Create file body (with automatic cleanup)
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, content_size, "text/plain", true,NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);

  // Create headers for the request
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "text/plain");
  fetch_headers_set(headers, "X-Test-Type", "file-streaming");
  fetch_headers_set(headers, "X-File-Size", "200"); // Approximate size
  fetch_headers_set(headers, "User-Agent", "libfetch-file-test/1.0");

  // Create request init
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 15000);

  // Send the request
  fetch_response_t *response = TRACK(fetch(BUILD_URL("/post"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  // Verify the response contains our file content
  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  printf("Response text: %s\n", response_text);
  
  // Check that the server received our test content
  TEST_ASSERT_NOT_NULL(strstr(response_text, "network test file"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "file upload functionality"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "End of file content"));
  
  // Check that our custom headers were sent
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Test-Type"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "file-streaming"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-File-Size"));
  
  // Verify content type
  TEST_ASSERT_NOT_NULL(strstr(response_text, "text/plain"));

  printf("File streaming POST test completed successfully!\n");
  printf("Sent %zu bytes of file data to server\n", content_size);

  // Clean up test file
  unlink(test_filename);
}

void test_fetch_body_file_async_network_post(void)
{
  const char *test_filename = "test_file_async.tmp";
  const char *test_content = "Async file streaming test content.\n"
                            "Testing asynchronous file upload with libfetch.\n"
                            "This file should be streamed chunk by chunk.\n"
                            "Binary test: \xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\n"
                            "Final line of async test file.";
  
  // Calculate size manually since strlen() stops at null bytes
  const size_t content_size = sizeof("Async file streaming test content.\n"
                                    "Testing asynchronous file upload with libfetch.\n"
                                    "This file should be streamed chunk by chunk.\n"
                                    "Binary test: \x00\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\n"
                                    "Final line of async test file.") - 1;

  // Create test file
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  DWORD bytes_written;
  WriteFile(file_handle, test_content, (DWORD)content_size, &bytes_written, NULL);
  CloseHandle(file_handle);

  // Open for reading
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  
  // Use fwrite with proper size handling for binary data
  size_t written = fwrite(test_content, 1, content_size, temp_file);
  TEST_ASSERT_EQUAL(content_size, written);
  fclose(temp_file);

  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
  
  // Verify file size matches expected content
  fseek(file_handle, 0, SEEK_END);
  long file_size = ftell(file_handle);
  fseek(file_handle, 0, SEEK_SET);
  TEST_ASSERT_EQUAL(content_size, (size_t)file_size);
#endif

  // Create file body
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, content_size, "text/plain", true, NULL, NULL), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);

  // Create headers
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "X-Async-File-Test", "true");
  fetch_headers_set(headers, "X-Stream-Type", "chunked-file");

  // Create async request
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers);
  fetch_init_body(init, body);
  UNTRACK(body);
  fetch_init_timeout(init, 20000);

  // Send async request
  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/post"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);

  // Wait for completion
  bool completed = fetch_promise_await(promise, 25000);
  TEST_ASSERT_TRUE(completed);
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(promise));

  // Verify response
  fetch_response_t *response = fetch_promise_response(promise);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));
  TEST_ASSERT_EQUAL(200, fetch_response_status(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  printf("Response text: %s\n", response_text);
  
  // Verify file content was received
  TEST_ASSERT_NOT_NULL(strstr(response_text, "Async file streaming"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "chunk by chunk"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "Final line of async"));
  
  // Verify headers
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Async-File-Test"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Stream-Type"));
  

  printf("Async file streaming POST test completed successfully!\n");
  printf("Async sent %zu bytes of file data to server\n", content_size);

  // Clean up test file
  unlink(test_filename);
}

void test_cookie_jar_creation_and_cleanup(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar1 = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar1);
  TEST_ASSERT_EQUAL(0, cookie_jar_count(jar1));

  const char *test_file = "test_cookie_jar.txt";
  cookie_jar_t *jar2 = TRACK(fetch_create_cookie_jar(test_file), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar2);
  TEST_ASSERT_EQUAL(0, cookie_jar_count(jar2));

  unlink(test_file);

  fetch_cookie_jar_free(NULL);
}

void test_cookie_enable_disable(void)
{
  fetch_global_dispose();

  TEST_ASSERT_NULL(fetch_get_cookie_jar());
  TEST_ASSERT_EQUAL(0, fetch_cookie_jar_count(NULL));

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  TEST_ASSERT_NOT_NULL(fetch_get_cookie_jar());
  TEST_ASSERT_EQUAL(jar, fetch_get_cookie_jar());

  fetch_disable_cookies();
  TEST_ASSERT_NULL(fetch_get_cookie_jar());

  fetch_global_dispose();
}

void test_cookie_basic_set_and_get(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  TEST_ASSERT_EQUAL(0, fetch_cookie_jar_count(NULL));

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/cookies/set?testcookie=testvalue"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "\"testcookie\": \"testvalue\""));

  fetch_disable_cookies();
}

void test_cookie_multiple_cookies(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_response_t *resp1 = TRACK(fetch(BUILD_URL("/cookies/set?cookie1=value1"), init), fetch_response_free);
  fetch_response_t *resp2 = TRACK(fetch(BUILD_URL("/cookies/set?cookie2=value2"), init), fetch_response_free);
  fetch_response_t *resp3 = TRACK(fetch(BUILD_URL("/cookies/set?cookie3=value3"), init), fetch_response_free);

  TEST_ASSERT_NOT_NULL(resp1);
  TEST_ASSERT_NOT_NULL(resp2);
  TEST_ASSERT_NOT_NULL(resp3);
  TEST_ASSERT_TRUE(fetch_response_ok(resp1));
  TEST_ASSERT_TRUE(fetch_response_ok(resp2));
  TEST_ASSERT_TRUE(fetch_response_ok(resp3));

  size_t cookie_count = fetch_cookie_jar_count(NULL);
  TEST_ASSERT_GREATER_OR_EQUAL(3, cookie_count);

  fetch_cookie_jar_print(jar, NULL);

  fetch_response_t *response = TRACK(fetch(BUILD_URL("/cookies"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(response);
  TEST_ASSERT_TRUE(fetch_response_ok(response));

  const char *response_text = fetch_response_text(response);
  TEST_ASSERT_NOT_NULL(response_text);

  TEST_ASSERT_NOT_NULL(strstr(response_text, "cookie1"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "value1"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "cookie2"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "value2"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "cookie3"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "value3"));

  fetch_disable_cookies();
}

void test_cookie_async_requests(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_promise_t *set_promise = TRACK(fetch_async(BUILD_URL("/cookies/set?asynccookie=asyncvalue"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(set_promise);

  bool completed = fetch_promise_await(set_promise, 10000);
  TEST_ASSERT_TRUE(completed);
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(set_promise));

  fetch_response_t *set_response = fetch_promise_response(set_promise);
  TEST_ASSERT_TRUE(fetch_response_ok(set_response));

  fetch_cookie_jar_print(jar, NULL);

  fetch_promise_t *get_promise = TRACK(fetch_async(BUILD_URL("/cookies"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(get_promise);

  bool get_completed = fetch_promise_await(get_promise, 10000);
  TEST_ASSERT_TRUE(get_completed);
  TEST_ASSERT_TRUE(fetch_promise_fulfilled(get_promise));

  fetch_response_t *get_response = fetch_promise_response(get_promise);
  TEST_ASSERT_TRUE(fetch_response_ok(get_response));

  const char *response_text = fetch_response_text(get_response);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "asynccookie"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "asyncvalue"));

  fetch_disable_cookies();
}

void test_cookie_persistence(void)
{
  fetch_global_dispose();

  const char *test_file = "test_cookies.txt";
  unlink(test_file);

  cookie_jar_t *jar1 = TRACK(fetch_create_cookie_jar(test_file), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar1);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar1;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_response_t *resp = TRACK(fetch(BUILD_URL("/cookies/set?persistent=persistvalue"), init), fetch_response_free);
  TEST_ASSERT_NOT_NULL(resp);
  TEST_ASSERT_TRUE(fetch_response_ok(resp));

  fetch_cookie_jar_print(jar1, NULL);

  bool saved = fetch_save_cookies(test_file, jar1);
  TEST_ASSERT_TRUE(saved);

  fetch_disable_cookies();
  fetch_global_dispose();

  cookie_jar_t *jar2 = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar2);

  bool loaded = fetch_load_cookies(test_file, jar2);
  TEST_ASSERT_TRUE(loaded);

  fetch_cookie_jar_print(jar2, NULL);

  size_t jar2_count = cookie_jar_count(jar2);
  TEST_ASSERT_GREATER_THAN(0, jar2_count);

  fetch_config_t config2 = fetch_config_default();
  config2.cookie_jar = jar2;
  config2.origin = BUILD_URL("");

  fetch_global_init(&config2);

  fetch_init_t *init2 = TRACK(fetch_init_new(), fetch_init_free);
  init2->redirect = FETCH_REDIRECT_FOLLOW;
  init2->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init2, HTTP_METHOD_GET);

  fetch_response_t *test_resp = TRACK(fetch(BUILD_URL("/cookies"), init2), fetch_response_free);
  TEST_ASSERT_NOT_NULL(test_resp);
  TEST_ASSERT_TRUE(fetch_response_ok(test_resp));

  const char *response_text = fetch_response_text(test_resp);
  TEST_ASSERT_NOT_NULL(response_text);
  TEST_ASSERT_NOT_NULL(strstr(response_text, "persistent"));
  TEST_ASSERT_NOT_NULL(strstr(response_text, "persistvalue"));

  fetch_disable_cookies();
  fetch_global_dispose();

  unlink(test_file);
}

void test_cookie_auto_persistence(void)
{
  fetch_global_dispose();

  const char *test_file = "test_auto_cookies.txt";

  { 
    cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(test_file), fetch_cookie_jar_free);
    TEST_ASSERT_NOT_NULL(jar);

    fetch_config_t config = fetch_config_default();
    config.cookie_jar = jar;
    config.origin = BUILD_URL("");

    fetch_global_init(&config);

    fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
    init->redirect = FETCH_REDIRECT_FOLLOW;
    init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
    fetch_init_method(init, HTTP_METHOD_GET);

    fetch_response_t *resp1 = TRACK(fetch(BUILD_URL("/cookies/set?autopersist1=value1"), init), fetch_response_free);
    fetch_response_t *resp2 = TRACK(fetch(BUILD_URL("/cookies/set?autopersist2=value2"), init), fetch_response_free);

    TEST_ASSERT_NOT_NULL(resp1);
    TEST_ASSERT_NOT_NULL(resp2);
    TEST_ASSERT_TRUE(fetch_response_ok(resp1));
    TEST_ASSERT_TRUE(fetch_response_ok(resp2));

    size_t cookie_count = fetch_cookie_jar_count(NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(2, cookie_count);

    fetch_cookie_jar_print(jar, NULL);

    fetch_disable_cookies();
    fetch_global_dispose();

    fetch_cookie_jar_free(jar);
    UNTRACK(jar); // Ensure jar is freed properly
  }

  {
    cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(test_file), fetch_cookie_jar_free);
    TEST_ASSERT_NOT_NULL(jar);

    size_t loaded_count = cookie_jar_count(jar);
    TEST_ASSERT_GREATER_OR_EQUAL(2, loaded_count);

    fetch_cookie_jar_print(jar, NULL);

    fetch_config_t config = fetch_config_default();
    config.cookie_jar = jar;
    config.origin = BUILD_URL("");

    fetch_global_init(&config);

    fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
    init->redirect = FETCH_REDIRECT_FOLLOW;
    init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
    fetch_init_method(init, HTTP_METHOD_GET);

    fetch_response_t *test_resp = TRACK(fetch(BUILD_URL("/cookies"), init), fetch_response_free);
    TEST_ASSERT_NOT_NULL(test_resp);
    TEST_ASSERT_TRUE(fetch_response_ok(test_resp));

    const char *response_text = fetch_response_text(test_resp);
    TEST_ASSERT_NOT_NULL(response_text);
    TEST_ASSERT_NOT_NULL(strstr(response_text, "autopersist1"));
    TEST_ASSERT_NOT_NULL(strstr(response_text, "value1"));
    TEST_ASSERT_NOT_NULL(strstr(response_text, "autopersist2"));
    TEST_ASSERT_NOT_NULL(strstr(response_text, "value2"));

    fetch_disable_cookies();
    fetch_global_dispose();

    unlink(test_file);
  }

  fetch_global_dispose();
}

void test_cookie_domain_filtering(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_response_t *resp1 = TRACK(fetch(BUILD_URL("/cookies/set?local1=value1"), init), fetch_response_free);
  fetch_response_t *resp2 = TRACK(fetch(BUILD_URL("/cookies/set?local2=value2"), init), fetch_response_free);

  TEST_ASSERT_NOT_NULL(resp1);
  TEST_ASSERT_NOT_NULL(resp2);
  TEST_ASSERT_TRUE(fetch_response_ok(resp1));
  TEST_ASSERT_TRUE(fetch_response_ok(resp2));

  size_t total_count = fetch_cookie_jar_count(NULL);
  TEST_ASSERT_GREATER_OR_EQUAL(2, total_count);

  size_t nonexistent_count = fetch_cookie_jar_count("nonexistent.com");
  TEST_ASSERT_EQUAL(0, nonexistent_count);

  fetch_cookie_jar_print(jar, NULL);
  fetch_cookie_jar_print(jar, "localhost");
  fetch_cookie_jar_print(jar, "nonexistent.com");

  fetch_disable_cookies();
}

void test_cookie_clear_operations(void)
{
  fetch_global_dispose();

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_config_t config = fetch_config_default();
  config.cookie_jar = jar;
  config.origin = BUILD_URL("");

  fetch_global_init(&config);

  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  init->redirect = FETCH_REDIRECT_FOLLOW;
  init->credentials = FETCH_CREDENTIALS_SAME_ORIGIN;
  fetch_init_method(init, HTTP_METHOD_GET);

  fetch_response_t *resp1 = TRACK(fetch(BUILD_URL("/cookies/set?clear1=value1"), init), fetch_response_free);
  fetch_response_t *resp2 = TRACK(fetch(BUILD_URL("/cookies/set?clear2=value2"), init), fetch_response_free);

  TEST_ASSERT_NOT_NULL(resp1);
  TEST_ASSERT_NOT_NULL(resp2);
  TEST_ASSERT_TRUE(fetch_response_ok(resp1));
  TEST_ASSERT_TRUE(fetch_response_ok(resp2));

  size_t initial_count = fetch_cookie_jar_count(NULL);
  TEST_ASSERT_GREATER_OR_EQUAL(2, initial_count);

  fetch_cookie_jar_print(jar, NULL);

  fetch_cookie_jar_clear();

  size_t after_clear_count = fetch_cookie_jar_count(NULL);
  TEST_ASSERT_EQUAL(0, after_clear_count);

  fetch_cookie_jar_print(jar, NULL);

  fetch_disable_cookies();
}

void test_cookie_null_safety(void)
{
  fetch_global_dispose();

  TEST_ASSERT_NULL(fetch_get_cookie_jar());
  TEST_ASSERT_EQUAL(0, fetch_cookie_jar_count(NULL));
  TEST_ASSERT_EQUAL(0, fetch_cookie_jar_count("example.com"));

  fetch_cookie_jar_clear();
  fetch_disable_cookies();

  TEST_ASSERT_FALSE(fetch_save_cookies("test.txt", NULL));

  cookie_jar_t *test_jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_FALSE(fetch_save_cookies(NULL, test_jar));

  TEST_ASSERT_FALSE(fetch_load_cookies("test.txt", NULL));

  test_jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_FALSE(fetch_load_cookies(NULL, test_jar));

  fetch_cookie_jar_print(NULL, NULL);
  fetch_cookie_jar_print(NULL, "example.com");

  cookie_jar_t *jar = TRACK(fetch_create_cookie_jar(NULL), fetch_cookie_jar_free);
  TEST_ASSERT_NOT_NULL(jar);

  fetch_global_dispose();
}

// Test context for streaming callback
typedef struct {
  int call_count;
  int chunks_added;
  bool should_skip;
  bool should_finish;
  const char *test_filename;
} stream_test_context_t;

// Streaming callback function for chunked upload test
static fetch_stream_result_t streaming_callback(void *userdata)
{
  stream_test_context_t *context = (stream_test_context_t*)userdata;
  context->call_count++;
  
  printf("Streaming callback called %d times\n", context->call_count);
  
  if (context->should_finish) {
    printf("Callback returning DONE - finishing stream\n");
    return FETCH_STREAM_DONE;
  }
  
  if (context->should_skip) {
    printf("Callback returning SKIP - no data available\n");  
    return FETCH_STREAM_SKIP;
  }
  
  printf("Callback returning READ - continue reading\n");
  return FETCH_STREAM_READ;
}

void test_fetch_file_streaming_chunked_upload(void)
{
  const char *test_filename = "test_streaming_chunked.tmp";
  
  // Create initial test file with some data
#if defined(_WIN32) || defined(_WIN64)
  HANDLE file_handle = CreateFileA(test_filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, 
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
  
  const char *initial_data = "Initial streaming data chunk\n";
  DWORD bytes_written;
  WriteFile(file_handle, initial_data, (DWORD)strlen(initial_data), &bytes_written, NULL);
  CloseHandle(file_handle);

  // Open for reading with shared access so we can append while reading
  file_handle = CreateFileA(test_filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  TEST_ASSERT_NOT_EQUAL(INVALID_HANDLE_VALUE, file_handle);
#else
  FILE *temp_file = fopen(test_filename, "wb");
  TEST_ASSERT_NOT_NULL(temp_file);
  
  const char *initial_data = "Initial streaming data chunk\n";
  fwrite(initial_data, 1, strlen(initial_data), temp_file);
  fclose(temp_file);

  FILE *file_handle = fopen(test_filename, "rb");
  TEST_ASSERT_NOT_NULL(file_handle);
#endif

  // Initialize callback context
  stream_test_context_t ctx = {0, 0, false, false, test_filename};

  // Create streaming file body with callback - this enables chunked encoding
  fetch_body_t *body = TRACK(fetch_body_file(file_handle, 0, "text/plain", true, streaming_callback, &ctx), fetch_body_free);
  TEST_ASSERT_NOT_NULL(body);
  TEST_ASSERT_EQUAL(FETCH_BODY_FILE, body->type);
  TEST_ASSERT_NOT_NULL(body->data.file.continue_cb);
  TEST_ASSERT_EQUAL(&ctx, body->data.file.userdata);

  // Create headers
  fetch_headers_t *headers = TRACK(fetch_headers_new(), fetch_headers_free);
  fetch_headers_set(headers, "Content-Type", "text/plain");
  fetch_headers_set(headers, "X-Stream-Test", "chunked-upload");
  fetch_headers_set(headers, "X-Test-Mode", "streaming");

  // Create async request
  fetch_init_t *init = TRACK(fetch_init_new(), fetch_init_free);
  fetch_init_method(init, HTTP_METHOD_POST);
  fetch_init_headers(init, headers);
  UNTRACK(headers); // init now owns headers
  fetch_init_body(init, body);
  UNTRACK(body); // init now owns body
  fetch_init_timeout(init, 30000);

  // Start async request
  fetch_promise_t *promise = TRACK(fetch_async(BUILD_URL("/post"), init), fetch_promise_free);
  TEST_ASSERT_NOT_NULL(promise);
  TEST_ASSERT_EQUAL(FETCH_PROMISE_PENDING, fetch_promise_state(promise));

  // Simulate streaming by adding data and processing events
  const char *additional_chunks[] = {
    "Chunk 1: More streaming data from callback\n",
    "Chunk 2: Even more data being streamed\n", 
    "Chunk 3: This is the final chunk of streaming data\n"
  };
  
  int chunk_index = 0;
  int iterations = 0;
  const int max_iterations = 150; // Give plenty of time for async operation
  
  printf("Starting chunked streaming upload test...\n");
  
  while (fetch_promise_pending(promise) && iterations < max_iterations) {
    // Process events to pump the network and callback system
    fetch_event_loop_process(50);
    
    // Add more data to file when the callback has been called enough times
    if (chunk_index < 3 && ctx.call_count > (chunk_index * 3 + 2)) {
      printf("Adding chunk %d to file: %s", chunk_index, additional_chunks[chunk_index]);
      
#if defined(_WIN32) || defined(_WIN64)
      HANDLE append_handle = CreateFileA(test_filename, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (append_handle != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(append_handle, additional_chunks[chunk_index], 
                 (DWORD)strlen(additional_chunks[chunk_index]), &written, NULL);
        CloseHandle(append_handle);
        ctx.chunks_added++;
      }
#else
      FILE *append_file = fopen(test_filename, "ab");
      if (append_file) {
        fwrite(additional_chunks[chunk_index], 1, strlen(additional_chunks[chunk_index]), append_file);
        fclose(append_file);
        ctx.chunks_added++;
      }
#endif
      
      chunk_index++;
    }
    
    // Test SKIP behavior occasionally (every 15 iterations)
    if (iterations % 15 == 7) {
      ctx.should_skip = true;
      printf("Setting callback to SKIP mode\n");
    } else {
      ctx.should_skip = false;
    }
    
    // Finish the stream after adding all chunks and processing for a while
    if (chunk_index >= 3 && ctx.call_count > 15) {
      if (!ctx.should_finish) {
        printf("Setting callback to DONE mode - finishing stream\n");
        ctx.should_finish = true;
      }
    }
    
    iterations++;
    usleep(100000); // 100ms delay between iterations
  }

  // Force completion if still pending
  if (fetch_promise_pending(promise)) {
    printf("Request still pending, forcing completion...\n");
    ctx.should_finish = true;
    for (int i = 0; i < 50 && fetch_promise_pending(promise); i++) {
      fetch_event_loop_process(100);
      usleep(100000);
    }
  }

  printf("Chunked streaming test completed after %d iterations\n", iterations);
  printf("Callback was called %d times total\n", ctx.call_count);
  printf("Successfully added %d chunks to file\n", ctx.chunks_added);

  // Verify the request completed
  TEST_ASSERT_FALSE_MESSAGE(fetch_promise_pending(promise), "Request should have completed");
  
  if (fetch_promise_fulfilled(promise)) {
    fetch_response_t *response = fetch_promise_response(promise);
    TEST_ASSERT_NOT_NULL(response);
    TEST_ASSERT_TRUE(fetch_response_ok(response));
    TEST_ASSERT_EQUAL(200, fetch_response_status(response));

    const char *response_text = fetch_response_text(response);
    TEST_ASSERT_NOT_NULL(response_text);
    printf("Server response preview: %s...\n", response_text);
    
    // Verify our test headers were sent
    TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Stream-Test"));
    TEST_ASSERT_NOT_NULL(strstr(response_text, "chunked-upload"));
    TEST_ASSERT_NOT_NULL(strstr(response_text, "X-Test-Mode"));
    
    // Verify some of our streaming data made it through
    TEST_ASSERT_NOT_NULL(strstr(response_text, "streaming data"));
    
    // Check for chunked encoding evidence (server should have received chunked data)
    // The httpbin service typically echoes back the request details
    
    printf("✅ Chunked file streaming upload test completed successfully!\n");
  } else if (fetch_promise_rejected(promise)) {
    printf("❌ Request failed: %s\n", 
           fetch_promise_error_message(promise) ? fetch_promise_error_message(promise) : "Unknown error");
    TEST_FAIL_MESSAGE("Chunked streaming request was rejected");
  }

  // Verify callback behavior was tested
  TEST_ASSERT_GREATER_THAN_MESSAGE(10, ctx.call_count, "Callback should have been invoked multiple times");
  TEST_ASSERT_GREATER_THAN_MESSAGE(0, ctx.chunks_added, "Should have successfully added chunks during streaming");
  TEST_ASSERT_EQUAL_MESSAGE(3, ctx.chunks_added, "All 3 chunks should have been added");

  printf("Test verified: Callback invoked %d times, added %d chunks\n", 
         ctx.call_count, ctx.chunks_added);

  // Clean up test file
  unlink(test_filename);
}

int main(void)
{
  UNITY_BEGIN();

    // Basic utility function tests
  RUN_TEST(test_fetch_method_to_string);
  RUN_TEST(test_fetch_method_from_string);
  RUN_TEST(test_fetch_is_valid_url);
  RUN_TEST(test_fetch_error_to_string);

  // Headers tests
  RUN_TEST(test_fetch_headers_basic_operations);
  RUN_TEST(test_fetch_headers_iteration);
  RUN_TEST(test_fetch_headers_null_safety);
  RUN_TEST(test_fetch_headers_case_sensitivity);
  RUN_TEST(test_multiple_headers_same_name);
  RUN_TEST(test_large_headers_and_body);
  RUN_TEST(test_empty_and_whitespace_headers);

  // Body tests
  RUN_TEST(test_fetch_body_text);
  RUN_TEST(test_fetch_body_json);
  RUN_TEST(test_fetch_body_binary);
  RUN_TEST(test_fetch_body_form_data);
  RUN_TEST(test_fetch_body_null_safety);

  // File body tests
  RUN_TEST(test_fetch_body_file_basic);
  RUN_TEST(test_fetch_body_file_manual_close);
  RUN_TEST(test_fetch_body_file_null_safety);
  RUN_TEST(test_fetch_body_file_content_types);
  RUN_TEST(test_fetch_body_file_network_post);
  RUN_TEST(test_fetch_body_file_async_network_post);
  RUN_TEST(test_fetch_file_streaming_chunked_upload);

  // Init tests
  RUN_TEST(test_fetch_init_new_and_free);
  RUN_TEST(test_fetch_init_fluent_interface);
  RUN_TEST(test_fetch_init_null_safety);

  // Abort controller tests
  RUN_TEST(test_fetch_abort_controller);
  RUN_TEST(test_fetch_abort_controller_null_safety);

  // Event loop tests
  RUN_TEST(test_fetch_event_loop_control);

  // Error handling tests
  RUN_TEST(test_fetch_invalid_parameters);
  RUN_TEST(test_fetch_method_validation);
  RUN_TEST(test_fetch_timeout_configuration);

  // Async promise tests
  RUN_TEST(test_fetch_async_basic_lifecycle);
  RUN_TEST(test_fetch_async_invalid_url);
  RUN_TEST(test_fetch_async_cancellation);
  RUN_TEST(test_fetch_async_null_safety);

  // Response accessor tests
  RUN_TEST(test_response_accessor_null_safety);

  // Configuration tests
  RUN_TEST(test_fetch_global_configuration);

  // Integration tests
  RUN_TEST(test_complete_post_request_flow);
  RUN_TEST(test_convenience_macros);
  RUN_TEST(test_concurrent_async_requests);

  // URL search params tests
  RUN_TEST(test_fetch_url_search_params_basic_operations);
  RUN_TEST(test_fetch_url_search_params_duplicate_keys);
  RUN_TEST(test_fetch_url_search_params_to_string);
  RUN_TEST(test_fetch_url_search_params_url_encoding);
  RUN_TEST(test_fetch_url_search_params_iteration);
  RUN_TEST(test_fetch_url_search_params_null_safety);
  RUN_TEST(test_fetch_body_url_search_params);
  RUN_TEST(test_fetch_url_search_params_edge_cases);
  RUN_TEST(test_url_search_params_integration);

  // Stress tests
  RUN_TEST(test_async_fetch_stress_test);

  // Background thread tests
  RUN_TEST(test_fetch_async_with_background_thread);
  RUN_TEST(test_rapid_fire_async_requests);
  RUN_TEST(test_cancellation_with_background_thread);
  RUN_TEST(test_post_request_with_background_thread);
  RUN_TEST(test_mixed_requests_with_background_thread);

  // Binary data tests
  RUN_TEST(test_fetch_binary_data_basic_post);
  RUN_TEST(test_fetch_binary_data_image_simulation);
  RUN_TEST(test_fetch_binary_data_async_post);
  RUN_TEST(test_fetch_binary_data_receive_bytes);
  RUN_TEST(test_fetch_binary_data_async_receive_bytes);
  RUN_TEST(test_fetch_binary_data_large_payload);
  RUN_TEST(test_fetch_binary_data_with_background_thread);
  RUN_TEST(test_fetch_binary_data_null_bytes_handling);
  RUN_TEST(test_fetch_binary_data_response_validation);

  // Cookie tests
  RUN_TEST(test_cookie_jar_creation_and_cleanup);
  RUN_TEST(test_cookie_enable_disable);
  RUN_TEST(test_cookie_basic_set_and_get);
  RUN_TEST(test_cookie_multiple_cookies);
  RUN_TEST(test_cookie_async_requests);
  RUN_TEST(test_cookie_persistence);
  RUN_TEST(test_cookie_auto_persistence);
  RUN_TEST(test_cookie_domain_filtering);
  RUN_TEST(test_cookie_clear_operations);
  RUN_TEST(test_cookie_null_safety);


  return UNITY_END();
}
