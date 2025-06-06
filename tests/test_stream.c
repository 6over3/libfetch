#include "unity.h"
#include "../src/stream.h"
#include <string.h>
#include <stdlib.h>

// =============================================================================
// CROSS-PLATFORM THREADING (SIMPLE)
// =============================================================================

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <process.h>

typedef HANDLE thread_t;
typedef unsigned int(__stdcall *thread_func_t)(void *);

#define THREAD_CREATE(thread, func, arg) \
    ((*(thread) = (HANDLE)_beginthreadex(NULL, 0, (func), (arg), 0, NULL)) != NULL)
#define THREAD_JOIN(thread) (WaitForSingleObject((thread), INFINITE) == WAIT_OBJECT_0)
#define THREAD_SLEEP_MS(ms) Sleep(ms)

// Simple atomics
typedef volatile LONG atomic_int_t;
#define ATOMIC_LOAD(ptr) (*(ptr))
#define ATOMIC_STORE(ptr, val) (*(ptr) = (val))
#define ATOMIC_INCREMENT(ptr) InterlockedIncrement(ptr)

#else
#include <pthread.h>
#include <unistd.h>

typedef pthread_t thread_t;
typedef void *(*thread_func_t)(void *);

#define THREAD_CREATE(thread, func, arg) (pthread_create((thread), NULL, (func), (arg)) == 0)
#define THREAD_JOIN(thread) (pthread_join((thread), NULL) == 0)
#define THREAD_SLEEP_MS(ms) usleep((ms) * 1000)

// Simple atomics
typedef volatile int atomic_int_t;
#define ATOMIC_LOAD(ptr) __sync_fetch_and_add((ptr), 0)
#define ATOMIC_STORE(ptr, val) __sync_lock_test_and_set((ptr), (val))
#define ATOMIC_INCREMENT(ptr) __sync_fetch_and_add((ptr), 1)

#endif

// =============================================================================
// TEST GLOBALS
// =============================================================================

static fetch_readable_stream_t *test_readable_stream;
static fetch_writable_stream_t *test_writable_stream;
static fetch_transform_stream_t *test_transform_stream;
static fetch_stream_reader_t *test_reader;
static fetch_stream_writer_t *test_writer;

// Simple thread coordination
static atomic_int_t producer_done;
static atomic_int_t consumer_done;
static atomic_int_t messages_written;
static atomic_int_t messages_read;

// Order validation globals
#define MAX_MESSAGES 100
static char received_messages[MAX_MESSAGES][64];
static int received_count;

// =============================================================================
// TEST SETUP/TEARDOWN
// =============================================================================

void setUp(void)
{
    test_readable_stream = NULL;
    test_writable_stream = NULL;
    test_transform_stream = NULL;
    test_reader = NULL;
    test_writer = NULL;

    ATOMIC_STORE(&producer_done, 0);
    ATOMIC_STORE(&consumer_done, 0);
    ATOMIC_STORE(&messages_written, 0);
    ATOMIC_STORE(&messages_read, 0);

    // Clear received messages
    memset(received_messages, 0, sizeof(received_messages));
    received_count = 0;
}

void tearDown(void)
{
    if (test_reader)
    {
        fetch_stream_reader_free(test_reader);
        test_reader = NULL;
    }

    if (test_writer)
    {
        fetch_stream_writer_free(test_writer);
        test_writer = NULL;
    }

    if (test_readable_stream)
    {
        fetch_readable_stream_free(test_readable_stream);
        test_readable_stream = NULL;
    }

    if (test_writable_stream)
    {
        fetch_writable_stream_free(test_writable_stream);
        test_writable_stream = NULL;
    }

    if (test_transform_stream)
    {
        fetch_transform_stream_free(test_transform_stream);
        test_transform_stream = NULL;
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

void test_stream_start_callback(fetch_readable_stream_controller_t *controller, void *userdata)
{
    const char *message = (const char *)userdata;
    if (message)
    {
        fetch_readable_stream_controller_enqueue(controller, message, strlen(message));
    }
    fetch_readable_stream_controller_close(controller);
}

// =============================================================================
// BASIC TESTS
// =============================================================================

void test_readable_stream_creation(void)
{
    const char *test_data = "Hello, World!";
    test_readable_stream = fetch_readable_stream_new(test_stream_start_callback, (void *)test_data);

    TEST_ASSERT_NOT_NULL(test_readable_stream);
    TEST_ASSERT_FALSE(fetch_readable_stream_locked(test_readable_stream));
}

void test_readable_stream_reader(void)
{
    const char *test_data = "Test Message";
    test_readable_stream = fetch_readable_stream_new(test_stream_start_callback, (void *)test_data);

    TEST_ASSERT_NOT_NULL(test_readable_stream);

    test_reader = fetch_readable_stream_get_reader(test_readable_stream);
    TEST_ASSERT_NOT_NULL(test_reader);
    TEST_ASSERT_TRUE(fetch_readable_stream_locked(test_readable_stream));

    fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_NOT_NULL(chunk.value);
    TEST_ASSERT_EQUAL_size_t(strlen(test_data), chunk.size);
    TEST_ASSERT_EQUAL_MEMORY(test_data, chunk.value, chunk.size);
    TEST_ASSERT_FALSE(chunk.done);

    fetch_stream_chunk_free(&chunk);

    // Next read should indicate done (stream was closed in callback)
    chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_TRUE(chunk.done);
}

void test_writable_stream_creation(void)
{
    test_writable_stream = fetch_writable_stream_new();

    TEST_ASSERT_NOT_NULL(test_writable_stream);
    TEST_ASSERT_FALSE(fetch_writable_stream_locked(test_writable_stream));
}

void test_transform_stream_creation(void)
{
    test_transform_stream = fetch_transform_stream_new();

    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    TEST_ASSERT_NOT_NULL(readable);
    TEST_ASSERT_NOT_NULL(writable);
    TEST_ASSERT_FALSE(fetch_readable_stream_locked(readable));
    TEST_ASSERT_FALSE(fetch_writable_stream_locked(writable));
}

void test_transform_stream_basic_operation(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    // Get writer and reader
    test_writer = fetch_writable_stream_get_writer(writable);
    test_reader = fetch_readable_stream_get_reader(readable);

    TEST_ASSERT_NOT_NULL(test_writer);
    TEST_ASSERT_NOT_NULL(test_reader);

    // Write some data
    const char *test_data = "Transform Test";
    fetch_stream_result_t result = fetch_stream_writer_write(test_writer, test_data, strlen(test_data));
    TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);

    // Close writer
    result = fetch_stream_writer_close(test_writer);
    TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);

    // Read the data back
    fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_NOT_NULL(chunk.value);
    TEST_ASSERT_EQUAL_size_t(strlen(test_data), chunk.size);
    TEST_ASSERT_EQUAL_MEMORY(test_data, chunk.value, chunk.size);

    fetch_stream_chunk_free(&chunk);
}

void test_stream_consume_all(void)
{
    const char *test_data = "Consume All Test Data";
    test_readable_stream = fetch_readable_stream_new(test_stream_start_callback, (void *)test_data);

    stream_buffer_t buffer = fetch_readable_stream_consume_all_default(test_readable_stream);

    TEST_ASSERT_NOT_NULL(buffer.data);
    TEST_ASSERT_EQUAL_size_t(strlen(test_data), buffer.size);
    TEST_ASSERT_EQUAL_MEMORY(test_data, buffer.data, buffer.size);

    stream_buffer_free(&buffer);
}

// =============================================================================
// ORDER VALIDATION TESTS
// =============================================================================

void test_multiple_messages_single_thread_ordered(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    test_writer = fetch_writable_stream_get_writer(writable);
    test_reader = fetch_readable_stream_get_reader(readable);

    TEST_ASSERT_NOT_NULL(test_writer);
    TEST_ASSERT_NOT_NULL(test_reader);

    // Write multiple messages in order
    const int MESSAGE_COUNT = 10;
    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        char message[32];
        snprintf(message, sizeof(message), "MSG-%04d", i);

        fetch_stream_result_t result = fetch_stream_writer_write(test_writer, message, strlen(message));
        TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);
    }

    // Close writer
    fetch_stream_writer_close(test_writer);

    // Read all messages back and verify order
    for (int expected = 0; expected < MESSAGE_COUNT; expected++)
    {
        fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);

        TEST_ASSERT_FALSE(chunk.done);
        TEST_ASSERT_NOT_NULL(chunk.value);
        TEST_ASSERT_TRUE(chunk.size > 0);

        // Create expected message
        char expected_message[32];
        snprintf(expected_message, sizeof(expected_message), "MSG-%04d", expected);

        // Verify exact content and size
        TEST_ASSERT_EQUAL_size_t(strlen(expected_message), chunk.size);
        TEST_ASSERT_EQUAL_MEMORY(expected_message, chunk.value, chunk.size);

        // Verify null termination is not included
        TEST_ASSERT_EQUAL_size_t(8, chunk.size); // "MSG-0000" = 8 chars

        fetch_stream_chunk_free(&chunk);
    }

    // Verify stream is done
    fetch_stream_chunk_t final_chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_TRUE(final_chunk.done);
}

void test_interleaved_write_read_ordered(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    test_writer = fetch_writable_stream_get_writer(writable);
    test_reader = fetch_readable_stream_get_reader(readable);

    TEST_ASSERT_NOT_NULL(test_writer);
    TEST_ASSERT_NOT_NULL(test_reader);

    // Write and read messages in interleaved pattern
    const int MESSAGE_COUNT = 5;
    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        // Write message
        char write_message[32];
        snprintf(write_message, sizeof(write_message), "DATA-%03d", i);

        fetch_stream_result_t result = fetch_stream_writer_write(test_writer, write_message, strlen(write_message));
        TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);

        // Immediately read it back
        fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);

        TEST_ASSERT_FALSE(chunk.done);
        TEST_ASSERT_NOT_NULL(chunk.value);
        TEST_ASSERT_EQUAL_size_t(strlen(write_message), chunk.size);
        TEST_ASSERT_EQUAL_MEMORY(write_message, chunk.value, chunk.size);

        fetch_stream_chunk_free(&chunk);
    }

    // Close and verify no more data
    fetch_stream_writer_close(test_writer);

    fetch_stream_chunk_t final_chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_TRUE(final_chunk.done);
}

void test_large_messages_ordered(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    test_writer = fetch_writable_stream_get_writer(writable);
    test_reader = fetch_readable_stream_get_reader(readable);

    TEST_ASSERT_NOT_NULL(test_writer);
    TEST_ASSERT_NOT_NULL(test_reader);

    // Write larger messages with simple sequence validation
    const int MESSAGE_COUNT = 5;

    // Use simpler, fixed-size messages
    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        char large_message[100];
        snprintf(large_message, sizeof(large_message),
                 "LARGE-MESSAGE-%03d-CONTENT-DATA-END", i);

        fetch_stream_result_t result = fetch_stream_writer_write(test_writer, large_message, strlen(large_message));
        TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);
    }

    fetch_stream_writer_close(test_writer);

    // Read and verify each message
    for (int expected = 0; expected < MESSAGE_COUNT; expected++)
    {
        fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);

        TEST_ASSERT_FALSE(chunk.done);
        TEST_ASSERT_NOT_NULL(chunk.value);

        // Create expected message
        char expected_message[100];
        snprintf(expected_message, sizeof(expected_message),
                 "LARGE-MESSAGE-%03d-CONTENT-DATA-END", expected);

        // Verify the message content matches exactly
        TEST_ASSERT_EQUAL_size_t(strlen(expected_message), chunk.size);
        TEST_ASSERT_EQUAL_MEMORY(expected_message, chunk.value, chunk.size);

        fetch_stream_chunk_free(&chunk);
    }

    // Verify stream is done
    fetch_stream_chunk_t final_chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_TRUE(final_chunk.done);
}

// =============================================================================
// THREADED TESTS WITH ORDER VALIDATION
// =============================================================================

typedef struct
{
    fetch_transform_stream_t *transform;
    int message_count;
    int start_index;
} ordered_thread_data_t;

#if defined(_WIN32) || defined(_WIN64)
unsigned int __stdcall ordered_producer_thread(void *arg)
{
#else
void *ordered_producer_thread(void *arg)
{
#endif
    ordered_thread_data_t *data = (ordered_thread_data_t *)arg;

    fetch_writable_stream_t *writable = fetch_transform_stream_writable(data->transform);
    fetch_stream_writer_t *writer = fetch_writable_stream_get_writer(writable);

    if (!writer)
    {
#if defined(_WIN32) || defined(_WIN64)
        return 1;
#else
        return (void *)1;
#endif
    }

    // Write messages in strict order
    for (int i = 0; i < data->message_count; i++)
    {
        char message[64];
        snprintf(message, sizeof(message), "ORDERED-%04d-VALUE-%08d",
                 data->start_index + i, (data->start_index + i) * 1000);

        fetch_stream_result_t result = fetch_stream_writer_write(writer, message, strlen(message));
        if (result == FETCH_STREAM_OK)
        {
            ATOMIC_INCREMENT(&messages_written);
        }

        // Small delay to allow reader to process
        THREAD_SLEEP_MS(1);
    }

    fetch_stream_writer_close(writer);
    fetch_stream_writer_free(writer);
    ATOMIC_STORE(&producer_done, 1);

#if defined(_WIN32) || defined(_WIN64)
    return 0;
#else
    return NULL;
#endif
}

#if defined(_WIN32) || defined(_WIN64)
unsigned int __stdcall ordered_consumer_thread(void *arg)
{
#else
void *ordered_consumer_thread(void *arg)
{
#endif
    ordered_thread_data_t *data = (ordered_thread_data_t *)arg;

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(data->transform);
    fetch_stream_reader_t *reader = fetch_readable_stream_get_reader(readable);

    if (!reader)
    {
#if defined(_WIN32) || defined(_WIN64)
        return 1;
#else
        return (void *)1;
#endif
    }

    int expected_index = data->start_index;

    while (1)
    {
        fetch_stream_chunk_t chunk = fetch_stream_reader_read(reader);

        if (chunk.done)
        {
            break;
        }

        if (chunk.value && chunk.size > 0)
        {
            // Store message for validation
            if (received_count < MAX_MESSAGES)
            {
                memcpy(received_messages[received_count], chunk.value,
                       chunk.size < 63 ? chunk.size : 63);
                received_messages[received_count][chunk.size < 63 ? chunk.size : 63] = '\0';
                received_count++;
            }

            // Validate message format and order
            char expected_message[64];
            snprintf(expected_message, sizeof(expected_message), "ORDERED-%04d-VALUE-%08d",
                     expected_index, expected_index * 1000);

            if (chunk.size == strlen(expected_message) &&
                memcmp(chunk.value, expected_message, chunk.size) == 0)
            {
                expected_index++;
                ATOMIC_INCREMENT(&messages_read);
            }

            fetch_stream_chunk_free(&chunk);
        }
        else
        {
            THREAD_SLEEP_MS(1);
        }
    }

    fetch_stream_reader_free(reader);
    ATOMIC_STORE(&consumer_done, 1);

#if defined(_WIN32) || defined(_WIN64)
    return 0;
#else
    return NULL;
#endif
}

void test_threaded_producer_consumer_ordered(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    // Reset counters
    ATOMIC_STORE(&producer_done, 0);
    ATOMIC_STORE(&consumer_done, 0);
    ATOMIC_STORE(&messages_written, 0);
    ATOMIC_STORE(&messages_read, 0);
    received_count = 0;

    const int MESSAGE_COUNT = 20;
    const int START_INDEX = 0;

    ordered_thread_data_t thread_data = {
        .transform = test_transform_stream,
        .message_count = MESSAGE_COUNT,
        .start_index = START_INDEX};

    // Create consumer thread first
    thread_t consumer_thread;
    TEST_ASSERT_TRUE(THREAD_CREATE(&consumer_thread, ordered_consumer_thread, &thread_data));

    // Small delay to ensure consumer is ready
    THREAD_SLEEP_MS(10);

    // Create producer thread
    thread_t producer_thread;
    TEST_ASSERT_TRUE(THREAD_CREATE(&producer_thread, ordered_producer_thread, &thread_data));

    // Wait for producer to finish
    TEST_ASSERT_TRUE(THREAD_JOIN(producer_thread));

    // Wait for consumer to finish
    TEST_ASSERT_TRUE(THREAD_JOIN(consumer_thread));

    // Verify results
    int final_written = ATOMIC_LOAD(&messages_written);
    int final_read = ATOMIC_LOAD(&messages_read);

    TEST_ASSERT_EQUAL(MESSAGE_COUNT, final_written);
    TEST_ASSERT_EQUAL(MESSAGE_COUNT, final_read);
    TEST_ASSERT_EQUAL(MESSAGE_COUNT, received_count);

    // Verify all messages were received in correct order
    for (int i = 0; i < received_count; i++)
    {
        char expected[64];
        snprintf(expected, sizeof(expected), "ORDERED-%04d-VALUE-%08d", i, i * 1000);
        TEST_ASSERT_EQUAL_STRING(expected, received_messages[i]);
    }
}

// =============================================================================
// STRESS TESTS
// =============================================================================

void test_many_small_messages_ordered(void)
{
    test_transform_stream = fetch_transform_stream_new();
    TEST_ASSERT_NOT_NULL(test_transform_stream);

    fetch_readable_stream_t *readable = fetch_transform_stream_readable(test_transform_stream);
    fetch_writable_stream_t *writable = fetch_transform_stream_writable(test_transform_stream);

    test_writer = fetch_writable_stream_get_writer(writable);
    test_reader = fetch_readable_stream_get_reader(readable);

    TEST_ASSERT_NOT_NULL(test_writer);
    TEST_ASSERT_NOT_NULL(test_reader);

    // Write many small messages
    const int MESSAGE_COUNT = 50;
    for (int i = 0; i < MESSAGE_COUNT; i++)
    {
        char message[16];
        snprintf(message, sizeof(message), "S%04d", i);

        fetch_stream_result_t result = fetch_stream_writer_write(test_writer, message, strlen(message));
        TEST_ASSERT_EQUAL(FETCH_STREAM_OK, result);
    }

    fetch_stream_writer_close(test_writer);

    // Read all messages back and verify order
    for (int expected = 0; expected < MESSAGE_COUNT; expected++)
    {
        fetch_stream_chunk_t chunk = fetch_stream_reader_read(test_reader);

        TEST_ASSERT_FALSE(chunk.done);
        TEST_ASSERT_NOT_NULL(chunk.value);

        char expected_message[16];
        snprintf(expected_message, sizeof(expected_message), "S%04d", expected);

        TEST_ASSERT_EQUAL_size_t(strlen(expected_message), chunk.size);
        TEST_ASSERT_EQUAL_MEMORY(expected_message, chunk.value, chunk.size);

        fetch_stream_chunk_free(&chunk);
    }

    // Verify stream is done
    fetch_stream_chunk_t final_chunk = fetch_stream_reader_read(test_reader);
    TEST_ASSERT_TRUE(final_chunk.done);
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

int main(void)
{
    UNITY_BEGIN();

    // Basic functionality tests
    RUN_TEST(test_readable_stream_creation);
    RUN_TEST(test_readable_stream_reader);
    RUN_TEST(test_writable_stream_creation);
    RUN_TEST(test_transform_stream_creation);
    RUN_TEST(test_transform_stream_basic_operation);
    RUN_TEST(test_stream_consume_all);

    // Order validation tests
    RUN_TEST(test_multiple_messages_single_thread_ordered);
    RUN_TEST(test_interleaved_write_read_ordered);
    RUN_TEST(test_large_messages_ordered);
    RUN_TEST(test_many_small_messages_ordered);

    // Threaded tests with order validation
    RUN_TEST(test_threaded_producer_consumer_ordered);

    return UNITY_END();
}