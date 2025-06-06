#ifndef FETCH_STREAM_H
#define FETCH_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// FORWARD DECLARATIONS (OPAQUE TYPES)
// =============================================================================

// These remain opaque to users - internal implementation details
typedef struct fetch_readable_stream fetch_readable_stream_t;
typedef struct fetch_writable_stream fetch_writable_stream_t;
typedef struct fetch_transform_stream fetch_transform_stream_t;
typedef struct fetch_stream_reader fetch_stream_reader_t;
typedef struct fetch_stream_writer fetch_stream_writer_t;

// =============================================================================
// PUBLIC STRUCTURES
// =============================================================================

// Stream chunk - users need to understand this structure
typedef struct {
  void *value;
  size_t size;
  bool done;
} fetch_stream_chunk_t;

// Stream results
typedef enum {
  FETCH_STREAM_OK = 0,
  FETCH_STREAM_ERROR = 1
} fetch_stream_result_t;

// Stream states
typedef enum {
  FETCH_STREAM_STATE_READABLE = 0,
  FETCH_STREAM_STATE_CLOSED = 1,
  FETCH_STREAM_STATE_ERRORED = 2
} fetch_stream_state_t;

// Stream buffer for consume operations
typedef struct {
  void *data;
  size_t size;
  size_t capacity;
} stream_buffer_t;

// Controller structure - users need to interact with this
typedef struct fetch_readable_stream_controller {
  fetch_readable_stream_t *stream; // Points to the associated stream
  void *_internal;                 // Reserved for internal use
} fetch_readable_stream_controller_t;

// =============================================================================
// READABLE STREAM CONTROLLER
// =============================================================================

fetch_stream_result_t fetch_readable_stream_controller_enqueue(
    fetch_readable_stream_controller_t *controller, const void *value,
    size_t size);
void fetch_readable_stream_controller_close(
    fetch_readable_stream_controller_t *controller);
void fetch_readable_stream_controller_error(
    fetch_readable_stream_controller_t *controller, const char *error);

// =============================================================================
// READABLE STREAM
// =============================================================================

typedef void (*fetch_readable_stream_start_fn)(
    fetch_readable_stream_controller_t *controller, void *userdata);

fetch_readable_stream_t *
fetch_readable_stream_new(fetch_readable_stream_start_fn start, void *userdata);
void fetch_readable_stream_free(fetch_readable_stream_t *stream);

// Properties
bool fetch_readable_stream_locked(const fetch_readable_stream_t *stream);

// Methods
fetch_stream_reader_t *
fetch_readable_stream_get_reader(fetch_readable_stream_t *stream);
void fetch_readable_stream_cancel(fetch_readable_stream_t *stream,
                                  const char *reason);
fetch_stream_result_t
fetch_readable_stream_pipe_to(fetch_readable_stream_t *readable,
                              fetch_writable_stream_t *writable);
fetch_readable_stream_t *
fetch_readable_stream_pipe_through(fetch_readable_stream_t *readable,
                                   fetch_transform_stream_t *transform);
fetch_readable_stream_t *
fetch_readable_stream_tee(fetch_readable_stream_t *stream);

// =============================================================================
// WRITABLE STREAM
// =============================================================================

fetch_writable_stream_t *fetch_writable_stream_new(void);
void fetch_writable_stream_free(fetch_writable_stream_t *stream);

// Properties
bool fetch_writable_stream_locked(const fetch_writable_stream_t *stream);

// Methods
fetch_stream_writer_t *
fetch_writable_stream_get_writer(fetch_writable_stream_t *stream);
fetch_stream_result_t
fetch_writable_stream_abort(fetch_writable_stream_t *stream,
                            const char *reason);
fetch_stream_result_t
fetch_writable_stream_close(fetch_writable_stream_t *stream);

// =============================================================================
// TRANSFORM STREAM
// =============================================================================

fetch_transform_stream_t *fetch_transform_stream_new(void);
void fetch_transform_stream_free(fetch_transform_stream_t *stream);

// Properties
fetch_readable_stream_t *
fetch_transform_stream_readable(fetch_transform_stream_t *stream);
fetch_writable_stream_t *
fetch_transform_stream_writable(fetch_transform_stream_t *stream);

// =============================================================================
// READER
// =============================================================================

void fetch_stream_reader_free(fetch_stream_reader_t *reader);

// Properties
bool fetch_stream_reader_closed(const fetch_stream_reader_t *reader);

// Methods
fetch_stream_chunk_t fetch_stream_reader_read(fetch_stream_reader_t *reader);
void fetch_stream_reader_cancel(fetch_stream_reader_t *reader,
                                const char *reason);
void fetch_stream_reader_release_lock(fetch_stream_reader_t *reader);

// =============================================================================
// WRITER
// =============================================================================

void fetch_stream_writer_free(fetch_stream_writer_t *writer);

// Properties
bool fetch_stream_writer_closed(const fetch_stream_writer_t *writer);
fetch_stream_state_t
fetch_stream_writer_ready(const fetch_stream_writer_t *writer);

// Methods
fetch_stream_result_t fetch_stream_writer_write(fetch_stream_writer_t *writer,
                                                const void *chunk, size_t size);
fetch_stream_result_t fetch_stream_writer_close(fetch_stream_writer_t *writer);
fetch_stream_result_t fetch_stream_writer_abort(fetch_stream_writer_t *writer,
                                                const char *reason);
void fetch_stream_writer_release_lock(fetch_stream_writer_t *writer);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Consume entire readable stream into a contiguous buffer
 * This is a blocking operation that reads until the stream is closed
 *
 * @param stream The readable stream to consume
 * @param initial_capacity Initial buffer capacity (will grow as needed)
 * @return stream_buffer_t containing the data, or {NULL, 0, 0} on error
 *
 * Note: Caller must free the returned buffer with stream_buffer_free()
 */
stream_buffer_t
fetch_readable_stream_consume_all(fetch_readable_stream_t *stream,
                                  size_t initial_capacity);

/**
 * Convenience function with default initial capacity (4KB)
 */
stream_buffer_t
fetch_readable_stream_consume_all_default(fetch_readable_stream_t *stream);

/**
 * Free a stream buffer
 */
void stream_buffer_free(stream_buffer_t *buffer);

// =============================================================================
// UTILITIES
// =============================================================================

void fetch_stream_chunk_free(fetch_stream_chunk_t *chunk);

#ifdef __cplusplus
}
#endif

#endif // FETCH_STREAM_H