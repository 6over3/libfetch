#include "stream.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
// CROSS-PLATFORM ALIGNED ALLOCATION
// =============================================================================

#if defined(_MSC_VER) || (defined(_WIN32) || defined(_WIN64))
// Windows _aligned_malloc (check Windows first)
#define HAS_WINDOWS_ALIGNED_MALLOC 1
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
// C11 aligned_alloc (but not on Windows)
#define HAS_ALIGNED_ALLOC 1
#elif defined(_POSIX_VERSION) && _POSIX_VERSION >= 200112L
// POSIX posix_memalign
#define HAS_POSIX_MEMALIGN 1
#else
// Fallback to regular malloc
#define HAS_FALLBACK_MALLOC 1
#endif

static void *aligned_malloc(size_t size, size_t alignment) {
#ifdef HAS_ALIGNED_ALLOC
  // C11 aligned_alloc requires size to be multiple of alignment
  size_t aligned_size = (size + alignment - 1) & ~(alignment - 1);
  return aligned_alloc(alignment, aligned_size);

#elif defined(HAS_POSIX_MEMALIGN)
  void *ptr;
  if (posix_memalign(&ptr, alignment, size) == 0) {
    return ptr;
  }
  return NULL;

#elif defined(HAS_WINDOWS_ALIGNED_MALLOC)
  return _aligned_malloc(size, alignment);

#else
  // Fallback: manual alignment with overhead tracking
  size_t total_size = size + alignment + sizeof(void *);
  void *raw_ptr = malloc(total_size);
  if (!raw_ptr)
    return NULL;

  uintptr_t addr = (uintptr_t)raw_ptr + sizeof(void *);
  uintptr_t aligned_addr = (addr + alignment - 1) & ~(alignment - 1);

  // Store original pointer just before aligned address
  *((void **)(aligned_addr - sizeof(void *))) = raw_ptr;

  return (void *)aligned_addr;
#endif
}

static void aligned_free(void *ptr) {
  if (!ptr)
    return;

#ifdef HAS_ALIGNED_ALLOC
  free(ptr);

#elif defined(HAS_POSIX_MEMALIGN)
  free(ptr);

#elif defined(HAS_WINDOWS_ALIGNED_MALLOC)
  _aligned_free(ptr);

#else
  // Fallback: retrieve original pointer
  void *original_ptr = *((void **)((uintptr_t)ptr - sizeof(void *)));
  free(original_ptr);
#endif
}

// =============================================================================
// CROSS-PLATFORM ATOMICS
// =============================================================================

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#ifdef HAS_WINDOWS_ALIGNED_MALLOC
#include <malloc.h>
#endif

typedef volatile LONG atomic_uint32_t;
typedef volatile LONG64 atomic_uint64_t;
typedef volatile PVOID atomic_ptr_t;

#define ATOMIC_LOAD_RELAXED(ptr) (*(ptr))
#define ATOMIC_STORE_RELAXED(ptr, val) (*(ptr) = (val))
#define ATOMIC_LOAD_ACQUIRE(ptr) (*(ptr))
#define ATOMIC_STORE_RELEASE(ptr, val) (*(ptr) = (val))
#define ATOMIC_CAS_WEAK(ptr, expected, desired)                                \
  (InterlockedCompareExchange((ptr), (desired), (expected)) == (expected))
#define ATOMIC_FETCH_ADD(ptr, val) InterlockedAdd((ptr), (val))

#else
#include <stdatomic.h>
#ifdef HAS_POSIX_MEMALIGN
#include <stdlib.h>
#endif

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#endif

typedef _Atomic(uint32_t) atomic_uint32_t;
typedef _Atomic(uint64_t) atomic_uint64_t;
typedef _Atomic(void *) atomic_ptr_t;

#define ATOMIC_LOAD_RELAXED(ptr)                                               \
  atomic_load_explicit((ptr), memory_order_relaxed)
#define ATOMIC_STORE_RELAXED(ptr, val)                                         \
  atomic_store_explicit((ptr), (val), memory_order_relaxed)
#define ATOMIC_LOAD_ACQUIRE(ptr)                                               \
  atomic_load_explicit((ptr), memory_order_acquire)
#define ATOMIC_STORE_RELEASE(ptr, val)                                         \
  atomic_store_explicit((ptr), (val), memory_order_release)
#define ATOMIC_CAS_WEAK(ptr, expected, desired)                                \
  atomic_compare_exchange_weak_explicit((ptr), &(expected), (desired),         \
                                        memory_order_acq_rel,                  \
                                        memory_order_relaxed)
#define ATOMIC_FETCH_ADD(ptr, val)                                             \
  atomic_fetch_add_explicit((ptr), (val), memory_order_acq_rel)

#endif

// =============================================================================
// LOCK-FREE RING BUFFER
// =============================================================================

#define RING_BUFFER_SIZE 1024 // Must be power of 2
#define RING_BUFFER_MASK (RING_BUFFER_SIZE - 1)

typedef struct {
  fetch_stream_chunk_t chunk;
  atomic_uint32_t sequence;
} ring_slot_t;

typedef struct {
  ring_slot_t slots[RING_BUFFER_SIZE];
  atomic_uint32_t head;   // Producer index
  atomic_uint32_t tail;   // Consumer index
  atomic_uint32_t closed; // 1 if closed, 0 if open
#ifndef HAS_FALLBACK_MALLOC
  char padding[64]; // Cache line padding (only when aligned allocation
                    // available)
#endif
} lock_free_ring_buffer_t;

static lock_free_ring_buffer_t *ring_buffer_new(void) {
#ifndef HAS_FALLBACK_MALLOC
  // Use aligned allocation for better cache performance
  lock_free_ring_buffer_t *buffer = (lock_free_ring_buffer_t *)aligned_malloc(
      sizeof(lock_free_ring_buffer_t), 64);
#else
  // Fallback to regular malloc
  lock_free_ring_buffer_t *buffer = malloc(sizeof(lock_free_ring_buffer_t));
#endif

  if (!buffer)
    return NULL;

  memset(buffer, 0, sizeof(lock_free_ring_buffer_t));

  // Initialize all slot sequences
  for (uint32_t i = 0; i < RING_BUFFER_SIZE; i++) {
    ATOMIC_STORE_RELAXED(&buffer->slots[i].sequence, i);
  }

  return buffer;
}

static void ring_buffer_free(lock_free_ring_buffer_t *buffer) {
  if (!buffer)
    return;

  // Clean up any remaining chunks
  uint32_t tail = ATOMIC_LOAD_RELAXED(&buffer->tail);
  uint32_t head = ATOMIC_LOAD_RELAXED(&buffer->head);

  while (tail != head) {
    uint32_t index = tail & RING_BUFFER_MASK;
    fetch_stream_chunk_free(&buffer->slots[index].chunk);
    tail++;
  }

#ifndef HAS_FALLBACK_MALLOC
  aligned_free(buffer);
#else
  free(buffer);
#endif
}

static bool ring_buffer_enqueue(lock_free_ring_buffer_t *buffer,
                                fetch_stream_chunk_t chunk) {
  if (!buffer) {
    fetch_stream_chunk_free(&chunk);
    return false;
  }

  if (ATOMIC_LOAD_RELAXED(&buffer->closed)) {
    fetch_stream_chunk_free(&chunk);
    return false;
  }

  uint32_t head = ATOMIC_LOAD_RELAXED(&buffer->head);

  while (true) {
    uint32_t index = head & RING_BUFFER_MASK;
    uint32_t sequence = ATOMIC_LOAD_ACQUIRE(&buffer->slots[index].sequence);

    if (sequence == head) {
      // Slot is available for writing
      buffer->slots[index].chunk = chunk;
      ATOMIC_STORE_RELEASE(&buffer->slots[index].sequence, head + 1);

      // Try to advance head
      uint32_t expected_head = head;
      if (ATOMIC_CAS_WEAK(&buffer->head, expected_head, head + 1)) {
        return true;
      }
      // CAS failed, retry with new head value
      head = ATOMIC_LOAD_RELAXED(&buffer->head);
    } else if (sequence < head) {
      // Buffer is full, try to advance head and retry
      uint32_t new_head = ATOMIC_LOAD_RELAXED(&buffer->head);
      if (new_head == head) {
        // Still full
        fetch_stream_chunk_free(&chunk);
        return false;
      }
      head = new_head;
    } else {
      // sequence > head, reload head and retry
      head = ATOMIC_LOAD_RELAXED(&buffer->head);
    }
  }
}

static fetch_stream_chunk_t
ring_buffer_dequeue(lock_free_ring_buffer_t *buffer) {
  fetch_stream_chunk_t empty = {0};

  if (!buffer) {
    empty.done = true;
    return empty;
  }

  uint32_t tail = ATOMIC_LOAD_RELAXED(&buffer->tail);

  // Try a few times before giving up (avoid infinite spinning)
  for (int attempts = 0; attempts < 3; attempts++) {
    uint32_t index = tail & RING_BUFFER_MASK;
    uint32_t sequence = ATOMIC_LOAD_ACQUIRE(&buffer->slots[index].sequence);

    if (sequence == tail + 1) {
      // Data is available
      fetch_stream_chunk_t chunk = buffer->slots[index].chunk;
      buffer->slots[index].chunk = (fetch_stream_chunk_t){0}; // Clear slot
      ATOMIC_STORE_RELEASE(&buffer->slots[index].sequence,
                           tail + RING_BUFFER_SIZE);

      // Try to advance tail
      uint32_t expected_tail = tail;
      if (ATOMIC_CAS_WEAK(&buffer->tail, expected_tail, tail + 1)) {
        return chunk;
      }
      // CAS failed, put chunk back and retry
      buffer->slots[index].chunk = chunk;
      ATOMIC_STORE_RELEASE(&buffer->slots[index].sequence, tail + 1);
      tail = ATOMIC_LOAD_RELAXED(&buffer->tail);
    } else if (sequence < tail + 1) {
      // No data available - check if stream is closed
      if (ATOMIC_LOAD_RELAXED(&buffer->closed)) {
        empty.done = true;
      }
      // If not closed, just return empty (not done)
      return empty;
    } else {
      // sequence > tail + 1, reload tail and retry
      tail = ATOMIC_LOAD_RELAXED(&buffer->tail);
    }
  }

  // After attempts, check if closed
  if (ATOMIC_LOAD_RELAXED(&buffer->closed)) {
    empty.done = true;
  }
  return empty;
}

static void ring_buffer_close(lock_free_ring_buffer_t *buffer) {
  if (buffer) {
    ATOMIC_STORE_RELAXED(&buffer->closed, 1);
  }
}

// =============================================================================
// ATOMIC BOOL
// =============================================================================

typedef struct {
  atomic_uint32_t value;
} atomic_bool_t;

static void atomic_bool_init(atomic_bool_t *atomic, bool initial) {
  ATOMIC_STORE_RELAXED(&atomic->value, initial ? 1 : 0);
}

static void atomic_bool_destroy(atomic_bool_t *atomic) {
  (void)atomic; // No cleanup needed
}

static bool atomic_bool_load(atomic_bool_t *atomic) {
  return ATOMIC_LOAD_RELAXED(&atomic->value) != 0;
}

static void atomic_bool_store(atomic_bool_t *atomic, bool value) {
  ATOMIC_STORE_RELAXED(&atomic->value, value ? 1 : 0);
}

// =============================================================================
// STREAM STRUCTURES (IMPLEMENTATION DETAILS)
// =============================================================================

struct fetch_readable_stream {
  lock_free_ring_buffer_t *buffer;
  atomic_uint32_t reader_count; // Number of active readers
  atomic_bool_t closed;
};

struct fetch_writable_stream {
  lock_free_ring_buffer_t *buffer;
  atomic_uint32_t writer_count; // Number of active writers
  atomic_bool_t closed;
};

struct fetch_transform_stream {
  fetch_readable_stream_t *readable;
  fetch_writable_stream_t *writable;
  lock_free_ring_buffer_t *shared_buffer;
};

struct fetch_stream_reader {
  fetch_readable_stream_t *stream;
  uint32_t reader_id;
};

struct fetch_stream_writer {
  fetch_writable_stream_t *stream;
  uint32_t writer_id;
};

// =============================================================================
// UTILITIES
// =============================================================================

void fetch_stream_chunk_free(fetch_stream_chunk_t *chunk) {
  if (!chunk)
    return;

  free(chunk->value);
  chunk->value = NULL;
  chunk->size = 0;
  chunk->done = false;
}

static fetch_stream_chunk_t chunk_copy(const void *data, size_t size) {
  fetch_stream_chunk_t chunk = {0};

  if (data && size > 0) {
    chunk.value = malloc(size);
    if (chunk.value) {
      memcpy(chunk.value, data, size);
      chunk.size = size;
    }
  }

  return chunk;
}

// =============================================================================
// READABLE STREAM CONTROLLER
// =============================================================================

fetch_stream_result_t fetch_readable_stream_controller_enqueue(
    fetch_readable_stream_controller_t *controller, const void *value,
    size_t size) {
  if (!controller || !controller->stream) {
    return FETCH_STREAM_ERROR;
  }

  fetch_stream_chunk_t chunk = chunk_copy(value, size);
  if (!ring_buffer_enqueue(controller->stream->buffer, chunk)) {
    return FETCH_STREAM_ERROR;
  }

  return FETCH_STREAM_OK;
}

void fetch_readable_stream_controller_close(
    fetch_readable_stream_controller_t *controller) {
  if (!controller || !controller->stream)
    return;

  atomic_bool_store(&controller->stream->closed, true);
  ring_buffer_close(controller->stream->buffer);
}

void fetch_readable_stream_controller_error(
    fetch_readable_stream_controller_t *controller, const char *error) {
  if (!controller || !controller->stream)
    return;

  (void)error; // Not implemented for simplicity
  atomic_bool_store(&controller->stream->closed, true);
  ring_buffer_close(controller->stream->buffer);
}

// =============================================================================
// READABLE STREAM
// =============================================================================

fetch_readable_stream_t *
fetch_readable_stream_new(fetch_readable_stream_start_fn start,
                          void *userdata) {
  fetch_readable_stream_t *stream = calloc(1, sizeof(fetch_readable_stream_t));
  if (!stream)
    return NULL;

  stream->buffer = ring_buffer_new();
  if (!stream->buffer) {
    free(stream);
    return NULL;
  }

  ATOMIC_STORE_RELAXED(&stream->reader_count, 0);
  atomic_bool_init(&stream->closed, false);

  if (start) {
    fetch_readable_stream_controller_t controller = {
        .stream = stream,
        ._internal = NULL // Reserved for future use
    };
    start(&controller, userdata);
  }

  return stream;
}

void fetch_readable_stream_free(fetch_readable_stream_t *stream) {
  if (!stream)
    return;

  ring_buffer_free(stream->buffer);
  atomic_bool_destroy(&stream->closed);
  free(stream);
}

bool fetch_readable_stream_locked(const fetch_readable_stream_t *stream) {
  return stream ? (ATOMIC_LOAD_RELAXED(&stream->reader_count) > 0) : false;
}

fetch_stream_reader_t *
fetch_readable_stream_get_reader(fetch_readable_stream_t *stream) {
  if (!stream)
    return NULL;

  fetch_stream_reader_t *reader = calloc(1, sizeof(fetch_stream_reader_t));
  if (!reader)
    return NULL;

  reader->stream = stream;
  reader->reader_id = ATOMIC_FETCH_ADD(&stream->reader_count, 1);

  return reader;
}

void fetch_readable_stream_cancel(fetch_readable_stream_t *stream,
                                  const char *reason) {
  if (!stream)
    return;

  (void)reason;
  atomic_bool_store(&stream->closed, true);
  ring_buffer_close(stream->buffer);
}

fetch_readable_stream_t *
fetch_readable_stream_tee(fetch_readable_stream_t *stream) {
  (void)stream;
  return NULL; // Not implemented for simplicity
}

// =============================================================================
// WRITABLE STREAM
// =============================================================================

fetch_writable_stream_t *fetch_writable_stream_new(void) {
  fetch_writable_stream_t *stream = calloc(1, sizeof(fetch_writable_stream_t));
  if (!stream)
    return NULL;

  stream->buffer = ring_buffer_new();
  if (!stream->buffer) {
    free(stream);
    return NULL;
  }

  ATOMIC_STORE_RELAXED(&stream->writer_count, 0);
  atomic_bool_init(&stream->closed, false);

  return stream;
}

void fetch_writable_stream_free(fetch_writable_stream_t *stream) {
  if (!stream)
    return;

  ring_buffer_free(stream->buffer);
  atomic_bool_destroy(&stream->closed);
  free(stream);
}

bool fetch_writable_stream_locked(const fetch_writable_stream_t *stream) {
  return stream ? (ATOMIC_LOAD_RELAXED(&stream->writer_count) > 0) : false;
}

fetch_stream_writer_t *
fetch_writable_stream_get_writer(fetch_writable_stream_t *stream) {
  if (!stream)
    return NULL;

  fetch_stream_writer_t *writer = calloc(1, sizeof(fetch_stream_writer_t));
  if (!writer)
    return NULL;

  writer->stream = stream;
  writer->writer_id = ATOMIC_FETCH_ADD(&stream->writer_count, 1);

  return writer;
}

fetch_stream_result_t
fetch_writable_stream_abort(fetch_writable_stream_t *stream,
                            const char *reason) {
  if (!stream)
    return FETCH_STREAM_ERROR;

  (void)reason;
  atomic_bool_store(&stream->closed, true);
  ring_buffer_close(stream->buffer);
  return FETCH_STREAM_OK;
}

fetch_stream_result_t
fetch_writable_stream_close(fetch_writable_stream_t *stream) {
  if (!stream)
    return FETCH_STREAM_ERROR;

  atomic_bool_store(&stream->closed, true);
  ring_buffer_close(stream->buffer);
  return FETCH_STREAM_OK;
}

// =============================================================================
// TRANSFORM STREAM
// =============================================================================

fetch_transform_stream_t *fetch_transform_stream_new(void) {
  fetch_transform_stream_t *transform =
      calloc(1, sizeof(fetch_transform_stream_t));
  if (!transform)
    return NULL;

  // Create shared lock-free buffer
  transform->shared_buffer = ring_buffer_new();
  if (!transform->shared_buffer) {
    free(transform);
    return NULL;
  }

  // Create readable stream
  transform->readable = calloc(1, sizeof(fetch_readable_stream_t));
  if (!transform->readable) {
    ring_buffer_free(transform->shared_buffer);
    free(transform);
    return NULL;
  }

  transform->readable->buffer = transform->shared_buffer;
  ATOMIC_STORE_RELAXED(&transform->readable->reader_count, 0);
  atomic_bool_init(&transform->readable->closed, false);

  // Create writable stream
  transform->writable = calloc(1, sizeof(fetch_writable_stream_t));
  if (!transform->writable) {
    atomic_bool_destroy(&transform->readable->closed);
    free(transform->readable);
    ring_buffer_free(transform->shared_buffer);
    free(transform);
    return NULL;
  }

  transform->writable->buffer = transform->shared_buffer;
  ATOMIC_STORE_RELAXED(&transform->writable->writer_count, 0);
  atomic_bool_init(&transform->writable->closed, false);

  return transform;
}

void fetch_transform_stream_free(fetch_transform_stream_t *stream) {
  if (!stream)
    return;

  if (stream->readable) {
    atomic_bool_destroy(&stream->readable->closed);
    free(stream->readable);
  }

  if (stream->writable) {
    atomic_bool_destroy(&stream->writable->closed);
    free(stream->writable);
  }

  ring_buffer_free(stream->shared_buffer);
  free(stream);
}

fetch_readable_stream_t *
fetch_transform_stream_readable(fetch_transform_stream_t *stream) {
  return stream ? stream->readable : NULL;
}

fetch_writable_stream_t *
fetch_transform_stream_writable(fetch_transform_stream_t *stream) {
  return stream ? stream->writable : NULL;
}

// =============================================================================
// READER
// =============================================================================

void fetch_stream_reader_free(fetch_stream_reader_t *reader) {
  if (!reader)
    return;

  if (reader->stream) {
    ATOMIC_FETCH_ADD(&reader->stream->reader_count, -1);
  }

  free(reader);
}

bool fetch_stream_reader_closed(const fetch_stream_reader_t *reader) {
  return reader ? atomic_bool_load((atomic_bool_t *)&reader->stream->closed)
                : true;
}

fetch_stream_chunk_t fetch_stream_reader_read(fetch_stream_reader_t *reader) {
  fetch_stream_chunk_t empty = {.done = true};

  if (!reader || !reader->stream) {
    return empty;
  }

  return ring_buffer_dequeue(reader->stream->buffer);
}

void fetch_stream_reader_cancel(fetch_stream_reader_t *reader,
                                const char *reason) {
  if (!reader || !reader->stream)
    return;

  fetch_readable_stream_cancel(reader->stream, reason);
}

void fetch_stream_reader_release_lock(fetch_stream_reader_t *reader) {
  if (!reader || !reader->stream)
    return;

  ATOMIC_FETCH_ADD(&reader->stream->reader_count, -1);
}

// =============================================================================
// WRITER
// =============================================================================

void fetch_stream_writer_free(fetch_stream_writer_t *writer) {
  if (!writer)
    return;

  if (writer->stream) {
    ATOMIC_FETCH_ADD(&writer->stream->writer_count, -1);
  }

  free(writer);
}

bool fetch_stream_writer_closed(const fetch_stream_writer_t *writer) {
  return writer ? atomic_bool_load((atomic_bool_t *)&writer->stream->closed)
                : true;
}

fetch_stream_state_t
fetch_stream_writer_ready(const fetch_stream_writer_t *writer) {
  if (!writer || !writer->stream)
    return FETCH_STREAM_STATE_ERRORED;

  if (atomic_bool_load(&writer->stream->closed))
    return FETCH_STREAM_STATE_CLOSED;

  return FETCH_STREAM_STATE_READABLE;
}

fetch_stream_result_t fetch_stream_writer_write(fetch_stream_writer_t *writer,
                                                const void *chunk,
                                                size_t size) {
  if (!writer || !writer->stream || !chunk || size == 0) {
    return FETCH_STREAM_ERROR;
  }

  if (atomic_bool_load(&writer->stream->closed)) {
    return FETCH_STREAM_ERROR;
  }

  fetch_stream_chunk_t stream_chunk = chunk_copy(chunk, size);
  if (!ring_buffer_enqueue(writer->stream->buffer, stream_chunk)) {
    return FETCH_STREAM_ERROR;
  }

  return FETCH_STREAM_OK;
}

fetch_stream_result_t fetch_stream_writer_close(fetch_stream_writer_t *writer) {
  if (!writer || !writer->stream)
    return FETCH_STREAM_ERROR;

  return fetch_writable_stream_close(writer->stream);
}

fetch_stream_result_t fetch_stream_writer_abort(fetch_stream_writer_t *writer,
                                                const char *reason) {
  if (!writer || !writer->stream)
    return FETCH_STREAM_ERROR;

  return fetch_writable_stream_abort(writer->stream, reason);
}

void fetch_stream_writer_release_lock(fetch_stream_writer_t *writer) {
  if (!writer || !writer->stream)
    return;

  ATOMIC_FETCH_ADD(&writer->stream->writer_count, -1);
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

stream_buffer_t
fetch_readable_stream_consume_all(fetch_readable_stream_t *stream,
                                  size_t initial_capacity) {
  stream_buffer_t result = {0};

  if (!stream)
    return result;

  // Get a reader for the stream
  fetch_stream_reader_t *reader = fetch_readable_stream_get_reader(stream);
  if (!reader)
    return result;

  // Initialize buffer
  size_t capacity = initial_capacity > 0 ? initial_capacity : 4096;
  void *data = malloc(capacity);
  if (!data) {
    fetch_stream_reader_free(reader);
    return result;
  }

  size_t total_size = 0;

  // Read until stream is done
  while (true) {
    fetch_stream_chunk_t chunk = fetch_stream_reader_read(reader);

    if (chunk.done) {
      // Stream is closed and no more data
      break;
    }

    if (chunk.value && chunk.size > 0) {
      // Ensure we have enough capacity
      if (total_size + chunk.size > capacity) {
        // Grow buffer (double capacity or fit the chunk, whichever is larger)
        size_t new_capacity = capacity * 2;
        if (new_capacity < total_size + chunk.size) {
          new_capacity = total_size + chunk.size;
        }

        void *new_data = realloc(data, new_capacity);
        if (!new_data) {
          // Out of memory
          fetch_stream_chunk_free(&chunk);
          free(data);
          fetch_stream_reader_free(reader);
          return (stream_buffer_t){0};
        }

        data = new_data;
        capacity = new_capacity;
      }

      // Copy chunk data to buffer
      memcpy((char *)data + total_size, chunk.value, chunk.size);
      total_size += chunk.size;

      fetch_stream_chunk_free(&chunk);
    } else {
      // No data available right now, but stream not closed
      // Small delay to avoid busy waiting
#if defined(_WIN32) || defined(_WIN64)
      Sleep(1);
#else
      usleep(1000);
#endif
    }
  }

  fetch_stream_reader_free(reader);

  // Trim buffer to actual size
  if (total_size < capacity && total_size > 0) {
    void *trimmed = realloc(data, total_size);
    if (trimmed) {
      data = trimmed;
      capacity = total_size;
    }
  }

  result.data = data;
  result.size = total_size;
  result.capacity = capacity;

  return result;
}

stream_buffer_t
fetch_readable_stream_consume_all_default(fetch_readable_stream_t *stream) {
  return fetch_readable_stream_consume_all(stream, 4096);
}

void stream_buffer_free(stream_buffer_t *buffer) {
  if (buffer && buffer->data) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->size = 0;
    buffer->capacity = 0;
  }
}

// =============================================================================
// PIPING
// =============================================================================

fetch_stream_result_t
fetch_readable_stream_pipe_to(fetch_readable_stream_t *readable,
                              fetch_writable_stream_t *writable) {
  if (!readable || !writable)
    return FETCH_STREAM_ERROR;

  fetch_stream_reader_t *reader = fetch_readable_stream_get_reader(readable);
  fetch_stream_writer_t *writer = fetch_writable_stream_get_writer(writable);

  if (!reader || !writer) {
    fetch_stream_reader_free(reader);
    fetch_stream_writer_free(writer);
    return FETCH_STREAM_ERROR;
  }

  while (true) {
    fetch_stream_chunk_t chunk = fetch_stream_reader_read(reader);

    if (chunk.done) {
      fetch_stream_writer_close(writer);
      break;
    }

    if (chunk.value && chunk.size > 0) {
      fetch_stream_writer_write(writer, chunk.value, chunk.size);
    }

    fetch_stream_chunk_free(&chunk);
  }

  fetch_stream_reader_free(reader);
  fetch_stream_writer_free(writer);

  return FETCH_STREAM_OK;
}

fetch_readable_stream_t *
fetch_readable_stream_pipe_through(fetch_readable_stream_t *readable,
                                   fetch_transform_stream_t *transform) {
  if (!readable || !transform)
    return NULL;

  fetch_readable_stream_pipe_to(readable, transform->writable);
  return transform->readable;
}