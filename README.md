# libfetch

A lightweight asynchronous HTTP/1.1 client library implementing a subset of the WHATWG Fetch API.

## Design Goals

libfetch is designed for applications requiring HTTP client functionality with strict constraints on memory usage and CPU utilization. The library provides asynchronous I/O operations without background threads or polling, allowing precise control over when network processing occurs.

The library maintains a small memory footprint through efficient connection pooling, zero-copy operations where possible, and configurable resource limits. Performance is achieved through an event-driven architecture using platform-native async I/O with no busy waiting or polling loops.

## Architecture

The library uses platform-specific asynchronous I/O mechanisms. On Windows, it leverages I/O Completion Ports (IOCP) for scalable async operations. Linux implementations use epoll with signalfd for event notification. BSD and macOS systems utilize kqueue, with a select()-based fallback for other platforms.

DNS lookups are performed asynchronously using native APIs rather than blocking the calling thread. Windows uses GetAddrInfoExW with overlapped I/O, Linux employs getaddrinfo_a with signal notifications, and macOS relies on libinfo.dylib async functions with Mach ports.

The event loop model is cooperative and application-controlled. There are no background threads or timers consuming CPU cycles. Network processing occurs only when `fetch_event_loop_process()` is called, allowing the library to integrate cleanly with existing event loops or single-threaded applications.

Connection management includes HTTP/1.1 keep-alive support and connection pooling to minimize overhead for multiple requests to the same host. TLS support is optional and can be disabled at compile time for environments where HTTPS is not required.

## TLS Certificate Handling

When TLS support is enabled (`LIBFETCH_ENABLE_TLS=ON`), libfetch automatically loads and validates certificates from platform-specific certificate stores:

- **Windows**: Loads trusted root certificates from the Windows Certificate Store ("ROOT" store), validating certificate expiry and key usage permissions
- **macOS**: Uses both Security Framework anchor certificates and system keychain certificates, with proper validation of certificate chains and expiry
- **Linux/Unix**: Attempts to load certificates from common system locations including:
  - `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu/Gentoo)
  - `/etc/pki/tls/certs/ca-bundle.crt` (Fedora/RHEL)
  - `/etc/ssl/ca-bundle.pem` (OpenSUSE)
  - Additional distribution-specific paths
- **Android**: Includes Android-specific certificate paths (`/system/etc/security/cacerts`)

If no certificates are found in standard locations, the library falls back to OpenSSL's default certificate verification paths. This ensures HTTPS connections are properly validated without requiring manual certificate configuration in most environments.

## Current Limitations

Most request and response bodies are handled in contiguous memory buffers. While file streaming is supported for uploads, it currently uses blocking I/O rather than overlapped operations. Full end-to-end streaming via the WHATWG Streams specification is planned for future versions, which would allow request and response bodies to be readable streams with non-blocking file I/O.

## Example Usage

```c
#include "fetch.h"

int main() {
    // Initialize and start the event loop
    fetch_global_init(NULL);
    fetch_event_loop_start();
    
    // Create an asynchronous request
    fetch_promise_t *promise = fetch_async("https://httpbin.org/get", NULL);
    
    // Process events until completion
    while (fetch_promise_pending(promise)) {
        fetch_event_loop_process(100);  // 100ms timeout
        // Application can perform other work here
    }
    
    // Handle the result
    if (fetch_promise_fulfilled(promise)) {
        fetch_response_t *response = fetch_promise_response(promise);
        if (fetch_response_ok(response)) {
            printf("Response: %s\n", fetch_response_text(response));
        }
    }
    
    // Cleanup
    fetch_promise_free(promise);
    fetch_event_loop_stop();
    fetch_global_dispose();
    return 0;
}
```

# Building libfetch

## Prerequisites
- CMake 4+
- C11 compiler (GCC, Clang, or MSVC with atomics enabled)
- Git
- OpenSSL (required when TLS support is enabled)

**Note for MSVC users**: Ensure that C11 atomics are enabled in your compiler settings. This typically requires Visual Studio 2022 or later with the `/std:c11` or `/std:c17` flag.

## Basic Build

```bash
git clone https://github.com/6over3/libfetch.git
cd libfetch
mkdir build && cd build
cmake ..
cmake --build .
```

## Build with HTTPS Support

```bash
cmake -DLIBFETCH_ENABLE_TLS=ON ..
cmake --build .
```

## Run Tests

```bash
cmake --build . --target run_tests
```

## Install

```bash
cmake --build . --target install
```

## License

libfetch is licensed under the MIT License.

### Third-Party Dependencies

- **[ada-url](https://github.com/ada-url/ada)**: Used for WHATWG compliant URL parsing
- **[picohttpparser](https://github.com/h2o/picohttpparser)**: Used for HTTP response parsing (modified to support ARM/NEON intrinsics with software fallback)
- **OpenSSL**: Required when TLS support is enabled

Please refer to the respective projects for their licensing terms.

## Project Status & Disclaimer

**Early Development Warning**: This project is in early development and is currently suitable primarily for experimental and specific production use-cases. While functional, it has not undergone extensive real-world testing across all platforms and scenarios.

We welcome feedback and contributions to help identify and resolve potential performance or security issues. If you encounter bugs, performance bottlenecks, or security concerns, please open an issue or submit a pull request.

**Scope & Goals**: libfetch is not intended as a replacement for [curl](https://curl.se). There are no active plans to implement HTTP/2 or HTTP/3 support. This library was primarily created to serve as the HTTP driver for the [hako JavaScript engine](https://github.com/andrewmd5/hako) and other novel embedded use cases where a lightweight, controllable HTTP client is preferred over a full-featured solution.

For production applications requiring comprehensive HTTP protocol support, battle-tested reliability, or HTTP/2+ capabilities, we recommend using established libraries like libcurl.