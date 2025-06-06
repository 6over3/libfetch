
#include "fetch.h"
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

static volatile bool g_interrupted = false;
static fetch_promise_t *g_current_promise = NULL;

typedef struct {
  char *url;
  http_method_t method;
  fetch_headers_t *headers;
  char *data;
  char *data_file;
  char *user_agent;
  char *referer;
  char *output_file;

  bool include_headers;
  bool head_only;
  bool location_follow;
  bool silent;
  bool verbose;
  bool show_error;
  bool fail_on_error;

  uint32_t timeout;
  uint32_t connect_timeout;
  uint32_t max_redirects;

  char *user;

  bool output_headers_only;
  bool write_out;
  char *write_out_format;

  bool progress_bar;
  bool no_progress;

  char *cookie;
  char *cookie_jar;
} cli_options_t;

static void init_options(cli_options_t *opts) {
  memset(opts, 0, sizeof(cli_options_t));
  opts->method = HTTP_METHOD_GET;
  opts->headers = fetch_headers_new();
  opts->timeout = 30;
  opts->connect_timeout = 30;
  opts->max_redirects = 20;
  opts->user_agent = FETCH_USER_AGENT;
  opts->show_error = true;
}

static void free_options(cli_options_t *opts) {
  if (!opts)
    return;

  free(opts->url);
  fetch_headers_free(opts->headers);
  free(opts->data);
  free(opts->data_file);
  if (opts->user_agent && strcmp(opts->user_agent, FETCH_USER_AGENT) != 0) {
    free(opts->user_agent);
  }
  free(opts->referer);
  free(opts->output_file);
  free(opts->user);
  free(opts->write_out_format);
  free(opts->cookie);
  free(opts->cookie_jar);
}

static char *safe_strdup(const char *str) {
  if (!str)
    return NULL;
  size_t len = strlen(str);
  char *copy = malloc(len + 1);
  if (copy) {
    memcpy(copy, str, len + 1);
  }
  return copy;
}

static void print_version(void) {
  printf("libfetch %s (libfetch CLI tool)\n", fetch_version());
  printf("Built with libfetch library\n");
  printf("Supports: HTTP/1.1\n");
#if defined(LIBFETCH_TLS_ENABLED)
  printf("TLS support: enabled\n");
#else
  printf("TLS support: disabled (HTTP only)\n");
#endif
}

static void print_usage(const char *program_name) {
  printf("Usage: %s [options...] <url>\n", program_name);
  printf("\nOptions:\n");
  printf("  -X, --request <method>     Specify request method (GET, POST, PUT, "
         "etc.)\n");
  printf("  -d, --data <data>          HTTP POST data\n");
  printf("  -H, --header <header>      Add custom header\n");
  printf("  -o, --output <file>        Write output to file\n");
  printf("  -i, --include              Include response headers in output\n");
  printf("  -I, --head                 Show document info only\n");
  printf("  -L, --location             Follow redirects\n");
  printf("  -s, --silent               Silent mode\n");
  printf("  -v, --verbose              Verbose output\n");
  printf("  -f, --fail                 Fail silently on HTTP errors\n");
  printf("  -S, --show-error           Show error messages\n");
  printf("  -u, --user <user:pass>     Server user and password\n");
  printf("  -A, --user-agent <agent>   User-Agent to send\n");
  printf("  -e, --referer <URL>        Referer URL\n");
  printf("  -m, --max-time <seconds>   Maximum time allowed for transfer\n");
  printf("  --connect-timeout <secs>   Maximum time for connection\n");
  printf("  --max-redirs <num>         Maximum number of redirects\n");
  printf("  -b, --cookie <data>        Cookie string or file\n");
  printf("  -c, --cookie-jar <file>    Write cookies to file\n");
  printf("  -w, --write-out <format>   Output format after completion\n");
  printf("  --progress-bar             Display progress bar\n");
  printf("  --no-progress              Disable progress meter\n");
  printf("  -V, --version              Show version information\n");
  printf("  -h, --help                 Show this help message\n");
  printf("\nExamples:\n");
  printf("  %s http://httpbin.org/get\n", program_name);
  printf("  %s -X POST -d 'name=value' http://httpbin.org/post\n",
         program_name);
  printf("  %s -H 'Content-Type: application/json' http://api.example.com\n",
         program_name);
  printf("  %s -o output.html http://example.com\n", program_name);
#if !defined(LIBFETCH_TLS_ENABLED)
  printf("\nNote: This build only supports HTTP (not HTTPS) connections.\n");
#endif
}

static void signal_handler(int signum) {
  g_interrupted = true;
  if (g_current_promise) {
    fetch_promise_cancel(g_current_promise, "Interrupted by user");
  }
}

static bool parse_args(int argc, char *argv[], cli_options_t *opts) {
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
      print_usage(argv[0]);
      return false;
    } else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
      print_version();
      return false;
    } else if (strcmp(arg, "-X") == 0 || strcmp(arg, "--request") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      opts->method = fetch_method_from_string(argv[i]);
    } else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--data") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->data);
      opts->data = safe_strdup(argv[i]);
      if (opts->method == HTTP_METHOD_GET) {
        opts->method = HTTP_METHOD_POST;
      }
    } else if (strcmp(arg, "-H") == 0 || strcmp(arg, "--header") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      char *header = safe_strdup(argv[i]);
      char *colon = strchr(header, ':');
      if (colon) {
        *colon = '\0';
        char *value = colon + 1;
        while (*value == ' ')
          value++;
        fetch_headers_set(opts->headers, header, value);
      } else {
        fprintf(stderr, "Error: Invalid header format: %s\n", argv[i]);
        free(header);
        return false;
      }
      free(header);
    } else if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->output_file);
      opts->output_file = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-i") == 0 || strcmp(arg, "--include") == 0) {
      opts->include_headers = true;
    } else if (strcmp(arg, "-I") == 0 || strcmp(arg, "--head") == 0) {
      opts->head_only = true;
      opts->method = HTTP_METHOD_HEAD;
    } else if (strcmp(arg, "-L") == 0 || strcmp(arg, "--location") == 0) {
      opts->location_follow = true;
    } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--silent") == 0) {
      opts->silent = true;
      opts->no_progress = true;
    } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
      opts->verbose = true;
    } else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--fail") == 0) {
      opts->fail_on_error = true;
    } else if (strcmp(arg, "-S") == 0 || strcmp(arg, "--show-error") == 0) {
      opts->show_error = true;
    } else if (strcmp(arg, "-u") == 0 || strcmp(arg, "--user") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->user);
      opts->user = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-A") == 0 || strcmp(arg, "--user-agent") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      if (opts->user_agent && strcmp(opts->user_agent, FETCH_USER_AGENT) != 0) {
        free(opts->user_agent);
      }
      opts->user_agent = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-e") == 0 || strcmp(arg, "--referer") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->referer);
      opts->referer = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-m") == 0 || strcmp(arg, "--max-time") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      opts->timeout = (uint32_t)atoi(argv[i]);
    } else if (strcmp(arg, "--connect-timeout") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      opts->connect_timeout = (uint32_t)atoi(argv[i]);
    } else if (strcmp(arg, "--max-redirs") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      opts->max_redirects = (uint32_t)atoi(argv[i]);
    } else if (strcmp(arg, "-b") == 0 || strcmp(arg, "--cookie") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->cookie);
      opts->cookie = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-c") == 0 || strcmp(arg, "--cookie-jar") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->cookie_jar);
      opts->cookie_jar = safe_strdup(argv[i]);
    } else if (strcmp(arg, "-w") == 0 || strcmp(arg, "--write-out") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return false;
      }
      free(opts->write_out_format);
      opts->write_out_format = safe_strdup(argv[i]);
      opts->write_out = true;
    } else if (strcmp(arg, "--progress-bar") == 0) {
      opts->progress_bar = true;
      opts->no_progress = false;
    } else if (strcmp(arg, "--no-progress") == 0) {
      opts->no_progress = true;
      opts->progress_bar = false;
    } else if (arg[0] != '-') {
      // URL argument
      if (opts->url) {
        fprintf(stderr, "Error: Multiple URLs specified\n");
        return false;
      }
      opts->url = safe_strdup(arg);
    } else {
      fprintf(stderr, "Error: Unknown option: %s\n", arg);
      return false;
    }
  }

  if (!opts->url) {
    fprintf(stderr, "Error: No URL specified\n");
    print_usage(argv[0]);
    return false;
  }

#if !defined(LIBFETCH_TLS_ENABLED)
  if (strncmp(opts->url, "https://", 8) == 0) {
    fprintf(stderr, "Error: HTTPS URLs are not supported in this build. Use "
                    "HTTP instead.\n");
    return false;
  }
#endif

  return true;
}

static bool read_file(const char *filename, char **data, size_t *size) {
  if (!filename || !data || !size)
    return false;

  FILE *file = fopen(filename, "rb");
  if (!file)
    return false;

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size <= 0) {
    fclose(file);
    return false;
  }

  *size = (size_t)file_size;
  *data = malloc(*size + 1);
  if (!*data) {
    fclose(file);
    return false;
  }

  size_t bytes_read = fread(*data, 1, *size, file);
  fclose(file);

  if (bytes_read != *size) {
    free(*data);
    *data = NULL;
    return false;
  }

  (*data)[*size] = '\0';
  return true;
}

static void write_headers(fetch_response_t *response, FILE *output) {
  if (!response || !output)
    return;

  fprintf(output, "HTTP/1.1 %d %s\n", fetch_response_status(response),
          fetch_response_status_text(response));

  fetch_headers_t *headers = fetch_response_headers(response);
  if (headers) {
    fetch_headers_iterator_t iter = fetch_headers_entries(headers);
    const char *key, *value;
    while (fetch_headers_next(&iter, &key, &value)) {
      fprintf(output, "%s: %s\n", key, value);
    }
  }
  fprintf(output, "\n");
}

static void write_body(fetch_response_t *response, FILE *output) {
  if (!response || !output)
    return;

  const char *text = fetch_response_text(response);
  if (text) {
    fputs(text, output);
  } else {
    size_t size;
    const void *data = fetch_response_array_buffer(response, &size);
    if (data && size > 0) {
      fwrite(data, 1, size, output);
    }
  }
}

static void print_write_out(fetch_response_t *response, const char *format) {
  if (!response || !format)
    return;

  const char *p = format;
  while (*p) {
    if (*p == '%' && *(p + 1)) {
      p++;
      switch (*p) {
      case '%':
        putchar('%');
        break;
      case 'u':
        printf("%s", fetch_response_url(response) ? fetch_response_url(response)
                                                  : "");
        break;
      case 's':
        printf("%d", fetch_response_status(response));
        break;
      case 'h':
        printf("%s", fetch_response_status_text(response)
                         ? fetch_response_status_text(response)
                         : "");
        break;
      case 'n':
        putchar('\n');
        break;
      case 't':
        putchar('\t');
        break;
      default:
        putchar('%');
        putchar(*p);
        break;
      }
    } else {
      putchar(*p);
    }
    p++;
  }
}

static void prepare_headers(cli_options_t *opts, fetch_headers_t *headers) {
  // Set Referer if specified
  if (opts->referer) {
    fetch_headers_set(headers, "Referer", opts->referer);
  }

  // Set Cookie if specified
  if (opts->cookie) {
    fetch_headers_set(headers, "Cookie", opts->cookie);
  }

  // Set Authorization header for basic auth
  if (opts->user) {
    char *colon = strchr(opts->user, ':');
    if (colon) {
      // Note: This is a simplified basic auth implementation
      // In production, you'd want to properly base64 encode the credentials
      char auth_header[1024];
      snprintf(auth_header, sizeof(auth_header), "Basic %s", opts->user);
      fetch_headers_set(headers, "Authorization", auth_header);
    }
  }
}

static int execute_request(cli_options_t *opts) {
  int exit_code = 0;
  FILE *output = stdout;
  fetch_init_t *init = NULL;
  fetch_body_t *body = NULL;
  fetch_promise_t *promise = NULL;
  fetch_config_t config;

  // Open output file if specified
  if (opts->output_file) {
    output = fopen(opts->output_file, "wb");
    if (!output) {
      fprintf(stderr, "Error: Cannot open output file '%s': %s\n",
              opts->output_file, strerror(errno));
      return 1;
    }
  }

  // Configure the library
  config = fetch_config_default();
  config.default_timeout_ms = opts->timeout * 1000;
  config.user_agent = opts->user_agent;

  // Set up cookie jar if specified
  cookie_jar_t *jar = NULL;
  if (opts->cookie_jar) {
    jar = fetch_create_cookie_jar(opts->cookie_jar);
    config.cookie_jar = jar;
  }

  fetch_global_init(&config);

  // Start the event loop
  if (!fetch_event_loop_start()) {
    fprintf(stderr, "Error: Failed to start event loop\n");
    exit_code = 1;
    goto cleanup;
  }

  // Create request initialization
  init = fetch_init_new();
  if (!init) {
    fprintf(stderr, "Error: Failed to create request options\n");
    exit_code = 1;
    goto cleanup;
  }

  // Set method
  fetch_init_method(init, opts->method);

  // Set timeout
  fetch_init_timeout(init, opts->timeout * 1000);

  // Set max redirects
  init->max_redirects = opts->location_follow ? opts->max_redirects : 20;

  // Prepare headers
  fetch_headers_t *headers = fetch_headers_new();
  if (!headers) {
    fprintf(stderr, "Error: Failed to create headers\n");
    exit_code = 1;
    goto cleanup;
  }

  // Copy existing headers from options
  if (opts->headers) {
    fetch_headers_iterator_t iter = fetch_headers_entries(opts->headers);
    const char *key, *value;
    while (fetch_headers_next(&iter, &key, &value)) {
      fetch_headers_set(headers, key, value);
    }
  }

  prepare_headers(opts, headers);
  fetch_init_headers(init, headers); // Transfer ownership

  // Create body if data is provided
  if (opts->data) {
    body = fetch_body_text(opts->data);
    if (!body) {
      fprintf(stderr, "Error: Failed to create request body\n");
      exit_code = 1;
      goto cleanup;
    }
    fetch_init_body(init, body); // Transfer ownership
  } else if (opts->data_file) {
    char *file_data = NULL;
    size_t file_size = 0;
    if (!read_file(opts->data_file, &file_data, &file_size)) {
      fprintf(stderr, "Error: Failed to read data file '%s'\n",
              opts->data_file);
      exit_code = 1;
      goto cleanup;
    }
    body = fetch_body_text(file_data);
    free(file_data);
    if (!body) {
      fprintf(stderr, "Error: Failed to create request body from file\n");
      exit_code = 1;
      goto cleanup;
    }
    fetch_init_body(init, body); // Transfer ownership
  }

  // Set up signal handling
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  if (opts->verbose && !opts->silent) {
    printf("* About to connect to %s\n", opts->url);
    printf("* Using libfetch %s\n", fetch_version());
  }

  // Make async request
  promise = fetch_async(opts->url, init);
  g_current_promise = promise;

  if (!promise) {
    fprintf(stderr, "Error: Failed to start request\n");
    exit_code = 1;
    goto cleanup;
  }

  // Drive the event loop until completion or interruption
  while (fetch_promise_pending(promise) && !g_interrupted) {
    int events = fetch_event_loop_process(1); // 100ms timeout
    if (events < 0) {
      fprintf(stderr, "Error: Event loop error\n");
      exit_code = 1;
      break;
    }
  }

  if (g_interrupted) {
    if (!opts->silent) {
      fprintf(stderr, "\nInterrupted by user\n");
    }
    exit_code = 130; // Standard exit code for SIGINT
    goto cleanup;
  }

  // Check if the promise was fulfilled
  if (fetch_promise_fulfilled(promise)) {
    fetch_response_t *response = fetch_promise_response(promise);
    if (!response) {
      fprintf(stderr, "Error: No response received\n");
      exit_code = 1;
      goto cleanup;
    }

    if (opts->fail_on_error && !fetch_response_ok(response)) {
      exit_code = 22; // curl-compatible exit code for HTTP error
      goto cleanup;
    }

    if (opts->verbose && !opts->silent) {
      printf("* HTTP %d %s\n", fetch_response_status(response),
             fetch_response_status_text(response));
    }

    // Write headers if requested
    if (opts->include_headers || opts->head_only) {
      write_headers(response, output);
    }

    // Write body unless it's a HEAD request
    if (!opts->head_only) {
      write_body(response, output);
    }

    // Write custom output format if requested
    if (opts->write_out && opts->write_out_format) {
      print_write_out(response, opts->write_out_format);
    }
  } else if (fetch_promise_rejected(promise)) {
    if (opts->show_error && !opts->silent) {
      fprintf(stderr, "Error: %s\n", fetch_promise_error_message(promise));
    }
    exit_code = 1;
  } else {
    // Should not happen since we waited for completion
    fprintf(stderr, "Error: Promise in unexpected state\n");
    exit_code = 1;
  }

cleanup:
  g_current_promise = NULL;

  if (promise) {
    fetch_promise_free(promise);
  }

  if (init) {
    fetch_init_free(init);
  }

  if (fetch_event_loop_is_running()) {
    fetch_event_loop_stop();
  }

  if (jar) {
    fetch_cookie_jar_free(jar);
  }

  fetch_global_dispose();

  if (output != stdout) {
    fclose(output);
  }

  return exit_code;
}

int main(int argc, char *argv[]) {
  cli_options_t opts;
  init_options(&opts);

  if (!parse_args(argc, argv, &opts)) {
    free_options(&opts);
    return argc == 1 ? 1 : 0; // Return 1 if no args, 0 if help/version shown
  }

  int exit_code = execute_request(&opts);
  free_options(&opts);
  return exit_code;
}