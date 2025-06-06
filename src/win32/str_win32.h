/*
 * str_win32.h - Windows compatibility for POSIX string functions
 * Provides implementations for strndup, strptime, and strtok_r on Windows
 */

#ifndef STR_WIN32_H
#define STR_WIN32_H

#if defined(_WIN32) || defined(_WIN64)

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996) // Disable deprecation warnings
#endif

/* Check if strndup is not already defined */
#ifndef HAVE_STRNDUP
static char *strndup(const char *s, size_t n) {
  size_t len;
  char *copy;

  if (s == NULL)
    return NULL;

  len = strlen(s);
  if (n < len)
    len = n;

  copy = (char *)malloc(len + 1);
  if (copy == NULL)
    return NULL;

  memcpy(copy, s, len);
  copy[len] = '\0';
  return copy;
}
#define HAVE_STRNDUP 1
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif /* _WIN32 */

#endif /* STR_WIN32_H */