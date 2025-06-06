#ifndef STRPTIME_H
#define STRPTIME_H
#if defined(_WIN32) || defined(_WIN64)
#include <time.h>

char *strptime(const char *buf, const char *fmt, struct tm *tm);
#endif

#endif // STRPTIME_H