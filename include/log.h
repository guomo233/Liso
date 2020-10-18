#ifndef LOG_H
#define LOG_H

#include <time.h>
#include <stdio.h>

#define LOG_LEVEL 0

extern FILE *logfile ;

#define LOG(level, fmt, ...) do { \
	time_t timep ; \
	struct tm *gmp ; \
	time (&timep) ; \
	gmp = gmtime (&timep) ; \
	if (level >= LOG_LEVEL) \
	{ \
		fprintf (logfile, "%d-%02d-%02d %02d:%02d:%02d [%s(%d)] "fmt"\n", \
				gmp->tm_year + 1900, gmp->tm_mon + 1, gmp->tm_mday, \
				gmp->tm_hour, gmp->tm_min, gmp->tm_sec, \
				__FILE__, __LINE__, ##__VA_ARGS__) ; \
		fflush (logfile); \
	} \
} while (0)

#define LOG_DEBUG(fmt, ...) LOG (0, "DEBUG "fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) LOG (1, "INFO "fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG (2, "ERROR "fmt, ##__VA_ARGS__)

#endif