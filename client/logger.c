#include <stdio.h>
#include <time.h>
#include "logger.h"
#include "settings.h"

time_t rawtime;
char timeBuf[256];

void _logInfo(FILE *stream, char * c, va_list args) {
	time(&rawtime);
	strftime(timeBuf, sizeof(timeBuf), "%F %T", localtime(&rawtime));
	fprintf(stream, "[%s] ", timeBuf);
	vfprintf(stream, c, args);
	putc('\n', stream);
}

void logInfo(char * c, ...) {
	va_list args;
	va_start(args, c);
	_logInfo(stdout, c, args);
	va_end(args);
}

void logError(char * c, ...) {
	va_list args;
	va_start(args, c);
	_logInfo(stderr, c, args);
	va_end(args);
}

void logDebug(char * c, ...) {
	if (settings.debug) {
		va_list args;
		va_start(args, c);
		_logInfo(stdout, c, args);
		va_end(args);
	}
}
