#include <stdarg.h>

#ifndef LOGGER_H_
#define LOGGER_H_

void logInfo(char * c, ...);
void logDebug(char * c, ...);
void logError(char * c, ...);

#endif /* LOGGER_H_ */
