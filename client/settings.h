#ifndef SETTINGS_H_
#define SETTINGS_H_

#include <stdbool.h>

struct settings{
	bool debug;
	bool useInvalidChecksum;
	char maxCookieExchangeAttempts;
	const char *networkInterface;
};

extern struct settings settings;

void loadSettings();

#endif /* SETTINGS_H_ */
