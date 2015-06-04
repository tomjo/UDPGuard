#include "settings.h"

struct settings settings;

void loadSettings() {
	//TODO read from settings file
	settings.debug = false;
	settings.useInvalidChecksum = true;
	settings.maxCookieExchangeAttempts = 20;
	settings.networkInterface = "eth0";
}
