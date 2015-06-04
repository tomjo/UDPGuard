#ifndef SETTINGS_H_
#define SETTINGS_H_

#include <stdbool.h>
#include "nodelist.h"

struct settings{
	bool debug;
	bool dropNonGuardedTraffic;
	NODE *guardedPorts;
	NODE *safeIps;
};

extern struct settings settings;

void loadSettings();

#endif /* SETTINGS_H_ */
