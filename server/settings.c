#include <arpa/inet.h>
#include "settings.h"

struct settings settings;

void loadSettings() {
	//TODO read from settings file
	settings.debug = false;
	settings.dropNonGuardedTraffic = true;
	settings.guardedPorts = insertNode(settings.guardedPorts, 27960);
	struct in_addr masterIp;
	inet_aton("192.246.40.60", &masterIp);
	settings.safeIps = insertNode(settings.safeIps, masterIp.s_addr);
}
