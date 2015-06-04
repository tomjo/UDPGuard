#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include "util.h"

uint32_t getMyIp(const char *networkInterface) {
	struct ifaddrs * ifAddrStruct = NULL;
	struct ifaddrs * ifa = NULL;

	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET) {
			if(strcmp(ifa->ifa_name, networkInterface) == 0){
				//freeifaddrs(ifAddrStruct);
				return (uint32_t)((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
			}
		}
	}
	if (ifAddrStruct != NULL)
		freeifaddrs(ifAddrStruct);
	return 0;
}

uint16_t getLocalPort(int fd){
	struct sockaddr_in sin = {};
	socklen_t slen = sizeof(struct sockaddr);
	bzero(&sin, slen);
	getsockname(fd, (struct sockaddr *)&sin, &slen);
	return sin.sin_port;
}
