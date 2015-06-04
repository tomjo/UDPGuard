#ifndef UTIL_H_
#define UTIL_H_

#include <sys/socket.h>
#include <stdint.h>

uint32_t getMyIp(const char *networkInterface);
uint16_t getLocalPort(int fd);

#endif /* UTIL_H_ */
