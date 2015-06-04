#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

uint16_t udpChecksum(uint32_t src, uint32_t dest, uint16_t srcPort, uint16_t destPort, uint16_t udpLen, unsigned char * data);

struct udp_pseudo {
	struct in_addr src_addr;
	struct in_addr dest_addr;
	uint8_t zeros;
	uint8_t protocol;
	uint16_t len;
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t datalen;
	uint16_t chksum;
};

#endif /* CHECKSUM_H_ */
