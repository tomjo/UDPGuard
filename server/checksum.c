#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/udp.h>
#include "checksum.h"
#include "logger.h"

uint16_t _checksum(struct udp_pseudo *pseudohdr, unsigned char * data);
uint16_t onesComplementOfOnesComplementSum(unsigned char * data, size_t len);

uint16_t onesComplementOfOnesComplementSum(unsigned char * data, size_t len) {
	uint32_t sum = 0;
	uint i;
	for (i = 0; i < len / 2 * 2; i += 2) {
		uint16_t val = htons(*((uint16_t *) (data + i)));
		sum += val;
	}
	if (i < len) {
		uint16_t val = htons(*((uint16_t *) (data + i)));
		sum += val;
	}
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = ~sum;
	return (uint16_t) sum;
}

uint16_t _checksum(struct udp_pseudo *pseudohdr, unsigned char * data) {
	size_t len = sizeof(struct udp_pseudo) + ntohs(pseudohdr->len) - 8;
	unsigned char * buf = (unsigned char *) malloc(len);
	memcpy(buf, (unsigned char *) pseudohdr, sizeof(struct udp_pseudo));
	memcpy(buf + sizeof(struct udp_pseudo), data, ntohs(pseudohdr->len) - 8);
	uint16_t sum = onesComplementOfOnesComplementSum(buf, len);
	free(buf);
	return sum;
}

uint16_t udpChecksum(uint32_t src, uint32_t dest, uint16_t srcPort, uint16_t destPort, uint16_t udpLen,
		unsigned char * data) {
	struct udp_pseudo pseudo;
	bzero(&pseudo, sizeof(struct udp_pseudo));
	pseudo.src_addr.s_addr = src;
	pseudo.dest_addr.s_addr = dest;
	pseudo.src_port = srcPort;
	pseudo.dest_port = destPort;
	pseudo.len = pseudo.datalen = udpLen;
	pseudo.protocol = IPPROTO_UDP;
	return _checksum(&pseudo, data);
}
