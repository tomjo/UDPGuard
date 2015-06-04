#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "protocol.h"
#include "logger.h"
#include "checksum.h"

bool isCookieRequest(struct rawudppacket *packet, struct udpghdr *udpg) {
	uint16_t calcChk = htons(
			udpChecksum(packet->ip.ip_src.s_addr, packet->ip.ip_dst.s_addr, packet->udp.uh_sport, packet->udp.uh_dport,
					packet->udp.uh_ulen, (unsigned char *) packet->payload));
	if (calcChk + 1 != packet->udp.uh_sum) {
		//checksum doesnt match +1version: data corrupt or not an initial request
		return false;
	}
	return udpg->type == 'c';
}

bool isData(struct udpghdr *udpg) {
	return udpg->type == 'd';
}

struct udpghdr * isUdpgPacket(struct udpghdr *packet, ssize_t size) {
	if (size < UDPG_HEADER_LEN)
		return NULL;
	return (ntohl(packet->header) == UDPG_HEADER && (packet->type == 'c' || packet->type == 'd')) ? packet : NULL;
}

struct udpghdr createCookieResponsePacket(char *cookiemsg) {
	struct udpghdr cookie;
	cookie.header = htonl(UDPG_HEADER);
	cookie.type = 'c';
	memcpy(cookie.cookie, cookiemsg, UDPG_COOKIE_LENGTH);
	return cookie;
}
