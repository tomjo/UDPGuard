#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "logger.h"
#include "checksum.h"
#include "settings.h"

struct udpghdr * isUdpgPacket(struct udpghdr *packet, ssize_t size) {
	if (size < UDPG_HEADER_LEN)
		return NULL;
	return (ntohl(packet->header) == UDPG_HEADER && (packet->type == 'c' || packet->type == 'd')) ? packet : NULL;
}

struct rawudpgpacket createCookieRequestPacket(struct sockaddr_in *src, struct sockaddr_in *dst) {
	struct rawudpgpacket request;
	bzero(&request.ip, sizeof(request.ip));
	request.ip.ip_v = 4;
	request.ip.ip_hl = sizeof(request.ip) >> 2;//5?
	request.ip.ip_dst = dst->sin_addr;
	request.ip.ip_src = src->sin_addr;
	request.ip.ip_p = SOL_UDP;
	request.ip.ip_ttl = 64; //TODO maybe set higher just in case? value in windows NT is 128
	request.ip.ip_len = htons(UDPG_HEADER_LEN + sizeof(request.udp) + sizeof(request.ip));
	bzero(&request.udp, sizeof(request.udp));
	request.udp.uh_dport = dst->sin_port;//TODO maybe readd htons
	request.udp.uh_sport = htons(src->sin_port);
	request.udp.uh_ulen = htons(UDPG_HEADER_LEN + sizeof(request.udp));
	bzero(&request.udpg, sizeof(request.udpg));
	request.udpg.header = htonl(UDPG_HEADER);
	request.udpg.type = 'c';

	memset(&request.udp.uh_sum, 0, sizeof(request.udp.uh_sum));
	if(settings.useInvalidChecksum)
		request.udp.uh_sum = htons(udpChecksum(request.ip.ip_src.s_addr, request.ip.ip_dst.s_addr, request.udp.uh_sport, request.udp.uh_dport, request.udp.uh_ulen, (unsigned char *)&request.udpg))+1;
	else
		request.udp.uh_sum = 0;
	return request;
}

struct udpgpacket wrapData(const char *buffer, size_t len, char *cookie) {
	struct udpgpacket packet;
	packet.udpg.header = htonl(UDPG_HEADER);
	packet.udpg.type = 'd';
	memcpy(packet.udpg.cookie, cookie, UDPG_COOKIE_LENGTH);
	memcpy(packet.payload, buffer, len);
	return packet;
}
