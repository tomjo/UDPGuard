#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define UDPG_HEADER 0x55445047
#define UDPG_HEADER_ID_LEN 4
#define UDPG_HEADER_TYPE_LEN 1
#define UDPG_COOKIE_LENGTH 32
#define UDPG_HEADER_LEN UDPG_HEADER_ID_LEN+UDPG_HEADER_TYPE_LEN+UDPG_COOKIE_LENGTH
#define MAX_PAYLOAD_SIZE 1472

struct udpghdr {
	uint32_t header;
	char type;
	char cookie[UDPG_COOKIE_LENGTH];
}__attribute__ ((packed));

struct rawudppacket {
	struct ip ip;
	struct udphdr udp;
	char payload[MAX_PAYLOAD_SIZE];
}__attribute__ ((packed));

struct rawudpgpacket {
	struct ip ip;
	struct udphdr udp;
	struct udpghdr udpg;
	char payload[MAX_PAYLOAD_SIZE];
}__attribute__ ((packed));

bool isCookieRequest(struct rawudppacket *packet, struct udpghdr *udpg);
bool isData(struct udpghdr *packet);
struct udpghdr * isUdpgPacket(struct udpghdr *packet, ssize_t size);
struct udpghdr createCookieResponsePacket(char *cookiemsg);

#endif /* PROTOCOL_H_ */
