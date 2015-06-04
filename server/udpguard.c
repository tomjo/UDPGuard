#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include "settings.h"
#include "udpguard.h"
#include "nodelist.h"
#include "cookie.h"
#include "protocol.h"
#include "logger.h"
#include "checksum.h"

NODE *socketHead = NULL;
int rawsock;
int rawBlocking = 1;
char * cookieReqBuf;
typeof(recvfrom) *RECV_FROM = NULL;
typeof(socket) *SOCKET = NULL;
typeof(bind) *BIND = NULL;
typeof(close) *CLOSE = NULL;

void initHooks();

__attribute__((constructor)) void init() {
	loadSettings();
	initCookie();
	initHooks();
	rawsock = SOCKET(AF_INET, SOCK_RAW, IPPROTO_UDP);
}

__attribute__((destructor)) void dispose() {
	deleteList(socketHead);
	disposeCookie();
	CLOSE(rawsock);
}

void initHooks() {
	//call hooked functions to get access to function pointer
	socket(0, 0, 0);
	close(0);
	bind(0, (struct sockaddr *) NULL, 0);
	recvfrom(0, (void *) NULL, 0, 0, (struct sockaddr *) NULL, 0);
}

int handleSocket(typeof(socket) socketfunc, int domain, int type, int protocol) {
	if (SOCKET == NULL) {
		SOCKET = socketfunc;
		return -1;
	}
	int sock = SOCKET(domain, type, protocol);
	if (domain == AF_INET && type == SOCK_DGRAM) {
		logDebug("Socket %d Registered", sock);
		if (findNode(socketHead, sock) == NULL)
			socketHead = insertNode(socketHead, sock);
	}
	return sock;
}

int handleConnect(typeof(connect) connectfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len) {
	int connect_ret = connectfunc(sd, addr, len);
	//logDebug("connect call on sock %d for port %d", sd, ((struct sockaddr_in *) addr)->sin_port);
	return connect_ret;
}

int handleClose(typeof(close) closefunc, int fd) {
	if (CLOSE == NULL) {
		CLOSE = closefunc;
		return -1;
	}
	logDebug("Closing socket %d", fd);
	NODE *node = findNode(socketHead, fd);
	if (node != NULL) {
		socketHead = deleteNode(socketHead, fd);
	}
	return closefunc(fd);
}

int handleBind(typeof(bind) bindfunc, int fd, const struct sockaddr *__restrict addr, socklen_t len) {
	if (BIND == NULL) {
		BIND = bindfunc;
		return -1;
	}
	int ret = bindfunc(fd, addr, len);
	NODE* n = findNode(socketHead, fd);
	if (n != NULL) {
		int port = ntohs(((struct sockaddr_in *) addr)->sin_port);
		logDebug("Socket %d bound on port %d", fd, port);
	}
	return ret;
}

ssize_t handleRecvfrom(typeof(recvfrom) recvfromfunc, int fd, void *__restrict buf, size_t n, int flags,
		struct sockaddr *__restrict addr, socklen_t *__restrict addr_len) {
	if (RECV_FROM == NULL) {
		RECV_FROM = recvfromfunc;
		return 0;
	}
	int sockflags = fcntl(fd, F_GETFL, 0);
	int rawflags = fcntl(rawsock, F_GETFL, 0);
	if((sockflags & O_NONBLOCK) != 0){//application uses non blocking sockets
		rawflags |= O_NONBLOCK;
		if(fcntl(rawsock, F_SETFL, rawflags) == 0)
			rawBlocking = 0;
	}else{
		if(rawBlocking == 0){
			rawflags &= ~O_NONBLOCK;
			if(fcntl(rawsock, F_SETFL, rawflags) == 0)
				rawBlocking = 1;
		}
	}

	NODE* node = findNode(socketHead, fd);
	if (node == NULL) {
		return RECV_FROM(fd, buf, n, flags, addr, addr_len);
	}

	cookieReqBuf = (char *) malloc(n);
	struct rawudppacket *packet;
	struct sockaddr_in recvaddr;
	socklen_t recvaddrlen = sizeof(struct sockaddr_in);

	ssize_t s = RECV_FROM(rawsock, cookieReqBuf, n, flags, (struct sockaddr *) &recvaddr, &recvaddrlen);
	if(s == -1){
		return -1;
	}
	packet = (struct rawudppacket *) cookieReqBuf;
	if(findNode(settings.guardedPorts, ntohs(packet->udp.uh_dport)) == NULL){
		//return RECV_FROM(fd, buf, n, flags, addr, addr_len);
		return handleRecvfrom(recvfromfunc, fd, buf, n, flags, addr, addr_len);
	}

	struct ifreq ifr;
	ioctl(rawsock, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags &= ~IFF_PROMISC;
	ioctl(rawsock, SIOCSIFFLAGS, &ifr);
	//logInfo("promisc? %d", (ifr.ifr_flags & IFF_PROMISC) != 0);

	struct udpghdr *udpg = isUdpgPacket((struct udpghdr *) (packet->payload), ntohs(packet->udp.uh_ulen) - sizeof(struct udphdr));

	if (udpg != NULL) {
		logDebug("Received UDPG packet.");
		struct sockaddr_in clientaddr;
		bzero(&clientaddr, sizeof(struct sockaddr_in));
		clientaddr.sin_addr = packet->ip.ip_src;
		clientaddr.sin_port = packet->udp.uh_sport;
		clientaddr.sin_family = AF_INET;
		RECV_FROM(fd, buf, n, flags, addr, addr_len);
		struct udpghdr *udpg = (struct udpghdr *)buf;
		char *calculatedCookie = (char *) malloc(UDPG_COOKIE_LENGTH);
		createCookie((struct sockaddr_in *)&addr, calculatedCookie);
		if (isCookieRequest(packet, udpg)
				|| (isData(udpg) && memcmp(udpg->cookie, calculatedCookie, UDPG_COOKIE_LENGTH) != 0)) {
			logDebug("Sending cookie to %s:%d", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
			struct udpghdr cookieResp = createCookieResponsePacket(calculatedCookie);
			sendto(fd, &cookieResp, UDPG_HEADER_LEN, 0, (struct sockaddr *)&clientaddr,
					sizeof(struct sockaddr_in));
			free(cookieReqBuf);
			return handleRecvfrom(RECV_FROM, fd, buf, n, flags, addr, addr_len);
		}
		logDebug("Received packet was data packet with valid cookie.");
		//data: strip header, put in buffer, set src addr
		int ss = ntohs(packet->udp.uh_ulen) - sizeof(struct udphdr) - (UDPG_HEADER_LEN);
		char *data = (char *) (packet->payload + UDPG_HEADER_LEN);
		memcpy(buf, data, ss);
		memcpy(addr, &clientaddr, sizeof(struct sockaddr_in));
		*addr_len = sizeof(struct sockaddr_in);
		free(cookieReqBuf);
		return ss;
	} else if(findNode(settings.safeIps, recvaddr.sin_addr.s_addr) != NULL){
		logDebug("Received packet from whitelisted IP.");
		free(cookieReqBuf);
		return RECV_FROM(fd, buf, n, flags, addr, addr_len);
	} else {
		logDebug("Received unguarded packet from unsafe IP.");
		if (settings.dropNonGuardedTraffic) {
			logDebug("Dropping..");
			free(cookieReqBuf);
			if(rawBlocking == 0){
				errno = EWOULDBLOCK;
				return -1;
			}else
				return handleRecvfrom(RECV_FROM, fd, buf, n, flags, addr, addr_len);
		}
		free(cookieReqBuf);
		bzero(addr, sizeof(struct sockaddr_in));
		*addr_len = sizeof(struct sockaddr_in);
		return RECV_FROM(fd, buf, n, flags, addr, addr_len);
	}
}
