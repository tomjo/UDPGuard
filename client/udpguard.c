#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "udpguard.h"
#include "socketnodelist.h"
#include "protocol.h"
#include "settings.h"
#include "util.h"

NODE *socketHead = NULL;
bool cookieInitialised = false;
int rawsock;
char cookie[UDPG_COOKIE_LENGTH];
typeof(sendto) *SEND_TO = NULL;
typeof(socket) *SOCKET = NULL;
typeof(close) *CLOSE = NULL;

void initHooks();
void retrieveCookie(int fd, struct sockaddr_in *addr);
int sendCookieRequest(struct sockaddr_in *addr, struct rawudpgpacket *cookieReq);
ssize_t wrapAndSend(NODE *node, const char *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);

__attribute__((constructor)) void init() {
	loadSettings();
	initHooks();
	rawsock = SOCKET(PF_INET, SOCK_RAW, IPPROTO_UDP);
}

__attribute__((destructor)) void dispose() {
	deleteList(socketHead);
	close(rawsock);
}

void initHooks() {
	//call hooked functions to get access to function pointer
	socket(0, 0, 0);
	sendto(0, (void *) NULL, 0, 0, (struct sockaddr *) NULL, 0);
	close(0);
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

int handleBind(typeof(bind) bindfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len){
	int bind_ret = bindfunc(sd, addr, len);
	NODE* n = findNode(socketHead, sd);
	if (n != NULL) {
		int port = ntohs(((struct sockaddr_in *) addr)->sin_port);
		n->port = port;
	}
	return bind_ret;
}

int handleConnect(typeof(connect) connectfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len) {
	int connect_ret = connectfunc(sd, addr, len);
	if (connect_ret == 0) {
		NODE * n = findNode(socketHead, sd);
		if (n != NULL) {
			n->serveraddr = (struct sockaddr_in *) addr;
		}
	}
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

ssize_t handleWrite(typeof(write) writefunc, int sd, const void *buf, size_t len) {
	NODE *node = findNode(socketHead, sd);
	if (node == NULL)
		return writefunc(sd, buf, len);
	return wrapAndSend(node, buf, len, 0, (struct sockaddr *) node->serveraddr, sizeof(struct sockaddr_in));
}

ssize_t handleSend(typeof(send) sendfunc, int sd, const void *buf, size_t len, int flags) {
	NODE *node = findNode(socketHead, sd);
	if (node == NULL)
		return sendfunc(sd, buf, len, flags);
	return wrapAndSend(node, buf, len, flags, (struct sockaddr *) node->serveraddr, sizeof(struct sockaddr_in));
}

ssize_t handleSendto(typeof(sendto) sendtofunc, int fd, const void *buf, size_t len, int flags,
		const struct sockaddr *to, socklen_t tolen) {
	if (SEND_TO == NULL) {
		SEND_TO = sendtofunc;
		return -1;
	}
	NODE *node = findNode(socketHead, fd);
	if (node == NULL)
		return SEND_TO(fd, buf, len, flags, to, tolen);
	return wrapAndSend(node, buf, len, flags, to, tolen);
}

ssize_t wrapAndSend(NODE *node, const char *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
	if (!cookieInitialised) {
		retrieveCookie(node->value, (struct sockaddr_in *)to);
	}
	struct udpgpacket packet = wrapData(buf, len, cookie);
	logDebug("Sending UDPG wrapped packet..");
	return SEND_TO(node->value, &packet, UDPG_HEADER_LEN + len, flags, to, tolen);
}

void retrieveCookie(int fd, struct sockaddr_in *addr) {
	int ret;
	struct timeval tv;
	struct timeval origtv;
	socklen_t fromlen;
	struct sockaddr_in from;
	char * response;
	int retry = -1;
	int attempts = 0;
	struct rawudppacket *packet;
	struct udpghdr *udpg;

	NODE *node = findNode(socketHead, fd);
	uint16_t p = getLocalPort(fd);
	if(node->port != htons(p)){
		node->port = htons(p);
	}

	response = (char *) malloc(1000);
	tv.tv_sec = 2;
	tv.tv_usec = 0; //not initing this can cause strange problems
	socklen_t optlen = sizeof(struct timeval);
	getsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (void *) &origtv, &optlen);
	setsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (void *) &tv, optlen);
	struct sockaddr_in src;
	bzero(&src, sizeof(src));
	src.sin_family = AF_INET;
	uint16_t BACKUPPORT = ((struct sockaddr_in *)addr)->sin_port;//necessary because for some mysterious reason getMyIp removes the port of addr
	src.sin_addr.s_addr = getMyIp(settings.networkInterface);
	src.sin_port = node->port;
	uint32_t BACKUPIP = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
	((struct sockaddr_in *)addr)->sin_port = BACKUPPORT;
	struct rawudpgpacket cookieReq = createCookieRequestPacket(&src, addr);
	((struct sockaddr_in *)addr)->sin_port = BACKUPPORT;
	((struct sockaddr_in *)addr)->sin_addr.s_addr = BACKUPIP;
	while (retry == -1 && settings.maxCookieExchangeAttempts > attempts++) {
		ret = sendCookieRequest(addr, &cookieReq);
		if (ret == -1) {
			logInfo("Could not send cookierequest: %s", strerror(errno));
			setsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (void *) &origtv, optlen);
			exit(1);
		}
		retry = recvfrom(node->value, (void *) response, 1000, 0, (struct sockaddr *) &from, &fromlen);
		udpg = isUdpgPacket((struct udpghdr *)response, retry);
		if(udpg == NULL){
			retry = -1;
		}

		if(retry == -1)
			sleep(1);
	}
	logDebug("Needed %d attempts to obtain cookie", attempts);
	setsockopt(rawsock, SOL_SOCKET, SO_RCVTIMEO, (void *) &origtv, optlen);
	memcpy(cookie, response + UDPG_HEADER_ID_LEN+UDPG_HEADER_TYPE_LEN, UDPG_COOKIE_LENGTH);
	cookieInitialised = true;
}

int sendCookieRequest(struct sockaddr_in *addr, struct rawudpgpacket *cookieReq) {
	int one = 1;
	logDebug("Sending cookie request..");
	if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof(one)) < 0)
		return -1;
	return SEND_TO(rawsock, cookieReq, UDPG_HEADER_LEN+sizeof(struct ip)+sizeof(struct udphdr), 0,
			(struct sockaddr *)addr, sizeof(struct sockaddr_in));
}
