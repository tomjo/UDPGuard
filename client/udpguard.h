#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <unistd.h>
#include "logger.h"

#ifndef UDPGUARD_H_
#define UDPGUARD_H_

int handleSocket(typeof(socket) socketfunc, int domain, int type, int protocol);
int handleBind(typeof(bind) bindfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len);
ssize_t handleSendto(typeof(sendto) sendtofunc, int s, const void *buf, size_t len, int flags,
		const struct sockaddr *to, socklen_t tolen);
ssize_t handleSend(typeof(send) sendfunc, int s, const void *buf, size_t len, int flags);
ssize_t handleWrite(typeof(write) writefunc, int s, const void *buf, size_t len);
int handleConnect(typeof(connect) connectfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len);
int handleClose(typeof(close) closefunc, int fd);

#endif /* UDPGUARD_H_ */
