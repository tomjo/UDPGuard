#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <unistd.h>

#ifndef UDPGUARD_H_
#define UDPGUARD_H_

int handleSocket(typeof(socket) socketfunc, int domain, int type, int protocol);
int handleClose(typeof(close) closefunc, int fd);
int handleBind(typeof(bind) bindfunc, int fd, const struct sockaddr *__restrict addr, socklen_t len);
ssize_t handleRecvfrom(typeof(recvfrom) recvfromfunc, int fd, void *__restrict buf, size_t n, int flags,
		struct sockaddr *__restrict addr, socklen_t *__restrict addr_len);
int handleConnect(typeof(connect) connectfunc, int sd, const struct sockaddr *__restrict addr, socklen_t len);

#endif /* UDPGUARD_H_ */
