#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "udpguard.h"

int socket(int domain, int type, int protocol) {
	typeof(socket) *original_socket;
	original_socket = dlsym(RTLD_NEXT, "socket");
	return handleSocket(original_socket, domain, type, protocol);
}

int bind(int fd, const struct sockaddr *__restrict addr, socklen_t len) {
	typeof(bind) *original_bind;
	original_bind = dlsym(RTLD_NEXT, "bind");
	return handleBind(original_bind, fd, addr, len);
}

int connect(int sd, const struct sockaddr *__restrict addr, socklen_t len){
	typeof(connect) *original_connect;
	original_connect = dlsym(RTLD_NEXT, "connect");
	return handleConnect(original_connect, sd, addr, len);
}

int close(int fd) {
	typeof(close) *original_close;
	original_close = dlsym(RTLD_NEXT, "close");
	return handleClose(original_close, fd);
}

ssize_t recvfrom(int fd, void *__restrict buf, size_t n, int flags, struct sockaddr *__restrict addr, socklen_t *__restrict addr_len) {
	typeof(recvfrom) *original_recvfrom;
	original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
	return handleRecvfrom(original_recvfrom, fd, buf, n, flags, addr, addr_len);
}
