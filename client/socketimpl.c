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
#include "logger.h"

int socket(int domain, int type, int protocol) {
	typeof(socket) *original_socket;
	original_socket = dlsym(RTLD_NEXT, "socket");
	return handleSocket(original_socket, domain, type, protocol);
}

int bind(int sd, const struct sockaddr *__restrict addr, socklen_t len){
	typeof(bind) *original_bind;
	original_bind = dlsym(RTLD_NEXT, "bind");
	return handleBind(original_bind, sd, addr, len);
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

ssize_t write(int s, const void *buf, size_t len){
	typeof(write) *original_write;
	original_write = dlsym(RTLD_NEXT, "write");
	return handleWrite(original_write, s, buf, len);
}

ssize_t send(int s, const void *buf, size_t len, int flags) {
	typeof(send) *original_send;
	original_send = dlsym(RTLD_NEXT, "send");
	return handleSend(original_send, s, buf, len, flags);
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
		const struct sockaddr *to, socklen_t tolen) {
	typeof(sendto) *original_sendto;
	original_sendto = dlsym(RTLD_NEXT, "sendto");
	return handleSendto(original_sendto, s, buf, len, flags, to, tolen);
}

