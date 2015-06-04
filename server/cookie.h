#ifndef COOKIE_H_
#define COOKIE_H_

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "protocol.h"

void createCookie(struct sockaddr_in *addr, char *cookie);
void initCookie();
void disposeCookie();

#endif /* COOKIE_H_ */
