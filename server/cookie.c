#include <gcrypt.h>
#include <string.h>
#include <arpa/inet.h>
#include "cookie.h"

gcry_md_hd_t hashAlgo;
void *secret;

void initCookie() {
	if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
	 if (!gcry_check_version(GCRYPT_VERSION)) {
	 fputs("libgcrypt version mismatch\n", stderr);
	 exit(2);
	 }
	 gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	 gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	 gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	 gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	 }
	 gcry_md_open(&hashAlgo, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	 secret = gcry_malloc_secure(UDPG_COOKIE_LENGTH);
	 gcry_randomize(secret, sizeof(secret), GCRY_STRONG_RANDOM);
}

void disposeCookie() {
	gcry_md_close(hashAlgo);
	gcry_free(secret);
}

void createCookie(struct sockaddr_in *addr, char *cookie) {
	 char *ip = inet_ntoa(addr->sin_addr);
	 in_port_t port = addr->sin_port;
	 gcry_md_write(hashAlgo, &port, sizeof(in_port_t));
	 gcry_md_write(hashAlgo, ip, sizeof(ip));
	 gcry_md_write(hashAlgo, secret, sizeof(secret));
	 unsigned char *hash = gcry_md_read(hashAlgo, GCRY_MD_SHA256);
	 memcpy(cookie, hash, UDPG_COOKIE_LENGTH);
	 gcry_md_reset(hashAlgo);
	//char *tmp = "12345678901234567890123456789012";
	//memcpy(cookie, tmp, UDPG_COOKIE_LENGTH);
}
