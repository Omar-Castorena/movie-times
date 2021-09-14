/******************************************************************************

PROGRAM:  server_tools.h
AUTHOR:   Omar Castorena
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This header file provides function signatures that allow applications
          to establish a secure TCP connection from a client. It creates an
          SSL/TLS connection using X509 certificates generated with the openssl 
          application. 
 
          Some of the code and descriptions can be found in "Network Security 
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/

#ifndef _SERVERTOOLS_H_
#define _SERVERTOOLS_H_

#include <openssl/ssl.h>

#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"

SSL_CTX* ctx;

void init_openssl();

int create_socket(unsigned int port);

SSL* create_ssl_socket(int sockfd);

void cleanup_ssl(SSL* ssl);

#endif
