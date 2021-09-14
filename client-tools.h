/******************************************************************************

PROGRAM:  client_tools.h
AUTHOR:   Omar Castorena
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This header file provides function signatures that allow applications
          to establish a secure TCP connection to a server. It creates an
          SSL/TLS connection using X509 certificates generated with the openssl 
          application. 
 
          Some of the code and descriptions can be found in "Network Security 
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/

#ifndef _CLIENTTOOLS_H_
#define _CLIENTTOOLS_H_

#include <openssl/ssl.h>

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "localhost"
#define MAX_HOSTNAME_LENGTH 256

int create_client_socket(char* hostname, unsigned int port);

SSL* create_client_ssl_socket(int sockfd);

#endif
