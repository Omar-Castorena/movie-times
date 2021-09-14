/******************************************************************************

PROGRAM:  server.c
AUTHOR:   Jeff Hemmes
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This header file provides function signatures that allow applications
          to establish a secure TCP connection from a client. It creates an
          SSL/TLS connection using X509 certificates generated with the openssl 
          application. 
 
          Some of the code and descriptions can be found in "Network Security 
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server-tools.h"

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of 
the machine to that socket, then listens on the socket for incoming TCP 
connections.

*******************************************************************************/
int create_socket(unsigned int port) {
  int    s;
  struct sockaddr_in addr;

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
  // any available network interface on the machine, so clients can connect
  // through any, e.g., external network interface, localhost, etc.
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Set the socket option to remove the annoying "address already in use"
  // error if you stop and restart the server too quickly while testing
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    fprintf(stderr, "setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
  
  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address 
  // already in use, or an invalid network address
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Server: Unable to bind to socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  
  // Listen for incoming TCP connections using the newly created and configured
  // socket. The second argument (1) indicates the number of pending connections
  // allowed, which in this case is one.  That means if the server is connected
  // to one client, a second client attempting to connect may receive an error,
  // e.g., connection refused.
  //
  // Failure could result from an invalid socket descriptor or from using a 
  // socket descriptor that is already in use.
  if (listen(s, 1) < 0) {
    fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  fprintf(stdout, "Server: Listening on TCP port %u\n", port);
  
  return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in 
this program.  The function SSL_load_error_strings registers the error strings 
for all of the libssl and libcrypto functions so that appropriate textual error 
messages can be displayed when errors occur. OpenSSL_add_ssl_algorithms 
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl() { 
  SSL_load_error_strings();	
  OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl() {
  EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters 
for the connection, and in this program, each context is configured using the 
configure_context() function below. Each context object is created using the 
function SSL_CTX_new(), and the result of that call is what is returned by this 
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context() {
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid
                                // getting a warning from the call to
                                // SSLv23_server_method()
  SSL_CTX*    ssl_ctx;
  
  // Use SSL/TLS method for server (negotiated at connect time)
  ssl_method = SSLv23_server_method();
  
  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  
  return ssl_ctx;
}

/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL 
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto(). 
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx) {
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
  
  // Set the certificate to use, i.e., 'cert.pem' 
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  
  // Set the private key contained in the key file, i.e., 'key.pem'
  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
    fprintf(stderr, "Server: cannot set certificate:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

/******************************************************************************

The sequence of steps required to establish a secure SSL/TLS connection is:

1.  Initialize the SSL algorithms
2.  Create and configure an SSL context object
3.  Create a new network socket in the traditional way
4.  Listen for incoming connections
5.  Accept incoming connections as they arrive
6.  Create a new SSL object for the newly arrived connection
7.  Bind the SSL object to the network socket descriptor

Once these steps are completed successfully, use the functions SSL_read() and
SSL_write() to read from/write to the socket, but using the SSL object rather 
then the socket descriptor.  Once the session is complete, free the memory
allocated to the SSL object and close the socket descriptor.

******************************************************************************/
SSL* create_ssl_socket(int sockfd) {

  SSL_CTX* ssl_ctx;
  SSL*     ssl;

  // Initialize and create SSL data structures and algorithms
  init_openssl();
  ssl_ctx = create_new_context();
  configure_context(ssl_ctx);

  // Create a new SSL object to bind to the socket descriptor
  ssl = SSL_new(ssl_ctx);

  // Bind the SSL object to the network socket descriptor.  The socket 
  // descriptor will be used by OpenSSL to communicate with a client. 
  // This function should only be called once the TCP connection is
  // established.
  SSL_set_fd(ssl, sockfd);
  
  return ssl;
}

void cleanup_ssl(SSL* ssl) {
  SSL_free(ssl);
}

