/******************************************************************************

PROGRAM:  ssl-server-tier1.c
AUTHOR:   Jeff Hemmes
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small server application that receives incoming TCP
          connections from clients, then establishes an SSL/TLS encrypted
          connection to a tier 2 server.  It receives a message from the other
          server and passes it back to the client. The secure SSL/TLS
          connection is created using certificates generated with the
          openssl application.  The purpose is to demonstrate how to establish
          secure communication between a client and server using public key
          cryptography in a multi-tier server architecture.

          Some of the code and descriptions can be found in "Network Security
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server-tools.h"
#include "client-tools.h"

#define BUFFER_SIZE 256

int main(int argc, char **argv) {
  struct sockaddr_in addr;
  char               client_addr[INET_ADDRSTRLEN];
  char               buffer[BUFFER_SIZE];
  char               remote_server[MAX_HOSTNAME_LENGTH];
  char               c;
  unsigned int       len = sizeof(addr);
  unsigned int       sockfd;
  unsigned int       port = DEFAULT_PORT;
  unsigned int       remote_server_port = DEFAULT_PORT;
  SSL*               clientssl;
  SSL*               server2ssl;
  int                clientsd;
  int                server2sd;
  pid_t              pid;

  // Do not create zombie processes
  signal(SIGCHLD, SIG_IGN);
  init_openssl();
    
  // Port can be specified on the command line. If it's not, use the default port
  while((c = getopt(argc, argv, "o:p:s:")) != -1)
    switch(c)
      {
      case 'p':
    port = atoi(optarg);
    break;
      case 's':
    strcpy(remote_server, optarg);
    break;
      case 'o':
    remote_server_port = atoi(optarg);
    break;
      default:
    fprintf(stderr, "Usage: ssl-server-tier1 -p <port> (optional) -s <remote server name/IP address> -o <remote server port>\n");
    return EXIT_FAILURE;
      }
  
  // This will create a network socket and return a socket descriptor, which is
  // and works just like a file descriptor, but for network communcations. Note
  // we have to specify which TCP/UDP port on which we are communicating as an
  // argument to our user-defined create_socket() function.
  sockfd = create_socket(port);
  
  // Wait for incoming connections and handle them as the arrive
  while(true) {
    // Once an incoming connection arrives, accept it.  If this is successful,
    // we now have a connection between client and server and can communicate
    // using the socket descriptor
    clientsd = accept(sockfd, (struct sockaddr*)&addr, &len);
    if (clientsd < 0) {
      fprintf(stderr, "Server: Unable to accept connection: %s\n", strerror(errno));
      return EXIT_FAILURE;
    }
    
    // This will be a concurrent, rather than an iterative, server
    pid = fork();
    
    if (pid == 0) {
      // Display the IPv4 network address of the connected client
      inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr, INET_ADDRSTRLEN);
      fprintf(stdout, "Server: Established TCP connection with client (%s) on port %u\n", client_addr, port);
      
      // Create a new SSL object to bind to the socket descriptor
      clientssl = create_ssl_socket(clientsd);
      
      // SSL_accept() executes the SSL/TLS handshake. Because network sockets
      // are blocking by default, this function will block as well until the
      // handshake is complete.
      if (SSL_accept(clientssl) <= 0) {
    fprintf(stderr, "Server: Could not establish secure connection:\n");
    ERR_print_errors_fp(stderr);
      }
      else
    fprintf(stdout, "Server: Established SSL/TLS connection with client (%s)\n", client_addr);

      // This is where the server establishes a connection with another server
      server2sd = create_client_socket(remote_server, remote_server_port);
      server2ssl = create_client_ssl_socket(server2sd);
      if (SSL_connect(server2ssl) == 1) {
    printf("Server: Established SSL/TLS session to '%s' on port %u\n",
           "localhost", remote_server_port);
      } else {
    fprintf(stderr, "Server: Could not establish SSL session to '%s' on port %u\n", remote_server, remote_server_port);
    exit(EXIT_FAILURE);
      }
      
      //**************************************************************************
      char delim[] = "/";
      char eq[] = "=";
      char movie[20], location[20], date[20], time[20], type[20];
      int count = 1;
      char query[BUFFER_SIZE] = "SELECT * FROM movie_times";
      char where[BUFFER_SIZE] = " WHERE ";
      int where_count = 0;
      int nbytes_read;
      bzero(buffer, BUFFER_SIZE);
      SSL_read(clientssl, buffer, BUFFER_SIZE);

        
      printf("Message from client: %s\n", buffer);

      char *ptr = strtok(buffer, delim);

      while(ptr != NULL){
            if (count == 1) {
                  strcpy(movie, ptr);
            }

            if (count == 2) {
                  strcpy(location, ptr);
            }

            if (count == 3) {
                  strcpy(date, ptr);
            }

            if (count == 4) {
                  strcpy(time, ptr);
            }
            ptr = strtok(NULL, delim);
            count = count + 1;
      }

      bzero(buffer, BUFFER_SIZE);
      
      if (strcmp(movie, "name = ''") != 0) {
            strcat(where, movie);
            where_count = where_count + 1;
      }

      if (strcmp(location, "location = ''") != 0) {
            if (where_count >= 1) {
                  strcat(where, " AND ");
            }
            strcat(where, location);
            where_count = where_count + 1;
      }

      if (strcmp(date, "date = ''") != 0) {
            if (where_count >= 1) {
                  strcat(where, " AND ");
            }
            strcat(where, date);
            where_count = where_count + 1;
      }

      if (strcmp(time, "time = ''") != 0) {
            if (where_count >= 1) {
                  strcat(where, " AND ");
            }
            strcat(where, time);
            where_count = where_count + 1;
      }
      
      if (where_count != 0) {
            strcat(query, where);
      }

      printf("Server: Sending query to database:\n%s\n", query);
      SSL_write(server2ssl, query, strlen(query)+1);
      bzero(buffer, BUFFER_SIZE);

      //**************************************************************************

      // Receive response back from other server that it will pass to the client
      while (1) {
            nbytes_read = SSL_read(server2ssl, buffer, BUFFER_SIZE);
            if (nbytes_read < 0) {
                  fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
                  break;
            }

            if (strcmp(buffer, "NO RESULTS") == 0)
            {
                  fprintf(stderr, "Server: No results\n");
                  break;
            }

            if (strcmp(buffer, "DONE") == 0)
            {
                  fprintf(stderr, "Server: The query has been recieved successfully\n");
                  break;
            }
            printf("Server: Received message from database:\n%s\n", buffer);
            SSL_write(clientssl, buffer, strlen(buffer)+1);
            bzero(buffer, BUFFER_SIZE);
      }
      
      printf("Server: Sending result to client (%s)\n", client_addr);

      // Server sends the message to the client
      SSL_write(clientssl, buffer, strlen(buffer)+1);
      
      // Terminate the SSL session, close the TCP connection, and clean up
      fprintf(stdout, "Server: Terminating SSL session and TCP connection with client (%s)\n", client_addr);
      
      SSL_free(clientssl);
      close(clientsd);
    } // Child process code ends here. Parent just resumes listening
  }
  
  // Tear down and clean up server data structures before terminating
  close(sockfd);
  
  return EXIT_SUCCESS;
}

