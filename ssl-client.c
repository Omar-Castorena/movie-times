/******************************************************************************

PROGRAM:  ssl-client.c
AUTHOR:   Omar Castorena
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small client application that establishes a secure 
          TCP connection to a server and simply exchanges messages.  It uses an
          SSL/TLS connection using X509 certificates generated with the openssl 
          application. The purpose is to demonstrate how to establish and use 
          secure communication channels between client and server using public 
          key cryptography.
 
          Some of the code and descriptions can be found in "Network Security
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "client-tools.h"

#define BUFFER_SIZE         256

int main(int argc, char** argv) {
  unsigned int      port = DEFAULT_PORT;
  char              remote_host[MAX_HOSTNAME_LENGTH];
  char              buffer[BUFFER_SIZE], message[BUFFER_SIZE];
  char*             temp_ptr;
  int               sockfd;
  SSL*              ssl;

  int nbytes_written, nbytes_read, len;
  char movie[20] = "";
  char location[20] = "";
  char date[20] = "";
  char time[20] = "";
  
  if (argc != 2) {
    fprintf(stderr, "Client: Usage: ssl-client <server name>:<port>\n");
    exit(EXIT_FAILURE);
  } else {
    // Search for ':' in the argument to see if port is specified
    temp_ptr = strchr(argv[1], ':');
    if (temp_ptr == NULL)    // Hostname only. Use default port
      strncpy(remote_host, argv[1], MAX_HOSTNAME_LENGTH);
    else {
      // Argument is formatted as <hostname>:<port>. Need to separate
      // First, split out the hostname from port, delineated with a colon
      // remote_host will have the <hostname> substring
      strncpy(remote_host, strtok(argv[1], ":"), MAX_HOSTNAME_LENGTH);
      // Port number will be the substring after the ':'. At this point
      // temp is a pointer to the array element containing the ':'
      port = (unsigned int) atoi(temp_ptr+sizeof(char));
    }
  }
  
  // Create the underlying TCP socket connection to the remote host
  sockfd = create_client_socket(remote_host, port);
  if(sockfd != 0) {
    printf("Client: Established TCP connection to '%s' on port %u\n",
	   remote_host, port);
  } else {
    fprintf(stderr, "Client: Could not establish TCP connection to %s on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  // Now create the SSL/TLS socket over the TCP socket
  ssl = create_client_ssl_socket(sockfd);

  // Initiates an SSL session over the existing socket connection. SSL_connect()
  // will return 1 if successful.
  if (SSL_connect(ssl) == 1) {
    printf("Client: Established SSL/TLS session to '%s' on port %u\n",
	   remote_host, port);
  } else {
    fprintf(stderr, "Client: Could not establish SSL session to '%s' on port %u\n", remote_host, port);
    exit(EXIT_FAILURE);
  }

  //***************************************************************
  printf("Welcome to Movie Times Searcher\n");
  printf("This program uses the following information to search for movie times\n");
  printf("movie name\n");
  printf("location\n");
  printf("date\n");
  printf("time\n");

  printf("Please provide any information or leave blank to search all\n");

  printf("Enter movie name: ");
  fgets(movie, 20, stdin);
  len = strlen(movie);
  if( movie[len-1] == '\n' )
    movie[len-1] = 0;

  printf("Enter location (city, state): ");
  fgets(location, 20, stdin);
  len = strlen(location);
  if( location[len-1] == '\n' )
    location[len-1] = 0;

  printf("Enter date (month, day): ");
  fgets(date, 20, stdin);
  len = strlen(date);
  if( date[len-1] == '\n' )
    date[len-1] = 0;

  printf("Enter time (hr:min am): ");
  fgets(time, 20, stdin);
  len = strlen(time);
  if( time[len-1] == '\n' )
    time[len-1] = 0;

  printf("Searching...\n");

  bzero(message, BUFFER_SIZE);
  
    strcat(message, "name = '");
    strcat(message, movie);
    strcat(message, "'/");
  
    strcat(message, "location = '");
    strcat(message, location);
    strcat(message, "'/");

    strcat(message, "date = '");
    strcat(message, date);
    strcat(message, "'/");

    strcat(message, "time = '");
    strcat(message, time);
    strcat(message, "'");
  printf("Sending message to client: \"%s\" \n", message);
  nbytes_written = SSL_write(ssl, message, strlen(message));

  bzero(message, BUFFER_SIZE);

  if (nbytes_written < 0)
  {
    fprintf(stderr, "Client: Could not write message to socket: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  //***************************************************************

  // Client reads a message sent by the server
  printf("-----------------Results-----------------\n");

   while (1)
  {
    nbytes_read = SSL_read(ssl, buffer, BUFFER_SIZE);
    if (nbytes_read < 0)
    {
      fprintf(stderr, "Server: Error reading from socket: %s\n", strerror(errno));
      break;
    }

    if (strcmp(buffer, "NO RESULTS") == 0)
    {
      fprintf(stderr, "No results\n");
      break;
    }

    if (strcmp(buffer, "DONE") == 0)
    {
      break;
    }
      printf("%s", buffer);
    bzero(buffer, BUFFER_SIZE);
  }

  // Deallocate memory for the SSL data structures and close the socket
  SSL_free(ssl);
  close(sockfd);
  
  return EXIT_SUCCESS;
}

