/******************************************************************************

PROGRAM:  ssl-server-tier2.c
AUTHOR:   Jeff Hemmes
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small server application that receives incoming TCP
          connections from clients and simply exchanges messages.  It uses a
          secure SSL/TLS connection using certificates generated with the
          openssl application.  The purpose is to demonstrate how to establish
          secure communication between a client and server using public key
          cryptography.
 
          To create a self-signed certificate your server can use, at the
          command prompt type:

          openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365
          -out cert.pem

          This will create two files: a private key contained in the file
          'key.pem' and a certificate containing a public key in the file
          'cert.pem'.  Your server will require both in order to operate
          properly.  The client requires neither.

          Some of the code and descriptions can be found in "Network Security
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mysql.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "server-tools.h"

#define BUFFER_SIZE 256
#define BUF_SIZE 2048



int main(int argc, char **argv) {
  struct sockaddr_in addr;
  unsigned int       len = sizeof(addr);
  unsigned int       sockfd;
  unsigned int       port;
  SSL_CTX*           ssl_ctx;
  SSL*               ssl;
  int                client;
  char         reply[BUFFER_SIZE] = "";
  char               client_addr[INET_ADDRSTRLEN];
  pid_t              pid;
  char               buffer[BUFFER_SIZE];
  long rows;
  MYSQL* connection;
  MYSQL_ROW row;
  MYSQL_RES* result;

  // Do not create zombie processes
  signal(SIGCHLD, SIG_IGN);
  init_openssl();
    
  // Port can be specified on the command line. If it's not, use the default port
  switch(argc)
    {
    case 1:
      port = DEFAULT_PORT;
      break;
    case 2:
      port = atoi(argv[1]);
      break;
    default:
      fprintf(stderr, "Usage: ssl-server-tier2 <port> (optional)\n");
      return EXIT_FAILURE;
    }
  //**********************************************************************



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
    client = accept(sockfd, (struct sockaddr*)&addr, &len);
    if (client < 0) {
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
      ssl = create_ssl_socket(client);
      
      // SSL_accept() executes the SSL/TLS handshake. Because network sockets are
      // blocking by default, this function will block as well until the handshake
      // is complete.
      if (SSL_accept(ssl) <= 0) {
    fprintf(stderr, "Server: Could not establish secure connection:\n");
    ERR_print_errors_fp(stderr);
      }
      else
    fprintf(stdout, "Server: Established SSL/TLS connection with client (%s)\n", client_addr);
      // This is where the server establishes a connection with another server

      // Receive response back from other server.  Then it gets passed to the client

      // Create Database
      // Initialize the MySQL connection object
      if ((connection = mysql_init(NULL)) == NULL) {
        fprintf(stderr, "Could not initialize mysql: %s\n", mysql_error(connection));
        return EXIT_FAILURE;
      }

  // Connect to mysql on 'localhost' and provide login credentials

  if (mysql_real_connect(connection, "localhost", "user", "password",
          NULL, 0, NULL, 0) == NULL) {
      fprintf(stderr, "Could not connect to MySQL database: %s\n",
          mysql_error(connection));
      mysql_close(connection);
      return EXIT_FAILURE;
  }
  // create database
  if (mysql_query(connection, "CREATE DATABASE IF NOT EXISTS movies")) {
    fprintf(stderr, "MySQL query failed: %s\n", mysql_error(connection));
    mysql_close(connection);
    return EXIT_FAILURE;
  }
  if (mysql_query(connection, "USE movies")) {
    fprintf(stderr, "MySQL query failed: %s\n", mysql_error(connection));
    mysql_close(connection);
    return EXIT_FAILURE;
  }
  if (mysql_query(connection, "CREATE TABLE IF NOT EXISTS movie_times(name VARCHAR(30) NOT NULL, location VARCHAR(30) NOT NULL, date VARCHAR(30) NOT NULL, time VARCHAR(30) NOT NULL )")) {
    fprintf(stderr, "MySQL query failed: %s\n", mysql_error(connection));
    mysql_close(connection);
    return EXIT_FAILURE;
  }
  if (mysql_query(connection, "ALTER TABLE movie_times ADD UNIQUE INDEX(name, location, date, time)")) {
    fprintf(stderr, "MySQL query failed: %s\n", mysql_error(connection));
    mysql_close(connection);
    return EXIT_FAILURE;
  }
        
    //read file to populate database
    char buf [BUF_SIZE];
    buffer[strlen(buffer)-1] = '\0';
    FILE *fptr;
    fptr = fopen("sqldata.txt","r");
    if (fptr == NULL) {
        fprintf(stderr, "File operations error: %s\n", strerror(errno));
        sprintf(buffer, "%d", errno);
    } else {
        int fs = fread(buf, strlen(buf)+1,2048, fptr);
    }
    fclose(fptr);
        
  if (mysql_query(connection, buf)) {
    fprintf(stderr, "MySQL query failed***: %s\n", mysql_error(connection));
      fprintf(stderr, "MySQL query failed***: %s\n", buf);
    mysql_close(connection);
    return EXIT_FAILURE;
  }

  SSL_read(ssl, buffer, BUFFER_SIZE);

  
  if (mysql_query(connection, buffer)) {
       bzero(reply, BUFFER_SIZE);
    strcat(reply, "No movies found");
    SSL_write(ssl, reply, strlen(reply)+1);
    mysql_close(connection);
    return EXIT_FAILURE;
  }

  // Get the result of the SQL query and reference it using the pointer
  // variable 'result'
  
  if ((result = mysql_store_result(connection)) == NULL) {
    fprintf(stderr, "%s\n", mysql_error(connection));
    mysql_close(connection);
    return EXIT_FAILURE;
  }

  // Get each row from the query result, then output the three fields in each
 fprintf(stdout, "Server: Sending message to client (%s)\n%s", client_addr, reply);
  bzero(reply, BUFFER_SIZE);
  while (row = mysql_fetch_row(result)) {
    strcat(reply, "Name: ");
    strcat(reply, row[0]);
    strcat(reply, " ");
    strcat(reply, "Location: ");
    strcat(reply, row[1]);
    strcat(reply, " ");
    strcat(reply, "Date: ");
    strcat(reply, row[2]);
    strcat(reply, " ");
    strcat(reply, "Time: ");
    strcat(reply, row[3]);
    strcat(reply, " ");
    strcat(reply, "\n");

    printf("%s", reply);

     SSL_write(ssl, reply, strlen(reply)+1);
      bzero(reply, BUFFER_SIZE);
  }

  
  if (result) {
    rows = mysql_num_rows( result );
} else {
    rows = 0;
}

if (rows == 0) {
  strcat(reply, "NO RESULTS");
} else {
  strcat(reply, "DONE");
}

  SSL_write(ssl, reply, strlen(reply)+1);
  bzero(reply, BUFFER_SIZE);


  // This is where the server actually does the work sending a message
     
      
  // Server sends the message to the client
     
  // Clean up and free dynamically allocated memory
  
  mysql_free_result(result);
  mysql_close(connection);

      // Terminate the SSL session, close the TCP connection, and clean up
      fprintf(stdout, "Server: Terminating SSL session and TCP connection with client (%s)\n", client_addr);
      
      SSL_free(ssl);
      close(client);
    } // Child process code ends here. Parent just resumes listening
  }
  
  // Tear down and clean up server data structures before terminating
  close(sockfd);
  
  return EXIT_SUCCESS;
}

