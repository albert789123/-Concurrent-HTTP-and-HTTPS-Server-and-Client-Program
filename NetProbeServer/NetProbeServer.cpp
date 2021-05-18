#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <string>
#include <cstring>
#include <iostream>
#include <pthread.h>
#include <cstdint>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <resolv.h>

#define SOCKET int
#define SOCKET_ERROR -1
#define WSAGetLastError() (errno)
#define closesocket(s) close(s)
#define ioctlsocket ioctl
#define WSAEWOULDBLOCK EWOULDBLOCK
#define SD_SEND SHUT_WR
#define SD_RECEIVE SHUT_RD
#define SD_BOTH SHUT_RDWR

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/x509v3.h>

#include "threadpool.h"

using namespace std;

#define TRUE   1
#define FALSE  0

void print_manual(); //Printing the user manual
void HTTP_threadpool(void* arg); //Thread handling HTTP request for threadpool_mode
void HTTPS_threadpool(void* arg); //Thread handling HTTP request for threadpool_mode
int thread_mode(int argc, char *argv[]); //the thread_mode
void *HTTP_pthread(void* arg); //Thread handling HTTP request for thread_mode
void *HTTPS_pthread(void* arg); //Thread handling HTTP request for thread_mode
void send_http_error(int clientfd); //Sending HTTP error
void send_http_reply(int clientfd); //Sending HTTP reply
void send_https_reply(SSL *ssl); //Sending HTTPS reply
//functions for SSL connection
void init_openssl();
void cleanup_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);

int http_client_num = 0;
int ssl_client_num = 0;

int main(int argc, char *argv[]) {
		print_manual();

		for (int i = 1; i < argc; i++) { //Checking if it is thread_mode or threadpool_mode
			if ((strcmp(argv[i], "-server") == 0)) {
				if ((strcmp(argv[i + 1], "thread") == 0))
						thread_mode(argc, argv);
			}
			if (argv[i] == NULL)
				break;
		}

		//the start of threadpool_mode
		//Reading the configurations
		int stat = 500;
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-stat") == 0)) {
				stat = atoi(argv[i + 1]);
				break;
			}
			if (argv[i] == NULL)
				break;
		}
		char* lhost = (char*)"IN_ADDR_ANY";
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-lhost") == 0)) {
				lhost = argv[i + 1];
				break;
			}
			if (argv[i] == NULL)
				break;
		}
		int lhttpport = 4080;
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-lhttpport") == 0)) {
				lhttpport = atoi(argv[i + 1]);
				break;
			}
			if (argv[i] == NULL)
				break;
		}
		int lhttpsport = 4081;
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-lhttpsport") == 0)) {
				lhttpsport = atoi(argv[i + 1]);
				break;
			}
			if (argv[i] == NULL)
				break;
		}
		int psize = 8;
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-poolsize") == 0)) {
				psize = atoi(argv[i + 1]);
				break;
			}
			if (argv[i] == NULL)
				break;
		}

		//print the configurations
		printf("NetProbeServer Configurations: \n");
		printf("-lhost = %s\n", lhost);
		printf("-lhttpport = %d\n", lhttpport);
		printf("-lhttpsport = %d\n", lhttpsport);
		printf("-servermodel = threadpool\n");
		printf("-psize = %d\n\n", psize);

		int httplistenfd, ssllistenfd, connfd;
		struct sockaddr_in httpservaddr, sslservaddr, httpcliaddr, sslcliaddr;
		socklen_t len;

		//Fillling in the address information for HTTP socket
    httpservaddr.sin_family = AF_INET;
		if (strcmp(lhost, "IN_ADDR_ANY") == 0)
			httpservaddr.sin_addr.s_addr = INADDR_ANY;
		else
			httpservaddr.sin_addr.s_addr = inet_addr(lhost);
    httpservaddr.sin_port = htons(lhttpport);

		//Fillling in the address information for HTTPS socket
		sslservaddr.sin_family = AF_INET;
		if (strcmp(lhost, "IN_ADDR_ANY") == 0)
			sslservaddr.sin_addr.s_addr = INADDR_ANY;
		else
			sslservaddr.sin_addr.s_addr = inet_addr(lhost);
    sslservaddr.sin_port = htons(lhttpsport);

		httplistenfd = socket(AF_INET, SOCK_STREAM, 0);
		ssllistenfd = socket(AF_INET, SOCK_STREAM, 0);

		//Binding the sockets
		bind(httplistenfd, (struct sockaddr*)&httpservaddr, sizeof(httpservaddr));
		bind(ssllistenfd, (struct sockaddr*)&sslservaddr, sizeof(sslservaddr));
		printf("Binding local HTTP socket to port number %d with late binding ... successful.\n", lhttpport);
		printf("Binding local HTTPS socket to port number %d with late binding ... successful.\n", lhttpsport);

		listen(httplistenfd, 10);
		listen(ssllistenfd, 10);
		printf("Listening to incoming connection request ...\n");

		//Creating thread pool using threadpool.h
		threadpool tp;
		tp = create_threadpool(psize);

		fd_set fdReadSet;
		int max_fd = 0;
		FD_ZERO(&fdReadSet);
		struct timeval timeout = {0, 500};
		if (stat == 0)
			timeout = {0, 500};
		else
			timeout = {0, stat};
		long double elapsed = 0;

		clock_t start = clock();
		clock_t now;
		clock_t round_start = start;

		//loop of the main function
		while (1) {
			FD_SET(httplistenfd, &fdReadSet);
			FD_SET(ssllistenfd, &fdReadSet);
			max_fd = max(httplistenfd, ssllistenfd);
			int ret;
			if ((ret = select(max_fd + 1, &fdReadSet, NULL, NULL, &timeout)) < 0){ //Using non blocking select() to read incoming connection
				printf("select() faild with error\n");
			}

			if (FD_ISSET(httplistenfd, &fdReadSet)){ //Accepting HTTP connection
				len = sizeof(httpcliaddr);
				connfd = accept(httplistenfd, (struct sockaddr*)&httpcliaddr, &len);
				printf("Connected to %s port %d, HTTP\n", inet_ntoa(httpcliaddr.sin_addr), httpcliaddr.sin_port);
				http_client_num++;
				now = clock();
				elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
				printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
				dispatch(tp, HTTP_threadpool, &connfd); //Assigning task to the threadpool
			}

			if (FD_ISSET(ssllistenfd, &fdReadSet)){ //Accepting HTTPS connection
				len = sizeof(sslservaddr);
				connfd = accept(ssllistenfd, (struct sockaddr*)&sslservaddr, &len);
				printf("Connected to %s port %d, HTTPS\n", inet_ntoa(sslservaddr.sin_addr), sslservaddr.sin_port);
				ssl_client_num++;
				now = clock();
				elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
				printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
				dispatch(tp, HTTPS_threadpool, &connfd); //Assigning task to the threadpool
			}

			now = clock();
			elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
			if ((((long double)now - round_start) / (double)CLOCKS_PER_SEC * 1000) >= stat){ //Printing the statistics
				printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
				round_start = clock();
			}

		}

		return 0;

}

void HTTP_threadpool(void* arg) { //Thread handling HTTP request for threadpool_mode
	int clientfd = *((int *)arg);
	char buff[65536];
	char request[65536];
	int error = 0;
	int recv_len = recv(clientfd, buff, sizeof(buff), 0);
	strcat(request, buff);
	if (strstr(request, "HTTP/") == NULL) {     // Checking if it is a HTTP request
		send_http_error(clientfd);
		close(clientfd);
		error = 1;
	}

	char method[10];
	strcpy(method, strtok(request, " /"));      // Checking if it is a GET request
	if ((!error)&&(strcmp(method, "GET") != 0)) {
		send_http_error(clientfd);
		close(clientfd);
		error = 1;
	}

	if (!error)
		send_http_reply(clientfd);

	close(clientfd);
	http_client_num--;

}

void HTTPS_threadpool(void* arg) { //Thread handling HTTPS request for threadpool_mode
	int clientfd = *((int *)arg);

	SSL_CTX *ctx;
  init_openssl();
  ctx = create_context();
  configure_context(ctx);

	SSL *ssl;

	ssl = SSL_new(ctx);
  SSL_set_fd(ssl, clientfd);

	if (SSL_accept(ssl) <= 0) {
  	ERR_print_errors_fp(stderr);
  }
  else {
			char reply[] = "HTTP/1.1 200 OK\r\nServer:IERG4180 Project 4 HTTPS Server\r\nContent-length:135\r\nContent-type:text/html\r\n\r\n<html><head><title>HTTPS</title></head><body><font size+=5><br>You have received a IERG4180 Project 4 HTTPS Reply!</font></body></html>";
			SSL_write(ssl, reply, strlen(reply));
  }

	SSL_free(ssl);
	closesocket(clientfd);
	ssl_client_num--;

	SSL_CTX_free(ctx);
	cleanup_openssl();

}

void send_http_error(int clientfd) {
	char reply[] = "HTTP/1.1 400 Bad Request\r\nServer:IERG4180 Project 4 HTTP Server\r\nContent-length:120\r\nContent-type:text/html\r\n\r\n<html><head><title>HTTP</title></head><body><font size+=5><br>Send error! Check the request method!</font></body></html>";
	send(clientfd, reply, strlen(reply), 0);

}

void send_http_reply(int clientfd) {
	char reply[] = "HTTP/1.1 200 OK\r\nServer:IERG4180 Project 4 HTTP Server\r\nContent-length:134\r\nContent-type:text/html\r\n\r\n<html><head><title>HTTP</title></head><body><font size+=5><br>You have received a IERG4180 Project 4 HTTP Reply!</font></body></html>";
	send(clientfd, reply, strlen(reply), 0);
}

int thread_mode(int argc, char *argv[]) { //the thread_mode
	//read the configurations
	int stat = 500;
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-stat") == 0)) {
			stat = atoi(argv[i + 1]);
			break;
		}
		if (argv[i] == NULL)
			break;
	}
	char* lhost = (char*)"IN_ADDR_ANY";
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-lhost") == 0)) {
			lhost = argv[i + 1];
			break;
		}
		if (argv[i] == NULL)
			break;
	}
	int lhttpport = 4080;
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-lhttpport") == 0)) {
			lhttpport = atoi(argv[i + 1]);
			break;
		}
		if (argv[i] == NULL)
			break;
	}
	int lhttpsport = 4081;
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "-lhttpsport") == 0)) {
			lhttpsport = atoi(argv[i + 1]);
			break;
		}
		if (argv[i] == NULL)
			break;
	}

	//print the configurations
	printf("NetProbeServer Configurations: \n");
	printf("-lhost = %s\n", lhost);
	printf("-lhttpport = %d\n", lhttpport);
	printf("-lhttpsport = %d\n", lhttpsport);
	printf("-servermodel = thread\n");

	int httplistenfd, ssllistenfd, connfd;
	struct sockaddr_in httpservaddr, sslservaddr, httpcliaddr, sslcliaddr;
	socklen_t len;

	//Fillling in the address information for HTTP socket
	httpservaddr.sin_family = AF_INET;
	if (strcmp(lhost, "IN_ADDR_ANY") == 0)
		httpservaddr.sin_addr.s_addr = INADDR_ANY;
	else
		httpservaddr.sin_addr.s_addr = inet_addr(lhost);
	httpservaddr.sin_port = htons(lhttpport);

	//Fillling in the address information for HTTPS socket
	sslservaddr.sin_family = AF_INET;
	if (strcmp(lhost, "IN_ADDR_ANY") == 0)
		sslservaddr.sin_addr.s_addr = INADDR_ANY;
	else
		sslservaddr.sin_addr.s_addr = inet_addr(lhost);
	sslservaddr.sin_port = htons(lhttpsport);

	httplistenfd = socket(AF_INET, SOCK_STREAM, 0);
	ssllistenfd = socket(AF_INET, SOCK_STREAM, 0);

	//Binding the sockets
	bind(httplistenfd, (struct sockaddr*)&httpservaddr, sizeof(httpservaddr));
	bind(ssllistenfd, (struct sockaddr*)&sslservaddr, sizeof(sslservaddr));
	printf("Binding local HTTP socket to port number %d with late binding ... successful.\n", lhttpport);
	printf("Binding local HTTPS socket to port number %d with late binding ... successful.\n", lhttpsport);

	listen(httplistenfd, 10);
	listen(ssllistenfd, 10);
	printf("Listening to incoming connection request ...\n");

	pthread_t thread_id;

	fd_set fdReadSet;
	int max_fd = 0;
	FD_ZERO(&fdReadSet);
	struct timeval timeout = {0, 500};
	if (stat == 0)
		timeout = {0, 500};
	else
		timeout = {0, stat};
	long double elapsed = 0;

	clock_t start = clock();
	clock_t now;
	clock_t round_start = start;

	//loop of the main function
	while (1) {
		FD_SET(httplistenfd, &fdReadSet);
		FD_SET(ssllistenfd, &fdReadSet);
		max_fd = max(httplistenfd, ssllistenfd);
		int ret;
		if ((ret = select(max_fd + 1, &fdReadSet, NULL, NULL, &timeout)) < 0){ //Using non blocking select() to read incoming connection
			printf("select() faild with error\n");
		}

		if (FD_ISSET(httplistenfd, &fdReadSet)){ //Accepting HTTP connection
			len = sizeof(httpcliaddr);
			connfd = accept(httplistenfd, (struct sockaddr*)&httpcliaddr, &len);
			printf("Connected to %s port %d, HTTP\n", inet_ntoa(httpcliaddr.sin_addr), httpcliaddr.sin_port);
			http_client_num++;
			now = clock();
			elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
			printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
			pthread_create(&thread_id, NULL, HTTP_pthread, &connfd); //Creating new thread
			pthread_detach(thread_id);
		}

		if (FD_ISSET(ssllistenfd, &fdReadSet)){ //Accepting HTTPS connection
			len = sizeof(sslservaddr);
			connfd = accept(ssllistenfd, (struct sockaddr*)&sslservaddr, &len);
			printf("Connected to %s port %d, HTTPS\n", inet_ntoa(sslservaddr.sin_addr), sslservaddr.sin_port);
			ssl_client_num++;
			now = clock();
			elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
			printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
			pthread_create(&thread_id, NULL, HTTPS_pthread, &connfd); //Creating new thread
			pthread_detach(thread_id);
		}

		now = clock();
		elapsed = ((long double)now - start) / (double)CLOCKS_PER_SEC;
		if ((((long double)now - round_start) / (double)CLOCKS_PER_SEC * 1000) >= stat){ //Printing the statistics
			printf("Elapsed [%.1Lfs] HTTP Clients [%d] HTTPS Clients [%d]\n", elapsed, http_client_num, ssl_client_num);
			round_start = clock();
		}

	}

	return 0;

}

void *HTTP_pthread(void* arg) { //Thread handling HTTP request for thread_mode
	int clientfd = *((int *)arg);
	char buff[65536];
	char request[65536];
	int error = 0;
	int recv_len = recv(clientfd, buff, sizeof(buff), 0);
	strcat(request, buff);
	if (strstr(request, "HTTP/") == NULL) {     // Checking if it is a HTTP request
		send_http_error(clientfd);
		close(clientfd);
		error = 1;
	}

	char method[10];
	strcpy(method, strtok(request, " /"));      // Checking if it is a GET request
	if ((!error)&&(strcmp(method, "GET") != 0)) {
		send_http_error(clientfd);
		close(clientfd);
		error = 1;
	}

	if (!error)
		send_http_reply(clientfd);

	close(clientfd);
	http_client_num--;

}

void *HTTPS_pthread(void* arg) { //Thread handling HTTPS request for thread_mode
	int clientfd = *((int *)arg);

	SSL_CTX *ctx;
  init_openssl();
  ctx = create_context();
  configure_context(ctx);

	SSL *ssl;

	ssl = SSL_new(ctx);
  SSL_set_fd(ssl, clientfd);

	if (SSL_accept(ssl) <= 0) {
  	ERR_print_errors_fp(stderr);
  }
  else {
			char header[] = "HTTP/1.1 200 OK\r\nServer:IERG4180 Project 4 HTTPS Server\r\nContent-length:135\r\nContent-type:text/html\r\n\r\n<html><head><title>HTTPS</title></head><body><font size+=5><br>You have received a IERG4180 Project 4 HTTPS Reply!</font></body></html>";
			SSL_write(ssl, header, strlen(header));
  }

	SSL_free(ssl);
	closesocket(clientfd);
	ssl_client_num--;

	SSL_CTX_free(ctx);
	cleanup_openssl();

}

void print_manual() { //Printing the user manual
	printf("NetProbeSrv <parameters>, see below:\n");
	printf("    <-stat yyy>           set update of statistics display to be once yyy ms. (Default = 500 ms)\n");
	printf("    <-lhost hostname>     hostname to bind to. (Default late binding, i.e., IN_ADDR_ANY)\n");
	printf("    <-lhttpport portnum>  port number to bind to for http connection. (Default “4080”)\n");
	printf("    <-lhttpsport portnum> port number to bind to for https connection. (Default “4081”)\n");
	printf("    <-server  model>      concurrent  server  model  where  model={thread,  threadpool}  for  both  HTTP  and  HTTPS. (Default threadpool)\n");
	printf("    <-poolsize numthread> If “-server threadpool” is specified, set the pool size to be numthread. (Default = 8)\n\n");
}

void init_openssl()
{
   SSL_load_error_strings();
   OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
   EVP_cleanup();
}

SSL_CTX *create_context()
{
   const SSL_METHOD *method;
   SSL_CTX *ctx;

   //method = SSLv23_server_method();
   method = TLSv1_server_method();

   ctx = SSL_CTX_new(method);
   if (!ctx) {
      perror("Unable to create SSL context");
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
   }

   return ctx;
}

void configure_context(SSL_CTX *ctx)
{
   SSL_CTX_set_ecdh_auto(ctx, 1);

   /* Set the key and cert */
   if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
   }

   if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stderr);
      exit(EXIT_FAILURE);
   }
}
