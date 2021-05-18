#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#define SOCKET int
#define SOCKET_ERROR -1
#define WSAGetLastError() (errno)
#define closesocket(s) close(s)
#define ioctlsocket ioctl
#define WSAEWOULDBLOCK EWOULDBLOCK

#include <stdio.h>
#include <string>
#include <time.h>
#include <iostream>
#include <math.h>
using namespace std;

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <openssl/x509v3.h>

void print_manual(); //Printing the user manual
int http_mode(char *url, char *filename, int SaveFile); //Sending HTTP request
int https_mode(char *url, char *filename, int SaveFile, char *hostname); //Sending HTTPS request
//functions for SSL connection
int InitTrustStore(SSL_CTX *ctx, char *hostname);
int create_socket(char url_str[], BIO *out, char *dest_url);

int main(int argc, char *argv[]) {
	if (argc == 1) {
		print_manual();
	}
	else if (argc > 1) {

		//Reading the configurations
		char *url = argv[1];

		char *filename;
		int SaveFile = 0;
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-file") == 0)) {
				filename = argv[i + 1];
				SaveFile = 1;
				break;
			}
			if (argv[i] == NULL)
				break;
		}

		char *hostname = (char *)"NULL";
		for (int i = 1; i < argc; i++) {
			if ((strcmp(argv[i], "-verifyhost") == 0)) {
				hostname = argv[i + 1];
				break;
			}
			if (argv[i] == NULL)
				break;
		}

		if (strstr(url, "https") != NULL)
			https_mode(url, filename, SaveFile, hostname); //Sending HTTPS request
		else if (strstr(url, "http") != NULL)
			http_mode(url, filename, SaveFile); //Sending HTTP request

	}

	return 0;

}

int http_mode(char *url, char *filename, int SaveFile) { //Sending HTTP request

	char DomainName[65536];
	strcpy(DomainName, strstr(url, "://") + 3); //Removing the "http://" part

	//Getting the specified port number
	char portchar[6] = "80";
	char *tmp_ptr;
	if (strchr(DomainName, ':')) {
		 tmp_ptr = strchr(DomainName, ':');
		 strcpy(portchar, tmp_ptr + 1);
		 *tmp_ptr = '\0';
	}
	int portint = atoi(portchar);

	string temp_str = DomainName;
	strcpy(DomainName, (temp_str.substr(0, DomainName - strchr(DomainName, ':'))).c_str()); //Removing the port number part

	//Fillling in the server information
	int socketfd;
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(portint);
	struct hostent *serverinfo = gethostbyname(DomainName);
	server_addr.sin_addr.s_addr = *(long*)(serverinfo->h_addr);

	if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket error");
		exit(-1);
	}

	if ((connect(socketfd, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0) {
		perror("connect error");
		exit(-1);
	}
	printf("Successfully made the TCP connection to: %s.\n", DomainName);

	printf("------------------ RESPONSE RECEIVED ---------------------\n");

	char request1[65536] = "GET / HTTP/1.1\r\nHost: ";
	char request2[30] = "\r\nConnection: close\r\n\r\n";
	strcat(request1, DomainName);
	strcat(request1, request2);

	if (send(socketfd, request1, strlen(request1), 0) < 0) {
		perror("send error");
		exit(-1);
	}

	char buff[65536];
	char *FilePart;
	long total = 0;
	long file = 0;

	FILE *fp;
	if (SaveFile) {
		fp = fopen(filename, "w");
	}

	int EnterFilePart = 0;
	clock_t start = clock();
	while (int recv_len = recv(socketfd, buff, sizeof(buff), 0)) {
		printf("%s", buff);
		if (EnterFilePart == 0) {
			FilePart = strstr(buff, "\r\n\r\n");
			if (FilePart != NULL)
				EnterFilePart = 1;
		}

		if (EnterFilePart == 2) {
			file += recv_len;
			if (SaveFile)
				fprintf(fp, "%s\n", buff);
		}
		else if (EnterFilePart == 1) {
			file += strlen(FilePart);
			if (SaveFile)
				fprintf(fp, "%s\n", FilePart);
			EnterFilePart = 2;
		}
		total += recv_len;
	}
	clock_t response_t = clock() - start;

	printf("\n----------------------------------------------------------\n");
	printf("\nFinished HTTP connection with server: %s.\n", DomainName);

	long double TotalRate = (double)total / response_t * 1000;
	long double FileRate = (double)file / response_t * 1000;
	printf("Response Time [%ldms] Total [%ldB, %.0LfBps] File [%ldB, %.0LfBps]\n", response_t, total, TotalRate, file, FileRate);

	if (SaveFile) {
		fclose(fp);
	}

	return 0;
}

int https_mode(char *url, char *filename, int SaveFile, char *hostname) { //Sending HTTPS request

	char dest_url[65536];
	strcpy(dest_url, strstr(url, "://") + 3); //Removing the "https://" part

	BIO               *outbio = NULL;
	X509                *cert = NULL;
	X509_NAME       *certname = NULL;
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	SSL *ssl;
	int server = 0;
	int ret, i;
	char *ptr = NULL;

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* initialize SSL library and register algorithms             *
	* ---------------------------------------------------------- */
	if (SSL_library_init() < 0)
		 BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

	/* ---------------------------------------------------------- *
	* Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
	* ---------------------------------------------------------- */
	method = TLSv1_method();

	/* ---------------------------------------------------------- *
	* Try to create a new SSL context                            *
	* ---------------------------------------------------------- */
	if ((ctx = SSL_CTX_new(method)) == NULL)
		 BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

	/* ---------------------------------------------------------- *
	* Disabling SSLv2/SSLv3 will leave TLS for negotiation    *
	* ---------------------------------------------------------- */
	//	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	InitTrustStore(ctx, hostname);

	/* ---------------------------------------------------------- *
	* Create new SSL connection state object                     *
	* ---------------------------------------------------------- */
	ssl = SSL_new(ctx);

	/* ---------------------------------------------------------- *
	* Make the underlying TCP socket connection                  *
	* ---------------------------------------------------------- */
	server = create_socket(dest_url, outbio, dest_url);
	if (server != 0)
		 BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);

	/* ---------------------------------------------------------- *
	* Attach the SSL session to the socket descriptor            *
	* ---------------------------------------------------------- */
	SSL_set_fd(ssl, server);

	/* ---------------------------------------------------------- *
	* Try to SSL-connect here, returns 1 for success             *
	* ---------------------------------------------------------- */
	SSL_set_tlsext_host_name(ssl, hostname); // Enable SNI
	if (SSL_connect(ssl) != 1)
		 BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
	else
		 BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

	/* ---------------------------------------------------------- *
	* Get the remote certificate into the X509 structure         *
	* ---------------------------------------------------------- */
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		 BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
	else
		 BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);
	/* ---------------------------------------------------------- *
	* extract various certificate information                    *
	* -----------------------------------------------------------*/
	certname = X509_NAME_new();
	certname = X509_get_subject_name(cert);

	/* ---------------------------------------------------------- *
	* display the cert subject here                              *
	* -----------------------------------------------------------*/
	BIO_printf(outbio, "Displaying the certificate subject data:\n");
	X509_NAME_print_ex(outbio, certname, 0, 0);
	BIO_printf(outbio, "\n");

	/* ---------------------------------------------------------- *
	* Validate the remote certificate is from a trusted root     *
	* ---------------------------------------------------------- */
	ret = SSL_get_verify_result(ssl);
	if (ret != X509_V_OK)
		 BIO_printf(outbio, "Warning: Validation failed for certificate from: %s.\n", dest_url);
	else{
		BIO_printf(outbio, "Successfully validated the server's certificate from: %s.\n", dest_url);
	}

	/* ---------------------------------------------------------- *
	* Perform hostname validation                                 *
	* ---------------------------------------------------------- */
	ret = X509_check_host(cert, hostname, strlen(hostname), 0, &ptr);
	if (ret == 1) {
		BIO_printf(outbio, "Successfully validated the server's hostname matched to: %s.\n", ptr);
		OPENSSL_free(ptr); ptr = NULL;
	}
	else if (ret == 0)
		BIO_printf(outbio, "Server's hostname validation failed: %s.\n", hostname);
	else
		BIO_printf(outbio, "hostname validation internal error: %s.\n", hostname);

	/* ---------------------------------------------------------- *
	* Send an HTTP GET request                                   *
	* ---------------------------------------------------------- */

	char request[8192];
	sprintf(request,
		 "GET / HTTP/1.1\r\n"
		 "Host: %s\r\n"
		 "Connection: close\r\n\r\n", dest_url);

	SSL_write(ssl, request, strlen(request));

	BIO_printf(outbio, "------------------ RESPONSE RECEIVED ---------------------\n");

	char *FilePart;
	long total = 0;
	long file = 0;

	FILE *fp;
	if (SaveFile) {
		fp = fopen(filename, "w");
	}

	int EnterFilePart = 0;
	char buff[65536];
	clock_t start = clock();
	while (int recv_len = SSL_read(ssl, buff, sizeof(buff))) {

		if (recv_len < 0)
			break;
		BIO_write(outbio, buff, recv_len);

		if (EnterFilePart == 0) {
			FilePart = strstr(buff, "\r\n\r\n");
			if (FilePart != NULL)
				EnterFilePart = 1;
		}

		if (EnterFilePart == 2) {
			file += recv_len;
			if (SaveFile){
				fprintf(fp, "%s\n", buff);
			}
		}
		else if (EnterFilePart == 1) {
			file += strlen(FilePart);
			if (SaveFile){
				fprintf(fp, "%s\n", FilePart);
			}
			EnterFilePart = 2;
		}
	  total += recv_len;

	}
	clock_t response_t = clock() - start;
	BIO_printf(outbio, "\n----------------------------------------------------------\n");


	/* ---------------------------------------------------------- *
	* Free the structures we don't need anymore                  *
	* -----------------------------------------------------------*/
	SSL_free(ssl);
	closesocket(server);
	X509_free(cert);
	SSL_CTX_free(ctx);
	BIO_printf(outbio, "\nFinished SSL/TLS connection with server: %s.\n", dest_url);
	long double TotalRate = (double)total / response_t * 1000;
	long double FileRate = (double)file / response_t * 1000;
	printf("Response Time [%ldms] Total [%ldB, %.0LfBps] File [%ldB, %.0LfBps]\n", response_t, total, TotalRate, file, FileRate);

	if (SaveFile) {
		fclose(fp);
	}

	return(0);
}

void print_manual() { //Printing the user manual
	printf("NetProbeClient [URL] <more parameters, see below>\n");
	printf("[URL]  The URL (HTTP or HTTPS) to retrieve.\n");
	printf("More parameters:\n");
	printf("   <-file  filename>      save  the  received  text  files  (excluded  the  response  header  infomation) to  the  file  named  ‘filename’. (Default: output to stdout)\n");
	printf("   <-verifyhost name>     set the hostname to be “name” such that we can do hostname verification for HTTPS(Default: name would be empty, so you must set it for HTTPS)\n\n");
}

int InitTrustStore(SSL_CTX *ctx, char *hostname)
{
   //	if (!SSL_CTX_set_default_verify_paths(ctx)) {
   if (!SSL_CTX_load_verify_locations(ctx, 0, "/etc/ssl/certs")) {
      fprintf(stderr, "Unable to set default verify paths.\n");
      return -1;
   }
   else
      return 0;
}

int create_socket(char url_str[], BIO *out, char *dest_url) {
   int sockfd;
   char    portchar[6] = "443";
   char      proto[6] = "";
   char      *tmp_ptr = NULL;
   int           portint;
   struct hostent *host;
   struct sockaddr_in dest_addr;

 	if (strchr(dest_url, ':')) { //Getting the specified port number
 		 tmp_ptr = strchr(dest_url, ':');
 		 strcpy(portchar, tmp_ptr + 1);
 		 *tmp_ptr = '\0';
 	}
 	portint = atoi(portchar);

 	string temp_str = dest_url;
 	strcpy(dest_url, (temp_str.substr(0, dest_url - strchr(dest_url, ':'))).c_str()); //Removing the port number part

   if ((host = gethostbyname(dest_url)) == NULL) {
      BIO_printf(out, "Error: Cannot resolve hostname %s.\n", dest_url);
      abort();
   }

   /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   dest_addr.sin_family = AF_INET;
   dest_addr.sin_port = htons(portint);
   dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

   /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */
   memset(&(dest_addr.sin_zero), '\0', 8);

   tmp_ptr = inet_ntoa(dest_addr.sin_addr);

   /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
   if (connect(sockfd, (struct sockaddr *) &dest_addr,
      sizeof(struct sockaddr)) == -1) {
      BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
         dest_url, tmp_ptr, portint);
      exit(-1);
   }

   return sockfd;
}
