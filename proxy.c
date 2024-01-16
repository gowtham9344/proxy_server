#include <string.h>  
#include <unistd.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h> 
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SA struct sockaddr 
#define BACKLOG 10 
#define PORT "8080"
#define NUM_FDS 2

SSL_CTX* ctx;
SSL_CTX* ctx1;

// give IPV4 or IPV6  based on the family set in the sa
void *get_in_addr(struct sockaddr *sa){
	if(sa->sa_family == AF_INET){
		return &(((struct sockaddr_in*)sa)->sin_addr);	
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


void create_SSL_context() {

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void create_SSL_context_client() {

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx1 = SSL_CTX_new(SSLv23_client_method());
    if (ctx1 == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


void cleanup(SSL *ssl,struct pollfd* pollfds) {
    SSL_free(ssl);
    close(pollfds->fd);
    pollfds->fd *= -1;
}

// this is the code for server creation. here i have used TCP instead of UDP because i need all the data without any loss. if we use UDP we
// have to implement those in the upper layers.
// this function will return socket descripter to the calling function.
int server_creation(){
	int sockfd;
	struct addrinfo hints,*servinfo,*p;
	int yes = 1;
	int rv;
	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;// my ip
	
	// set the address of the server with the port info.
	if((rv = getaddrinfo(NULL,PORT,&hints,&servinfo)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(rv));	
		return 1;
	}
	
	// loop through all the results and bind to the socket in the first we can
	for(p = servinfo; p!= NULL; p=p->ai_next){
		sockfd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
		if(sockfd==-1){ 
			perror("server: socket\n"); 
			continue; 
		} 
		
		// SO_REUSEADDR is used to reuse the same port even if it was already created by this.
		// this is needed when the program is closed due to some system errors then socket will be closed automaticlly after few
		// minutes in that case before the socket is closed if we rerun the program then we have use the already used port 	
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt");
			exit(1);	
		}
		
		// it will help us to bind to the port.
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
	}
	
	// server will be listening with maximum simultaneos connections of BACKLOG
	if(listen(sockfd,BACKLOG) == -1){ 
		perror("listen");
		exit(1); 
	} 
	return sockfd;
}


void connection_accepting(int sockfd, struct pollfd **pollfds, int *maxfds, int *numfds, SSL*** sslfds, SSL_CTX* ctx) {
    int connfd;
    struct sockaddr_storage their_addr;
    char s[INET6_ADDRSTRLEN];
    socklen_t sin_size;

    sin_size = sizeof(their_addr);
    connfd = accept(sockfd, (SA*)&their_addr, &sin_size);
    if (connfd == -1) {
        perror("accept");
        exit(1);
    }

    if (*numfds == *maxfds) {
        *pollfds = realloc(*pollfds, (*maxfds + NUM_FDS) * sizeof(struct pollfd));
        *sslfds = realloc(*sslfds, (*maxfds + NUM_FDS) * sizeof(SSL*));

        if (*pollfds == NULL || *sslfds == NULL) {
            perror("realloc");
            exit(1);
        }

        *maxfds += NUM_FDS;
    }
    (*numfds)++;

    ((*pollfds) + *numfds - 1)->fd = connfd;
    ((*pollfds) + *numfds - 1)->events = POLLIN;
    ((*pollfds) + *numfds - 1)->revents = 0;

    // Create a new SSL connection
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, connfd);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(connfd);
        exit(1);
    }

    // Store the SSL structure pointer in the array
    (*sslfds)[*numfds - 1] = ssl;

    // Printing the client name
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s));
    printf("\nproxy server: got connection from %s\n", s);
}

// this is the code for client creation. here i have used TCP instead of UDP because i need all the data without any loss. if we use UDP we
// have to implement those in the upper layers.
// this function will return socket descripter to the calling function.
int client_creation(char* port,char* destination_server_addr){
	int sockfd;
	struct addrinfo hints,*servinfo,*p;
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints,0,sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	

	if((rv = getaddrinfo(destination_server_addr,port,&hints,&servinfo)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(rv));	
		return -1;
	}
	
	struct sockaddr_in proxy_addr;
	memset(&proxy_addr,0,sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_port = htons(8070);
	proxy_addr.sin_addr.s_addr = INADDR_ANY;

	for(p = servinfo; p!= NULL; p=p->ai_next){
		sockfd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
		if(sockfd==-1){ 
			perror("client: socket\n"); 
			continue; 
		}
		
		int yes = 1;
		
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1){
			perror("setsockopt");
			exit(1);	
		}
		
		// it will help us to bind to the port.
		if (bind(sockfd, (SA*) &proxy_addr,sizeof(proxy_addr) ) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
		
		// connect will help us to connect to the server with the addr given in arguments.
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		} 
		break;
	}

	if(p == NULL){
		fprintf(stderr, "client: failed to connect\n");
		return -1;	
	}
	
	//printing ip address of the server.
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof(s));
	printf("proxy client: connecting to %s\n", s);
	freeaddrinfo(servinfo);
	
	return sockfd;
}

void message_handler(SSL* client_ssl,SSL* destination_ssl,int client_socket,int destination_socket){
	    // Forward the data between client and destination using SSL 
	char data_buffer[2048];
	ssize_t n;

	
	while (1) {
	
			n = SSL_read(client_ssl, data_buffer, sizeof(data_buffer));
			if (n <= 0) {
			    break;
			}
			data_buffer[n]='\0';
			SSL_write(destination_ssl, data_buffer, n);
			
			n = SSL_read(destination_ssl, data_buffer, sizeof(data_buffer));
			if (n <= 0) {
			    break;
			}
			data_buffer[n]='\0';
			SSL_write(client_ssl, data_buffer, n);
		
	}
}



//simple webserver with support to http methods such as get as well as post (basic functionalities)
void proxy_server_handler(SSL* ssl,struct pollfd* pollfds){
	int c = 0;
	char buff[1024];

	// receiving the message from the client either get request or post request
	c = SSL_read(ssl, buff, sizeof(buff));
	
	if (c <= 0) {
		ERR_print_errors_fp(stderr);
		cleanup(ssl, pollfds);
		exit(EXIT_FAILURE);
    	}

	buff[c] = '\0';

	
	// Extract the method and host from the request
    	char method[16];
    	char host[256];
    	sscanf(buff, "%s %s", method, host);
    	
    	 if (strcmp(method, "CONNECT") == 0) {
		// Handling CONNECT method
		char *port_str = strchr(host, ':');
		if (port_str != NULL) {
		    *port_str = '\0';
		    char* port = port_str + 1;
		    int destination_sockfd = client_creation(port,host);
		    
		    if(destination_sockfd == -1){
		    	perror("socket");
		        cleanup(ssl, pollfds);
		        exit(EXIT_FAILURE);
		    }
		    
		    // Notify the client that the connection is established
		    const char *response = "HTTP/1.1 200 Connection established\r\n\r\n";
		    
		    SSL_write(ssl, response, strlen(response));
		    
		    // Create an SSL connection object
		    SSL *destination_ssl = SSL_new(ctx1);
		    
		    // Attach the SSL connection object to the socket file descriptor
		    SSL_set_fd(destination_ssl, destination_sockfd);
		    // Initiate SSL handshake
		    
		    if (SSL_connect(destination_ssl) == -1) {
			ERR_print_errors_fp(stderr);
			cleanup(ssl, pollfds);
			exit(EXIT_FAILURE);
		    }
		    
		    message_handler(ssl,destination_ssl,pollfds->fd,destination_sockfd);

		    // Clean up
		    SSL_free(destination_ssl);
		    close(destination_sockfd);
		    SSL_shutdown(ssl);
		    cleanup(ssl, pollfds); 
		}
	}
}




int main(){ 
	int sockfd,connfd;
	nfds_t nfds = 0;
	struct pollfd *pollfds;
	int maxfds = 0;
	int numfds = 0;
	SSL** sslfds;
	
	//create SSL context
	create_SSL_context();
 	create_SSL_context_client();
	
	//server creation .
	sockfd = server_creation();
	
	if((pollfds = malloc(NUM_FDS*sizeof(struct pollfd))) == NULL){
		perror("malloc");
		exit(1);
	}
	if((sslfds = malloc(NUM_FDS*sizeof(SSL*))) == NULL){
		perror("malloc");
		exit(1);
	}
	maxfds = NUM_FDS;
	
	
	pollfds -> fd = sockfd;
	pollfds -> events = POLLIN;
	pollfds -> revents = 0;
	numfds = 1;

	printf("server: waiting for connections...\n");
	 
	while(1){ 
		
		nfds = numfds;
		if(poll(pollfds,nfds,-1) == -1){
			perror("poll");
			exit(1);
		}
		
		for(int fd = 0; fd < nfds;fd++){
			if((pollfds + fd)->fd <= 0)
				continue;
			
			if(((pollfds + fd)->revents & POLLIN) == POLLIN){
				if((pollfds + fd)->fd == sockfd){
					connection_accepting(sockfd,&pollfds,&maxfds,&numfds,&sslfds,ctx);
				}
				else{
					proxy_server_handler(sslfds[fd],pollfds+fd);
				}
			}
		}		
		
	} 
	SSL_CTX_free(ctx);
	close(sockfd); 
	return 0;
} 



