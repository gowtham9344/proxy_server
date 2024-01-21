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
#include <stdlib.h>
#include <ctype.h>
#include <time.h> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#define SA struct sockaddr 
#define BACKLOG 10 
#define PORT "8080"


SSL_CTX* ctx;
SSL_CTX* ctx1;
//it helps us to handle all the dead process which was created with the fork system call.
void sigchld_handler(int s){
	int saved_errno = errno;
	while(waitpid(-1,NULL,WNOHANG) > 0);
	errno = saved_errno;
}
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
void cleanup(SSL *ssl, int client_socket) {
    SSL_free(ssl);
    close(client_socket);
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
		break;
	}
	if(p == NULL){
		fprintf(stderr, "server: failed to bind\n");
		exit(1);	
	}
	
	// server will be listening with maximum simultaneos connections of BACKLOG
	if(listen(sockfd,BACKLOG) == -1){ 
		perror("listen");
		exit(1); 
	} 
	return sockfd;
}
//connection establishment with the client
//return connection descriptor to the calling function
int connection_accepting(int sockfd){
	int connfd;
	struct sockaddr_storage their_addr;
	char s[INET6_ADDRSTRLEN];
	socklen_t sin_size;
	
	sin_size = sizeof(their_addr); 
	connfd=accept(sockfd,(SA*)&their_addr,&sin_size); 
	if(connfd == -1){ 
		perror("\naccept error\n");
		return -1;
	} 
	//printing the client name
	inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof(s));
	printf("\nserver: got connection from %s\n", s);
	
	return connfd;
}
// reap all dead processes that are created as child processes
void signal_handler(){
	struct sigaction sa;
	sa.sa_handler = sigchld_handler; 
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
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
		/*if (bind(sockfd, (SA*) &proxy_addr,sizeof(proxy_addr) ) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}*/
		
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
void message_handler(SSL* ssl,SSL* destination_ssl,int client_socket,int destination_socket){
	    // Forward the data between client and destination using SSL 
	char data_buffer[2048];
	ssize_t n;
		n = SSL_read(ssl, data_buffer, sizeof(data_buffer));
		
		if (n <= 0) {
		    return;
		}
		data_buffer[n]='\0';
		SSL_write(destination_ssl, data_buffer, n);
		
		
		while ((n = SSL_read(destination_ssl, data_buffer, sizeof(data_buffer))) > 0) {
			SSL_write(ssl, data_buffer, n);
		}

}


void message_handler_http(int client_socket,int destination_socket,char data[]){
	// Forward the data between client and destination sockets
	
	ssize_t n;
	n = write(destination_socket, data, 2048);
	
	while ((n = recv(destination_socket, data, 2048, 0)) > 0) {
		send(client_socket, data, n, 0);
	}
}
//simple webserver with support to http methods such as get as well as post (basic functionalities)
void proxy_server_handler(int connfd){
	int c = 0;
	char buff[2048],data[2048];
	// receiving the message from the client either get request or post request
	c = read(connfd, buff, sizeof(buff));
	
	if (c <= 0) {
		close(connfd);
		exit(EXIT_FAILURE);
    	}
    	
	buff[c] = '\0';
	strcpy(data,buff);
	
	// Extract the method and host from the request
    	char method[16];
    	char host[256];
    	printf("%s",buff);
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
		        close(connfd);
		        exit(EXIT_FAILURE);
		    }
		    
		    
		    
		    // Notify the client that the connection is established
		    const char *response = "HTTP/1.1 200 Connection established\r\n\r\n";
		    int r = write(connfd, response, strlen(response));
		    
		    // Create an SSL connection object
		    SSL *destination_ssl = SSL_new(ctx1);
		    // Attach the SSL connection object to the socket file descriptor
		    SSL_set_fd(destination_ssl, destination_sockfd);
		    // Initiate SSL handshake
		    if (SSL_connect(destination_ssl) == -1) {
			ERR_print_errors_fp(stderr);
			close(connfd);
			exit(EXIT_FAILURE);
		    }
		    
		   // Create an SSL connection
		   SSL* ssl = SSL_new(ctx);
		   SSL_set_fd(ssl, connfd);
		   // Perform SSL handshake
		   
		   if (SSL_accept(ssl) <= 0) {
			 ERR_print_errors_fp(stderr);
			 cleanup(destination_ssl,connfd);
			 close(destination_sockfd);
			 return;
		   }
		 
		    
		    message_handler(ssl,destination_ssl,connfd,destination_sockfd);
		    // Clean up
		    SSL_free(destination_ssl);
		    close(destination_sockfd);
		    SSL_shutdown(ssl);
        	    SSL_free(ssl);
		}
	}
	else{
	
		// Extract the target server information from the GET request
	       char *host_start = strstr(buff, "Host: ") + 6;
	       char *host_end = strstr(host_start, "\r\n");
	       *host_end = '\0';  // Null-terminate to extract the host

	       // Print target server information
	       printf("Target Host: %s\n", host_start);
	       printf("Target URL: %s\n", host);
	      
	       int destination_sockfd = client_creation("80",host_start);
	       
	       if(destination_sockfd == -1){
		    	perror("socket");
		        close(connfd);
		        exit(EXIT_FAILURE);
	       }
	       
	       message_handler_http(connfd,destination_sockfd,data);
	       close(destination_sockfd);
	}
}
int main(){ 
	int sockfd,connfd;
	//create SSL context
	create_SSL_context();
 	create_SSL_context_client();
	
	//server creation .
	sockfd = server_creation();
	
	signal_handler();	
	printf("server: waiting for connections...\n");
	 
	while(1){ 
		connfd = connection_accepting(sockfd);
			
		if(connfd == -1){
			break;
		}
		// fork is used for concurrent server.
		// here fork is used to create child process to handle single client connection because if two clients needs to 
		// connect to the server simultaneously if we do the client acceptence without fork if some client got connected then until 
		// the client releases the server no one can able to connect to the server.
		// to avoid this , used fork, that creates child process to handle the connection.
  
		int fk=fork(); 
		if (fk==0){ 
			close(sockfd);
			proxy_server_handler(connfd);
			close(connfd);
			exit(0);
		} 
		close(connfd);  
	} 
	SSL_CTX_free(ctx);
	close(sockfd); 
	return 0;
} 
