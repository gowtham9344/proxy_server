#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <poll.h>

#define PROXY_PORT 8082

// SSL context for the proxy server
SSL_CTX *ssl_ctx;

void cleanup(SSL *ssl, int client_socket) {
    SSL_free(ssl);
    close(client_socket);
}

void get_data(SSL* sslc,SSL* ssld){
	char buffer[65525];
	int bytes = 0;
	memset(buffer,'\0',sizeof(buffer));
	bytes = SSL_read(sslc , buffer,sizeof(buffer));
	
	if(bytes > 0){
		SSL_write(ssld,buffer,sizeof(buffer));
		printf("%s" , buffer);
	}
}

void* runsocket(SSL* sslc,SSL* ssld){
	while(1){
		get_data(sslc,ssld);
		fflush(stdout);
		get_data(ssld,sslc);
		fflush(stdout);
	}
	return NULL;
}

void handle_client(int client_socket) {
    // SSL setup
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        perror("SSL_new");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        perror("SSL_accept");
        cleanup(ssl, client_socket);
        exit(EXIT_FAILURE);
    }

    // Receive the client's request
    char buffer[4096];
    ssize_t bytes_received = SSL_read(ssl, buffer, sizeof(buffer));

    if (bytes_received <= 0) {
        ERR_print_errors_fp(stderr);
        cleanup(ssl, client_socket);
        exit(EXIT_FAILURE);
    }

    // Extract the method and host from the request
    char method[16];
    char host[256];
    sscanf(buffer, "%s %s", method, host);

    if (strcmp(method, "CONNECT") == 0) {
        // Handling CONNECT method
        char *port_str = strchr(host, ':');
        if (port_str != NULL) {
            *port_str = '\0';
            int port = atoi(port_str + 1);

            // Create a socket to connect to the destination server
            int destination_socket = socket(AF_INET, SOCK_STREAM, 0);
            if (destination_socket == -1) {
                perror("socket");
                cleanup(ssl, client_socket);
                exit(EXIT_FAILURE);
            }

            // Set up the address structure for the destination server
            struct sockaddr_in destination_addr;
            memset(&destination_addr, 0, sizeof(destination_addr));
            destination_addr.sin_family = AF_INET;
            destination_addr.sin_port = htons(port);
            inet_pton(AF_INET, host, &destination_addr.sin_addr);

            // Connect to the destination server
            if (connect(destination_socket, (struct sockaddr *)&destination_addr, sizeof(destination_addr)) == -1) {
                perror("connect");
                cleanup(ssl, client_socket);
                close(destination_socket);
                exit(EXIT_FAILURE);
            }

            // Notify the client that the connection is established
            const char *response = "HTTP/1.1 200 Connection established\r\n\r\n";
            SSL_write(ssl, response, strlen(response));

            // Set up SSL for the destination server
            SSL *destination_ssl = SSL_new(ssl_ctx);
            if (!destination_ssl) {
                perror("SSL_new");
                cleanup(ssl, client_socket);
                close(destination_socket);
                exit(EXIT_FAILURE);
            }

            SSL_set_fd(destination_ssl, destination_socket);
            if (SSL_accept(destination_ssl) <= 0) {
                perror("SSL_accept");
                cleanup(ssl, client_socket);
                close(destination_socket);
                exit(EXIT_FAILURE);
            }

           // Forward the data between client and destination using SSL

            char data_buffer[4096];
            ssize_t n;
            

            while(1)
            	runsocket(ssl,destination_ssl);

            // Clean up
            SSL_free(destination_ssl);
            close(destination_socket);
        }
    }

    // For other methods or non-CONNECT requests, handle accordingly
    // (e.g., forward the request to the destination server)

    // This example doesn't handle other methods, so it closes the client socket
    cleanup(ssl, client_socket);
    exit(EXIT_SUCCESS);
}


void sigchld_handler(int s) {
    (void)s;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main() {
    int proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Initialize SSL
    SSL_library_init();
    SSL_load_error_strings();
    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        perror("SSL_CTX_new");
        close(proxy_socket);
        exit(EXIT_FAILURE);
    }

    // Load certificate and private key (replace with your own)
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        close(proxy_socket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) == -1) {
        perror("bind");
        close(proxy_socket);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(proxy_socket, 10) == -1) {
        perror("listen");
        close(proxy_socket);
        SSL_CTX_free(ssl_ctx);
        exit(EXIT_FAILURE);
    }

    // Set up a signal handler to reap zombie processes
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    printf("Proxy server is running on port %d\n", PROXY_PORT);

    while (1) {
        int client_socket = accept(proxy_socket, NULL, NULL);
        if (client_socket == -1) {
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            close(client_socket);
            continue;
        } else if (pid == 0) {
            // In the child process (handle the client request)
            close(proxy_socket);
            handle_client(client_socket);
        } else {
            // In the parent process (continue accepting new connections)
            close(client_socket);
        }
    }

    // Clean up
    close(proxy_socket);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

