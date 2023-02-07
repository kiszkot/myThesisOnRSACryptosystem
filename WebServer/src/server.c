#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 9001

#define CERT_FILE "./cert/certS.pem"
#define KEY_FILE "./cert/key.pem"

static void ShowCiphers(void) {
    char ciphers[255];
    int ret = wolfSSL_get_ciphers(&ciphers[0], (int)sizeof(ciphers));

    if (ret == SSL_SUCCESS) printf("Available ciphers:\n%s\n", &ciphers[0]);
}

int main() {
    int sockfd;
    int connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t size = sizeof(clientAddr);
    char buff[25500];
    size_t len;
    int shutdown = 0;
    WOLFSSL_CTX * ctx;
    WOLFSSL * ssl;
    char * ciphers = "AES128-SHA256:AES256-SHA256";
    int err;

    wolfSSL_Debugging_ON();
    wolfSSL_Init();

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: Failed to create socket\n");
        return -1;
    }

    if((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create CTX (context)\n");
        return -1;
    }

    if(wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) 
            != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load certificate %s\n", CERT_FILE);
        return -1;
    }

    if(wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) 
            != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load private key file %s\n", KEY_FILE);
        return -1;
    }

    if(wolfSSL_CTX_set_cipher_list(ctx, ciphers) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to set cipher list\n");
        return -1;
    }

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(DEFAULT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: Failed to bind to port\n");
        return -1;
    }

    if(listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: Failed to listen\n");
        return -1;
    }

    // Connection skeleton
    char * reply = "Here is some data from the server. Use it well";
    char * password = "password123";
    char * shutdown_message = "Shutting down...";
    ShowCiphers();
    while(!shutdown) {
        printf("Waiting for connection...\n");

        if((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
            fprintf(stderr, "ERROR: connection refused\n");
            return -1;
        }
        printf("Accepted connection from %s:%d\n", 
                inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);

        if((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            return -1;
        }
        wolfSSL_set_fd(ssl, connd);

        memset(buff, 0, sizeof(buff));
        if((err = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
            fprintf(stderr, "ERROR: failed to read or handshake error\n");
            fprintf(stderr, "ERROR: Resetting connection...\n");
            wolfSSL_write(ssl, "ERROR", sizeof("ERROR"));
            wolfSSL_free(ssl);
            close(connd);
            continue;
            //return -1;
        }
        printf("Message from client: %s\n", buff);

        if(strncmp(buff, "get", 3) == 0) {
            memset(buff, 0, sizeof(buff));
            memcpy(buff, password, strlen(password));
            len = strnlen(buff, sizeof(buff));
        } else if(strncmp(buff, "shutdown", 8) == 0) {
            printf("Shutting down\n");
            memset(buff, 0, sizeof(buff));
            memcpy(buff, shutdown_message, strlen(shutdown_message));
            len = strnlen(buff, sizeof(buff));
            shutdown = 1;
        } else {
            memset(buff, 0, sizeof(buff));
            memcpy(buff, reply, strlen(reply));
            len = strnlen(buff, sizeof(buff));
        }

        if(wolfSSL_write(ssl, buff, len) != len) {
            fprintf(stderr, "ERROR: failed to write data\n");
            return -1;
        }

        wolfSSL_free(ssl);
        close(connd);
    }
    printf("Server closed\n");

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);
    return 0;
}