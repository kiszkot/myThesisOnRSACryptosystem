#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 9001

#define CERT_FILE "./cert/rootCA.pem"

int main(int argc, char ** argv) {
    int sockfd;
    struct sockaddr_in servAddr;
    char buff[255];
    size_t len;
    WOLFSSL_CTX * ctx;
    WOLFSSL * ssl;

    wolfSSL_Init();

    if(argc != 2) {
        printf("Usage: %s <IPV4 address>\n", argv[0]);
        return 0;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: Failed to create socket\n");
        return -1;
    }

    if((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create CTX (context)\n");
        return -1;
    }

    if(wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load CA list %s\n", CERT_FILE);
        return -1;
    }

    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(DEFAULT_PORT);

    if(inet_pton(AF_INET, argv[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid server adress\n");
        return -1;
    }

    if(connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: Failed to connect\n");
        return -1;
    }

    if((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }
    wolfSSL_set_fd(ssl, sockfd);

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect with wolfssl\n");
        return -1;
    }

    printf("Chiper used: %s\n", wolfSSL_get_cipher(ssl));
    printf("get - get password, shutdown - shutdown\n");
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    fgets(buff, sizeof(buff), stdin);
    len = strnlen(buff, sizeof(buff));

    if(wolfSSL_write(ssl, buff, len) != len) {
        fprintf(stderr, "ERROR: failed to write to server\n");
        return -1;
    }

    memset(buff, 0, sizeof(buff));
    if(wolfSSL_read(ssl, buff, sizeof(buff)-1) == -1) {
        fprintf(stderr, "ERROR: failed to read from server\n");
    }

    printf("Message from server: %s\n", buff);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);
    return 0;
}