#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "chuongduong.net"
#define PORT 28002

// Compile:
// gcc -o test_openssl test_openssl.c -lssl -lcrypto && ./test_openssl

void print_ssl_error() {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "SSL Error: %s\n", str);
    }
}

int main() {
    int sock;
    struct sockaddr_in server;
    SSL_CTX *ctx;
    SSL *ssl;
    char hostname[256] = HOST;
    int port = PORT;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    printf("Creating SSL context...\n");
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ctx = SSL_CTX_new(TLS_client_method());
    #else
    ctx = SSL_CTX_new(SSLv23_client_method());
    #endif

    if (!ctx) {
        printf("Failed to create SSL context\n");
        print_ssl_error();
        return 1;
    }

    // Set TLS version (try different versions)
    printf("Setting TLS version restrictions...\n");
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // For OpenSSL 1.1.0+
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    #else
    // For OpenSSL 1.0.x
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    #endif

    // Disable certificate verification for testing
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Create socket
    printf("Creating socket...\n");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Could not create socket");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Resolve hostname
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        herror("gethostbyname failed");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Setup server address
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);

    // Connect to server
    printf("Connecting to %s:%d...\n", hostname, port);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connect failed");
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }
    printf("TCP connection established\n");

    // Create SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Failed to create SSL\n");
        print_ssl_error();
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    SSL_set_fd(ssl, sock);

    // Set SNI (Server Name Indication)
    printf("Setting SNI hostname: %s\n", hostname);
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_set_tlsext_host_name(ssl, hostname);
    #else
    // For OpenSSL 1.0.x
    SSL_set_tlsext_host_name(ssl, hostname);
    #endif

    // Perform SSL handshake
    printf("Starting SSL handshake...\n");
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        printf("SSL handshake failed with error code: %d\n", err);
        print_ssl_error();

        // Print more detailed error information
        if (err == SSL_ERROR_SYSCALL) {
            perror("SSL_ERROR_SYSCALL");
        }

        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("SSL handshake successful!\n");
    printf("SSL version: %s\n", SSL_get_version(ssl));
    printf("Cipher: %s\n", SSL_get_cipher(ssl));

    // Get server certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        printf("Server certificate:\n");

        char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        printf("  Subject: %s\n", subject);
        free(subject);

        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        printf("  Issuer: %s\n", issuer);
        free(issuer);

        X509_free(cert);
    } else {
        printf("No server certificate\n");
    }

    // Send WebSocket handshake request
    printf("Sending WebSocket handshake request...\n");
    char request[1024];
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n", hostname, port);

    ret = SSL_write(ssl, request, strlen(request));
    if (ret <= 0) {
        printf("Failed to send WebSocket handshake request\n");
        print_ssl_error();
    } else {
        printf("WebSocket handshake request sent (%d bytes)\n", ret);
    }

    // Read WebSocket handshake response
    printf("Reading WebSocket handshake response...\n");
    char buffer[4096];
    ret = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (ret <= 0) {
        printf("Failed to read WebSocket handshake response\n");
        print_ssl_error();
    } else {
        buffer[ret] = '\0';
        printf("Received %d bytes:\n%s\n", ret, buffer);
    }

    // Clean up
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
