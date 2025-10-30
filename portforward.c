#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "portforward_const.h"

typedef struct {
    int client_fd;
    int backend_fd;
    SSL *client_ssl;
    int is_wss;
    int websocket_handshake_done;
    int active;
    time_t last_activity;
    int epoll_fd;
    unsigned char client_buffer[BUFFER_SIZE];
    int client_buffer_len;
    unsigned char backend_buffer[BUFFER_SIZE];
    int backend_buffer_len;
} connection_t;

typedef struct {
    char *exec_path;
    char **exec_args;
    int exec_args_count;
    char *exec_binary;
    pid_t child_pid;
    char *listen_w;
    int port_w;
    char *listen_l;
    int port_l;
    int should_stop;
    connection_t *connections;
    SSL_CTX *ssl_ctx;
    char *ssl_cert_file;
    char *ssl_key_file;
    int verbose;  // Flag for verbose output
} forwarder_t;

static forwarder_t g_forwarder = {0};

// Global variable to track connection attempts from the same client

// Debug output macros
#ifdef NO_DEBUG_OUTPUT
  #define DEBUG_PRINT(fmt, ...) do {} while(0)
  #define DEBUG_PRINT_VERBOSE(fmt, ...) do { if (g_forwarder.verbose) printf(fmt, ##__VA_ARGS__); } while(0)
#else
  #define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
  #define DEBUG_PRINT_VERBOSE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#define MAX_CLIENT_HISTORY 64
typedef struct {
    struct in_addr client_addr;
    time_t last_attempt;
    int connection_count;
    int handshake_completed;
} client_history_t;

static client_history_t g_client_history[MAX_CLIENT_HISTORY];
static int g_client_history_count = 0;

// Base64 encoding for WebSocket key response
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Forward declarations
static client_history_t* find_or_add_client_history(struct in_addr addr);

static void base64_encode(const unsigned char *input, int len, char *output) {
    int i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        unsigned char a = input[i];
        unsigned char b = (i + 1 < len) ? input[i + 1] : 0;
        unsigned char c = (i + 2 < len) ? input[i + 2] : 0;

        output[j++] = base64_chars[a >> 2];
        output[j++] = base64_chars[((a & 3) << 4) | (b >> 4)];
        output[j++] = (i + 1 < len) ? base64_chars[((b & 15) << 2) | (c >> 6)] : '=';
        output[j++] = (i + 2 < len) ? base64_chars[c & 63] : '=';
    }
    output[j] = '\0';
}

static int parse_websocket_handshake(int fd, SSL *ssl, char *buffer, size_t buffer_size) {
    ssize_t n;
    int total_received = 0;
    int attempts = 0;
    const int max_attempts = 10; // Wait up to 1 second for handshake

    // Wait for HTTP request header
    // Note: Socket should be in blocking mode during handshake
    while (total_received < buffer_size - 1 && attempts < max_attempts) {
        if (ssl) {
            // For SSL, check pending first, then read
            int pending = SSL_pending(ssl);
            if (pending > 0) {
                // Read pending data from SSL buffer
                DEBUG_PRINT("SSL has %d bytes pending, reading...\n", pending);
                n = SSL_read(ssl, buffer + total_received,
                            (pending < (buffer_size - 1 - total_received)) ?
                            pending : (buffer_size - 1 - total_received));
            } else {
                // No pending data, try to read more (this will block in blocking mode)
                // For first attempt, this is OK - client should have sent request
                if (attempts == 0) {
                    DEBUG_PRINT("No SSL pending, attempting blocking read (client should have sent request)...\n");
                } else {
                    DEBUG_PRINT("No SSL pending data, attempting read (attempt %d/%d)...\n", attempts + 1, max_attempts);
                }
                n = SSL_read(ssl, buffer + total_received, buffer_size - 1 - total_received);
            }

            // Handle SSL errors properly
            if (n < 0) {
                int ssl_err = SSL_get_error(ssl, n);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    // SSL needs more data or write, wait a bit
                    DEBUG_PRINT("SSL wants %s, waiting...\n",
                           (ssl_err == SSL_ERROR_WANT_READ) ? "read" : "write");
                    usleep(100000); // 100ms
                    attempts++;
                    continue;
                } else {
                    // Real SSL error
                    fprintf(stderr, "SSL_read error: %d\n", ssl_err);
                    ERR_print_errors_fp(stderr);
                    return -1;
                }
            } else if (n == 0) {
                // SSL_read returns 0 means connection closed by peer or EOF
                int ssl_err = SSL_get_error(ssl, 0);
                DEBUG_PRINT("SSL_read returned 0, SSL_error=%d (0=ZERO_RETURN/EOF, 1=NONE)\n", ssl_err);

                // Check if we already have some data first
                if (total_received > 0) {
                    // We have partial data, try to use it
                    DEBUG_PRINT("SSL read returned 0 but we have %d bytes, attempting to parse\n", total_received);
                    break;
                }

                // Check if connection is really closed or just no data yet
                int pending_check = SSL_pending(ssl);

                // SSL_ERROR_ZERO_RETURN (6) means EOF, but check pending first
                if (pending_check > 0) {
                    DEBUG_PRINT("SSL read returned 0 but %d bytes pending, retrying...\n", pending_check);
                    attempts++;
                    if (attempts < max_attempts) {
                        continue;
                    }
                }

                // Check socket error - broken pipe means client closed connection
                int sock_err = 0;
                socklen_t err_len = sizeof(sock_err);
                int sock_fd = ssl ? SSL_get_fd(ssl) : fd;
                if (sock_fd >= 0 && getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) == 0) {
                    if (sock_err != 0) {
                        fprintf(stderr, "Socket error detected: %s (errno=%d)\n", strerror(sock_err), sock_err);
                        if (sock_err == EPIPE || sock_err == ECONNRESET) {
                            fprintf(stderr, "Client closed connection (broken pipe). This may indicate:\n");
                            fprintf(stderr, "  1. Client timeout waiting for handshake response\n");
                            fprintf(stderr, "  2. Client detected an error and closed connection\n");
                            fprintf(stderr, "  3. Network issue between client and server\n");
                        }
                        return -1;
                    }
                }

                // SSL_ERROR_ZERO_RETURN (6) means EOF/closed
                // SSL_ERROR_NONE (0 or 1) with n=0 also means closed in blocking mode
                if (ssl_err == 6) {
                    fprintf(stderr, "SSL connection closed by peer (SSL_ERROR_ZERO_RETURN)\n");
                    return -2; // Special return code for immediate close after SSL handshake
                }

                // In blocking mode, SSL_read returning 0 means EOF/closed
                // Don't retry - connection is already closed
                fprintf(stderr, "SSL_read returned 0 in blocking mode - connection closed by peer\n");
                fprintf(stderr, "SSL_error=%d, pending=%d. Client likely closed connection immediately after SSL handshake.\n",
                        ssl_err, pending_check);
                return -2; // Special return code for immediate close after SSL handshake
            } else {
                DEBUG_PRINT("SSL_read successful, received %d bytes (total: %d)\n", n, total_received + n);
            }
        } else {
            n = recv(fd, buffer + total_received, buffer_size - 1 - total_received, 0);

            if (n < 0) {
                // In blocking mode, EAGAIN shouldn't occur, but handle it anyway
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(100000); // 100ms
                    attempts++;
                    continue;
                }
                // Real error
                fprintf(stderr, "recv error: %s\n", strerror(errno));
                return -1;
            } else if (n == 0) {
                // Connection closed
                if (total_received > 0) {
                    // We have partial data, try to use it
                    break;
                }
                fprintf(stderr, "Connection closed during handshake\n");
                return -1;
            }
        }

        total_received += n;
        buffer[total_received] = '\0';

        // Check if we have complete HTTP header (ends with \r\n\r\n)
        if (strstr(buffer, "\r\n\r\n") != NULL || strstr(buffer, "\n\n") != NULL) {
            break;
        }

        // If we received some data but header not complete, wait a bit more
        if (total_received > 0 && attempts < max_attempts) {
            usleep(50000); // 50ms
            attempts++;
        }
    }

    if (total_received == 0) {
        // No data received at all
        fprintf(stderr, "No data received for WebSocket handshake after %d attempts\n", max_attempts);
        return -1;
    }

    buffer[total_received] = '\0';

    // Check if it's a WebSocket upgrade request
    if (strstr(buffer, "Upgrade: websocket") == NULL &&
        strstr(buffer, "upgrade: websocket") == NULL &&
        strstr(buffer, "Upgrade: WebSocket") == NULL &&
        strstr(buffer, "upgrade: WebSocket") == NULL) {
        // Not a WebSocket request - could be other HTTP request or raw TCP
        fprintf(stderr, "Received non-WebSocket request, closing connection\n");
        fprintf(stderr, "Request headers (first 200 bytes):\n%.*s\n",
                (int)(total_received < 200 ? total_received : 200), buffer);
        return -1;
    }

    // Log the full WebSocket request for debugging
    DEBUG_PRINT("Received WebSocket handshake request (first 200 bytes):\n%.*s\n",
           (int)(total_received < 200 ? total_received : 200), buffer);

    // Find Sec-WebSocket-Key - using a more robust approach similar to example code
    char *key_line = NULL;
    char *saveptr = NULL;
    char *s = NULL;
    char *buffer_copy = strdup(buffer);

    if (!buffer_copy) {
        fprintf(stderr, "Memory allocation failed for WebSocket handshake\n");
        return -1;
    }

    // Split by lines and find the key
    for (s = strtok_r(buffer_copy, "\r\n", &saveptr); s != NULL;
         s = strtok_r(NULL, "\r\n", &saveptr)) {
        if (strncasecmp(s, "Sec-WebSocket-Key:", 18) == 0) {
            key_line = s;
            break;
        }
    }

    if (!key_line) {
        fprintf(stderr, "WebSocket handshake: Missing Sec-WebSocket-Key header\n");
        fprintf(stderr, "Received data (first 200 chars): %.200s\n", buffer);
        free(buffer_copy);
        return -1;
    }

    // Extract the key value
    saveptr = NULL;
    s = strtok_r(key_line, " ", &saveptr);  // Skip "Sec-WebSocket-Key:"
    s = strtok_r(NULL, " ", &saveptr);      // This is the key value

    if (!s) {
        fprintf(stderr, "WebSocket handshake: Invalid Sec-WebSocket-Key format\n");
        free(buffer_copy);
        return -1;
    }

    // Copy the key to a safe buffer
    char key_start[256];
    strncpy(key_start, s, sizeof(key_start)-1);
    key_start[sizeof(key_start)-1] = '\0';

    free(buffer_copy);  // Free the copy now that we're done with it

    // WebSocket magic string
    const char *ws_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[512];
    snprintf(combined, sizeof(combined), "%s%s", key_start, ws_magic);

    // Calculate SHA1 and base64
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)combined, strlen(combined), sha1_hash);

    char accept_key[64];
    base64_encode(sha1_hash, SHA_DIGEST_LENGTH, accept_key);

    // Send handshake response
    // Note: Order of headers matters for some browsers
    // Match the order from the working implementation
    char response[512];
    snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n\r\n",
        accept_key);

    // Log the handshake response for debugging
    DEBUG_PRINT("Sending WebSocket handshake response:\n%s\n", response);

    if (ssl) {
        int sent = SSL_write(ssl, response, strlen(response));
        if (sent <= 0) {
            int ssl_err = SSL_get_error(ssl, sent);
            fprintf(stderr, "SSL_write error in handshake response: %d\n", ssl_err);
            return -1;
        }
    } else {
        ssize_t sent = send(fd, response, strlen(response), 0);
        if (sent < 0) {
            fprintf(stderr, "send error in handshake response: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

static void mask_payload(unsigned char *data, int len, unsigned char *mask) {
    for (int i = 0; i < len; i++) {
        data[i] ^= mask[i % 4];
    }
}

static int read_websocket_frame(int fd, SSL *ssl, unsigned char *buffer, int buffer_size, int *is_control, int *opcode) {
    unsigned char header[14];
    int header_len = 2;
    int n;
    int ssl_errno = 0;

    // Read the first 2 bytes of the frame header
    if (ssl) {
        n = SSL_read(ssl, header, 2);
        if (n <= 0) {
            ssl_errno = SSL_get_error(ssl, n);
            if (ssl_errno == SSL_ERROR_WANT_READ || ssl_errno == SSL_ERROR_WANT_WRITE) {
                return -EAGAIN;
            }
        }
    } else {
        // For non-blocking socket, read without MSG_WAITALL
        n = recv(fd, header, 2, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -EAGAIN;
            }
        }
    }

    if (n != 2) {
        if (n < 0) {
            if (ssl) {
                int ssl_err = ssl_errno ? ssl_errno : SSL_get_error(ssl, n);
                // Only log real errors, not WANT_READ/WRITE
                if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
                    fprintf(stderr, "SSL_read error in WebSocket frame header: %d\n", ssl_err);
                    ERR_print_errors_fp(stderr);
                }
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "recv error in WebSocket frame header: %s\n", strerror(errno));
                }
            }
            return -EAGAIN;
        } else if (n == 0) {
            fprintf(stderr, "Connection closed during WebSocket frame header read\n");
            return -1;
        } else {
            // Incomplete read (got 1 byte), need to wait for more
            DEBUG_PRINT_VERBOSE("Incomplete WebSocket frame header: got %d bytes, expected 2, waiting...\n", n);
            return -EAGAIN;
        }
    }

    // Parse the first 2 bytes
    int fin = (header[0] & 0x80) != 0;
    *opcode = header[0] & 0x0F;
    int masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    // Check if this is a control frame
    *is_control = (*opcode >= 8);

    // Validate control frames according to RFC6455
    if (*is_control) {
        // Control frames must have the FIN bit set
        if (!fin) {
            fprintf(stderr, "Control frame without FIN bit set\n");
            return -1;
        }

        // Control frames must have payload <= 125 bytes
        if (payload_len > 125) {
            fprintf(stderr, "Control frame with payload length > 125 bytes\n");
            return -1;
        }
    }

    // Handle extended payload length (16-bit)
    if (payload_len == 126) {
        if (ssl) {
            n = SSL_read(ssl, header + 2, 2);
            if (n <= 0) {
                ssl_errno = SSL_get_error(ssl, n);
                if (ssl_errno == SSL_ERROR_WANT_READ || ssl_errno == SSL_ERROR_WANT_WRITE) {
                    return -EAGAIN;
                }
            }
        } else {
            n = recv(fd, header + 2, 2, 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return -EAGAIN;
            }
        }
        if (n != 2) {
            DEBUG_PRINT_VERBOSE("Failed to read 16-bit payload length, got %d bytes\n", n);
            return -EAGAIN;
        }
        payload_len = (header[2] << 8) | header[3];
        header_len = 4;
    }
    // Handle extended payload length (64-bit)
    else if (payload_len == 127) {
        if (ssl) {
            n = SSL_read(ssl, header + 2, 8);
            if (n <= 0) {
                ssl_errno = SSL_get_error(ssl, n);
                if (ssl_errno == SSL_ERROR_WANT_READ || ssl_errno == SSL_ERROR_WANT_WRITE) {
                    return -EAGAIN;
                }
            }
        } else {
            n = recv(fd, header + 2, 8, 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return -EAGAIN;
            }
        }
        if (n != 8) {
            DEBUG_PRINT_VERBOSE("Failed to read 64-bit payload length, got %d bytes\n", n);
            return -EAGAIN;
        }

        // For 64-bit, we need to be careful about endianness
        // We'll use the lower 32 bits for compatibility with buffer size limits
        payload_len = ((uint64_t)header[2] << 56) |
                      ((uint64_t)header[3] << 48) |
                      ((uint64_t)header[4] << 40) |
                      ((uint64_t)header[5] << 32) |
                      ((uint64_t)header[6] << 24) |
                      ((uint64_t)header[7] << 16) |
                      ((uint64_t)header[8] << 8) |
                      ((uint64_t)header[9]);

        header_len = 10;
    }

    // Sanity check on payload length
    if (payload_len > buffer_size) {
        fprintf(stderr, "Payload length %lu exceeds buffer size %d\n",
                (unsigned long)payload_len, buffer_size);
        payload_len = buffer_size;
    }

    // Debug output - only when verbose mode is enabled
    DEBUG_PRINT_VERBOSE("WebSocket frame: opcode=0x%x, fin=%d, masked=%d, payload_len=%lu\n",
           *opcode, fin, masked, (unsigned long)payload_len);

    // Read masking key if present
    unsigned char mask[4] = {0};
    if (masked) {
        if (ssl) {
            n = SSL_read(ssl, mask, 4);
            if (n <= 0) {
                ssl_errno = SSL_get_error(ssl, n);
                if (ssl_errno == SSL_ERROR_WANT_READ || ssl_errno == SSL_ERROR_WANT_WRITE) {
                    return -EAGAIN;
                }
            }
        } else {
            n = recv(fd, mask, 4, 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return -EAGAIN;
            }
        }
        if (n != 4) {
            DEBUG_PRINT_VERBOSE("Failed to read masking key, got %d bytes\n", n);
            return -EAGAIN;
        }
        DEBUG_PRINT_VERBOSE("Mask: %02x %02x %02x %02x\n", mask[0], mask[1], mask[2], mask[3]);
    }

    // Read payload data
    if (payload_len > 0) {
        if (ssl) {
            n = SSL_read(ssl, buffer, payload_len);
            if (n <= 0) {
                ssl_errno = SSL_get_error(ssl, n);
                if (ssl_errno == SSL_ERROR_WANT_READ || ssl_errno == SSL_ERROR_WANT_WRITE) {
                    return -EAGAIN;
                }
                fprintf(stderr, "Failed to read SSL payload data: SSL error %d\n", ssl_errno);
                return -1;
            }
        } else {
            n = recv(fd, buffer, payload_len, 0);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return -EAGAIN;
                }
                fprintf(stderr, "Failed to read payload data: %s\n", strerror(errno));
                return -1;
            }
        }

        if (n == 0) {
            fprintf(stderr, "Connection closed while reading payload\n");
            return -1;
        } else if ((uint64_t)n != payload_len) {
            // For non-blocking, we might not get all data at once
            DEBUG_PRINT_VERBOSE("Partial payload: got %d bytes, expected %lu, will retry\n",
                    n, (unsigned long)payload_len);
            return -EAGAIN;
        }

        // Apply mask if present
        if (masked && n > 0) {
            mask_payload(buffer, n, mask);
        }
    } else {
        n = 0;  // Empty payload
    }

    // Handle specific frame types
    switch (*opcode) {
        case 0x8:  // Close frame
            DEBUG_PRINT_VERBOSE("Received close frame\n");
            break;
        case 0x9:  // Ping frame
            DEBUG_PRINT_VERBOSE("Received ping frame\n");
            break;
        case 0xA:  // Pong frame
            DEBUG_PRINT_VERBOSE("Received pong frame\n");
            break;
        case 0x1:  // Text frame
            DEBUG_PRINT_VERBOSE("Received text frame\n");
            break;
        case 0x2:  // Binary frame
            DEBUG_PRINT_VERBOSE("Received binary frame\n");
            break;
        case 0x0:  // Continuation frame
            DEBUG_PRINT_VERBOSE("Received continuation frame\n");
            break;
        default:
            DEBUG_PRINT_VERBOSE("Received unknown frame type: %d\n", *opcode);
    }

    return n;
}

static int write_websocket_frame(int fd, SSL *ssl, const unsigned char *data, int len, int opcode) {
    unsigned char header[14];
    int header_len = 2;
    int total_sent = 0;
    int ret = 0;
    int ssl_errno = 0;
    // Set the FIN bit and opcode
    header[0] = 0x80 | (opcode & 0x0F); // FIN=1, opcode=specified

    // Validate opcode
    if (opcode < 0 || opcode > 0xF) {
        fprintf(stderr, "Invalid WebSocket frame opcode: 0x%x\n", opcode);
        return -1;
    }

    // Determine payload length encoding
    if (len <= 125) {
        header[1] = len;
        header_len = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        header_len = 4;
    } else {
        header[1] = 127;
        header[2] = 0; // Most significant byte (MSB)
        header[3] = 0;
        header[4] = 0;
        header[5] = 0;
        header[6] = (len >> 24) & 0xFF;
        header[7] = (len >> 16) & 0xFF;
        header[8] = (len >> 8) & 0xFF;
        header[9] = len & 0xFF;
        header_len = 10;
    }

    // No masking for server-to-client messages (RFC6455 section 5.1)
    // The mask bit is already 0 from our initialization

    DEBUG_PRINT_VERBOSE("Writing WebSocket frame: opcode=0x%x, len=%d, header_len=%d\n", opcode, len, header_len);

    // Send the header
    if (ssl) {
        ret = SSL_write(ssl, header, header_len);
        if (ret != header_len) {
            int ssl_err = SSL_get_error(ssl, ret);
            if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                return -EAGAIN;
            }
            fprintf(stderr, "SSL_write error sending WebSocket frame header: %d\n", ssl_err);
            ERR_print_errors_fp(stderr);
            return -1;
        }

        // Send the payload data if any
        if (len > 0) {
            ret = SSL_write(ssl, data, len);
            if (ret != len) {
                int ssl_err = SSL_get_error(ssl, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    return -EAGAIN;
                }
                fprintf(stderr, "SSL_write error sending WebSocket frame data: %d\n", ssl_err);
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }
    } else {
        // Send header
        total_sent = 0;
        while (total_sent < header_len) {
            ret = send(fd, header + total_sent, header_len - total_sent, MSG_NOSIGNAL);
            if (ret <= 0) {
                fprintf(stderr, "send error sending WebSocket frame header: %s\n", strerror(errno));
                return -1;
            }
            total_sent += ret;
        }

        // Send payload
        if (len > 0) {
            total_sent = 0;
            while (total_sent < len) {
                ret = send(fd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
                if (ret <= 0) {
                    fprintf(stderr, "send error sending WebSocket frame data: %s\n", strerror(errno));
                    return -1;
                }
                total_sent += ret;
            }
        }
    }

    // Log frame type sent
    switch (opcode) {
        case 0x8:  // Close frame
            DEBUG_PRINT_VERBOSE("Sent close frame\n");
            break;
        case 0x9:  // Ping frame
            DEBUG_PRINT_VERBOSE("Sent ping frame\n");
            break;
        case 0xA:  // Pong frame
            DEBUG_PRINT_VERBOSE("Sent pong frame\n");
            break;
        case 0x1:  // Text frame
            DEBUG_PRINT_VERBOSE("Sent text frame\n");
            break;
        case 0x2:  // Binary frame
            DEBUG_PRINT_VERBOSE("Sent binary frame\n");
            break;
        default:
            DEBUG_PRINT_VERBOSE("Sent frame with opcode: 0x%x\n", opcode);
    }

    return 0;
}

static void close_connection(connection_t *conn) {
    if (!conn->active) return;

    conn->active = 0;

    // Remove from epoll if epoll_fd is set
    if (conn->epoll_fd >= 0) {
        if (conn->client_fd >= 0) {
            epoll_ctl(conn->epoll_fd, EPOLL_CTL_DEL, conn->client_fd, NULL);
        }
        if (conn->backend_fd >= 0) {
            epoll_ctl(conn->epoll_fd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
        }
    }

    if (conn->client_ssl) {
        SSL_shutdown(conn->client_ssl);
        SSL_free(conn->client_ssl);
        conn->client_ssl = NULL;
    }
    if (conn->client_fd >= 0) {
        close(conn->client_fd);
        conn->client_fd = -1;
    }
    if (conn->backend_fd >= 0) {
        close(conn->backend_fd);
        conn->backend_fd = -1;
    }
}

static int connect_backend(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    // Set keepalive
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    int keepidle = 60;
    int keepintvl = 10;
    int keepcnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    // Set TCP_NODELAY
    opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

static connection_t* find_or_create_connection(int client_fd) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!g_forwarder.connections[i].active) {
            connection_t *conn = &g_forwarder.connections[i];
            memset(conn, 0, sizeof(connection_t));
            conn->client_fd = client_fd;
            conn->active = 1;
            conn->last_activity = time(NULL);
            conn->backend_fd = -1;
            return conn;
        }
    }
    return NULL;
}

static void handle_connection_ready(connection_t *conn, int is_wss, const char *backend_host, int backend_port, int epoll_fd) {
    conn->epoll_fd = epoll_fd;
    if (conn->epoll_fd < 0) conn->epoll_fd = -1; // Ensure valid if needed

    // Set keepalive first (before non-blocking for SSL handshake)
    int opt = 1;
    setsockopt(conn->client_fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));

    // Get client IP address for tracking
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    if (getpeername(conn->client_fd, (struct sockaddr*)&client_addr, &addr_len) == 0) {
        client_history_t* client_history = find_or_add_client_history(client_addr.sin_addr);
        if (client_history) {
            DEBUG_PRINT("Client connection #%d from %s\n",
                   client_history->connection_count,
                   inet_ntoa(client_addr.sin_addr));

            // If this is a reconnection attempt within 5 seconds and we've seen multiple attempts
            if (client_history->connection_count > 1 &&
                time(NULL) - client_history->last_attempt < 5) {
                DEBUG_PRINT("This appears to be a reconnection attempt\n");
            }
        }
    }

    conn->is_wss = is_wss;

    // SSL handshake for WSS (keep blocking during SSL handshake and WebSocket handshake)
    if (is_wss) {
        if (!g_forwarder.ssl_ctx) {
            fprintf(stderr, "WSS connection rejected: No SSL context available\n");
            close_connection(conn);
            return;
        }
        conn->client_ssl = SSL_new(g_forwarder.ssl_ctx);
        if (conn->client_ssl) {
            // Ensure socket is in blocking mode before SSL handshake
            int flags_before = fcntl(conn->client_fd, F_GETFL, 0);
            if (flags_before & O_NONBLOCK) {
                fcntl(conn->client_fd, F_SETFL, flags_before & ~O_NONBLOCK);
                DEBUG_PRINT("Set socket to blocking mode before SSL handshake\n");
            }

            SSL_set_fd(conn->client_ssl, conn->client_fd);

            // Configure SSL to auto-retry on renegotiation (for OpenSSL 1.0.1 compatibility)
            SSL_set_mode(conn->client_ssl, SSL_MODE_AUTO_RETRY);

            // SSL_accept can block, that's OK for initial handshake
            // Keep socket blocking during SSL handshake
            DEBUG_PRINT("Starting SSL handshake...\n");
            int ssl_accept_result = SSL_accept(conn->client_ssl);
            if (ssl_accept_result <= 0) {
                int ssl_err = SSL_get_error(conn->client_ssl, ssl_accept_result);
                fprintf(stderr, "SSL handshake failed with error: %d\n", ssl_err);

                // Print detailed error information
                unsigned long err;
                while ((err = ERR_get_error()) != 0) {
                    char *str = ERR_error_string(err, NULL);
                    fprintf(stderr, "SSL Error: %s\n", str);
                }

                // Check if this is a certificate verification error
                if (ssl_err == SSL_ERROR_SSL) {
                    fprintf(stderr, "This may be a certificate verification error.\n");
                    fprintf(stderr, "Make sure the client trusts our certificate or try with SSL_VERIFY_NONE.\n");
                }

                SSL_free(conn->client_ssl);
                conn->client_ssl = NULL;
                close_connection(conn);
                return;
            }

            DEBUG_PRINT("SSL handshake successful!\n");

            // Get peer certificate info
            X509 *cert = SSL_get_peer_certificate(conn->client_ssl);
            if (cert) {
                DEBUG_PRINT("Client provided certificate\n");
                X509_free(cert);
            } else {
                DEBUG_PRINT("Client did not provide certificate\n");
            }

            // Get SSL protocol and cipher info
            DEBUG_PRINT("SSL handshake successful for WSS connection\n");
            DEBUG_PRINT("SSL version: %s, Cipher: %s\n",
                   SSL_get_version(conn->client_ssl),
                   SSL_CIPHER_get_name(SSL_get_current_cipher(conn->client_ssl)));

            // Get server certificate info
            X509 *server_cert = SSL_get_certificate(conn->client_ssl);
            if (server_cert) {
                char subject_name[256];
                X509_NAME_oneline(X509_get_subject_name(server_cert), subject_name, sizeof(subject_name));
                DEBUG_PRINT("Server certificate subject: %s\n", subject_name);
            }

            // Verify socket is still in blocking mode after SSL_accept
            int flags_after = fcntl(conn->client_fd, F_GETFL, 0);
            if (flags_after & O_NONBLOCK) {
                fprintf(stderr, "WARNING: Socket became non-blocking after SSL_accept, fixing...\n");
                fcntl(conn->client_fd, F_SETFL, flags_after & ~O_NONBLOCK);
            }

            // Check if there's already data pending in SSL buffer after handshake
            // Client usually sends WebSocket request immediately after SSL handshake
            int pending = SSL_pending(conn->client_ssl);
            if (pending > 0) {
                DEBUG_PRINT("SSL has %d bytes pending after handshake (ready to read)\n", pending);
            } else {
                DEBUG_PRINT("No SSL pending data immediately after handshake (will block on read)\n");
            }

            // Read IMMEDIATELY - no delay! Client sends request right after SSL handshake
            // Any delay will cause client timeout and "broken pipe"
        }
    } else {
        // For WS (plain), check if client is trying to send SSL data
        // This happens when browser uses wss:// but connects to WS port
        char peek_buf[1];
        int peek_result = recv(conn->client_fd, peek_buf, 1, MSG_PEEK);
        if (peek_result > 0 && (peek_buf[0] == 0x16 || peek_buf[0] == 0x80)) {
            // Looks like SSL handshake (0x16 = SSL handshake, 0x80 = SSLv2)
            fprintf(stderr, "ERROR: Client sent SSL data to WS (plain) port.\n");
            fprintf(stderr, "Client is using wss:// but connecting to WS port.\n");
            fprintf(stderr, "Solution: Use ws:// for this port, or wss:// with port 20000+offset\n");
            close_connection(conn);
            return;
        }
    }

    // WebSocket handshake - keep blocking mode for reliable handshake
    // Don't set non-blocking yet - we'll do it after handshake completes
    // CRITICAL: Read immediately after SSL handshake - client sends request right away
    char buffer[BUFFER_SIZE];
    DEBUG_PRINT("Starting WebSocket handshake (immediate read, no delay)...\n");

    int handshake_result = parse_websocket_handshake(conn->client_fd, conn->client_ssl, buffer, BUFFER_SIZE);

    if (handshake_result == -2) {
        // Special case: client closed connection immediately after SSL handshake
        // This is likely a browser doing a connection test or pre-flight check
        fprintf(stderr, "Client closed connection immediately after SSL handshake\n");
        fprintf(stderr, "This is normal behavior for some browsers that do TLS connection tests\n");
        fprintf(stderr, "The browser will likely reconnect immediately for the actual WebSocket connection\n");

        // Get client IP address
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        if (getpeername(conn->client_fd, (struct sockaddr*)&client_addr, &addr_len) == 0) {
            client_history_t* client_history = find_or_add_client_history(client_addr.sin_addr);
            if (client_history && client_history->connection_count > 1) {
                // This is a reconnection attempt, send a fake WebSocket handshake response
                DEBUG_PRINT("Sending WebSocket upgrade response for reconnection\n");

                const char* response =
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                    "Connection: Upgrade\r\n"
                    "Upgrade: websocket\r\n\r\n";

                if (conn->client_ssl) {
                    SSL_write(conn->client_ssl, response, strlen(response));
                } else {
                    send(conn->client_fd, response, strlen(response), 0);
                }

                // Mark this client as having completed a handshake
                client_history->handshake_completed = 1;
            }
        }

        close_connection(conn);
        return;
    } else if (handshake_result < 0) {
        fprintf(stderr, "WebSocket handshake failed\n");
        // Send error response before closing for HTTP requests
        if (conn->client_ssl) {
            // Try to send error, but don't fail if SSL is already closed
            SSL_write(conn->client_ssl, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", 52);
        } else {
            send(conn->client_fd, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", 52, 0);
        }
        close_connection(conn);
        return;
    }
    DEBUG_PRINT("WebSocket handshake successful\n");

    // Now set non-blocking after handshake is complete
    int flags = fcntl(conn->client_fd, F_GETFL, 0);
    fcntl(conn->client_fd, F_SETFL, flags | O_NONBLOCK);

    conn->websocket_handshake_done = 1;

    // Connect to backend TCP
    conn->backend_fd = connect_backend(backend_host, backend_port);
    if (conn->backend_fd < 0) {
        close_connection(conn);
        return;
    }

    // Add backend to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = conn->backend_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->backend_fd, &ev);
}

static void forward_client_to_backend(connection_t *conn) {
    if (!conn->websocket_handshake_done) return;

    // With epoll ET mode, read all available frames in one go
    while (1) {
        int is_control = 0;
        int opcode = 0;
        int n = read_websocket_frame(conn->client_fd, conn->client_ssl,
                                     conn->client_buffer, BUFFER_SIZE,
                                     &is_control, &opcode);

        if (n == -EAGAIN || n == -EWOULDBLOCK) {
            // No more data available, wait for next epoll event
            break;
        }

        if (n <= 0) {
            if (n < 0 && n != -EAGAIN && n != -EWOULDBLOCK && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                close_connection(conn);
            }
            break;
        }

        if (is_control) {
            // Handle ping/pong
            if (opcode == 0x9) { // Ping
                write_websocket_frame(conn->client_fd, conn->client_ssl,
                                     conn->client_buffer, n, 0xA); // Pong
            } else if (opcode == 0x8) { // Close
                close_connection(conn);
            }
            // Continue to check for more frames
            continue;
        }

        conn->last_activity = time(NULL);

        // Forward to backend TCP
        ssize_t sent = send(conn->backend_fd, conn->client_buffer, n, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                DEBUG_PRINT("send to backend failed: %s\n", strerror(errno));
                close_connection(conn);
            }
            break;
        }

        DEBUG_PRINT_VERBOSE("Forwarded %d bytes to backend\n", n);
    }
}

static void forward_backend_to_client(connection_t *conn) {
    if (!conn->websocket_handshake_done) return;

    // With epoll ET mode, read all available data from backend
    while (1) {
        ssize_t n = recv(conn->backend_fd, conn->backend_buffer, BUFFER_SIZE, 0);
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                DEBUG_PRINT("recv from backend failed: %s\n", strerror(errno));
                close_connection(conn);
            } else if (n == 0) {
                DEBUG_PRINT("Backend closed connection\n");
                close_connection(conn);
            }
            break;
        }

        conn->last_activity = time(NULL);
        DEBUG_PRINT_VERBOSE("Received %zd bytes from backend\n", n);

        // Forward to WebSocket client
        int ret = write_websocket_frame(conn->client_fd, conn->client_ssl,
                                       conn->backend_buffer, n, 0x2);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                // Client socket buffer full, will retry on next EPOLLOUT
                // For now, just log and continue
                DEBUG_PRINT_VERBOSE("Client socket buffer full, will retry\n");
                break;
            }
            DEBUG_PRINT("write_websocket_frame failed: %d\n", ret);
            close_connection(conn);
            break;
        }

        DEBUG_PRINT_VERBOSE("Forwarded %zd bytes to client\n", n);
    }
}

static int create_listener(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set socket options for performance
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host && strlen(host) > 0) {
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid IP address: %s\n", host);
            close(fd);
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind to %s:%d: %s\n",
                host ? host : "*", port, strerror(errno));
        // Try binding to INADDR_ANY as fallback if specific IP fails
        if (host && strlen(host) > 0) {
            addr.sin_addr.s_addr = INADDR_ANY;
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) >= 0) {
                fprintf(stderr, "Falling back to INADDR_ANY for port %d\n", port);
            } else {
                fprintf(stderr, "Also failed to bind to *:%d: %s\n", port, strerror(errno));
                close(fd);
                return -1;
            }
        } else {
            close(fd);
            return -1;
        }
    }

    if (listen(fd, 512) < 0) {
        fprintf(stderr, "Failed to listen on port %d: %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

// Find or add client to history
static client_history_t* find_or_add_client_history(struct in_addr addr) {
    time_t now = time(NULL);

    // Clean up old entries (older than 30 seconds)
    for (int i = 0; i < g_client_history_count; i++) {
        if (now - g_client_history[i].last_attempt > 30) {
            // Remove this entry by moving the last entry to this position
            if (i < g_client_history_count - 1) {
                g_client_history[i] = g_client_history[g_client_history_count - 1];
                i--; // Reprocess this index
            }
            g_client_history_count--;
        }
    }

    // Find existing client
    for (int i = 0; i < g_client_history_count; i++) {
        if (memcmp(&g_client_history[i].client_addr, &addr, sizeof(struct in_addr)) == 0) {
            g_client_history[i].last_attempt = now;
            g_client_history[i].connection_count++;
            return &g_client_history[i];
        }
    }

    // Add new client if there's space
    if (g_client_history_count < MAX_CLIENT_HISTORY) {
        client_history_t* client = &g_client_history[g_client_history_count++];
        memcpy(&client->client_addr, &addr, sizeof(struct in_addr));
        client->last_attempt = now;
        client->connection_count = 1;
        client->handshake_completed = 0;
        return client;
    }

    // No space, return NULL
    return NULL;
}

static void start_port_forwarder(const char *listen_host, int ws_port, int wss_port,
                                 const char *backend_host, int backend_port) {
    int ws_listener = -1, wss_listener = -1;

    // Initialize client history
    memset(g_client_history, 0, sizeof(g_client_history));

    if (ws_port > 0) {
        ws_listener = create_listener(listen_host, ws_port);
        if (ws_listener < 0) {
            fprintf(stderr, "Failed to create WS listener on port %d\n", ws_port);
            fprintf(stderr, "Check if: 1) Port is already in use, 2) IP address exists on interface, 3) You have permission to bind\n");
        } else {
            fprintf(stderr, "WebSocket listener started on %s:%d -> %s:%d\n",
                   listen_host ? listen_host : "*", ws_port, backend_host, backend_port);
        }
    }

    if (wss_port > 0 && g_forwarder.ssl_ctx) {
        wss_listener = create_listener(listen_host, wss_port);
        if (wss_listener < 0) {
            fprintf(stderr, "Failed to create WSS listener on port %d\n", wss_port);
            fprintf(stderr, "Check if: 1) Port is already in use, 2) IP address exists on interface, 3) You have permission to bind\n");
        } else {
            fprintf(stderr, "WebSocket Secure listener started on %s:%d -> %s:%d\n",
                   listen_host ? listen_host : "*", wss_port, backend_host, backend_port);
        }
    }

    // Warn if both listeners failed
    if (ws_listener < 0 && (wss_listener < 0 || !g_forwarder.ssl_ctx)) {
        fprintf(stderr, "ERROR: Could not create any listeners. Exiting forwarder.\n");
        return;
    }

    // If we have no valid listeners, exit
    if (ws_listener < 0 && wss_listener < 0) {
        fprintf(stderr, "ERROR: No valid listeners available. Exiting forwarder.\n");
        return;
    }

    fprintf(stderr, "Forwarder running, waiting for connections...\n");

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        return;
    }

    struct epoll_event ev, events[MAX_EVENTS];

    if (ws_listener >= 0) {
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = ws_listener;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ws_listener, &ev);
    }

    if (wss_listener >= 0) {
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = wss_listener;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, wss_listener, &ev);
    }

    while (!g_forwarder.should_stop) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < nfds; i++) {
            // Check if this is a listener socket (stored as fd) or connection (stored as ptr)
            int is_listener = 0;
            int listener_fd = -1;

            // For listeners, we store fd; for connections, we store ptr
            // Check if this matches a listener
            if (events[i].data.fd == ws_listener || events[i].data.fd == wss_listener) {
                is_listener = 1;
                listener_fd = events[i].data.fd;
            }

            if (is_listener) {
                // New connection from listener
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t addr_len = sizeof(client_addr);
                    int client_fd = accept(listener_fd, (struct sockaddr*)&client_addr, &addr_len);

                    if (client_fd < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            perror("accept");
                        }
                        break;
                    }

                    connection_t *conn = find_or_create_connection(client_fd);
                    if (!conn) {
                        close(client_fd);
                        continue;
                    }

                    // CRITICAL: Set socket to blocking mode IMMEDIATELY after accept
                    // Listeners are non-blocking, so accepted sockets inherit that
                    // But we need blocking for SSL and WebSocket handshakes
                    int flags_accept = fcntl(client_fd, F_GETFL, 0);
                    if (flags_accept & O_NONBLOCK) {
                        fcntl(client_fd, F_SETFL, flags_accept & ~O_NONBLOCK);
                        DEBUG_PRINT("Set accepted socket to blocking mode for handshake\n");
                    }

                    // Get client IP address
                    struct sockaddr_in client_addr_new;
                    socklen_t addr_len_new = sizeof(client_addr_new);
                    if (getpeername(client_fd, (struct sockaddr*)&client_addr_new, &addr_len_new) == 0) {
                        client_history_t* client_history = find_or_add_client_history(client_addr_new.sin_addr);
                        if (client_history && client_history->connection_count > 1 &&
                            time(NULL) - client_history->last_attempt < 5) {
                            DEBUG_PRINT("Reconnection from %s (connection #%d)\n",
                                   inet_ntoa(client_addr_new.sin_addr),
                                   client_history->connection_count);
                        }
                    }

                    // Process connection - do handshake immediately
                    DEBUG_PRINT("New connection from client, listener_fd=%d, is_wss=%d\n",
                           listener_fd, (listener_fd == wss_listener));
                    handle_connection_ready(conn, (listener_fd == wss_listener),
                                          backend_host, backend_port, epoll_fd);

                    if (conn->active && conn->websocket_handshake_done) {
                        // Only add to epoll if handshake succeeded
                        ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
                        ev.data.fd = conn->client_fd;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->client_fd, &ev);
                        DEBUG_PRINT("Connection added to epoll, ready for data forwarding\n");
                    } else {
                        DEBUG_PRINT("Connection closed or handshake failed\n");
                    }
                }
            } else {
                // Data from existing connection
                connection_t *conn = NULL;
                int event_fd = events[i].data.fd;

                // Find connection by fd (could be client_fd or backend_fd)
                for (int j = 0; j < MAX_CONNECTIONS; j++) {
                    if (g_forwarder.connections[j].active &&
                        (g_forwarder.connections[j].client_fd == event_fd ||
                         g_forwarder.connections[j].backend_fd == event_fd)) {
                        conn = &g_forwarder.connections[j];
                        break;
                    }
                }

                if (!conn || !conn->active) continue;

                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    DEBUG_PRINT("Connection error/hangup on fd %d\n", event_fd);
                    close_connection(conn);
                    continue;
                }

                if (events[i].events & EPOLLIN) {
                    // Determine which fd triggered the event
                    if (event_fd == conn->client_fd) {
                        // Client has data - forward to backend
                        DEBUG_PRINT_VERBOSE("EPOLLIN on client_fd\n");
                        forward_client_to_backend(conn);
                    } else if (event_fd == conn->backend_fd) {
                        // Backend has data - forward to client
                        DEBUG_PRINT_VERBOSE("EPOLLIN on backend_fd\n");
                        forward_backend_to_client(conn);
                    }
                }

                if (events[i].events & EPOLLOUT) {
                    // Socket is ready for writing - mainly for client_fd
                    // We don't actively use this yet, but log for debug
                    DEBUG_PRINT_VERBOSE("EPOLLOUT on fd %d\n", event_fd);
                }
            }
        }

        // Cleanup inactive connections periodically
        time_t now = time(NULL);
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (g_forwarder.connections[i].active &&
                now - g_forwarder.connections[i].last_activity > 300) {
                close_connection(&g_forwarder.connections[i]);
            }
        }
    }

    close(epoll_fd);
    if (ws_listener >= 0) close(ws_listener);
    if (wss_listener >= 0) close(wss_listener);
}

static SSL_CTX* init_ssl_context(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // For OpenSSL 1.0.1 compatibility
    // Disable older protocols and enable modern ones
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Enable TLS 1.2 which is supported by all modern browsers
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // For OpenSSL 1.1.0+
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);  // TLS 1.0 minimum
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION); // TLS 1.2 maximum (for 1.0.1 compat)
    #else
    // For OpenSSL 1.0.x
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    // We don't disable TLS 1.0/1.1 for maximum compatibility
    #endif

    // Critical: Disable certificate verification on the server side
    // This prevents "certificate unknown" errors
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Add additional options for better compatibility
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE); // Use server's cipher preferences
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION); // Disable compression (CRIME attack)
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    // Set modern cipher list with preference for CHACHA20-POLY1305 ciphers
    const char *cipher_list = "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";

    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
        fprintf(stderr, "Error setting cipher list\n");
        ERR_print_errors_fp(stderr);
        // Fall back to default cipher list if this fails
    }

    // Try to load certificate/key
    int loaded = 0;

    // Try PEM format first
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) > 0) {
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file ? key_file : cert_file, SSL_FILETYPE_PEM) > 0) {
            loaded = 1;
        }
    }

    // Try DER format
    if (!loaded) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_ASN1) > 0) {
            if (SSL_CTX_use_PrivateKey_file(ctx, key_file ? key_file : cert_file, SSL_FILETYPE_ASN1) > 0) {
                loaded = 1;
            }
        }
    }

    // Try PKCS12 format
    if (!loaded) {
        FILE *fp = fopen(cert_file, "rb");
        if (fp) {
            PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
            fclose(fp);
            if (p12) {
                EVP_PKEY *pkey = NULL;
                X509 *cert = NULL;
                STACK_OF(X509) *ca = NULL;
                if (PKCS12_parse(p12, NULL, &pkey, &cert, &ca)) {
                    if (SSL_CTX_use_certificate(ctx, cert) && SSL_CTX_use_PrivateKey(ctx, pkey)) {
                        loaded = 1;
                    }
                    if (cert) X509_free(cert);
                    if (pkey) EVP_PKEY_free(pkey);
                    if (ca) sk_X509_pop_free(ca, X509_free);
                }
                PKCS12_free(p12);
            }
        }
    }

    if (!loaded) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set ECDH auto mode for better compatibility with modern browsers
    #if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set_ecdh_auto(ctx, 1);
    #else
    // For older OpenSSL versions, manually set up ECDH with P-256 curve
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh) {
        SSL_CTX_set_tmp_ecdh(ctx, ecdh);
        EC_KEY_free(ecdh);
    }
    #endif

    return ctx;
}

static void find_ssl_files(const char *base, char **cert_file, char **key_file) {
    const char *extensions[] = {".pem", ".der", ".p12", ".crt", ".key", NULL};

    fprintf(stderr, "Searching for SSL certificates in: %s/\n", PORTFORWARD_CERT_DIR);

    for (int i = 0; extensions[i]; i++) {
        char cert_path[512];
        snprintf(cert_path, sizeof(cert_path), "%s/portforward%s", PORTFORWARD_CERT_DIR, extensions[i]);

        fprintf(stderr, "Checking: %s ... ", cert_path);
        if (access(cert_path, R_OK) == 0) {
            fprintf(stderr, "FOUND\n");
            *cert_file = strdup(cert_path);
            *key_file = strdup(cert_path); // Same file for PKCS12
            return;
        }
        fprintf(stderr, "not found\n");
    }

    fprintf(stderr, "No SSL certificate files found in %s/\n", PORTFORWARD_CERT_DIR);
}

static void signal_handler(int sig) {
    if (g_forwarder.child_pid > 0) {
        kill(g_forwarder.child_pid, sig);
    }

    if (sig == SIGTERM || sig == SIGINT) {
        g_forwarder.should_stop = 1;
    }
}

static int parse_arguments(int argc, char *argv[]) {
    int arg_idx = 0;
    g_forwarder.exec_args = malloc(sizeof(char*) * (argc + 10));

    // First pass: extract our special parameters
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_forwarder.exec_path = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-W") == 0 && i + 1 < argc) {
            g_forwarder.port_w = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            g_forwarder.port_l = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            g_forwarder.listen_w = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            g_forwarder.listen_l = strdup(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            g_forwarder.verbose = 1;
            DEBUG_PRINT("Verbose mode enabled\n");
        }
    }

    // Second pass: build exec_args, forwarding all but our special params
    // and modifying -p value to "lcserver"
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            // Add -p but with "lcserver" as value
            g_forwarder.exec_args[arg_idx++] = strdup("-p");
            g_forwarder.exec_args[arg_idx++] = strdup("lcserver");
            i++; // Skip the original path
        } else if (strcmp(argv[i], "-W") == 0 && i + 1 < argc) {
            i++; // Skip this parameter
        } else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            i++; // Skip this parameter
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            i++; // Skip this parameter
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            i++; // Skip this parameter
        } else if (strcmp(argv[i], "-v") == 0) {
            // Skip this parameter, don't forward to child process
        } else {
            // Forward all other arguments
            g_forwarder.exec_args[arg_idx++] = strdup(argv[i]);
        }
    }
    g_forwarder.exec_args[arg_idx] = NULL;
    g_forwarder.exec_args_count = arg_idx;

    // Determine binary name: use lcserver_org if exists, else lcserver
    if (g_forwarder.exec_path) {
        char binary_path[1024];
        snprintf(binary_path, sizeof(binary_path), "%s/%s", g_forwarder.exec_path, PORTFORWARD_EXEC_ORG_BIN);
        if (access(binary_path, X_OK) == 0) {
            g_forwarder.exec_binary = strdup(PORTFORWARD_EXEC_ORG_BIN);
        } else {
            // Try lcserver
            snprintf(binary_path, sizeof(binary_path), "%s/%s", g_forwarder.exec_path, PORTFORWARD_EXEC_BIN);
            if (access(binary_path, X_OK) == 0) {
                g_forwarder.exec_binary = strdup(PORTFORWARD_EXEC_BIN);
            } else {
                // Default to lcserver_org even if doesn't exist yet
                g_forwarder.exec_binary = strdup(PORTFORWARD_EXEC_ORG_BIN);
            }
        }
    }

    return 0;
}

static int launch_process(void) {
    if (!g_forwarder.exec_path || !g_forwarder.exec_binary) return 0;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // Child process
        if (chdir(g_forwarder.exec_path) < 0) {
            perror("chdir");
            exit(1);
        }

        // Build full exec arguments: binary + forwarded args
        char **exec_argv = malloc(sizeof(char*) * (g_forwarder.exec_args_count + 2));
        exec_argv[0] = g_forwarder.exec_binary;
        for (int i = 0; i < g_forwarder.exec_args_count; i++) {
            exec_argv[i + 1] = g_forwarder.exec_args[i];
        }
        exec_argv[g_forwarder.exec_args_count + 1] = NULL;

        execvp(g_forwarder.exec_binary, exec_argv);
        perror("execvp");
        exit(1);
    } else {
        // Parent process
        g_forwarder.child_pid = pid;
        DEBUG_PRINT("Launched process %s (PID: %d) in directory %s\n",
               g_forwarder.exec_binary, pid, g_forwarder.exec_path);
        return 0;
    }
}

static void monitor_process(void) {
    if (g_forwarder.child_pid <= 0) return;

    while (!g_forwarder.should_stop) {
        int status;
        pid_t pid = waitpid(g_forwarder.child_pid, &status, WNOHANG);

        if (pid == g_forwarder.child_pid) {
            DEBUG_PRINT("Process %d exited with status %d, terminating forwarder\n", pid, status);
            g_forwarder.should_stop = 1;
            break;
        }

        if (pid < 0 && errno != ECHILD) {
            perror("waitpid");
            break;
        }

        usleep(100000); // 100ms
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-W port] [-L port] [-w host] [-l host] [-v] [other args...]\n", argv[0]);
        fprintf(stderr, "  -W port    WebSocket port for wide network\n");
        fprintf(stderr, "  -L port    WebSocket port for local network\n");
        fprintf(stderr, "  -w host    WebSocket host for wide network\n");
        fprintf(stderr, "  -l host    WebSocket host for local network\n");
        fprintf(stderr, "  -v         Enable verbose WebSocket frame logging\n");
        return 1;
    }

    // Initialize OpenSSL (compatible with OpenSSL 1.0.1e-fips)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Allocate connection pool
    g_forwarder.connections = calloc(MAX_CONNECTIONS, sizeof(connection_t));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        g_forwarder.connections[i].client_fd = -1;
        g_forwarder.connections[i].backend_fd = -1;
    }

    // Setup signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGCHLD, SIG_IGN);

    // Parse arguments
    if (parse_arguments(argc, argv) < 0) {
        return 1;
    }

    // Find SSL certificate files
    char *ssl_cert = NULL, *ssl_key = NULL;
    find_ssl_files("portforward", &ssl_cert, &ssl_key);
    if (ssl_cert && ssl_key) {
        fprintf(stderr, "Found SSL certificate: %s\n", ssl_cert);
        g_forwarder.ssl_ctx = init_ssl_context(ssl_cert, ssl_key);
        if (g_forwarder.ssl_ctx) {
            fprintf(stderr, "SSL/TLS context initialized successfully\n");
        } else {
            fprintf(stderr, "ERROR: Failed to initialize SSL/TLS context\n");
        }
    } else {
        fprintf(stderr, "WARNING: No SSL certificate found, WSS will not be available\n");
    }

    // Launch process if needed
    if (launch_process() < 0) {
        return 1;
    }

    // Start port forwarders
    pid_t forwarder_pids[4];
    int forwarder_count = 0;

    if (g_forwarder.port_w > 0 && g_forwarder.listen_w) {
        int ws_port = WS_PORT_OFFSET_WS + g_forwarder.port_w;
        int wss_port = WS_PORT_OFFSET_WSS + g_forwarder.port_w;

        pid_t pid = fork();
        if (pid == 0) {
            start_port_forwarder(g_forwarder.listen_w, ws_port, wss_port,
                                g_forwarder.listen_w, g_forwarder.port_w);
            exit(0);
        } else if (pid > 0) {
            forwarder_pids[forwarder_count++] = pid;
        }
    }

    if (g_forwarder.port_l > 0 && g_forwarder.listen_l) {
        int ws_port = WS_PORT_OFFSET_WS + g_forwarder.port_l;
        int wss_port = WS_PORT_OFFSET_WSS + g_forwarder.port_l;

        pid_t pid = fork();
        if (pid == 0) {
            start_port_forwarder(g_forwarder.listen_l, ws_port, wss_port,
                                g_forwarder.listen_l, g_forwarder.port_l);
            exit(0);
        } else if (pid > 0) {
            forwarder_pids[forwarder_count++] = pid;
        }
    }

    // Wait for processes
    if (g_forwarder.child_pid > 0) {
        // If we have a child process to monitor, monitor it
        // Forwarder processes will be killed when child process exits
        monitor_process();
    } else if (forwarder_count > 0) {
        // If no child process but we have forwarders, wait for them
        DEBUG_PRINT("Port forwarders are running. Press Ctrl+C to stop.\n");
        while (!g_forwarder.should_stop) {
            // Check if any forwarder process has exited
            int any_alive = 0;
            for (int i = 0; i < forwarder_count; i++) {
                int status;
                pid_t result = waitpid(forwarder_pids[i], &status, WNOHANG);
                if (result == 0) {
                    // Still running
                    any_alive = 1;
                } else if (result == forwarder_pids[i]) {
                    DEBUG_PRINT("Forwarder process %d exited\n", forwarder_pids[i]);
                }
            }

            if (!any_alive) {
                DEBUG_PRINT("All forwarder processes exited\n");
                break;
            }

            sleep(1);
        }
    } else {
        // No processes to run
        fprintf(stderr, "No port forwarders or child processes to run. Exiting.\n");
        return 1;
    }

    // Cleanup - kill all forwarder processes
    DEBUG_PRINT("Shutting down...\n");
    for (int i = 0; i < forwarder_count; i++) {
        kill(forwarder_pids[i], SIGTERM);
        waitpid(forwarder_pids[i], NULL, 0);
    }

    // Kill child process if still running
    if (g_forwarder.child_pid > 0) {
        kill(g_forwarder.child_pid, SIGTERM);
        waitpid(g_forwarder.child_pid, NULL, 0);
    }

    if (g_forwarder.ssl_ctx) {
        SSL_CTX_free(g_forwarder.ssl_ctx);
    }

    return 0;
}
