// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h> // Required for SSL_CTX
#include <stdbool.h>     // Required for bool type
#include <netinet/in.h>
#include <arpa/inet.h>
#include "parser.h" // Include the parser header for request handling

// Define common constants that handle_client might need
#define MAX_REQUEST_SIZE 8192 // Maximum size of the incoming request to read
#define BUFFER_SIZE 1024      // General buffer size

// Assume these are defined by the build system (e.g., via configure and config.h)
// #define GLOBAL_CONFIG_PATH "/etc/webserver/webserver.conf"
// #define SITES_DIR_PATH "/etc/webserver/sites-enabled"

// Provide default values for standalone compilation/testing
#ifndef GLOBAL_CONFIG_PATH
#define GLOBAL_CONFIG_PATH "webserver.conf"
#endif

#ifndef SITES_DIR_PATH
#define SITES_DIR_PATH "sites-enabled"
#endif

// Removed BUFFER_SIZE, MAX_REQUEST_SIZE if they are now in client.h
// If you want them global, consider putting them in a separate common_defs.h
// For now, they are in client.h and implicitly used by www.c for ListenConfig's PATH_MAX_LEN, etc.

#define MAX_LINE_SIZE 256 // Max line for config parsing
#define MAX_LISTEN_SOCKETS 50 // Max number of listen sockets
#define PATH_MAX_LEN 4096 // Max file path length


// Structure to hold global configuration settings
typedef struct {
    bool ipv4_enabled;
    bool ipv6_enabled;
    char worker_user[MAX_LINE_SIZE];
    bool specified; // True if global config file was processed
} GlobalConfig;

// Structure to hold parsed listening configuration
typedef struct {
    bool is_ipv6;
    char address[INET6_ADDRSTRLEN];
    int port;
    bool ssl_enabled; // Flag to indicate if SSL is enabled for this listener
	char* *server_name; // server name settings, _ for any FQDN
    SSL_CTX *ssl_ctx; // SSL context for this listener (created later)
    char site_ssl_cert_file[PATH_MAX_LEN];
    char site_ssl_key_file[PATH_MAX_LEN];
    char site_ssl_chain_file[PATH_MAX_LEN];
	char root_dir[PATH_MAX_LEN]; // Root directory for this listener, if applicable
} ListenConfig;

// Structure to hold the result of parsing a single line
typedef struct {
    ListenConfig configs[2]; // Max 2 for port-only (IPv4 & IPv6)
    int count;
} ParsedListenDirectives;

// Structure to pass arguments to the client handling thread
typedef struct {
    int sock;
    SSL_CTX *ssl_ctx; // Pass the SSL_CTX for this connection (NULL if non-SSL)
	char* root_dir; // Root directory for this listener, if applicable
} ClientThreadArgs;

// Function to handle a single client connection
// This function will be executed in a separate thread.
void *handle_client(void *thread_args_ptr);

#endif // CLIENT_H