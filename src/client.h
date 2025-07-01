// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h> // Required for SSL_CTX
#include <stdbool.h>     // Required for bool type
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h> // Required for sa_family_t

// --- NEW: Include parser.h for HandleRequest() ---
#include "parser.h" // Assumed to provide HandleRequest() and other parsing related definitions
// --- END NEW ---

// Common constants
#define MAX_REQUEST_SIZE 8192 // Maximum size of the incoming request to read
#define BUFFER_SIZE 1024      // General buffer size
#define MAX_LINE_SIZE 256     // Max line for config parsing
#define PATH_MAX_LEN 4096     // Max file path length

// Configuration paths (can be overridden by build system)
#ifndef GLOBAL_CONFIG_PATH
#define GLOBAL_CONFIG_PATH "webserver.conf"
#endif

#ifndef SITES_DIR_PATH
#define SITES_DIR_PATH "sites-enabled"
#endif

#define MAX_LISTEN_SOCKETS 50 // Max number of unique listen sockets (IP:Port:SSL)
#define MAX_SITES_PER_LISTENER 10 // Max number of sites a single ListenSocket can serve
#define MAX_SITE_LISTENERS 4  // Max number of listen directives per site config file (IPv4/6, HTTP/S)


// Structure to hold global configuration settings
typedef struct {
    bool ipv4_enabled;
    bool ipv6_enabled;
    char worker_user[MAX_LINE_SIZE];
    bool specified; // True if global config file was processed
} GlobalConfig;

// Structure to hold configuration for a single network listener (IP:Port combo)
typedef struct {
    char address[INET6_ADDRSTRLEN]; // Address for the listener (IPv4 or IPv6)
    int port;                       // Port number for the listener
    sa_family_t family;             // Address family (AF_INET for IPv4, AF_INET6 for IPv6)
    bool ssl_enabled;               // Flag to indicate if SSL is enabled for this listener
} ListenSocketConfig;

// Structure to hold parsed site configuration
typedef struct {
    // Basic site details
    char** server_name;         // Array of server names (FQDNs), _ for any FQDN
    int num_server_names;       // Number of server names in the array
    char root_dir[PATH_MAX_LEN]; // Root directory for this site

    // Site-specific SSL configuration (for SNI)
    SSL_CTX *ssl_ctx;                   // SSL context for this site (created from its certs)
    char site_ssl_cert_file[PATH_MAX_LEN]; // Path to site's SSL certificate file
    char site_ssl_key_file[PATH_MAX_LEN];  // Path to site's SSL private key file
    char site_ssl_chain_file[PATH_MAX_LEN]; // Path to site's SSL chain file

    // Listeners this site wants to bind to (not actual sockets, just configurations)
    ListenSocketConfig listen_sockets[MAX_SITE_LISTENERS];
    int listen_socket_count;
} SiteConfig;

// Structure to represent an actual active listening socket
// This links a network listener to the multiple sites it might serve
typedef struct {
    ListenSocketConfig config;          // Configuration for this specific listen socket
    int sock_fd;                        // Actual file descriptor for the bound socket
    SSL_CTX *listener_ssl_ctx;          // Listener-level SSL context (for SNI callback)
    SiteConfig **sites;                 // Pointer to an array of SiteConfig pointers served by this listener
    int site_count;                     // Number of sites served by this listener
} ListenSocket;

// Structure to hold all active listening sockets
typedef struct {
    ListenSocket sockets[MAX_LISTEN_SOCKETS]; // Array of active listen sockets
    int count;                               // Number of active listen sockets
} GlobalListenConfig;

// Structure to pass arguments to the client handling thread
typedef struct {
    int sock;                       // Client socket file descriptor
    ListenSocket *listener_socket;  // Pointer to the ListenSocket this client connected through
    struct sockaddr_storage remote_addr; // Store remote address for client.c to pass to parser.c
    socklen_t remote_addr_len;
} ClientThreadArgs;

// --- Function Prototypes ---

// From www.c
bool parse_listen_value_into_config(char *value_part, ListenSocketConfig *config); // Updated name
SiteConfig *parse_site_file(const char *filepath, GlobalConfig *global_config);
void read_all_site_configs(const char *sites_dir_path, GlobalConfig *global_config, GlobalListenConfig *global_listeners_ptr);
SSL_CTX *create_ssl_context(const char *cert_file, const char *key_file, const char *chain_file);
void free_site_config(SiteConfig *site);
void free_listen_socket(ListenSocket *ls);
void free_global_listeners(GlobalListenConfig *listeners);
void parse_global_config(const char *filepath, GlobalConfig *config);


// From client.c
void *handle_client(void *thread_args_ptr);
// SNI callback for OpenSSL
int sni_callback(SSL *ssl, int *ad, void *arg);
// Function to find a site based on hostname
SiteConfig* find_site_for_hostname(ListenSocket *listener, const char *hostname);

// --- REMOVED: HandleRequest() declaration here as it's from parser.h ---

#endif // CLIENT_H
