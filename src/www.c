#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

// Include OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

// --- Corrected Include: client.h ---
#include "client.h"
// --- END Corrected Include ---

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

// parse_single_listen_directive, read_global_config, parse_site_file, read_all_site_configs
// (These functions remain in www.c as they are part of the main server configuration logic)

// Function to parse a single listen directive line
ParsedListenDirectives parse_single_listen_directive(char *line) {
    ParsedListenDirectives result = {{0}, 0};

    char *listen_keyword = strtok(line, " \t");
    if (listen_keyword == NULL || strcmp(listen_keyword, "listen") != 0) {
        return result;
    }

    char *address_part = strtok(NULL, " \t;");
    if (address_part == NULL) {
        fprintf(stderr, "Invalid listen directive format: missing address or port in '%s', file: %s\n", line, "N/A"); // Cannot know filepath here easily
        return result;
    }

    char *ssl_keyword = NULL;
    char *semicolon = strtok(NULL, " \t;");

    if (semicolon != NULL) {
        ssl_keyword = semicolon;
    }

    char *port_str = NULL;
    char *address_str = NULL;
    bool is_ipv6_format = false;
    bool is_port_only = false;

    if (address_part[0] == '[') {
        char *bracket_end = strchr(address_part, ']');
        if (bracket_end != NULL) {
            *bracket_end = '\0';
            address_str = address_part + 1;
            if (*(bracket_end + 1) == ':') {
                port_str = bracket_end + 2;
            }
            is_ipv6_format = true;
        } else {
            fprintf(stderr, "Invalid IPv6 listen directive format: %s\n", address_part);
            return result;
        }
    } else {
        char *colon = strchr(address_part, ':');
        if (colon != NULL) {
            *colon = '\0';
            address_str = address_part;
            port_str = colon + 1;
            is_ipv6_format = false;
        } else {
            port_str = address_part;
            address_str = NULL;
            is_port_only = true;
            is_ipv6_format = false;
        }
    }

    if (port_str == NULL) {
        fprintf(stderr, "Port not specified in listen directive: %s\n", address_part);
        return result;
    }
    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %s\n", port_str);
        return result;
    }

    bool ssl_enabled_for_directive = false;
    if (ssl_keyword != NULL && strcmp(ssl_keyword, "ssl") == 0) {
        ssl_enabled_for_directive = true;
        char *extra_token = strtok(NULL, " \t;");
        if (extra_token != NULL) {
            fprintf(stderr, "Warning: Extra tokens after 'ssl;' in listen directive: %s. Ignoring.\n", extra_token);
        }
    } else if (ssl_keyword != NULL) {
         fprintf(stderr, "Warning: Unknown token after address/port in listen directive: %s. Expected 'ssl;'.\n", ssl_keyword);
    }


    if (is_port_only) {
        result.count = 2;

        result.configs[0].is_ipv6 = false;
        strcpy(result.configs[0].address, "0.0.0.0");
        result.configs[0].port = port;
        result.configs[0].ssl_enabled = ssl_enabled_for_directive;
        result.configs[0].ssl_ctx = NULL;
        result.configs[0].site_ssl_cert_file[0] = '\0';
        result.configs[0].site_ssl_key_file[0] = '\0';
        result.configs[0].site_ssl_chain_file[0] = '\0';
		result.configs[0].root_dir[0] = '\0'; 

        result.configs[1].is_ipv6 = true;
        strcpy(result.configs[1].address, "::");
        result.configs[1].port = port;
        result.configs[1].ssl_enabled = ssl_enabled_for_directive;
        result.configs[1].ssl_ctx = NULL;
        result.configs[1].site_ssl_cert_file[0] = '\0';
        result.configs[1].site_ssl_key_file[0] = '\0';
        result.configs[1].site_ssl_chain_file[0] = '\0';
		result.configs[0].root_dir[0] = '\0'; 

    } else {
        result.count = 1;
        result.configs[0].is_ipv6 = is_ipv6_format;
        result.configs[0].port = port;
        result.configs[0].ssl_enabled = ssl_enabled_for_directive;
        result.configs[0].ssl_ctx = NULL;
        result.configs[0].site_ssl_cert_file[0] = '\0';
        result.configs[0].site_ssl_key_file[0] = '\0';
        result.configs[0].site_ssl_chain_file[0] = '\0';
		result.configs[0].root_dir[0] = '\0'; 

        if (address_str != NULL && strlen(address_str) > 0) {
             strncpy(result.configs[0].address, address_str, INET6_ADDRSTRLEN - 1);
             result.configs[0].address[INET6_ADDRSTRLEN - 1] = '\0';
        } else {
             if (is_ipv6_format) {
                strcpy(result.configs[0].address, "::");
            } else {
                strcpy(result.configs[0].address, "0.0.0.0");
            }
        }
    }

    return result;
}

// Function to read global configuration
GlobalConfig read_global_config(const char *filepath) {
    GlobalConfig config = {true, true, "nobody", false};
    FILE *file = fopen(filepath, "r");

    if (file == NULL) {
        perror("Error opening global config file");
        fprintf(stderr, "Could not open global config file: %s. Using default settings (ipv4 on, ipv6 on, worker nobody).\n", filepath);
        return config;
    }

    char line[MAX_LINE_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = 0;

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        char line_copy[MAX_LINE_SIZE];
        strncpy(line_copy, line, MAX_LINE_SIZE - 1);
        line_copy[MAX_LINE_SIZE - 1] = '\0';

        char *key = strtok(line_copy, " \t");
        if (key == NULL) continue;

        char *value = strtok(NULL, " \t;");
        if (value == NULL) {
            fprintf(stderr, "Invalid global config directive: %s\n", line);
            continue;
        }

        if (strcmp(key, "ipv4") == 0) {
            if (strcmp(value, "on") == 0) config.ipv4_enabled = true;
            else if (strcmp(value, "off") == 0) config.ipv4_enabled = false;
            else fprintf(stderr, "Invalid value for ipv4 directive: %s\n", value);
        } else if (strcmp(key, "ipv6") == 0) {
            if (strcmp(value, "on") == 0) config.ipv6_enabled = true;
            else if (strcmp(value, "off") == 0) config.ipv6_enabled = false;
            else fprintf(stderr, "Invalid value for ipv6 directive: %s\n", value);
        } else if (strcmp(key, "worker") == 0) {
            strncpy(config.worker_user, value, MAX_LINE_SIZE - 1);
            config.worker_user[MAX_LINE_SIZE - 1] = '\0';
        }
        else {
            fprintf(stderr, "Unknown global config directive: %s\n", key);
        }
    }

    fclose(file);
    config.specified = true;
    return config;
}

// Function to parse a single site configuration file and add listeners to a list
ListenConfig* parse_site_file(const char *filepath, const GlobalConfig *global_config, ListenConfig *current_listeners, int *current_num_listeners) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Error opening site config file");
        fprintf(stderr, "Could not open site config file: %s. Skipping.\n", filepath);
        return current_listeners;
    }

    char line[MAX_LINE_SIZE];
    ListenConfig *last_parsed_listener = NULL;

    bool listen_directive_found_in_this_file = false;

    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = 0;

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        char line_copy[MAX_LINE_SIZE];
        strncpy(line_copy, line, MAX_LINE_SIZE - 1);
        line_copy[MAX_LINE_SIZE - 1] = '\0';

        char *key = strtok(line_copy, " \t");
        if (key == NULL) continue;

        char *value = strtok(NULL, " \t;");

        if (strcmp(key, "listen") == 0) {
            if (listen_directive_found_in_this_file) {
                fprintf(stderr, "Error in %s: Only one 'listen' directive is allowed per site file. Skipping subsequent 'listen' directives.\n", filepath);
                continue;
            }

            char original_line_for_parse[MAX_LINE_SIZE];
            strncpy(original_line_for_parse, line, MAX_LINE_SIZE - 1);
            original_line_for_parse[MAX_LINE_SIZE - 1] = '\0';

            ParsedListenDirectives parsed = parse_single_listen_directive(original_line_for_parse);

            for (int i = 0; i < parsed.count; ++i) {
                 if ((parsed.configs[i].is_ipv6 && !global_config->ipv6_enabled) ||
                     (!parsed.configs[i].is_ipv6 && !global_config->ipv4_enabled)) {
                     fprintf(stderr, "Skipping listener %s port %d from %s due to global IPv%d setting.\n",
                             parsed.configs[i].address, parsed.configs[i].port, filepath, parsed.configs[i].is_ipv6 ? 6 : 4);
                     continue;
                 }

                 if (*current_num_listeners < MAX_LISTEN_SOCKETS) {
                    ListenConfig *temp = realloc(current_listeners, (*current_num_listeners + 1) * sizeof(ListenConfig));
                    if (temp == NULL) {
                        perror("realloc failed during site file parsing");
                        fclose(file);
                        return current_listeners;
                    }
                    current_listeners = temp;
                    current_listeners[*current_num_listeners] = parsed.configs[i];
                    last_parsed_listener = &current_listeners[*current_num_listeners];
                    (*current_num_listeners)++;
                    listen_directive_found_in_this_file = true;
                 } else {
                     fprintf(stderr, "Warning: Maximum number of listeners (%d) reached. Ignoring subsequent listen directives.\n", MAX_LISTEN_SOCKETS);
                     break;
                 }
            }
            if (*current_num_listeners >= MAX_LISTEN_SOCKETS) {
                break;
            }
        } 
		else if(strcmp(key, "ssl_certificate") == 0 ||
				strcmp(key, "ssl_key") == 0 ||
				strcmp(key, "ssl_chain") == 0)
			{ 
				if (last_parsed_listener != NULL && last_parsed_listener->ssl_enabled) {
				if (value == NULL) {
					fprintf(stderr, "Invalid directive format: %s in %s\n", key, filepath);
					continue;
				}

				if (strcmp(key, "ssl_certificate") == 0) {
					strncpy(last_parsed_listener->site_ssl_cert_file, value, PATH_MAX_LEN - 1);
					last_parsed_listener->site_ssl_cert_file[PATH_MAX_LEN - 1] = '\0';
				} else if (strcmp(key, "ssl_key") == 0) {
					strncpy(last_parsed_listener->site_ssl_key_file, value, PATH_MAX_LEN - 1);
					last_parsed_listener->site_ssl_key_file[PATH_MAX_LEN - 1] = '\0';
				} else if (strcmp(key, "ssl_chain") == 0) {
					strncpy(last_parsed_listener->site_ssl_chain_file, value, PATH_MAX_LEN - 1);
					last_parsed_listener->site_ssl_chain_file[PATH_MAX_LEN - 1] = '\0';
				} 
			} 
		} else if (strcmp(key, "root") == 0) {
                strncpy(last_parsed_listener->root_dir, value, PATH_MAX_LEN - 1);
                last_parsed_listener->root_dir[PATH_MAX_LEN - 1] = '\0';
		} else {
            fprintf(stderr, "Warning: Unhandled directive outside of 'listen' block or without a preceding listen directive: %s in %s\n", line, filepath);
        }
    }

    fclose(file);
    return current_listeners;
}


// Function to read configuration from all site files in a directory
ListenConfig* read_all_site_configs(const char *sitedir_path, const GlobalConfig *global_config, int *num_listeners) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char filepath[PATH_MAX_LEN];

    ListenConfig *listeners = NULL;
    *num_listeners = 0;

    if ((dir = opendir(sitedir_path)) == NULL) {
        perror("Error opening site configuration directory");
        fprintf(stderr, "Could not open site configuration directory: %s. Using default listener based on global config.\n", sitedir_path);
         listeners = malloc(2 * sizeof(ListenConfig));
        if (listeners == NULL) {
             perror("malloc failed for default listeners");
             *num_listeners = 0;
             return NULL;
        }

        int default_count = 0;
        if (global_config->ipv4_enabled) {
            listeners[default_count].port = 8080;
            strcpy(listeners[default_count].address, "0.0.0.0");
            listeners[default_count].is_ipv6 = false;
            listeners[default_count].ssl_enabled = false;
            listeners[default_count].ssl_ctx = NULL;
            listeners[default_count].site_ssl_cert_file[0] = '\0';
            listeners[default_count].site_ssl_key_file[0] = '\0';
            listeners[default_count].site_ssl_chain_file[0] = '\0';
			listeners[default_count].root_dir[0] = '\0'; // Default root directory
            default_count++;
        }
         if (global_config->ipv6_enabled) {
            listeners[default_count].port = 8080;
            strcpy(listeners[default_count].address, "::");
            listeners[default_count].is_ipv6 = true;
            listeners[default_count].ssl_enabled = false;
            listeners[default_count].ssl_ctx = NULL;
            listeners[default_count].site_ssl_cert_file[0] = '\0';
            listeners[default_count].site_ssl_key_file[0] = '\0';
            listeners[default_count].site_ssl_chain_file[0] = '\0';
			listeners[default_count].root_dir[0] = '\0'; // Default root directory
            default_count++;
        }
        *num_listeners = default_count;

         if (*num_listeners == 0) {
             fprintf(stderr, "Global configuration disables both IPv4 and IPv6. No listeners configured.\n");
             free(listeners);
             return NULL;
         }

        return listeners;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (snprintf(filepath, sizeof(filepath), "%s/%s", sitedir_path, entry->d_name) >= sizeof(filepath)) {
             fprintf(stderr, "Error: File path too long for %s/%s. Skipping.\n", sitedir_path, entry->d_name);
             continue;
        }


        if (stat(filepath, &file_stat) == -1) {
            perror("Error getting file status");
            fprintf(stderr, "Could not get status of %s. Skipping.\n", filepath);
            continue;
        }

        if (S_ISREG(file_stat.st_mode)) {
            listeners = parse_site_file(filepath, global_config, listeners, num_listeners);
             if (listeners == NULL && *num_listeners > 0) {
                 fprintf(stderr, "Memory reallocation failed during site config parsing. Stopping.\n");
                 break;
             }
        }
    }

    closedir(dir);

     if (*num_listeners == 0) {
         fprintf(stderr, "No valid listen directives found in site configuration directory %s (or all disabled by global config). Using default listener based on global config.\n", sitedir_path);
        listeners = malloc(2 * sizeof(ListenConfig));
        if (listeners == NULL) {
             perror("malloc failed for default listeners");
             *num_listeners = 0;
             return NULL;
        }

        int default_count = 0;
        if (global_config->ipv4_enabled) {
            listeners[default_count].port = 8080;
            strcpy(listeners[default_count].address, "0.0.0.0");
            listeners[default_count].is_ipv6 = false;
            listeners[default_count].ssl_enabled = false;
            listeners[default_count].ssl_ctx = NULL;
            listeners[default_count].site_ssl_cert_file[0] = '\0';
            listeners[default_count].site_ssl_key_file[0] = '\0';
            listeners[default_count].site_ssl_chain_file[0] = '\0';
            default_count++;
        }
         if (global_config->ipv6_enabled) {
            listeners[default_count].port = 8080;
            strcpy(listeners[default_count].address, "::");
            listeners[default_count].is_ipv6 = true;
            listeners[default_count].ssl_enabled = false;
            listeners[default_count].ssl_ctx = NULL;
            listeners[default_count].site_ssl_cert_file[0] = '\0';
            listeners[default_count].site_ssl_key_file[0] = '\0';
            listeners[default_count].site_ssl_chain_file[0] = '\0';
            default_count++;
        }
        *num_listeners = default_count;

        if (*num_listeners == 0) {
             fprintf(stderr, "Global configuration disables both IPv4 and IPv6. No listeners configured.\n");
             free(listeners);
             return NULL;
         }
    }

    return listeners;
}


int main() {
    int opt = 1;

    // --- OpenSSL Initialization ---
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // --- End OpenSSL Initialization ---


    GlobalConfig global_config = read_global_config(GLOBAL_CONFIG_PATH);

    int num_listeners = 0;
    ListenConfig *listen_configs = read_all_site_configs(SITES_DIR_PATH, &global_config, &num_listeners);

    if (listen_configs == NULL || num_listeners == 0) {
        fprintf(stderr, "Failed to configure any listeners. Exiting.\n");
        free(listen_configs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    int *listen_sockets = malloc(num_listeners * sizeof(int));
    if (listen_sockets == NULL) {
        perror("malloc failed for listen sockets");
         for (int i = 0; i < num_listeners; i++) {
             if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
         }
        free(listen_configs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    SSL_CTX **listener_ssl_ctxs = malloc(num_listeners * sizeof(SSL_CTX *));
     if (listener_ssl_ctxs == NULL) {
         perror("malloc failed for listener SSL contexts array");
         for (int i = 0; i < num_listeners; i++) {
             if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
         }
         free(listen_configs);
         free(listen_sockets);
         EVP_cleanup();
         ERR_free_strings();
         exit(EXIT_FAILURE);
     }


    struct pollfd *poll_fds = malloc(num_listeners * sizeof(struct pollfd));
     if (poll_fds == NULL) {
        perror("malloc failed for poll fds");
         for (int i = 0; i < num_listeners; i++) {
             if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
         }
        free(listen_configs);
        free(listen_sockets);
        free(listener_ssl_ctxs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    int actual_listeners_count = 0;
    for (int i = 0; i < num_listeners; i++) {
        int server_fd;
        socklen_t addrlen;

        if (listen_configs[i].is_ipv6) {
            server_fd = socket(AF_INET6, SOCK_STREAM, 0);
            addrlen = sizeof(struct sockaddr_in6);
        } else {
            server_fd = socket(AF_INET, SOCK_STREAM, 0);
            addrlen = sizeof(struct sockaddr_in);
        }

        if (server_fd == -1) {
            perror("socket failed");
            fprintf(stderr, "Could not create socket for %s port %d\n", listen_configs[i].address, listen_configs[i].port);
            listen_sockets[i] = -1;
            continue;
        }

        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt failed for listener");
            fprintf(stderr, "Could not set socket options for %s port %d\n", listen_configs[i].address, listen_configs[i].port);
            close(server_fd);
             listen_sockets[i] = -1;
            continue;
        }

        if (listen_configs[i].is_ipv6) {
             int on = 1;
             if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
                 perror("Warning: setsockopt(IPV6_V6ONLY) failed");
             }
        }

        // --- SSL Context Setup for SSL Listeners ---
        if (listen_configs[i].ssl_enabled) {
            listen_configs[i].ssl_ctx = SSL_CTX_new(TLS_server_method());
            if (listen_configs[i].ssl_ctx == NULL) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Error creating SSL context for %s port %d\n", listen_configs[i].address, listen_configs[i].port);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (strlen(listen_configs[i].site_ssl_cert_file) == 0 || SSL_CTX_use_certificate_file(listen_configs[i].ssl_ctx, listen_configs[i].site_ssl_cert_file, SSL_FILETYPE_PEM) <= 0) {
                 ERR_print_errors_fp(stderr);
                 fprintf(stderr, "Error loading SSL certificate file %s for %s port %d. Is it configured in the site file?\n", listen_configs[i].site_ssl_cert_file, listen_configs[i].address, listen_configs[i].port);
                 SSL_CTX_free(listen_configs[i].ssl_ctx);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (strlen(listen_configs[i].site_ssl_key_file) == 0 || SSL_CTX_use_PrivateKey_file(listen_configs[i].ssl_ctx, listen_configs[i].site_ssl_key_file, SSL_FILETYPE_PEM) <= 0) {
                 ERR_print_errors_fp(stderr);
                 fprintf(stderr, "Error loading SSL private key file %s for %s port %d. Is it configured in the site file?\n", listen_configs[i].site_ssl_key_file, listen_configs[i].address, listen_configs[i].port);
                 SSL_CTX_free(listen_configs[i].ssl_ctx);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (SSL_CTX_check_private_key(listen_configs[i].ssl_ctx) <= 0) {
                 ERR_print_errors_fp(stderr);
                 fprintf(stderr, "SSL private key does not match the certificate for %s port %d\n", listen_configs[i].address, listen_configs[i].port);
                 SSL_CTX_free(listen_configs[i].ssl_ctx);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (strlen(listen_configs[i].site_ssl_chain_file) > 0) {
                 if (SSL_CTX_use_certificate_chain_file(listen_configs[i].ssl_ctx, listen_configs[i].site_ssl_chain_file) <= 0) {
                     ERR_print_errors_fp(stderr);
                     fprintf(stderr, "Warning: Error loading SSL certificate chain file %s for %s port %d. Continuing without chain.\n", listen_configs[i].site_ssl_chain_file, listen_configs[i].address, listen_configs[i].port);
                 }
            }

             SSL_CTX_set_options(listen_configs[i].ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
             SSL_CTX_set_cipher_list(listen_configs[i].ssl_ctx, "HIGH:!aNULL:!MD5");

        } else {
            listen_configs[i].ssl_ctx = NULL;
        }
        // --- End SSL Context Setup ---


        if (listen_configs[i].is_ipv6) {
            struct sockaddr_in6 address;
            memset(&address, 0, sizeof(address));
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(listen_configs[i].port);

            if (inet_pton(AF_INET6, listen_configs[i].address, &address.sin6_addr) <= 0) {
                 perror("Invalid IPv6 address for listener");
                 fprintf(stderr, "Invalid IPv6 address in config: %s\n", listen_configs[i].address);
                 if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (bind(server_fd, (struct sockaddr *)&address, addrlen) < 0) {
                perror("IPv6 bind failed");
                fprintf(stderr, "Could not bind IPv6 socket to %s port %d\n", listen_configs[i].address, listen_configs[i].port);
                 if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
                close(server_fd);
                listen_sockets[i] = -1;
                continue;
            }
        } else {
            struct sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_port = htons(listen_configs[i].port);

            if (inet_pton(AF_INET, listen_configs[i].address, &address.sin_addr) <= 0) {
                 perror("Invalid IPv4 address for listener");
                 fprintf(stderr, "Invalid IPv4 address in config: %s\n", listen_configs[i].address);
                 if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
                 close(server_fd);
                 listen_sockets[i] = -1;
                 continue;
            }

            if (bind(server_fd, (struct sockaddr *)&address, addrlen) < 0) {
                perror("IPv4 bind failed");
                 fprintf(stderr, "Could not bind IPv4 socket to %s port %d\n", listen_configs[i].address, listen_configs[i].port);
                 if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
                close(server_fd);
                listen_sockets[i] = -1;
                continue;
            }
        }

        if (listen(server_fd, 10) < 0) {
            perror("listen failed for listener");
            fprintf(stderr, "Could not listen on socket for %s port %d\n", listen_configs[i].address, listen_configs[i].port);
            if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
            close(server_fd);
            listen_sockets[i] = -1;
            continue;
        }

        listen_sockets[i] = server_fd;
        poll_fds[actual_listeners_count].fd = server_fd;
        poll_fds[actual_listeners_count].events = POLLIN;
        poll_fds[actual_listeners_count].revents = 0;
        listener_ssl_ctxs[actual_listeners_count] = listen_configs[i].ssl_ctx;

        printf("Listening on %s port %d %s(Socket FD: %d)\n", listen_configs[i].address, listen_configs[i].port, listen_configs[i].ssl_enabled ? "SSL " : "", server_fd);
        actual_listeners_count++;
    }

    if (actual_listeners_count == 0) {
        fprintf(stderr, "Failed to set up any listening sockets. Exiting.\n");
        free(listen_configs);
        free(listen_sockets);
        free(poll_fds);
        free(listener_ssl_ctxs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    struct passwd *pw = getpwnam(global_config.worker_user);
    if (pw == NULL) {
        perror("getpwnam failed");
        fprintf(stderr, "Worker user '%s' not found. Cannot drop privileges. Exiting.\n", global_config.worker_user);
        for (int i = 0; i < num_listeners; i++) {
            if (listen_sockets[i] != -1) {
                close(listen_sockets[i]);
            }
            if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
        }
        free(listen_configs);
        free(listen_sockets);
        free(poll_fds);
        free(listener_ssl_ctxs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    if (setgid(pw->pw_gid) != 0) {
        perror("setgid failed");
        fprintf(stderr, "Failed to set group ID to %d. Cannot drop privileges. Exiting.\n", pw->pw_gid);
        for (int i = 0; i < num_listeners; i++) {
            if (listen_sockets[i] != -1) {
                close(listen_sockets[i]);
            }
            if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
        }
        free(listen_configs);
        free(listen_sockets);
        free(poll_fds);
        free(listener_ssl_ctxs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    if (setuid(pw->pw_uid) != 0) {
        perror("setuid failed");
        fprintf(stderr, "Failed to set user ID to %d. Cannot drop privileges. Exiting.\n", pw->pw_uid);
        for (int i = 0; i < num_listeners; i++) {
            if (listen_sockets[i] != -1) {
                close(listen_sockets[i]);
            }
            if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
        }
        free(listen_configs);
        free(listen_sockets);
        free(poll_fds);
        free(listener_ssl_ctxs);
        EVP_cleanup();
        ERR_free_strings();
        exit(EXIT_FAILURE);
    }

    printf("Dropped privileges to user '%s' (UID: %d, GID: %d)\n", global_config.worker_user, pw->pw_uid, pw->pw_gid);

    printf("CUI Threaded HTTP Listener running with %d listeners.\n", actual_listeners_count);
    printf("Press Ctrl+C to stop the server\n");


    while (1) {
        int poll_count = poll(poll_fds, actual_listeners_count, -1);

        if (poll_count < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                perror("poll error");
                break;
            }
        }

        for (int i = 0; i < actual_listeners_count; i++) {
            if (poll_fds[i].revents & POLLIN) {
                int new_socket;
                 struct sockaddr_storage client_address;
                 socklen_t client_addrlen = sizeof(client_address);

                if ((new_socket = accept(poll_fds[i].fd, (struct sockaddr *)&client_address, &client_addrlen)) < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    } else {
                        perror("accept error");
                        continue;
                    }
                }

                ClientThreadArgs *thread_args = malloc(sizeof(ClientThreadArgs));
                if (thread_args == NULL) {
                    perror("malloc failed for thread arguments");
                    close(new_socket);
                    continue;
                }
                thread_args->sock = new_socket;
                thread_args->ssl_ctx = listener_ssl_ctxs[i];
				thread_args->root_dir = listen_configs[i].root_dir;


                pthread_t client_thread;
                if (pthread_create(&client_thread, NULL, handle_client, (void*) thread_args) < 0) {
                    perror("could not create thread");
                    close(new_socket);
                    free(thread_args);
                    continue;
                }
                pthread_detach(client_thread);
            }
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                 fprintf(stderr, "Error or hangup on listener socket %d\n", poll_fds[i].fd);
            }
        }
    }

    printf("\nServer shutting down...\n");

    for (int i = 0; i < num_listeners; i++) {
        if (listen_sockets[i] != -1) {
            close(listen_sockets[i]);
        }
         if (listen_configs[i].ssl_ctx) SSL_CTX_free(listen_configs[i].ssl_ctx);
    }

    free(listen_configs);
    free(listen_sockets);
    free(poll_fds);
    free(listener_ssl_ctxs);

    EVP_cleanup();
    ERR_free_strings();


    return 0;
}