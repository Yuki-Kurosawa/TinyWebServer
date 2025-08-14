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
#include <ctype.h> // For isdigit

// Include OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client.h" 

// Global storage for all parsed SiteConfig structures
// These are allocated once and pointed to by ListenSocket structures
SiteConfig* all_parsed_sites[MAX_LISTEN_SOCKETS * MAX_SITE_LISTENERS]; // A bit over-allocated but simple
int num_total_parsed_sites = 0;


// --- Helper Functions Implementation ---

// Function to parse the *value part* of a listen directive (e.g., "0.0.0.0:4443 ssl" or "8080")
// Returns true on success, false on failure.
bool parse_listen_value_into_config(char *value_part, ListenSocketConfig *config) {
    memset(config, 0, sizeof(ListenSocketConfig)); // Clear structure

    char *current_token = strtok(value_part, " \t"); // First token is address or port
    if (current_token == NULL) {
        fprintf(stderr, "Invalid listen value format: missing address/port in '%s'\n", value_part);
        return false;
    }

    char *next_token = strtok(NULL, " \t;"); // Next token could be 'ssl' or part of address:port or NULL

    char *port_str = NULL;
    char *address_only = NULL;
    int port = 0;

    // Determine if the first token is a port-only or an address part
    // A simple heuristic: if it contains '.' or ':', it's likely an address. Otherwise, a port.
    bool is_port_only = true;
    for (char* p = current_token; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) { // Use isdigit for robustness
            is_port_only = false;
            break;
        }
    }

    if (is_port_only) {
        port_str = current_token;
        strcpy(config->address, "0.0.0.0"); // Default to IPv4 ANY address
        config->family = AF_INET;
        // If there was a next_token, it could be "ssl" or an error
        if (next_token != NULL && strcmp(next_token, "ssl") == 0) {
            config->ssl_enabled = true;
        } else if (next_token != NULL) { // Unexpected token
             fprintf(stderr, "Invalid token '%s' after port in listen directive.\n", next_token);
             return false;
        }
    } else {
        // It's an address:port or just an address
        address_only = current_token;

        // Check for IPv6 address with brackets
        if (address_only[0] == '[') {
            char *bracket_end = strchr(address_only, ']');
            if (bracket_end == NULL) {
                fprintf(stderr, "Invalid IPv6 address format: missing ']' in '%s'\n", address_only);
                return false;
            }
            *bracket_end = '\0'; // Null-terminate at ']'
            address_only++; // Address starts after '['

            if ( *(bracket_end + 1) == ':' ) { // Check if port is explicitly provided after ]
                port_str = bracket_end + 2; // Port starts after ']:'
            } else {
                fprintf(stderr, "Invalid IPv6 address format: missing ':' after ']' in '%s'\n", current_token);
                return false;
            }
            config->family = AF_INET6;
        } else {
            // IPv4 address:port or just IPv4 address
            char *colon = strchr(address_only, ':');
            if (colon != NULL) {
                *colon = '\0'; // Null-terminate address part
                port_str = colon + 1; // Port starts after ':'
            }
            config->family = AF_INET;
        }

        // Now handle the next_token for SSL
        if (next_token != NULL && strcmp(next_token, "ssl") == 0) {
            config->ssl_enabled = true;
        } else if (next_token != NULL) { // Unexpected token
             fprintf(stderr, "Invalid token '%s' after address/port in listen directive.\n", next_token);
             return false;
        }
    }

    if (port_str == NULL) {
        fprintf(stderr, "Invalid listen value format: missing port for address '%s'\n", current_token);
        return false;
    }

    port = atoi(port_str);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number: %d\n", port);
        return false;
    }
    config->port = port;

    // Copy address (if it was part of an address:port string)
    if (address_only != NULL) {
        if (strcmp(address_only, "*") == 0 || strcmp(address_only, "0.0.0.0") == 0) {
            strcpy(config->address, "0.0.0.0");
        } else if (strcmp(address_only, "::") == 0) {
            strcpy(config->address, "::");
        } else if (config->family == AF_INET && inet_pton(AF_INET, address_only, &(struct in_addr){0}) == 1) {
            strncpy(config->address, address_only, INET_ADDRSTRLEN - 1);
            config->address[INET_ADDRSTRLEN - 1] = '\0';
        } else if (config->family == AF_INET6 && inet_pton(AF_INET6, address_only, &(struct in6_addr){0}) == 1) {
            strncpy(config->address, address_only, INET6_ADDRSTRLEN - 1);
            config->address[INET6_ADDRSTRLEN - 1] = '\0';
        } else {
            fprintf(stderr, "Invalid address '%s' in listen value.\n", address_only);
            return false;
        }
    }
    // If address_only is NULL, it was a port-only directive, address is already "0.0.0.0"

    return true;
}


// Function to parse a single site config file and return a SiteConfig
// This function parses directives specific to a site (server_name, root, ssl_certs, listen directives)
SiteConfig *parse_site_file(const char *filepath, GlobalConfig *global_config) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Failed to open site config file");
        fprintf(stderr, "Could not open site config file: %s. Skipping.\n", filepath);
        return NULL;
    }

    SiteConfig *site = (SiteConfig *)malloc(sizeof(SiteConfig));
    if (site == NULL) {
        perror("Failed to allocate SiteConfig");
        fclose(file);
        return NULL;
    }
    memset(site, 0, sizeof(SiteConfig)); // Initialize all members to 0

    site->num_server_names = 0;
    site->listen_socket_count = 0;
    site->ssl_ctx = NULL; // Will be created if certs are found

    char line[MAX_LINE_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        char *trimmed_line = line;
        // Trim leading whitespace
        while (*trimmed_line == ' ' || *trimmed_line == '\t') {
            trimmed_line++;
        }
        // Remove comments and trailing whitespace
        char *comment_pos = strchr(trimmed_line, '#');
        if (comment_pos != NULL) {
            *comment_pos = '\0';
        }
        size_t len = strlen(trimmed_line);
        while (len > 0 && (trimmed_line[len - 1] == '\n' || trimmed_line[len - 1] == '\r' || trimmed_line[len - 1] == ' ' || trimmed_line[len - 1] == '\t')) {
            trimmed_line[--len] = '\0';
        }

        if (len == 0) {
            continue; // Empty or comment-only line
        }

        char *line_copy = strdup(trimmed_line); // Use a copy for strtok
        if (line_copy == NULL) {
            perror("strdup failed for line_copy in parse_site_file");
            free_site_config(site);
            fclose(file);
            return NULL;
        }

        char *key = strtok(line_copy, " \t");
        if (key == NULL) {
            free(line_copy);
            continue;
        }

        // Get the rest of the line as value by continuing strtok on the same line_copy
        char *value = strtok(NULL, ";"); // This will get everything after the key up to ';' or end of line

        if (value == NULL) {
            fprintf(stderr, "Warning: Invalid directive format in %s: %s\n", filepath, trimmed_line);
            free(line_copy);
            continue;
        }
        // Trim leading/trailing whitespace from value
        while (*value == ' ' || *value == '\t') value++; // Trim leading whitespace
        len = strlen(value); // Recalculate length after trimming leading
        while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\t')) value[--len] = '\0'; // Trim trailing whitespace


        if (strcmp(key, "listen") == 0) {
            if (site->listen_socket_count < MAX_SITE_LISTENERS) {
                ListenSocketConfig new_listen_config;
                // Need a mutable copy of value for strtok in parse_listen_value_into_config
                char *value_copy_for_parse = strdup(value);
                if (value_copy_for_parse == NULL) {
                     perror("strdup failed for listen value_copy");
                     free(line_copy); free_site_config(site); fclose(file); return NULL;
                }
                if (parse_listen_value_into_config(value_copy_for_parse, &new_listen_config)) { // Changed function call
                    // Check global IPv4/IPv6 settings
                    if ((new_listen_config.family == AF_INET6 && !global_config->ipv6_enabled) ||
                        (new_listen_config.family == AF_INET && !global_config->ipv4_enabled)) {
                        fprintf(stderr, "Skipping listen directive '%s' in %s due to global IPv%d setting.\n",
                                trimmed_line, filepath, (new_listen_config.family == AF_INET6 ? 6 : 4));
                    } else {
                        site->listen_sockets[site->listen_socket_count++] = new_listen_config;
                    }
                } else {
                    fprintf(stderr, "Error parsing listen directive: %s in %s\n", value, filepath);
                }
                free(value_copy_for_parse);
            } else {
                fprintf(stderr, "Warning: Too many listen directives for site %s, max %d. Ignoring: %s\n", filepath, MAX_SITE_LISTENERS, trimmed_line);
            }
        } else if (strcmp(key, "server_name") == 0) {
            // Free previous server_name if re-defined
            if (site->server_name != NULL) {
                for (int i = 0; i < site->num_server_names; ++i) {
                    free(site->server_name[i]);
                }
                free(site->server_name);
                site->server_name = NULL;
                site->num_server_names = 0;
            }

            // Count tokens first to allocate array size
            char *temp_value_copy = strdup(value);
            if (temp_value_copy == NULL) { perror("strdup failed for server_name count copy"); free(line_copy); free_site_config(site); fclose(file); return NULL; }
            int count = 0;
            char *token = strtok(temp_value_copy, " \t");
            while (token != NULL) {
                count++;
                token = strtok(NULL, " \t");
            }
            free(temp_value_copy);

            site->server_name = (char**)malloc(count * sizeof(char*));
            if (site->server_name == NULL) { perror("malloc failed for server_name pointers"); free(line_copy); free_site_config(site); fclose(file); return NULL; }
            site->num_server_names = 0;

            char *token_value_copy = strdup(value); // Another copy for actual tokenizing
            if (token_value_copy == NULL) { perror("strdup failed for server_name parse copy"); free(line_copy); free_site_config(site); fclose(file); return NULL; }

            token = strtok(token_value_copy, " \t");
            while (token != NULL && site->num_server_names < count) {
                site->server_name[site->num_server_names] = strdup(token);
                if (site->server_name[site->num_server_names] == NULL) {
                    perror("strdup failed for individual server_name token");
                    // Clean up partially allocated server_name array
                    for(int i = 0; i < site->num_server_names; ++i) free(site->server_name[i]);
                    free(site->server_name);
                    site->server_name = NULL;
                    free(token_value_copy); free(line_copy); free_site_config(site); fclose(file); return NULL;
                }
                site->num_server_names++;
                token = strtok(NULL, " \t");
            }
            free(token_value_copy);
        } else if (strcmp(key, "root") == 0) {
            strncpy(site->root_dir, value, PATH_MAX_LEN - 1);
            site->root_dir[PATH_MAX_LEN - 1] = '\0';
        } else if (strcmp(key, "ssl_certificate") == 0) {
            strncpy(site->site_ssl_cert_file, value, PATH_MAX_LEN - 1);
            site->site_ssl_cert_file[PATH_MAX_LEN - 1] = '\0';
        } else if (strcmp(key, "ssl_key") == 0) {
            strncpy(site->site_ssl_key_file, value, PATH_MAX_LEN - 1);
            site->site_ssl_key_file[PATH_MAX_LEN - 1] = '\0';
        } else if (strcmp(key, "ssl_chain") == 0) {
            strncpy(site->site_ssl_chain_file, value, PATH_MAX_LEN - 1);
            site->site_ssl_chain_file[PATH_MAX_LEN - 1] = '\0';
        } else {
            fprintf(stderr, "Warning: Unhandled directive '%s' in file %s\n", key, filepath);
        }
        free(line_copy);
    }
    fclose(file);

    // If no server_name was specified, default to "_"
    if (site->num_server_names == 0) {
        site->server_name = (char**)malloc(sizeof(char*));
        if (site->server_name == NULL) { perror("malloc failed for default server_name"); free_site_config(site); return NULL; }
        site->server_name[0] = strdup("_");
        if (site->server_name[0] == NULL) { perror("strdup failed for default server_name"); free_site_config(site); return NULL; }
        site->num_server_names = 1;
    }

    // Load SSL_CTX for the site if certificate paths are present
    if (strlen(site->site_ssl_cert_file) > 0 && strlen(site->site_ssl_key_file) > 0) {
        site->ssl_ctx = create_ssl_context(site->site_ssl_cert_file, site->site_ssl_key_file, site->site_ssl_chain_file);
        if (site->ssl_ctx == NULL) {
            fprintf(stderr, "Error loading SSL context for site from %s. Make sure certificate files exist and are valid.\n", filepath);
            // Optionally, set a flag or disable site if SSL context fails to load
        }
    }

    return site;
}

// Function to read all site configurations from a directory
// This function now populates the global_listeners structure
void read_all_site_configs(const char *sites_dir_path, GlobalConfig *global_config, GlobalListenConfig *global_listeners_ptr) {
    DIR *d;
    struct dirent *dir;
    char filepath[PATH_MAX_LEN];

    d = opendir(sites_dir_path);
    if (!d) {
        perror("Failed to open sites-enabled directory");
        return;
    }

    // First pass: Parse all site config files into a temporary array
    num_total_parsed_sites = 0;
    while ((dir = readdir(d)) != NULL) {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", sites_dir_path, dir->d_name);

        struct stat st;
        if (stat(filepath, &st) == -1 || !S_ISREG(st.st_mode)) {
            continue; // Skip directories and non-regular files
        }

        SiteConfig *site = parse_site_file(filepath, global_config);
        if (site != NULL) {
            if (num_total_parsed_sites < (sizeof(all_parsed_sites) / sizeof(all_parsed_sites[0]))) {
                all_parsed_sites[num_total_parsed_sites++] = site;
            } else {
                fprintf(stderr, "Warning: Max parsed sites capacity reached. Ignoring %s\n", filepath);
                free_site_config(site); // Free if not stored
            }
        }
    }
    closedir(d);

    if (num_total_parsed_sites == 0) {
        fprintf(stderr, "No site configurations found in '%s'.\n", sites_dir_path);
        return;
    }

    // Second pass: Aggregate SiteConfigs into GlobalListenConfig
    // This handles port reuse by associating multiple sites with a single ListenSocket
    global_listeners_ptr->count = 0;
    for (int i = 0; i < num_total_parsed_sites; ++i) {
        SiteConfig *current_site = all_parsed_sites[i];

        if (current_site->listen_socket_count == 0) {
            fprintf(stderr, "Warning: Site '%s' (root: %s) has no 'listen' directives. It will not be served.\n", filepath, current_site->root_dir);
            continue;
        }

        for (int j = 0; j < current_site->listen_socket_count; ++j) {
            ListenSocketConfig *site_listen_cfg = &current_site->listen_sockets[j];
            bool found_existing_listener = false;

            // Check if this (address, port, ssl_enabled, family) listener already exists
            for (int k = 0; k < global_listeners_ptr->count; ++k) {
                ListenSocket *existing_ls = &global_listeners_ptr->sockets[k];
                if (strcmp(existing_ls->config.address, site_listen_cfg->address) == 0 &&
                    existing_ls->config.port == site_listen_cfg->port &&
                    existing_ls->config.ssl_enabled == site_listen_cfg->ssl_enabled &&
                    existing_ls->config.family == site_listen_cfg->family) {

                    // Found existing listener, add this site to its sites array
                    if (existing_ls->site_count < MAX_SITES_PER_LISTENER) {
                        existing_ls->sites = (SiteConfig**)realloc(existing_ls->sites, (existing_ls->site_count + 1) * sizeof(SiteConfig*));
                        if (existing_ls->sites == NULL) { perror("realloc failed for existing listener sites"); exit(EXIT_FAILURE); }
                        existing_ls->sites[existing_ls->site_count++] = current_site;
                        found_existing_listener = true;
                    } else {
                        fprintf(stderr, "Warning: Listener %s:%d (SSL: %s) reached max sites (%d). Ignoring site from %s.\n",
                                site_listen_cfg->address, site_listen_cfg->port, site_listen_cfg->ssl_enabled ? "true" : "false",
                                MAX_SITES_PER_LISTENER, filepath);
                    }
                    break;
                }
            }

            if (!found_existing_listener) {
                // Create a new ListenSocket
                if (global_listeners_ptr->count >= MAX_LISTEN_SOCKETS) {
                    fprintf(stderr, "Error: Max unique listen sockets (%d) reached. Cannot add more listeners.\n", MAX_LISTEN_SOCKETS);
                    continue;
                }
                ListenSocket *new_ls = &global_listeners_ptr->sockets[global_listeners_ptr->count];
                memset(new_ls, 0, sizeof(ListenSocket)); // Initialize new_ls
                new_ls->config = *site_listen_cfg; // Copy the ListenSocketConfig
                new_ls->sites = (SiteConfig**)malloc(sizeof(SiteConfig*)); // Allocate for first site
                if (new_ls->sites == NULL) { perror("malloc failed for new listener sites"); exit(EXIT_FAILURE); }
                new_ls->sites[0] = current_site;
                new_ls->site_count = 1;

                // Initialize listener-level SSL_CTX if SSL enabled
                if (new_ls->config.ssl_enabled) {
                    // This listener-level SSL_CTX primarily manages SNI callbacks.
                    // It doesn't load specific certs from files; those are in SiteConfig.ssl_ctx.
                    new_ls->listener_ssl_ctx = SSL_CTX_new(TLS_server_method());
                    if (new_ls->listener_ssl_ctx == NULL) {
                        ERR_print_errors_fp(stderr);
                        fprintf(stderr, "Error creating listener SSL_CTX for %s:%d\n", new_ls->config.address, new_ls->config.port);
                        new_ls->config.ssl_enabled = false; // Disable SSL for this listener if context creation fails
                    } else {
                        // Set the SNI callback for this listener. The 'arg' will be a pointer to this ListenSocket.
                        SSL_CTX_set_tlsext_servername_callback(new_ls->listener_ssl_ctx, sni_callback);
                        SSL_CTX_set_tlsext_servername_arg(new_ls->listener_ssl_ctx, new_ls);
                    }
                }

                global_listeners_ptr->count++;
            }
        }
    }
}


// Function to create an SSL context (for a SiteConfig's specific certificate)
SSL_CTX *create_ssl_context(const char *cert_file, const char *key_file, const char *chain_file) {
    SSL_CTX *ctx;

    // Initialize SSL library if not already (redundant if main does it, but safer)
    SSL_library_init();
    SSL_load_error_strings();
    // ERR_load_BIO_strings(); // Deprecated in OpenSSL 3.0, removed
    OpenSSL_add_all_algorithms();

    // Use TLS_server_method for general purpose server SSL/TLS
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Load server certificate
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Load certificate chain if provided
    if (chain_file != NULL && strlen(chain_file) > 0) {
        if (SSL_CTX_use_certificate_chain_file(ctx, chain_file) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Warning: Could not load certificate chain file %s\n", chain_file);
            // This might not be a fatal error, depending on policy
        }
    }

    // Recommended security options (disable old, insecure protocols)
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    // Use SSL_CTX_set_cipher_list for setting ciphers for TLSv1.2 and earlier
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!DSS:!RC4:!MD5:!EXP:!LOW:!NULL:!eNULL:!DES:!3DES:!ADH:!AECDH") <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error setting cipher list.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

// Function to free allocated SiteConfig memory
void free_site_config(SiteConfig *site) {
    if (site == NULL) return;

    if (site->server_name != NULL) {
        for (int i = 0; i < site->num_server_names; ++i) {
            if (site->server_name[i] != NULL) {
                free(site->server_name[i]);
            }
        }
        free(site->server_name);
    }
    if (site->ssl_ctx) {
        SSL_CTX_free(site->ssl_ctx);
    }
    free(site);
}

// Function to free allocated ListenSocket memory
void free_listen_socket(ListenSocket *ls) {
    if (ls == NULL) return;
    if (ls->sites) {
        // Only free the array of pointers, not the SiteConfig themselves
        // because SiteConfigs are managed by all_parsed_sites array
        free(ls->sites);
    }
    if (ls->listener_ssl_ctx) {
        SSL_CTX_free(ls->listener_ssl_ctx);
    }
    // Note: sock_fd is closed in main loop, not here
}

// Function to free all global ListenSocket and SiteConfig memory
void free_global_listeners(GlobalListenConfig *listeners) {
    for (int i = 0; i < listeners->count; ++i) {
        free_listen_socket(&listeners->sockets[i]);
    }
    // Free all SiteConfig objects that were parsed
    for (int i = 0; i < num_total_parsed_sites; ++i) {
        free_site_config(all_parsed_sites[i]);
    }
    num_total_parsed_sites = 0; // Reset count
}


// Function to parse global configuration settings (e.g., worker user, IPv4/IPv6 enabled)
void parse_global_config(const char *filepath, GlobalConfig *config) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Error opening global config file");
        fprintf(stderr, "Could not open global config file: %s. Using default settings.\n", filepath);
        return; // Use default values
    }

    char line[MAX_LINE_SIZE];
    config->specified = true; // Mark that a config file was processed

    while (fgets(line, sizeof(line), file) != NULL) {
        char *trimmed_line = line;
        while (*trimmed_line == ' ' || *trimmed_line == '\t') trimmed_line++;
        char *comment_pos = strchr(trimmed_line, '#');
        if (comment_pos != NULL) *comment_pos = '\0';
        size_t len = strlen(trimmed_line);
        while (len > 0 && (trimmed_line[len - 1] == '\n' || trimmed_line[len - 1] == '\r' || trimmed_line[len - 1] == ' ' || trimmed_line[len - 1] == '\t')) trimmed_line[--len] = '\0';
        if (len == 0) continue;

        char *line_copy = strdup(trimmed_line);
        if (line_copy == NULL) { perror("strdup failed"); fclose(file); return; }
        char *key = strtok(line_copy, " \t");
        if (key == NULL) { free(line_copy); continue; }
        char *value = strtok(NULL, ";");
        if (value == NULL) { fprintf(stderr, "Warning: Invalid directive format: %s\n", trimmed_line); free(line_copy); continue; }
        while (*value == ' ' || *value == '\t') value++;

        if (strcmp(key, "ipv4") == 0) {
            config->ipv4_enabled = (strcmp(value, "on") == 0);
        } else if (strcmp(key, "ipv6") == 0) {
            config->ipv6_enabled = (strcmp(value, "on") == 0);
        } else if (strcmp(key, "worker_user") == 0) {
            strncpy(config->worker_user, value, MAX_LINE_SIZE - 1);
            config->worker_user[MAX_LINE_SIZE - 1] = '\0';
        } else {
            fprintf(stderr, "Warning: Unhandled global config directive: %s\n", trimmed_line);
        }
        free(line_copy);
    }
    fclose(file);
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    // Initialize OpenSSL library (should be done once at application startup)
    SSL_library_init();
    SSL_load_error_strings();
    // OpenSSL_add_all_algorithms(); // Not strictly necessary with newer OpenSSL for general use

    // --- Global Config Parsing ---
    GlobalConfig global_config = {true, true, "nobody", false}; // Default values

    char global_config_filepath[PATH_MAX_LEN];
    if (argc > 1) {
        strncpy(global_config_filepath, argv[1], PATH_MAX_LEN - 1);
        global_config_filepath[PATH_MAX_LEN - 1] = '\0';
    } else {
        strncpy(global_config_filepath, GLOBAL_CONFIG_PATH, PATH_MAX_LEN - 1);
        global_config_filepath[PATH_MAX_LEN - 1] = '\0';
    }
    parse_global_config(global_config_filepath, &global_config);

    // --- Read All Site Configurations and Build Global Listeners ---
    GlobalListenConfig current_global_listeners;
    memset(&current_global_listeners, 0, sizeof(GlobalListenConfig)); // Initialize it
    read_all_site_configs(SITES_DIR_PATH, &global_config, &current_global_listeners);

    if (current_global_listeners.count == 0) {
        fprintf(stderr, "No active listeners configured. Exiting.\n");
        return EXIT_FAILURE;
    }

    // --- Drop Privileges ---
    if (global_config.specified && strlen(global_config.worker_user) > 0) {
        struct passwd *pw = getpwnam(global_config.worker_user);
        if (pw) {
            if (setgid(pw->pw_gid) != 0) {
                perror("setgid failed");
                return EXIT_FAILURE;
            }
            if (setuid(pw->pw_uid) != 0) {
                perror("setuid failed");
                return EXIT_FAILURE;
            }
            printf("Dropped privileges to user '%s' (UID: %d, GID: %d)\n",
                   global_config.worker_user, (int)pw->pw_uid, (int)pw->pw_gid);
        } else {
            fprintf(stderr, "Warning: Worker user '%s' not found. Running as current user.\n", global_config.worker_user);
        }
    } else {
        // Fallback to nobody if no user specified or config not found
        // Make sure nobody user exists (UID 65534 on many Linux systems)
        if (setgid(65534) != 0) { perror("setgid failed for nobody"); /* not critical */ }
        if (setuid(65534) != 0) { perror("setuid failed for nobody"); /* not critical */ }
        printf("Dropped privileges to user 'nobody' (UID: 65534, GID: 65534) (fallback)\n");
    }

    // --- Create and Bind Sockets ---
    struct pollfd *poll_fds = calloc(current_global_listeners.count, sizeof(struct pollfd));
    if (poll_fds == NULL) { perror("calloc failed for poll_fds"); return EXIT_FAILURE; }

    // Store socket FDs directly in ListenSocket for easier cleanup
    for (int i = 0; i < current_global_listeners.count; ++i) {
        ListenSocket *current_ls = &current_global_listeners.sockets[i];
        int sock_fd = -1;
        int opt = 1;

        if (current_ls->config.family == AF_INET) {
            sock_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (sock_fd == -1) { perror("IPv4 socket creation failed"); current_ls->sock_fd = -1; continue; }

            if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                perror("setsockopt SO_REUSEADDR failed for IPv4"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }
            if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) { // Enable SO_REUSEPORT for true port reuse
                perror("setsockopt SO_REUSEPORT failed for IPv4"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }

            struct sockaddr_in server_addr_in;
            memset(&server_addr_in, 0, sizeof(server_addr_in));
            server_addr_in.sin_family = AF_INET;
            server_addr_in.sin_port = htons(current_ls->config.port);
            if (inet_pton(AF_INET, current_ls->config.address, &server_addr_in.sin_addr) <= 0) {
                perror("Invalid IPv4 address for pton"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }

            if (bind(sock_fd, (struct sockaddr *)&server_addr_in, sizeof(server_addr_in)) < 0) {
                perror("IPv4 bind failed"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }
            printf("Listening on %s:%d %s (Socket FD: %d)\n", current_ls->config.address, current_ls->config.port,
                   current_ls->config.ssl_enabled ? "SSL" : "HTTP", sock_fd);

        } else if (current_ls->config.family == AF_INET6) {
            sock_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (sock_fd == -1) { perror("IPv6 socket creation failed"); current_ls->sock_fd = -1; continue; }

            if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                perror("setsockopt SO_REUSEADDR failed for IPv6"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }
            if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) { // Enable SO_REUSEPORT for true port reuse
                perror("setsockopt SO_REUSEPORT failed for IPv6"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }
            // For IPv6, explicitly disable IPv4-mapped addresses if not requested
            // int v6only = 1;
            // if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
            //     perror("setsockopt IPV6_V6ONLY failed"); close(sock_fd); current_ls->sock_fd = -1; continue;
            

            struct sockaddr_in6 server_addr_in6;
            memset(&server_addr_in6, 0, sizeof(server_addr_in6));
            server_addr_in6.sin6_family = AF_INET6;
            server_addr_in6.sin6_port = htons(current_ls->config.port);
            if (inet_pton(AF_INET6, current_ls->config.address, &server_addr_in6.sin6_addr) <= 0) {
                perror("Invalid IPv6 address for pton"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }

            if (bind(sock_fd, (struct sockaddr *)&server_addr_in6, sizeof(server_addr_in6)) < 0) {
                perror("IPv6 bind failed"); close(sock_fd); current_ls->sock_fd = -1; continue;
            }
            printf("Listening on [%s]:%d %s (Socket FD: %d)\n", current_ls->config.address, current_ls->config.port,
                   current_ls->config.ssl_enabled ? "SSL" : "HTTP", sock_fd);
        } else {
             fprintf(stderr, "Unknown address family for listener at index %d.\n", i);
             current_ls->sock_fd = -1;
             continue;
        }

        if (listen(sock_fd, 50) < 0) { // Max 50 pending connections
            perror("listen failed"); close(sock_fd); current_ls->sock_fd = -1; continue;
        }

        current_ls->sock_fd = sock_fd; // Store the actual socket FD in the ListenSocket struct
        poll_fds[i].fd = sock_fd;
        poll_fds[i].events = POLLIN;

        // Print site info associated with this listener for debugging
        printf("  Associated Sites (%d): \n", current_ls->site_count);
        for(int s_idx = 0; s_idx < current_ls->site_count; ++s_idx) {
            printf("    - Root: %s, Server Names: ", current_ls->sites[s_idx]->root_dir);
            for(int sn_idx = 0; sn_idx < current_ls->sites[s_idx]->num_server_names; ++sn_idx) {
                printf("%s%s", current_ls->sites[s_idx]->server_name[sn_idx], (sn_idx == current_ls->sites[s_idx]->num_server_names - 1) ? "" : ",");
            }
            printf("\n");
        }
        printf("--------------------------------------------------\n");
    }

    // Filter out failed sockets from poll_fds
    int active_listeners_count = 0;
    for(int i = 0; i < current_global_listeners.count; ++i) {
        if (current_global_listeners.sockets[i].sock_fd != -1) {
            poll_fds[active_listeners_count] = (struct pollfd){
                .fd = current_global_listeners.sockets[i].sock_fd,
                .events = POLLIN,
                .revents = 0
            };
            active_listeners_count++;
        } else {
            // Free SSL_CTX if listener failed to bind
            if (current_global_listeners.sockets[i].listener_ssl_ctx) {
                SSL_CTX_free(current_global_listeners.sockets[i].listener_ssl_ctx);
                current_global_listeners.sockets[i].listener_ssl_ctx = NULL;
            }
        }
    }
    if (active_listeners_count == 0) {
        fprintf(stderr, "No active listener sockets after binding. Exiting.\n");
        free(poll_fds);
        free_global_listeners(&current_global_listeners); // Free all allocated memory
        return EXIT_FAILURE;
    }


    // --- Main Server Loop ---
    printf("CUI Threaded HTTP/HTTPS Listener running with %d active listeners.\n", active_listeners_count);
    printf("Press Ctrl+C to stop the server\n");

    while (1) {
        int poll_count = poll(poll_fds, active_listeners_count, -1); // Wait indefinitely

        if (poll_count < 0) {
            if (errno == EINTR) continue; // Interrupted by signal
            perror("poll failed");
            break;
        }

        for (int i = 0; i < active_listeners_count; ++i) {
            if (poll_fds[i].revents & POLLIN) {
                struct sockaddr_storage client_addr; // Declare client_addr here
                socklen_t client_addr_len = sizeof(client_addr); // Initialize length

                int new_socket = accept(poll_fds[i].fd, (struct sockaddr *)&client_addr, &client_addr_len);
                if (new_socket < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue; // No pending connections, non-blocking
                    }
                    perror("accept failed");
                    continue;
                }

                ClientThreadArgs *thread_args = malloc(sizeof(ClientThreadArgs));
                if (thread_args == NULL) {
                    perror("malloc failed for thread arguments");
                    close(new_socket);
                    continue;
                }
                thread_args->sock = new_socket;
                // Copy the client address information
                thread_args->remote_addr = client_addr;
                thread_args->remote_addr_len = client_addr_len;

                // Find the correct ListenSocket from global_listeners based on fd
                thread_args->listener_socket = NULL;
                for(int j = 0; j < current_global_listeners.count; ++j) {
                    if (current_global_listeners.sockets[j].sock_fd == poll_fds[i].fd) {
                        thread_args->listener_socket = &current_global_listeners.sockets[j];
                        break;
                    }
                }

                if (thread_args->listener_socket == NULL) {
                    fprintf(stderr, "Error: Could not find ListenSocket for FD %d. Closing client connection.\n", poll_fds[i].fd);
                    free(thread_args);
                    close(new_socket);
                    continue;
                }

                pthread_t client_thread;
                if (pthread_create(&client_thread, NULL, handle_client, (void*) thread_args) < 0) {
                    perror("could not create thread");
                    close(new_socket);
                    free(thread_args);
                    continue;
                }
                pthread_detach(client_thread); // Detach thread to auto-clean resources
            }
            if (poll_fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                 fprintf(stderr, "Error or hangup on listener socket %d (FD: %d)\n", i, poll_fds[i].fd);
            }
        }
    }

    printf("\nServer shutting down...\n");

    // --- Cleanup ---
    for (int i = 0; i < current_global_listeners.count; i++) {
        if (current_global_listeners.sockets[i].sock_fd != -1) {
            close(current_global_listeners.sockets[i].sock_fd);
        }
    }

    free(poll_fds);
    free_global_listeners(&current_global_listeners); // Free all allocated memory (sites and listeners)
    ERR_free_strings();
    EVP_cleanup();
    
    return EXIT_SUCCESS;
}
