// client.c
#include "client.h" // Include our own header (which now includes parser.h)
#include <stdio.h>
#include <stdlib.h> // For malloc, free, perror
#include <string.h> // For memset, strlen, strstr, strchr, strncpy, strcmp, strcpy
#include <unistd.h> // For close, read, write
#include <pthread.h> // For pthread_exit
#include <errno.h>        // For errno
#include <fcntl.h>        // For fcntl (setting non-blocking) - though select is used for timeout
#include <sys/time.h>     // For struct timeval
#include <openssl/err.h>  // For SSL_get_error and ERR_print_errors_fp
#include <arpa/inet.h>    // For inet_ntop
#include <netinet/in.h>   // For sockaddr_in, sockaddr_in6
#include <sys/socket.h>   // For getsockname, setsockopt, SOL_SOCKET, SO_RCVTIMEO


// Function to find a site based on hostname
// This will be used by both SNI callback and HTTP Host header parsing
SiteConfig* find_site_for_hostname(ListenSocket *listener, const char *hostname) {
    SiteConfig *default_site = NULL;

    for (int i = 0; i < listener->site_count; ++i) {
        SiteConfig *current_site = listener->sites[i];
        for (int j = 0; j < current_site->num_server_names; ++j) {
            // Exact match
            if (strcmp(current_site->server_name[j], hostname) == 0) {
                return current_site;
            }
            // Default site fallback (the "_" server_name)
            if (strcmp(current_site->server_name[j], "_") == 0) {
                default_site = current_site;
            }
        }
    }
    // No exact match found, return default site if available
    return default_site;
}


// SNI callback for OpenSSL
// This function is called by OpenSSL during the TLS handshake when a server name is received.
int sni_callback(SSL *ssl, int *ad, void *arg) {
    ListenSocket *listener = (ListenSocket *)arg; // Retrieve the ListenSocket pointer passed during setup
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (servername) {
        fprintf(stderr, "SNI callback: Client requested server name: %s\n", servername);
        SiteConfig *matched_site = find_site_for_hostname(listener, servername);

        if (matched_site && matched_site->ssl_ctx) {
            // Successfully found a site with a loaded SSL context for this hostname
            SSL_set_SSL_CTX(ssl, matched_site->ssl_ctx); // Set the correct SSL_CTX for this connection
            fprintf(stderr, "SNI callback: Switched SSL_CTX for hostname %s.\n", servername);
            return SSL_TLSEXT_ERR_OK; // Indicate success
        } else {
            fprintf(stderr, "SNI callback: No matching site or SSL_CTX found for hostname %s. Using default or failing.\n", servername);
            return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context
        }
    }
    // No server name provided by client, or an error from SSL_get_servername
    return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context
}


// Function to handle a single client connection
void *handle_client(void *thread_args_ptr) {
    ClientThreadArgs *args = (ClientThreadArgs*) thread_args_ptr;
    int sock = args->sock;
    ListenSocket *listener = args->listener_socket; // Pointer to the ListenSocket this connection came from
    struct sockaddr_storage remote_addr = args->remote_addr; // Copy remote address
    socklen_t remote_addr_len = args->remote_addr_len; // Copy remote address length
    free(thread_args_ptr); // Free the dynamically allocated thread arguments

    SSL *ssl = NULL;
    bool use_ssl = listener->config.ssl_enabled;
    SiteConfig *active_site = NULL; // This will hold the dynamically selected SiteConfig

    // --- Allocate buffers on the heap to avoid stack overflow ---
    // MAX_REQUEST_SIZE for request buffer (for headers, POST body will be handled by parser)
    // CACHE_SIZE (from parser.h) for response buffer (to hold full response including file content)
    char *request_buffer = (char *)malloc(MAX_REQUEST_SIZE + 1); // +1 for null terminator
    char *response_buffer = (char *)malloc(MAX_REQUEST_SIZE+CACHE_SIZE); 

    if (!request_buffer) {
        perror("Failed to allocate request_buffer in handle_client");
        close(sock);
        pthread_exit(NULL);
    }
    if (!response_buffer) {
        perror("Failed to allocate response_buffer in handle_client");
        free(request_buffer); // Clean up already allocated request buffer
        close(sock);
        pthread_exit(NULL);
    }
    
    // Initialize buffers to zero
    memset(request_buffer, 0, MAX_REQUEST_SIZE + 1);
    memset(response_buffer, 0, MAX_REQUEST_SIZE+CACHE_SIZE);

    size_t actual_response_len = 0; // This will be filled by HandleRequest


    // --- PERFORM SSL HANDSHAKE IMMEDIATELY IF SSL IS ENABLED ---
    if (use_ssl) {
        // Use the listener's SSL_CTX for the initial handshake.
        // SNI callback will switch to site-specific SSL_CTX if needed.
        ssl = SSL_new(listener->listener_ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Error creating SSL object for socket %d.\n", sock);
            close(sock);
            free(request_buffer); // Clean up
            free(response_buffer); // Clean up
            pthread_exit(NULL);
        }
        SSL_set_fd(ssl, sock);

        if (SSL_accept(ssl) <= 0) {
            // Handle SSL handshake failure (e.g., client sent plain HTTP to HTTPS port, or bad certificate negotiation)
            int ssl_err = SSL_get_error(ssl, -1);
            fprintf(stderr, "SSL handshake failed for socket %d. Error: %d\n", sock, ssl_err);
            ERR_print_errors_fp(stderr); // Print OpenSSL error stack
            close(sock);
            SSL_free(ssl);
            free(request_buffer); // Clean up
            free(response_buffer); // Clean up
            pthread_exit(NULL);
        }
        fprintf(stderr, "SSL handshake successful for socket %d.\n", sock);
    }
    // --- END SSL HANDSHAKE ---


    // --- Read the HTTP Request (using SSL_read or read) ---
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;

    // Set a receive timeout to prevent blocking indefinitely
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 second timeout
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);

    while (total_bytes_received < MAX_REQUEST_SIZE - 1) {
        if (use_ssl) {
            bytes_received = SSL_read(ssl, request_buffer + total_bytes_received, MAX_REQUEST_SIZE - 1 - total_bytes_received);
        } else {
            bytes_received = read(sock, request_buffer + total_bytes_received, MAX_REQUEST_SIZE - 1 - total_bytes_received);
        }

        if (bytes_received < 0) {
            if (use_ssl) {
                int ssl_err = SSL_get_error(ssl, bytes_received);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    continue; // Non-blocking SSL_read, data not ready yet
                }
                fprintf(stderr, "SSL_read error for socket %d, error: %d\n", sock, ssl_err);
                ERR_print_errors_fp(stderr);
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; // Non-blocking read, data not ready yet
                }
                if (errno == ETIMEDOUT) { // Handle read timeout
                    fprintf(stderr, "Read timeout for socket %d.\n", sock);
                    break;
                }
                perror("read error");
            }
            break; // Break on fatal read error
        }
        if (bytes_received == 0) {
            // Client closed connection
            fprintf(stderr, "Client closed connection on socket %d.\n", sock);
            break;
        }

        total_bytes_received += bytes_received;
        request_buffer[total_bytes_received] = '\0'; // Null-terminate the buffer

        // Check for end of HTTP headers (empty line)
        if (total_bytes_received >= 4) {
            if (strstr(request_buffer, "\r\n\r\n") != NULL) {
                break; // End of headers found
            }
        }
    }

    if (total_bytes_received == 0) {
        fprintf(stderr, "No data received or connection closed immediately for socket %d.\n", sock);
        if (use_ssl) SSL_free(ssl);
        close(sock);
        free(request_buffer); // Clean up
        free(response_buffer); // Clean up
        pthread_exit(NULL);
    }

    // --- Determine Active Site based on Host header (HTTP and HTTPS after handshake) ---
    char *host_header_start = strstr(request_buffer, "\r\nHost: ");
    char hostname[MAX_LINE_SIZE] = {0};
    if (host_header_start) {
        host_header_start += strlen("\r\nHost: ");
        char *host_header_end = strchr(host_header_start, '\r');
        if (host_header_end) {
            strncpy(hostname, host_header_start, host_header_end - host_header_start);
            hostname[host_header_end - host_header_start] = '\0';
        }
    }

    if (strlen(hostname) > 0) {
        active_site = find_site_for_hostname(listener, hostname);
        if (active_site) {
            fprintf(stderr, "Selected site for Host '%s': %s (root: %s)\n", hostname, active_site->server_name[0], active_site->root_dir);
        } else {
            fprintf(stderr, "No specific site found for Host '%s'. Attempting to use default site if any.\n", hostname);
        }
    }

    // Fallback to the first site associated with this listener if no Host header or no match
    if (active_site == NULL && listener->site_count > 0) {
        active_site = listener->sites[0]; // Use the first site as a default if no Host header or no match
        fprintf(stderr, "Using default/first associated site: %s (root: %s)\n", active_site->server_name[0], active_site->root_dir);
    } else if (active_site == NULL) {
        fprintf(stderr, "Error: No site configured for this listener! Cannot serve request on socket %d.\n", sock);
        const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nNo site configured for this port.";
        if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
        else write(sock, error_response, strlen(error_response));
        if (use_ssl) SSL_free(ssl);
        close(sock);
        free(request_buffer); // Clean up
        free(response_buffer); // Clean up
        pthread_exit(NULL);
    }

    // --- NEW: Prepare ServerInfo for HandleRequest ---
    ServerInfo *server_info = (ServerInfo*)malloc(sizeof(ServerInfo));
    if (server_info == NULL) {
        perror("malloc failed for ServerInfo in client.c");
        // Handle error, send 500 or exit thread
        const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nServer out of memory.";
        if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
        else write(sock, error_response, strlen(error_response));
        if (use_ssl) SSL_free(ssl);
        close(sock);
        free(request_buffer); // Clean up
        free(response_buffer); // Clean up
        pthread_exit(NULL);
    }
    memset(server_info, 0, sizeof(ServerInfo));

    // Get server IP and port (local address of the listener socket)
    char server_ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);

    if (getsockname(listener->sock_fd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
        if (local_addr.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&local_addr)->sin_addr, server_ip_str, sizeof(server_ip_str));
            server_info->server_port = ntohs(((struct sockaddr_in*)&local_addr)->sin_port);
        } else if (local_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&local_addr)->sin6_addr, server_ip_str, sizeof(server_ip_str));
            server_info->server_port = ntohs(((struct sockaddr_in6*)&local_addr)->sin6_port);
        } else {
            strcpy(server_ip_str, "N/A");
            server_info->server_port = 0;
        }
        server_info->server_ip = strdup(server_ip_str); // Duplicate for parser.c to free
        if (!server_info->server_ip) {
            perror("strdup failed for server_ip in client.c");
            // Handle error, send 500 or exit thread
            const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nServer out of memory.";
            if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
            else write(sock, error_response, strlen(error_response));
            if (use_ssl) SSL_free(ssl);
            close(sock);
            free(request_buffer);
            free(response_buffer);
            free(server_info); // Free server_info if strdup failed
            pthread_exit(NULL);
        }
    } else {
        perror("getsockname failed for server IP in client.c");
        server_info->server_ip = strdup("N/A");
        server_info->server_port = 0;
        if (!server_info->server_ip) { // Check strdup failure even for N/A
            perror("strdup failed for server_ip N/A in client.c");
            // Handle error, send 500 or exit thread
            const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nServer out of memory.";
            if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
            else write(sock, error_response, strlen(error_response));
            if (use_ssl) SSL_free(ssl);
            close(sock);
            free(request_buffer);
            free(response_buffer);
            free(server_info); // Free server_info if strdup failed
            pthread_exit(NULL);
        }
    }

    // Get remote IP and port (client's address)
    char remote_ip_str[INET6_ADDRSTRLEN];
    if (remote_addr_len > 0) { // Check if remote_addr was successfully populated
        if (remote_addr.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)&remote_addr)->sin_addr, remote_ip_str, sizeof(remote_ip_str));
            server_info->remote_port = ntohs(((struct sockaddr_in*)&remote_addr)->sin_port);
        } else if (remote_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)&remote_addr)->sin6_addr, remote_ip_str, sizeof(remote_ip_str));
            server_info->remote_port = ntohs(((struct sockaddr_in6*)&remote_addr)->sin6_port);
        } else {
            strcpy(remote_ip_str, "N/A");
            server_info->remote_port = 0;
        }
        server_info->remote_ip = strdup(remote_ip_str); // Duplicate for parser.c to free
        if (!server_info->remote_ip) {
            perror("strdup failed for remote_ip in client.c");
            // Handle error, send 500 or exit thread
            const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nServer out of memory.";
            if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
            else write(sock, error_response, strlen(error_response));
            if (use_ssl) SSL_free(ssl);
            close(sock);
            free(request_buffer);
            free(response_buffer);
            free(server_info->server_ip); // Free server_ip if it was allocated
            free(server_info); // Free server_info if strdup failed
            pthread_exit(NULL);
        }
    } else {
        server_info->remote_ip = strdup("N/A");
        server_info->remote_port = 0;
        if (!server_info->remote_ip) { // Check strdup failure even for N/A
            perror("strdup failed for remote_ip N/A in client.c");
            // Handle error, send 500 or exit thread
            const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nServer out of memory.";
            if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
            else write(sock, error_response, strlen(error_response));
            if (use_ssl) SSL_free(ssl);
            close(sock);
            free(request_buffer);
            free(response_buffer);
            free(server_info->server_ip); // Free server_ip if it was allocated
            free(server_info); // Free server_info if strdup failed
            pthread_exit(NULL);
        }
    }
    
    server_info->root_dir = active_site->root_dir; // This is a pointer, not a copy. Ownership remains with SiteConfig.
    server_info->default_page = active_site->default_page; 
    server_info->num_default_page = active_site->num_default_page;
    server_info->server_name = active_site->server_name;
    server_info->num_server_names = active_site->num_server_names;
    // --- END NEW ---


    // --- Prepare and Send the HTTP Response (using SSL_write or write) ---
    // HandleRequest now receives ServerInfo* directly
    HandleRequest(server_info, total_bytes_received, request_buffer,
                &actual_response_len, response_buffer);

    // server_info and its strdup'd members are freed by free_request_members in parser.c
    // Note: response_buffer is now heap-allocated in this function and will be freed here.

    if (use_ssl) {
        if (SSL_write(ssl, response_buffer, actual_response_len) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "SSL_write error for socket %d.\\n", sock);
        }
    } else {
        if (write(sock, response_buffer, actual_response_len) <= 0) {
            perror("write error");
        }
    }

    // --- Shutdown and Cleanup ---
    if (use_ssl) {
        SSL_shutdown(ssl); // Perform graceful SSL shutdown
        SSL_free(ssl);     // Free the SSL object
    }
    close(sock); // Close the underlying socket

    // Free heap-allocated buffers
    free(request_buffer);
    free(response_buffer);

    pthread_exit(NULL); // Exit the thread
}
