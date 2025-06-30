// client.c
#include "client.h" // Include our own header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>        // For errno
#include <openssl/err.h>  // For SSL_get_error and ERR_print_errors_fp

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
            // Default site fallback
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
            fprintf(stderr, "SNI callback: No matching site or SSL_CTX found for hostname %s. Using default.\n", servername);
            // Optionally, return SSL_TLSEXT_ERR_NOACK or SSL_TLSEXT_ERR_ALERT_FATAL if strict
            return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context if set, or proceed
        }
    }
    // No server name provided by client, or an error
    return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context
}


// Function to handle a single client connection
void *handle_client(void *thread_args_ptr) {
    ClientThreadArgs *args = (ClientThreadArgs*) thread_args_ptr;
    int sock = args->sock;
    ListenSocket *listener = args->listener_socket; // Pointer to the ListenSocket this connection came from
    free(thread_args_ptr); // Free the dynamically allocated thread arguments

    SSL *ssl = NULL;
    bool use_ssl = listener->config.ssl_enabled;
    SiteConfig *active_site = NULL; // This will hold the dynamically selected SiteConfig

    char response_buffer[MAX_REQUEST_SIZE + BUFFER_SIZE]; // Give some extra room for headers
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
            pthread_exit(NULL);
        }
        fprintf(stderr, "SSL handshake successful for socket %d.\n", sock);
        // After handshake, the SSL object *might* have been switched to a site-specific SSL_CTX
        // We can get the active SSL_CTX from the SSL object itself.
        // For simplicity, we'll rely on find_site_for_hostname based on Host header for now,
        // but a more robust SNI implementation might pass a reference to the selected SiteConfig
        // directly from the SNI callback to handle_client.
    }
    // --- END SSL HANDSHAKE ---


    // --- Read the HTTP Request (using SSL_read or read) ---
    char request_buffer[MAX_REQUEST_SIZE] = {0};
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;

    // Set socket to non-blocking for a short period to avoid blocking indefinitely
    // fcntl(sock, F_SETFL, O_NONBLOCK); // This is usually done for poll/epoll, direct read should block or timeout
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
                    continue; // SSL handshake might still be in progress (shouldn't happen after SSL_accept)
                }
                fprintf(stderr, "SSL_read error for socket %d, error: %d\n", sock, ssl_err);
                ERR_print_errors_fp(stderr);
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; // No data available right now, try again
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
            fprintf(stderr, "Selected site for Host '%s': %s\n", hostname, active_site->root_dir);
        } else {
            fprintf(stderr, "No specific site found for Host '%s'. Attempting to use default site if any.\n", hostname);
            // find_site_for_hostname already handles fallback to '_' site
        }
    }

    // Fallback to the first site associated with this listener if no Host header or no match
    if (active_site == NULL && listener->site_count > 0) {
        active_site = listener->sites[0];
        fprintf(stderr, "Using default/first associated site: %s\n", active_site->root_dir);
    } else if (active_site == NULL) {
        fprintf(stderr, "Error: No site configured for this listener! Cannot serve request on socket %d.\n", sock);
        const char* error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 30\r\n\r\nNo site configured for this port.";
        if (use_ssl) SSL_write(ssl, error_response, strlen(error_response));
        else write(sock, error_response, strlen(error_response));
        if (use_ssl) SSL_free(ssl);
        close(sock);
        pthread_exit(NULL);
    }


    // --- Prepare and Send the HTTP Response (using SSL_write or write) ---
    HandleRequest(active_site->root_dir, total_bytes_received, request_buffer,
                &actual_response_len, response_buffer);

    if (use_ssl) {
        if (SSL_write(ssl, response_buffer, actual_response_len) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "SSL_write error for socket %d.\n", sock);
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

    pthread_exit(NULL); // Exit the thread
}
