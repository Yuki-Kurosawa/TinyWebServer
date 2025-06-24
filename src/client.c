// client.c
#include "client.h" // Include our own header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h> // For errno
#include <openssl/err.h> // For SSL_get_error and ERR_print_errors_fp

// Function to handle a single client connection
void *handle_client(void *thread_args_ptr) {
    ClientThreadArgs *args = (ClientThreadArgs*) thread_args_ptr;
    int sock = args->sock;
    SSL_CTX *ssl_ctx = args->ssl_ctx;
	char* root_dir = args->root_dir; // Root directory for this listener, if applicable
    free(thread_args_ptr); // Free the dynamically allocated thread arguments

    SSL *ssl = NULL;
    bool use_ssl = (ssl_ctx != NULL);

	char response_buffer[MAX_REQUEST_SIZE + BUFFER_SIZE]; // Give some extra room for headers
    size_t actual_response_len = 0; // This will be filled by HandleRequest

    // --- PERFORM SSL HANDSHAKE IMMEDIATELY IF SSL IS ENABLED ---
    if (use_ssl) {
        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "Error creating SSL object.\n");
            close(sock);
            pthread_exit(NULL);
        }
        SSL_set_fd(ssl, sock);

        if (SSL_accept(ssl) <= 0) {
            // Handle SSL handshake failure (e.g., client sent plain HTTP to HTTPS port)
            close(sock);
            SSL_free(ssl);
            pthread_exit(NULL);
        }
    }
    // --- END SSL HANDSHAKE ---


    // --- Read the HTTP Request (using SSL_read or read) ---
    char request_buffer[MAX_REQUEST_SIZE] = {0};
    ssize_t bytes_received = 0;
    ssize_t total_bytes_received = 0;

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
			continue;
			}
			} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) { continue; }
			}
            break;
        }
        if (bytes_received == 0) {
            break;
        }

        total_bytes_received += bytes_received;
        request_buffer[total_bytes_received] = '\0';

        if (total_bytes_received >= 4) {
            if (strstr(request_buffer, "\r\n\r\n") != NULL) {
                break;
            }
        }
    }

     if (total_bytes_received == 0) {
		if (use_ssl) SSL_free(ssl);
		close(sock);
		pthread_exit(NULL);
     }

    // --- Prepare and Send the HTTP Response (using SSL_write or write) ---
    HandleRequest(root_dir, total_bytes_received, request_buffer,
				&actual_response_len, response_buffer);
 

    if (use_ssl) {
        if (SSL_write(ssl, response_buffer, actual_response_len) <= 0) {
            SSL_free(ssl);
            close(sock);
            pthread_exit(NULL);
        }
    } else {
		if (write(sock, response_buffer, actual_response_len) <= 0) {
			close(sock);
			pthread_exit(NULL);
		}
    }

    if (use_ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(sock);

    pthread_exit(NULL);
}