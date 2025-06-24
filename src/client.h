// client.h
#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h> // Required for SSL_CTX
#include <stdbool.h>     // Required for bool type
#include "parser.h" // Include the parser header for request handling

// Define common constants that handle_client might need
#define MAX_REQUEST_SIZE 8192 // Maximum size of the incoming request to read
#define BUFFER_SIZE 1024      // General buffer size

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