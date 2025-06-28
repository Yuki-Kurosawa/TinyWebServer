#include "parser.h"
#include <string.h> // For memcpy and strlen
#include <stdio.h>  // For printf (if needed for debugging)
#include <stdlib.h> // For malloc and free
#include <ctype.h> // For isspace

#include "demo.h" // a demo handler for the HTTP request

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> // For PCRE2 regex matching

/* begin handler registrations */

Handler handlers[] = {
	{ {"Static Handler","/", HANDLER_STATIC}, DemoProcessRequest }, 
	{ {"Prefix Handler","/test", HANDLER_PREFIX}, DemoProcessRequest }, 
    { {"Suffix Handler","suffix.do", HANDLER_SUFFIX}, DemoProcessRequest },
    { {"Regex Handler", "regex(.*).do", HANDLER_REGEX}, DemoProcessRequest },
	{ NULL, NULL } // End marker for the handlers array
};

/* end handler registrations */

/* Object Parsers */
// In parser.c (add this function)
void ParseQueryString(Request *req) {
    if (req == NULL || req->query_string == NULL || strlen(req->query_string) == 0) {
        req->query_count = 0;
        req->query = NULL;
        return;
    }

    // Make a mutable copy of the query string for strtok_r
    char *query_copy = strdup(req->query_string);
    if (!query_copy) {
        perror("strdup failed for query_copy in ParseQueryString");
        return; // Handle allocation failure
    }

    char *token;
    char *strtok_ctx;
    int capacity = 5; // Initial capacity, realloc if needed
    req->query = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->query) {
        perror("malloc failed for req->query");
        free(query_copy);
        return;
    }
    req->query_count = 0;

    // Tokenize by '&' to get individual parameter pairs (e.g., "q=1", "kw=2")
    token = strtok_r(query_copy, "&", &strtok_ctx);
    while (token != NULL) {
        if (req->query_count >= capacity) {
            capacity *= 2;
            KeyValuePair *new_query = (KeyValuePair *)realloc(req->query, sizeof(KeyValuePair) * capacity);
            if (!new_query) {
                perror("realloc failed for req->query");
                // Critical: Need to free existing key/values before freeing query
                // For now, simplify and just free query_copy and return.
                // A robust solution would free partially parsed KVP.
                free(query_copy);
                // You might want to free existing req->query here if realloc failed after some items were added
                // And set req->query = NULL; req->query_count = 0;
                return; 
            }
            req->query = new_query;
        }

        // Parse each pair by '=' (e.g., "q", "1")
        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0'; // Null-terminate key
            req->query[req->query_count].key = strdup(token);
            req->query[req->query_count].value = strdup(eq_pos + 1);
            if (!req->query[req->query_count].key || !req->query[req->query_count].value) {
                perror("strdup failed for query key/value");
                // Handle malloc failure: free what was already allocated for this KVP
                free(req->query[req->query_count].key); // Safe to free(NULL)
                free(req->query[req->query_count].value); // Safe to free(NULL)
                free(query_copy);
                return;
            }
            req->query_count++;
        } else {
            // Handle parameters without a value (e.g., "?flag&q=1")
            req->query[req->query_count].key = strdup(token);
            req->query[req->query_count].value = NULL; // No value
            if (!req->query[req->query_count].key) {
                perror("strdup failed for query key (no value)");
                free(query_copy);
                return;
            }
            req->query_count++;
        }

        token = strtok_r(NULL, "&", &strtok_ctx);
    }

    free(query_copy); // Free the working copy
}

void ParseCookies(Request *req, const char *cookie_header_value) {
    if (req == NULL || cookie_header_value == NULL || strlen(cookie_header_value) == 0) {
        req->cookie_count = 0;
        req->cookies = NULL;
        req->cookie_capacity = 0;
        return;
    }

    // Make a mutable copy of the cookie header value for strtok_r
    char *cookie_copy = strdup(cookie_header_value);
    if (!cookie_copy) {
        perror("strdup failed for cookie_copy in ParseCookies");
        return; // Handle allocation failure
    }

    char *token;
    char *strtok_ctx;
    
    int capacity = 5; // Initial capacity for cookies
    req->cookies = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->cookies) {
        perror("malloc failed for req->cookies");
        free(cookie_copy);
        return;
    }
    req->cookie_count = 0;
    req->cookie_capacity = capacity;

    // Tokenize by "; " (semicolon followed by space) to get individual cookie pairs
    // Note: Some clients might just use ";", so ":;" or " ;" can be problematic.
    // "; " is standard, but a robust parser might handle just ";" too.
    token = strtok_r(cookie_copy, "; ", &strtok_ctx);
    while (token != NULL) {
        if (req->cookie_count >= req->cookie_capacity) {
            req->cookie_capacity *= 2;
            KeyValuePair *new_cookies = (KeyValuePair *)realloc(req->cookies, sizeof(KeyValuePair) * req->cookie_capacity);
            if (!new_cookies) {
                perror("realloc failed for req->cookies");
                // Cleanup: free already parsed cookies before returning
                for (size_t i = 0; i < req->cookie_count; i++) {
                    free(req->cookies[i].key);
                    free(req->cookies[i].value);
                }
                free(req->cookies);
                req->cookies = NULL;
                req->cookie_count = 0;
                free(cookie_copy);
                return;
            }
            req->cookies = new_cookies;
        }

        // Parse each cookie pair by '=' (e.g., "sessionid", "abc123")
        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0'; // Null-terminate cookie name
            req->cookies[req->cookie_count].key = strdup(token);
            req->cookies[req->cookie_count].value = strdup(eq_pos + 1);
            if (!req->cookies[req->cookie_count].key || !req->cookies[req->cookie_count].value) {
                 perror("strdup failed for cookie key/value");
                 free(req->cookies[req->cookie_count].key);
                 free(req->cookies[req->cookie_count].value);
                 free(cookie_copy);
                 // Further cleanup of already parsed KVP in req->cookies if needed
                 return;
            }
            // TODO: URL-decode key and value here if necessary (cookies can have URL-encoded characters)
            req->cookie_count++;
        } else {
            // Handle cookies without a value (e.g., "flag_set")
            req->cookies[req->cookie_count].key = strdup(token);
            req->cookies[req->cookie_count].value = NULL; // No value
            if (!req->cookies[req->cookie_count].key) {
                 perror("strdup failed for cookie key (no value)");
                 free(cookie_copy);
                 // Further cleanup of already parsed KVP in req->cookies if needed
                 return;
            }
            // TODO: URL-decode key here if necessary
            req->cookie_count++;
        }

        token = strtok_r(NULL, "; ", &strtok_ctx);
    }

    free(cookie_copy); // Free the working copy
}

void ParseFormData(Request *req) {
    // Only parse if it's a POST/PUT, body exists, and content type is application/x-www-form-urlencoded
    if (req == NULL || req->body == NULL || req->body_len == 0 ||
        !(req->method == METHOD_POST /*|| req->method == METHOD_PUT*/) || // Or just POST is more common for forms
        (req->content_type == NULL || strcasecmp(req->content_type, "application/x-www-form-urlencoded") != 0)) {
        
        req->form_length = 0;
        req->form = NULL;
        req->form_capacity = 0;
        return;
    }

    // Make a mutable copy of the body for strtok_r
    // This is crucial as strtok_r modifies the string in place.
    char *body_copy = strdup(req->body);
    if (!body_copy) {
        perror("strdup failed for body_copy in ParseFormData");
        return; // Handle allocation failure
    }

    char *token;
    char *strtok_ctx; // Context pointer for strtok_r
    
    int capacity = 5; // Initial capacity for form parameters
    req->form = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->form) {
        perror("malloc failed for req->form");
        free(body_copy);
        return;
    }
    req->form_length = 0;
    req->form_capacity = capacity;

    // Tokenize by '&' to get individual parameter pairs (e.g., "c=3", "d=4")
    token = strtok_r(body_copy, "&", &strtok_ctx);
    while (token != NULL) {
        // Expand form array if needed
        if (req->form_length >= req->form_capacity) {
            req->form_capacity *= 2; // Double capacity
            KeyValuePair *new_form = (KeyValuePair *)realloc(req->form, sizeof(KeyValuePair) * req->form_capacity);
            if (!new_form) {
                perror("realloc failed for req->form");
                // Cleanup: Free already parsed key/values before freeing req->form itself if realloc fails
                for (size_t i = 0; i < req->form_length; i++) {
                    free(req->form[i].key);
                    free(req->form[i].value); // Safe to free(NULL)
                }
                free(req->form);
                req->form = NULL;
                req->form_length = 0;
                free(body_copy);
                return;
            }
            req->form = new_form;
        }

        // Parse each pair by '=' (e.g., "c", "3")
        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0'; // Null-terminate key
            req->form[req->form_length].key = strdup(token);
            req->form[req->form_length].value = strdup(eq_pos + 1);
            if (!req->form[req->form_length].key || !req->form[req->form_length].value) {
                 perror("strdup failed for form key/value");
                 free(req->form[req->form_length].key); // Safe to free(NULL)
                 free(req->form[req->form_length].value); // Safe to free(NULL)
                 free(body_copy);
                 // Consider more robust error handling/cleanup for partial allocation
                 return;
            }
            // TODO: URL-decode key and value here if necessary (e.g., %20 to space, + to space)
            req->form_length++;
        } else {
            // Handle parameters without an explicit value (e.g., "d" in "c=3&d")
            req->form[req->form_length].key = strdup(token);
            req->form[req->form_length].value = NULL; // No value
            if (!req->form[req->form_length].key) {
                 perror("strdup failed for form key (no value)");
                 free(body_copy);
                 // Consider more robust error handling/cleanup for partial allocation
                 return;
            }
            // TODO: URL-decode key here if necessary
            req->form_length++;
        }

        token = strtok_r(NULL, "&", &strtok_ctx); // Get next token
    }

    free(body_copy); // Free the working copy of the body
}

int PacketToRequestObject(char* request_buffer, size_t req_len, Request *req)
{
	// This function will parse the HTTP request packet and fill the Request object.
	
	if (request_buffer == NULL || req_len == 0 || req == NULL) {
		return 0; // Invalid request packet or request object, do nothing
	}

	// no need to Initialize the request object due to it initialized from caller functions
	
	// Set some default values for the request object
	req->method = METHOD_GET; // Default to GET method
	req->version = HTTP_1_1; // Default to HTTP/1.1
	req->query_count = 0; // No query parameters for now
	req->query = NULL; // No query parameters for now
	req->accept = "*/*"; // Default accept header
	req->content_type = NULL; // No content type for now
	req->content_length = 0; // No content length for now
	req->cookie_count = 0; // No cookies for now
	req->cookies = NULL; // No cookies for now
	req->header_count = 0; // No additional headers for now
	req->headers = NULL; // No additional headers for now
	req->body_len = 0; // No body data for now
	req->body = NULL; // No body data for now
	req->form_length = 0; // No form data for now
	req->form = NULL; // No form data for now

	// Here you would parse the actual request packet and fill in the fields accordingly.

	// Create a mutable copy of the request buffer for strtok_r (if used)
    // Remember to free this copy before returning if you malloc it.
    char *request_copy = (char *)malloc(req_len + 1);
    if (!request_copy) {
        perror("malloc failed for request_copy");
        return -1; // Memory allocation failure
    }
    memcpy(request_copy, request_buffer, req_len);
    request_copy[req_len] = '\0'; // Null-terminate the copy
	
	char *current_pos = request_copy;
    char *line_end = NULL;
    char *next_line_start = NULL;

	//1. Parse the Request Line: Method, Path, Version
	line_end = strstr(current_pos, "\r\n");
    if (line_end == NULL) {
        free(request_copy);
        return -2; // Malformed request line (no CRLF)
    }
    *line_end = '\0'; // Null-terminate the request line for parsing

    // Tokenize the request line: METHOD PATH HTTP/VERSION
    char *method_str = strtok_r(current_pos, " ", &next_line_start);
    char *path_and_query_str = strtok_r(NULL, " ", &next_line_start);
    char *version_str = strtok_r(NULL, "\r\n", &next_line_start); // Use \r\n as delimiter here

    if (!method_str || !path_and_query_str || !version_str) {
        free(request_copy);
        return -2; // Malformed request line (missing parts)
    }


	// Store Method
    if (strcmp(method_str, "GET") == 0) {
        req->method = METHOD_GET;
    } else if (strcmp(method_str, "POST") == 0) {
        req->method = METHOD_POST;
    }
    // Add more methods as needed (HEAD, PUT, DELETE, etc.)
    else {
        free(request_copy);
        return -3; // Unsupported method
    }

	// Store Path and Query
    req->path_and_query = strdup(path_and_query_str);
    // Parse pure path from path_and_query (before '?')
    char *query_start = strchr(req->path_and_query, '?');
    if (query_start) {
        *query_start = '\0'; // Null-terminate path at '?'
        req->path = strdup(req->path_and_query); // Path without query
        req->query_string = strdup(query_start + 1); // Query string
        // Remember to reset query_start to '?' if request_copy is processed further using this
        // Or better, just work with the duplicate.
        *query_start = '?'; // Restore for req->path_and_query
    } else {
        req->path = strdup(req->path_and_query); // Path is the whole URI
        req->query_string = NULL; // No query string
    }

	// Store Version
    if (strcmp(version_str, "HTTP/1.1") == 0) {
        req->version = HTTP_1_1;
    } else if (strcmp(version_str, "HTTP/1.0") == 0) {
        req->version = HTTP_1_0;
    } else {
        free(request_copy);
        // Free strdup'd paths if returning early! (Critical memory leak point)
        // This is why Request_free needs to be robust.
        // For now, rely on Request_free at the end of HandleRequest.
        return -4; // Unsupported HTTP version
    }

	ParseQueryString(req);

    // Move current_pos past the request line (the original \r\n)
    current_pos = line_end + 2; // +2 to skip past "\r\n"

	// 2. Parse Headers
    // Headers are in "Key: Value\r\n" format
    // Loop until an empty line "\r\n" (i.e., "\r\n\r\n" from original string)
    while ( (line_end = strstr(current_pos, "\r\n")) != NULL && line_end != current_pos ) {
        *line_end = '\0'; // Null-terminate the current header line

        char *colon_pos = strchr(current_pos, ':');
        if (colon_pos) {
            *colon_pos = '\0'; // Null-terminate header name
            char *header_name = current_pos;
            char *header_value = colon_pos + 1;
            
            // Trim leading whitespace from value
            while (*header_value && isspace((unsigned char)*header_value)) {
                header_value++;
            }

            // Store important headers in specific fields
            if (strcasecmp(header_name, "Host") == 0) { // case-insensitive compare
                req->host = strdup(header_value);
            } else if (strcasecmp(header_name, "User-Agent") == 0) {
                req->user_agent = strdup(header_value);
            } else if (strcasecmp(header_name, "Content-Type") == 0) {
                req->content_type = strdup(header_value);
            } else if (strcasecmp(header_name, "Content-Length") == 0) {
                req->content_length = strtol(header_value, NULL, 10); // Convert string to long
				req->body_len =req->content_length;
            } else if (strcasecmp(header_name, "Accept") == 0) {
				req->accept = strdup(header_value);
			} else if (strcasecmp(header_name, "Connection") == 0) {
				// Handle Connection header if needed
				// For now, we can ignore it or set a flag for keep-alive
				//req->keep_alive = (strcasecmp(header_value, "keep-alive") == 0);
			} else if (strcasecmp(header_name, "Cookie") == 0) {
                ParseCookies(req, header_value); // Call the new cookie parsing function
                // No need to strdup header_value here as ParseCookies makes its own copy
            } 
            else {
                // Expand headers array if needed
                if (req->header_count >= req->header_capacity) {
                    if (req->header_capacity == 0) {
                        req->header_capacity = 5; // Initial capacity
                    } else {
                        req->header_capacity *= 2; // Double capacity
                    }
                    KeyValuePair *new_headers = (KeyValuePair *)realloc(req->headers, sizeof(KeyValuePair) * req->header_capacity);
                    if (!new_headers) {
                        perror("realloc failed for generic headers");
                        // --- IMPORTANT: Clean up existing req->headers elements before returning ---
                        for (size_t i = 0; i < req->header_count; i++) {
                            free(req->headers[i].key);
                            free(req->headers[i].value);
                        }
                        free(req->headers); // Free the array itself
                        req->headers = NULL;
                        req->header_count = 0;
                        // --- End cleanup ---
                        free(request_copy); // Free the request_copy buffer
                        return -1; // Memory allocation failure
                    }
                    req->headers = new_headers;
                }

                // Store the generic/custom header
                req->headers[req->header_count].key = strdup(header_name);
                req->headers[req->header_count].value = strdup(header_value);
                if (!req->headers[req->header_count].key || !req->headers[req->header_count].value) {
                    perror("strdup failed for generic header key/value");
                    free(req->headers[req->header_count].key); // Safe to free(NULL)
                    free(req->headers[req->header_count].value); // Safe to free(NULL)
                    // --- IMPORTANT: Clean up existing req->headers elements before returning ---
                    for (size_t i = 0; i < req->header_count; i++) {
                        free(req->headers[i].key);
                        free(req->headers[i].value);
                    }
                    free(req->headers); // Free the array itself
                    req->headers = NULL;
                    req->header_count = 0;
                    // --- End cleanup ---
                    free(request_copy);
                    return -1; // Memory allocation failure
                }
                req->header_count++;
            }
            // --- END CRITICAL 'ELSE' BLOCK ---

            *colon_pos = ':'; // Restore ':' if original buffer needs to remain intact (though we're using a copy)
        }

        current_pos = line_end + 2; // Move to the start of the next line
    }

	// 3. Parse Request Body (if any)
    // current_pos should now be pointing just after the "\r\n\r\n" (empty line)
    // If there's a Content-Length and content after headers
    if (req->method == METHOD_POST /*|| req->method == METHOD_PUT*/) { // Only for methods that typically have a body
        if (req->content_length > 0) {
			current_pos = line_end + 2;

            size_t body_offset = current_pos - request_copy;
            if (body_offset + req->content_length <= req_len) {
                req->body = (char *)malloc(req->content_length + 1);
                if (req->body) {
                    memcpy(req->body, current_pos, req->content_length);
                    req->body[req->content_length] = '\0'; // Null-terminate body
                }
            } else {
                // Content-Length specifies more bytes than available in the buffer
                free(request_copy);
                return -5; // Malformed body/length mismatch
            }
        }
    }

	// 4. Parse form data if content type is x-www-form-urlencoded
    if (req->body != NULL && req->body_len > 0 && 
        req->content_type != NULL && strcasecmp(req->content_type, "application/x-www-form-urlencoded") == 0) {
        ParseFormData(req);
    }

    free(request_copy); // Free the mutable copy of the request buffer


	return 0;
}


void ResponseObjectToPacket(Response *resp, char *response, size_t *resp_len)
{
	// This function will convert the Response object to a response packet.

	if(resp_len==NULL || *resp_len == 0)
	{
		*resp_len = 0; // Set response length to 0 if not provided
		return; // No response cache length provided, do nothing
	}
	
	if (resp == NULL || response == NULL) {
		return; // Invalid response object or buffer, do nothing
	}

	// Parse Now
	// Construct the response packet as a string
	char response_body[*resp_len]; // Buffer to hold the response body
	size_t body_len = 0; // Length of the response body

	body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
		"HTTP/1.1 %d %s\r\n", resp->status_code, resp->status_msg ? resp->status_msg : "OK");

	body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
		"Content-Type: %s\r\n", resp->content_type ? resp->content_type : "text/html");

	body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
		"Content-Length: %zu\r\n", resp->body_len);

	body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
		"Server: %s\r\n", resp->server ? resp->server : SERVER_MOTD_TO_CLIENT);
	
	// Add cookies if present
	if (resp->cookie_count > 0 && resp->cookies != NULL) {
		for (int i = 0; i < resp->cookie_count; i++) {
			body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
				"Set-Cookie: %s=%s\r\n", resp->cookies[i].key, resp->cookies[i].value);
		}
	}

	// Add additional headers if present
	if (resp->header_count > 0 && resp->headers != NULL) {
		for (int i = 0; i < resp->header_count; i++) {
			body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,	
				"%s: %s\r\n", resp->headers[i].key, resp->headers[i].value);
		}
	}

	// Add the keep-alive header if applicable
	if (resp->keep_alive) {
		body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
			"Connection: keep-alive\r\n");		
	} else {
		body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
			"Connection: close\r\n");
	}

	// Add a blank line to separate headers from the body
	body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len, "\r\n");

	// Add the response body
	if (resp->body != NULL && resp->body_len > 0) {
		body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
			"%s", resp->body);
	} else {
		// If no body is provided, set it to an empty string
		// body_len += snprintf(response_body + body_len, sizeof(response_body) - body_len,
		// 	"");
	}

	// Ensure the response body is null-terminated
	response_body[body_len] = '\0';

	// Copy the response body to the response buffer
	memcpy(response, response_body, body_len);
	*resp_len = body_len;
}

/* the http request outer handler */
void HandleRequest(char* root_dir, size_t req_len, char request[], size_t *resp_len, char response[])
{
	// This function will parse the HTTP request and generate a response.
	// For now, it just returns a simple "Hello, World!" response.
	
	// Set the response length to 0 initially
	*resp_len = 0;

	// Check if the request length is valid
	if (req_len == 0 || request == NULL) {
		return; // Invalid request, do nothing
	}

	/* Init Request and Response Objects */
	Request *req = (Request*)malloc(sizeof(Request)); // Create a request object
	memset(req, 0, sizeof(Request)); // Initialize the request object to zero
	Response *resp=(Response*)malloc(sizeof(Response)); // Create a fake response object
	memset(resp, 0, sizeof(Response)); // Initialize the response object to zero

	/* Parse Request Packet to RequestObject(struct Request) Here */
	int ERR_PARSE=PacketToRequestObject(request, req_len, req); // Parse the request packet into the request object
	req->root_dir = root_dir; // Set the root directory for the request object

	/* Select Handler and Process Request Here */
	resp->status_code = 200; // Default to 200 OK
	resp->status_msg = "OK"; // Default status message
	resp->content_type = "text/html"; // Default content type
	resp->body_len = 0; // Initialize body length to 0
	resp->body = NULL; // Initialize body to NULL
	resp->server = SERVER_MOTD_TO_CLIENT; // Set the server header to a constant string
	resp->keep_alive = false; // Default to not keeping the connection alive
	resp->cookie_count = 0; // Initialize cookie count to 0
	resp->cookies = NULL; // Initialize cookies to NULL
	resp->header_count = 0; // Initialize header count to 0
	resp->headers = NULL; // Initialize headers to NULL
	resp->content_length = 0; // Initialize content length to 0

	if(ERR_PARSE==0 && req->path != NULL) // Check if parsing was successful and path is not NULL
	{
        bool match_found = false;
        HandlerMetadata *current_handler_meta = NULL;
        RequestHandler current_handler = NULL;

		// Find the appropriate handler for the request path
		for (int i = 0; handlers[i].metadata.path != NULL; i++) 
        {            
            switch(handlers[i].metadata.type)
            {
                case HANDLER_STATIC:                    
                {
                    if (strcmp(handlers[i].metadata.path, req->path) == 0) 
                    {                        
                        current_handler_meta = &handlers[i].metadata;
                        current_handler = handlers[i].handler;
                        match_found = true;
                        break; // Handler found and called, exit loop
                    }
                    break;
                    case HANDLER_PREFIX:
                    {
                        size_t prefix_len = strlen(handlers[i].metadata.path);
                        if (strncmp(req->path, handlers[i].metadata.path, prefix_len) == 0) {
                            // Ensure it's a true prefix match, not just starts-with (e.g., "/test" matches "/test/abc" but not "/testing")
                            if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
                                current_handler_meta = &handlers[i].metadata;
                                current_handler = handlers[i].handler;
                                match_found = true;
                            }
                        }
                        break;
                    }
                    case HANDLER_SUFFIX:
                    {
                        size_t path_len = strlen(req->path);
                        size_t suffix_len = strlen(handlers[i].metadata.path);
                        if (path_len >= suffix_len &&
                            strcmp(req->path + (path_len - suffix_len), handlers[i].metadata.path) == 0) 
                            {
                                current_handler_meta = &handlers[i].metadata;
                                current_handler = handlers[i].handler;
                                match_found = true;
                            }
                        break;
                    }
                    case HANDLER_REGEX:
                    {
                        // --- PCRE2 Regex Matching Implementation ---
                        pcre2_code *re;
                        PCRE2_SPTR pattern = (PCRE2_SPTR)handlers[i].metadata.path;
                        PCRE2_SPTR subject = (PCRE2_SPTR)req->path;
                        int errorcode;
                        PCRE2_SIZE erroroffset;
                        pcre2_match_data *match_data;
                        int rc;

                        // 1. Compile the regex pattern
                        // In a production system, you would compile this once during startup
                        // and store the compiled 're' in HandlerMetadata to avoid recompiling per request.
                        re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroroffset, NULL);
                        if (re == NULL) {
                            PCRE2_UCHAR buffer[256];
                            pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
                            fprintf(stderr, "PCRE2 compilation failed at offset %lu: %s\n", erroroffset, buffer);
                            // Consider how to handle a bad regex pattern (e.g., skip this handler, log error)
                            break; 
                        }

                        // 2. Create match data block
                        match_data = pcre2_match_data_create_from_pattern(re, NULL);
                        if (match_data == NULL) {
                            perror("PCRE2 match data creation failed");
                            pcre2_code_free(re);
                            break;
                        }

                        // 3. Execute the regex match
                        rc = pcre2_match(re, subject, strlen((char *)subject), 0, 0, match_data, NULL);

                        if (rc >= 0) { // Match successful
                            match_found = true;
                            current_handler_meta = &handlers[i].metadata;
                            current_handler = handlers[i].handler;

                            // Optional: Extract captured substrings
                            // PCRE2_SPTR ovector = pcre2_get_ovector_pointer(match_data);
                            // for (int j = 0; j < rc; j++) {
                            //     PCRE2_SIZE start = ovector[2*j];
                            //     PCRE2_SIZE end = ovector[2*j+1];
                            //     printf("Match %d: %.*s\n", j, (int)(end - start), (char*)subject + start);
                            //     // If you need to pass captures to the handler, you'd extend Request struct
                            // }
                        } else if (rc == PCRE2_ERROR_NOMATCH) {
                            // No match, this is expected for non-matching paths
                        } else {
                            // Other PCRE2 error during match
                            PCRE2_UCHAR buffer[256];
                            pcre2_get_error_message(rc, buffer, sizeof(buffer));
                            fprintf(stderr, "PCRE2 matching error: %s\n", buffer);
                        }

                        // 4. Free PCRE2 resources
                        pcre2_match_data_free(match_data);
                        pcre2_code_free(re); // Free compiled regex (if compiled here)
                        break;
                    }
                }
		    }
	    } 
            
        if (match_found) 
        {
            printf("Handler found for path %s with \"%s\"\n", req->path, current_handler_meta->name);
            req->handler = *current_handler_meta; // Set the handler metadata in the request object
            current_handler(req, resp); // Call the registered handler function
        }
    }
    else 
    {
		// If parsing failed or no handler found, set a default response
		resp->status_code = 400; // Bad Request
		resp->status_msg = "Bad Request";
		resp->content_type = "text/html";
		resp->body_len = 0;
		resp->body = NULL;
	}

	/* Convert ResponseObject(struct Response) To Response Packet Here */
	size_t response_size = 16384; // Define a fixed size for the response buffer
	char *response_body = (char *)malloc(response_size); // Allocate a buffer for the response
	ResponseObjectToPacket(resp, response_body, &response_size); // Convert the response object to a packet

	// Copy the response body to the response buffer
	size_t body_len = strlen(response_body);

	memcpy(response, response_body, body_len);
	*resp_len = body_len;

	free(resp);
	free(req); // Free the request object

}

