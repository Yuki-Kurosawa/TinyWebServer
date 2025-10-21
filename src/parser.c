#include "parser.h"
#include <string.h> // For memcpy and strlen, strncmp, strcmp, strrchr
#include <stdio.h>  // For printf (if needed for debugging), fprintf
#include <stdlib.h> // For malloc and free
#include <ctype.h>  // For isspace, isalnum, isxdigit, isprint
#include <arpa/inet.h> // For inet_ntop
#include <netinet/in.h> // For sockaddr_in, sockaddr_in6
#include <stdbool.h> // For bool


#include "handlers/info.h" 
#include "handlers/static_file.h" 
#include "handlers/dynamic_handler.h" 

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> // For PCRE2 regex matching



char* URLDecode(const char* encoded_str) {
    if (encoded_str == NULL) {
        return NULL;
    }

    size_t len = strlen(encoded_str);
    char* decoded_str = (char*)malloc(len + 1); 
    if (decoded_str == NULL) {
        perror("memory allocation failed for decoded_str in URLDecode");
        return NULL;
    }

    size_t i = 0; 
    size_t j = 0; 

    while (i < len) {
        if (encoded_str[i] == '%') {
            
            if (i + 2 < len && isxdigit(encoded_str[i+1]) && isxdigit(encoded_str[i+2])) {
                char hex[3];
                hex[0] = encoded_str[i+1];
                hex[1] = encoded_str[i+2];
                hex[2] = '\0';
                decoded_str[j++] = (char)strtol(hex, NULL, 16);
                i += 3;
            } else {
                
                decoded_str[j++] = encoded_str[i++];
            }
        } else if (encoded_str[i] == '+') {
            
            decoded_str[j++] = ' ';
            i++;
        } else {
            
            decoded_str[j++] = encoded_str[i++];
        }
    }
    decoded_str[j] = '\0'; 

    
    char* temp = realloc(decoded_str, j + 1);
    if (temp != NULL) {
        decoded_str = temp;
    } else {
        
        fprintf(stderr, "realloc failed for decoded_str in URLDecode\n");
    }

    return decoded_str;
}

/* begin handler registrations */

bool AlwaysTrueFunction(HandlerMetadata meta, char *path) {
    return true;
}



// Handlers are ordered by specificity. More specific handlers should come first.
// StaticFileHandler with "/" prefix should always be the last as a catch-all.
Handler handlers[] = {
    { {"ServerInfoHandler",".info", HANDLER_SUFFIX}, InfoProcessRequest, AlwaysTrueFunction },

    /* Begin tons of dynamic handlers */
    
    
    { {"DynamicAPIHandler", ".do", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".aspx", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".ashx", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".asmx", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".php", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".asp", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage},
    { {"DynamicAPIHandler", ".jsp", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".jspx", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".action", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".py", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".rb", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".pl", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".cgi", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    { {"DynamicAPIHandler", ".fcgi", HANDLER_SUFFIX }, DynamicHandlerProcessRequest, DynamicHandlerCheckPage },
    /* End tons of dynamic handlers */

    // StaticFileHandler はプレフィックスマッチングで、パスは "/" なので、
    
    
    { {"StaticFileHandler","/", HANDLER_PREFIX}, StaticFileProcessRequest, StaticFileCheckPage },
    { NULL, NULL , 0 } // End marker for the handlers array
};

/* end handler registrations */

/* Object Parsers */
void ParseQueryString(Request *req) {
    if (req == NULL || req->query_string == NULL || strlen(req->query_string) == 0) {
        req->query_count = 0;
        req->query = NULL;
        return;
    }

    char *query_copy = strdup(req->query_string);
    if (!query_copy) {
        perror("strdup failed for query_copy in ParseQueryString");
        return;
    }

    char *token;
    char *strtok_ctx;
    int capacity = 5;
    req->query = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->query) {
        perror("malloc failed for req->query");
        free(query_copy);
        return;
    }
    req->query_count = 0;

    token = strtok_r(query_copy, "&", &strtok_ctx);
    while (token != NULL) {
        if (req->query_count >= capacity) {
            capacity *= 2;
            KeyValuePair *new_query = (KeyValuePair *)realloc(req->query, sizeof(KeyValuePair) * capacity);
            if (!new_query) {
                perror("realloc failed for req->query");
                free(query_copy);
                // Proper cleanup for partially allocated KVP is needed in a robust app
                return;
            }
            req->query = new_query;
        }

        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0';
            req->query[req->query_count].key = strdup(token);
            
            char *encoded_value = eq_pos + 1;
            char *decoded_value = URLDecode(encoded_value); 
            req->query[req->query_count].value = decoded_value; 

            
            fprintf(stderr, "DEBUG: Query Param: Key='%s', Decoded Value='%s'\n",
                    req->query[req->query_count].key,
                    req->query[req->query_count].value ? req->query[req->query_count].value : "NULL");


            if (!req->query[req->query_count].key || !req->query[req->query_count].value) {
                perror("strdup or URLDecode failed for query key/value");
                free(req->query[req->query_count].key);
                free(req->query[req->query_count].value); 
                free(query_copy);
                return;
            }
            req->query_count++;
        } else {
            req->query[req->query_count].key = strdup(token);
            // FIX: Ensure value is always a valid string, even if empty
            req->query[req->query_count].value = strdup("");
            
            fprintf(stderr, "DEBUG: Query Param: Key='%s', Decoded Value='(empty)'\n",
                    req->query[req->query_count].key);

            if (!req->query[req->query_count].key || !req->query[req->query_count].value) { // Check both key and value strdup
                perror("strdup failed for query key (no value)");
                free(req->query[req->query_count].key); // Free key if value strdup fails
                free(query_copy);
                return;
            }
            req->query_count++;
        }

        token = strtok_r(NULL, "&", &strtok_ctx);
    }

    free(query_copy);
}

void ParseCookies(Request *req, const char *cookie_header_value) {
    if (req == NULL || cookie_header_value == NULL || strlen(cookie_header_value) == 0) {
        req->cookie_count = 0;
        req->cookies = NULL;
        req->cookie_capacity = 0;
        return;
    }

    char *cookie_copy = strdup(cookie_header_value);
    if (!cookie_copy) {
        perror("strdup failed for cookie_copy in ParseCookies");
        return;
    }

    char *token;
    char *strtok_ctx;

    int capacity = 5;
    req->cookies = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->cookies) {
        perror("malloc failed for req->cookies");
        free(cookie_copy);
        return;
    }
    req->cookie_count = 0;
    req->cookie_capacity = capacity;

    token = strtok_r(cookie_copy, "; ", &strtok_ctx);
    while (token != NULL) {
        if (req->cookie_count >= req->cookie_capacity) {
            req->cookie_capacity *= 2;
            KeyValuePair *new_cookies = (KeyValuePair *)realloc(req->cookies, sizeof(KeyValuePair) * req->cookie_capacity);
            if (!new_cookies) {
                perror("realloc failed for req->cookies");
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

        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0';
            req->cookies[req->cookie_count].key = strdup(token);
            req->cookies[req->cookie_count].value = strdup(eq_pos + 1);
            if (!req->cookies[req->cookie_count].key || !req->cookies[req->cookie_count].value) {
                 perror("strdup failed for cookie key/value");
                 free(req->cookies[req->cookie_count].key);
                 free(req->cookies[req->cookie_count].value);
                 free(cookie_copy);
                 return;
            }
            req->cookie_count++;
        } else {
            req->cookies[req->cookie_count].key = strdup(token);
            req->cookies[req->cookie_count].value = strdup(""); // FIX: Ensure value is always a valid string
            if (!req->cookies[req->cookie_count].key || !req->cookies[req->cookie_count].value) { // Check both
                 perror("strdup failed for cookie key (no value)");
                 free(req->cookies[req->cookie_count].key); // Free key if value strdup fails
                 free(cookie_copy);
                 return;
            }
            req->cookie_count++;
        }

        token = strtok_r(NULL, "; ", &strtok_ctx);
    }

    free(cookie_copy);
}

void ParseFormData(Request *req) {
    if (req == NULL || req->body == NULL || req->body_len == 0 ||
        !(req->method == METHOD_POST) ||
        (req->content_type == NULL || strcasecmp(req->content_type, "application/x-www-form-urlencoded") != 0)) {

        req->form_length = 0;
        req->form = NULL;
        req->form_capacity = 0;
        return;
    }

    char *body_copy = strdup(req->body);
    if (!body_copy) {
        perror("strdup failed for body_copy in ParseFormData");
        return;
    }

    char *token;
    char *strtok_ctx;

    int capacity = 5;
    req->form = (KeyValuePair *)malloc(sizeof(KeyValuePair) * capacity);
    if (!req->form) {
        perror("malloc failed for req->form");
        free(body_copy);
        return;
    }
    req->form_length = 0;
    req->form_capacity = capacity;

    token = strtok_r(body_copy, "&", &strtok_ctx);
    while (token != NULL) {
        if (req->form_length >= req->form_capacity) {
            req->form_capacity *= 2;
            KeyValuePair *new_form = (KeyValuePair *)realloc(req->form, sizeof(KeyValuePair) * req->form_capacity);
            if (!new_form) {
                perror("realloc failed for req->form");
                for (size_t i = 0; i < req->form_length; i++) {
                    free(req->form[i].key);
                    free(req->form[i].value);
                }
                free(req->form);
                req->form = NULL;
                req->form_length = 0;
                free(body_copy);
                return;
            }
            req->form = new_form;
        }

        char *eq_pos = strchr(token, '=');
        if (eq_pos) {
            *eq_pos = '\0';
            req->form[req->form_length].key = strdup(token);
            
            char *encoded_value = eq_pos + 1;
            char *decoded_value = URLDecode(encoded_value); 
            req->form[req->form_length].value = decoded_value; 

            
            fprintf(stderr, "DEBUG: Form Field: Key='%s', Decoded Value='%s'\n",
                    req->form[req->form_length].key,
                    req->form[req->form_length].value ? req->form[req->form_length].value : "NULL");

            if (!req->form[req->form_length].key || !req->form[req->form_length].value) {
                 perror("strdup or URLDecode failed for form key/value");
                 free(req->form[req->form_length].key);
                 free(req->form[req->form_length].value); 
                 free(body_copy);
                 return;
            }
            req->form_length++;
        } else {
            req->form[req->form_length].key = strdup(token);
            req->form[req->form_length].value = strdup(""); // FIX: Ensure value is always a valid string
            
            fprintf(stderr, "DEBUG: Form Field: Key='%s', Decoded Value='(empty)'\n",
                    req->form[req->form_length].key);

            if (!req->form[req->form_length].key || !req->form[req->form_length].value) { // Check both
                 perror("strdup failed for form key (no value)");
                 free(req->form[req->form_length].key); // Free key if value strdup fails
                 free(body_copy);
                 return;
            }
            req->form_length++;
        }

        token = strtok_r(NULL, "&", &strtok_ctx);
    }

    free(body_copy);
}

int PacketToRequestObject(char* request_buffer, size_t req_len, Request *req)
{
	if (request_buffer == NULL || req_len == 0 || req == NULL) {
		return 0;
	}

	// Set some default values for the request object
	req->method = METHOD_GET;
	req->version = HTTP_1_1;
	req->query_count = 0;
	req->query = NULL;
	req->accept = "*/*";
	req->content_type = NULL;
	req->content_length = 0;
	req->cookie_count = 0;
	req->cookies = NULL;
	req->header_count = 0;
	req->headers = NULL;
	req->body_len = 0;
	req->body = NULL;
	req->form_length = 0;
	req->form = NULL;

    char *request_copy = (char *)malloc(req_len + 1);
    if (!request_copy) {
        perror("malloc failed for request_copy");
        return -1;
    }
    memcpy(request_copy, request_buffer, req_len);
    request_copy[req_len] = '\0';

	char *current_pos = request_copy;
    char *line_end = NULL;
    char *next_line_start = NULL;

	line_end = strstr(current_pos, "\r\n");
    if (line_end == NULL) {
        free(request_copy);
        return -2;
    }
    *line_end = '\0';

    char method_buf[MAX_METHOD_LEN]; // Use temporary buffers for sscanf
    char uri_buf[MAX_URI_LEN];
    char version_buf[MAX_VERSION_LEN];

    // FIX: Use width specifiers to prevent buffer overflows with sscanf
    // MAX_METHOD_LEN (10) -> %9s
    // MAX_URI_LEN (2048) -> %2047s
    // MAX_VERSION_LEN (10) -> %9s
    char *first_space = strchr(current_pos, ' ');
    char *second_space = first_space ? strchr(first_space + 1, ' ') : NULL;

    if (!first_space || !second_space) {
        free(request_copy);
        return -2; // Malformed request line
    }

    *first_space = '\0'; // Temporarily null-terminate method
    strncpy(method_buf, current_pos, MAX_METHOD_LEN - 1);
    method_buf[MAX_METHOD_LEN - 1] = '\0';

    *second_space = '\0'; // Temporarily null-terminate URI
    strncpy(uri_buf, first_space + 1, MAX_URI_LEN - 1);
    uri_buf[MAX_URI_LEN - 1] = '\0';

    strncpy(version_buf, second_space + 1, MAX_VERSION_LEN - 1);
    version_buf[MAX_VERSION_LEN - 1] = '\0';

    // Restore original string for strtok_r to continue later
    *first_space = ' ';
    *second_space = ' ';
    *line_end = '\r'; // Restore the original \r\n

	if (strcmp(method_buf, "GET") == 0) {
        req->method = METHOD_GET;
    } else if (strcmp(method_buf, "POST") == 0) {
        req->method = METHOD_POST;
    }
    else {
        free(request_copy);
        return -3; // Unsupported method
    }

    req->path_and_query = strdup(uri_buf); // Use uri_buf (safe)
    char *query_start = strchr(req->path_and_query, '?');
    if (query_start) {
        *query_start = '\0';
        req->path = strdup(req->path_and_query);
        req->query_string = strdup(query_start + 1);
        *query_start = '?'; // Restore for req->path_and_query
    } else {
        req->path = strdup(req->path_and_query);
        req->query_string = NULL;
    }

    if (strcmp(version_buf, "HTTP/1.1") == 0) {
        req->version = HTTP_1_1;
    } else if (strcmp(version_buf, "HTTP/1.0") == 0) {
        req->version = HTTP_1_0;
    } else {
        free(request_copy);
        return -4; // Unsupported HTTP version
    }

	ParseQueryString(req); 

    current_pos = line_end + 2; // Move past the first line's \r\n

    while ( (line_end = strstr(current_pos, "\r\n")) != NULL && line_end != current_pos ) {
        *line_end = '\0'; // Temporarily null-terminate the header line

        char *colon_pos = strchr(current_pos, ':');
        if (colon_pos) {
            *colon_pos = '\0';
            char *header_name = current_pos;
            char *header_value = colon_pos + 1;

            while (*header_value && isspace((unsigned char)*header_value)) {
                header_value++;
            }

            if (strcasecmp(header_name, "Host") == 0) {
                // No need to free here, HandleRequest initializes and free_request_members cleans up
                req->host = strdup(header_value);
            } else if (strcasecmp(header_name, "User-Agent") == 0) {
                // No need to free here
                req->user_agent = strdup(header_value);
            } else if (strcasecmp(header_name, "Content-Type") == 0) {
                // No need to free here
                req->content_type = strdup(header_value);
            } else if (strcasecmp(header_name, "Content-Length") == 0) {
                req->content_length = strtol(header_value, NULL, 10);
				req->body_len =req->content_length;
            } else if (strcasecmp(header_name, "Accept") == 0) {
				// No need to free here
				req->accept = strdup(header_value);
			} else if (strcasecmp(header_name, "Cookie") == 0) {
                ParseCookies(req, header_value);
            }
            else {
                if (req->header_count >= req->header_capacity) {
                    if (req->header_capacity == 0) {
                        req->header_capacity = 5;
                    } else {
                        req->header_capacity *= 2;
                    }
                    KeyValuePair *new_headers = (KeyValuePair *)realloc(req->headers, sizeof(KeyValuePair) * req->header_capacity);
                    if (!new_headers) {
                        perror("realloc failed for generic headers");
                        for (size_t i = 0; i < req->header_count; i++) {
                            free(req->headers[i].key);
                            free(req->headers[i].value);
                        }
                        free(req->headers);
                        req->headers = NULL;
                        req->header_count = 0;
                        free(request_copy);
                        return -1;
                    }
                    req->headers = new_headers;
                }

                req->headers[req->header_count].key = strdup(header_name);
                req->headers[req->header_count].value = strdup(header_value);
                if (!req->headers[req->header_count].key || !req->headers[req->header_count].value) {
                    perror("strdup failed for generic header key/value");
                    free(req->headers[req->header_count].key);
                    free(req->headers[req->header_count].value);
                    for (size_t i = 0; i < req->header_count; i++) {
                        free(req->headers[i].key);
                        free(req->headers[i].value);
                    }
                    free(req->headers);
                    req->headers = NULL;
                    req->header_count = 0;
                    free(request_copy);
                    return -1;
                }
                req->header_count++;
            }
            *colon_pos = ':'; // Restore the colon
        }

        current_pos = line_end + 2; // Move past the current line's \r\n
    }

	current_pos = line_end + 2;
	
    // After header parsing, current_pos points to the beginning of the body (if any)
    // or the final \r\n\r\n if no body.
    // We need to find the actual start of the body relative to request_buffer.
    size_t header_end_offset = current_pos - request_copy;

    // FIX: Find the actual start of the body in the original request_buffer
    // This assumes the request_buffer contains the full raw request including headers and body.
    char *body_start_in_original_buffer = request_buffer + header_end_offset;
    size_t available_body_bytes = req_len - header_end_offset;

    // The `current_pos` in `request_copy` points to the `\r\n` that separates headers from body.
    // We need to find the actual start of the body in the original `request_buffer`.
    // The `header_end_offset` is the offset from the beginning of `request_copy` to the start of the body.
    // This offset should be applied to the original `request_buffer`.

    if (req->method == METHOD_POST) {
        if (req->content_length > 0) {
            // Check if the declared Content-Length is within the bounds of the received data
            if (req->content_length <= available_body_bytes) {
                req->body = (char *)malloc(req->content_length + 1);
                if (req->body) {
                    memcpy(req->body, body_start_in_original_buffer, req->content_length); // Read from original buffer
                    req->body[req->content_length] = '\0';
                    
                    /*
                    fprintf(stderr, "DEBUG: Raw Request Body (Hex) - Length: %zu, Content: '", req->body_len);
                    for (size_t k = 0; k < req->body_len; ++k) {
                        fprintf(stderr, "%%%02X", (unsigned char)req->body[k]);
                    }
                    fprintf(stderr, "'\n");
                    
                    fprintf(stderr, "DEBUG: Raw Request Body (String) - Length: %zu, Content: '%s'\n", req->body_len, req->body);
                    */

                } else {
                    perror("malloc failed for req->body");
                    free(request_copy);
                    return -1; // Memory allocation failure
                }
            } else {
                fprintf(stderr, "Content-Length exceeds remaining request buffer size. Declared: %zu, Available: %zu\n",
                        req->content_length, available_body_bytes);
                free(request_copy);
                return -5; // Malformed request or truncated body
            }
        }
    }

    if (req->body != NULL && req->body_len > 0 &&
        req->content_type != NULL && strcasecmp(req->content_type, "application/x-www-form-urlencoded") == 0) {
        ParseFormData(req); 
    }

    free(request_copy);

	return 0;
}

// Modified: Use the provided buffer directly instead of a VLA
void ResponseObjectToPacket(Response *resp, char *response_buffer_ptr, size_t *response_buffer_capacity)
{
    if (response_buffer_capacity == NULL || *response_buffer_capacity == 0)
    {
        if (response_buffer_capacity) *response_buffer_capacity = 0;
        return;
    }

    if (resp == NULL || response_buffer_ptr == NULL) {
        if (response_buffer_capacity) *response_buffer_capacity = 0;
        return;
    }

    size_t current_len = 0;
    size_t remaining_capacity = *response_buffer_capacity;

    // Write status line
    int written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                           "HTTP/1.1 %d %s\r\n", resp->status_code, resp->status_msg ? resp->status_msg : "OK");
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len; // Indicate how much was written before overflow
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // Write Content-Type
    written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                       "Content-Type: %s\r\n", resp->content_type ? resp->content_type : "text/html");
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len;
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // Write Content-Length
    written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                       "Content-Length: %zu\r\n", resp->body_len);
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len;
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // Write Server header
    written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                       "Server: %s\r\n", resp->server ? resp->server : SERVER_MOTD_TO_CLIENT);
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len;
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // Write Set-Cookie headers
    if (resp->cookie_count > 0 && resp->cookies != NULL) {
        for (int i = 0; i < resp->cookie_count; i++) {
            written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                               "Set-Cookie: %s=%s\r\n", resp->cookies[i].key, resp->cookies[i].value);
            if (written < 0 || (size_t)written >= remaining_capacity) {
                *response_buffer_capacity = current_len;
                return;
            }
            current_len += written;
            remaining_capacity -= written;
        }
    }

    // Write generic headers
    if (resp->header_count > 0 && resp->headers != NULL) {
        for (int i = 0; i < resp->header_count; i++) {
            written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                               "%s: %s\r\n", resp->headers[i].key, resp->headers[i].value);
            if (written < 0 || (size_t)written >= remaining_capacity) {
                *response_buffer_capacity = current_len;
                return;
            }
            current_len += written;
            remaining_capacity -= written;
        }
    }

    // Write Connection header
    if (resp->keep_alive) {
        written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                           "Connection: keep-alive\r\n");
    } else {
        written = snprintf(response_buffer_ptr + current_len, remaining_capacity,
                           "Connection: close\r\n");
    }
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len;
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // End of headers
    written = snprintf(response_buffer_ptr + current_len, remaining_capacity, "\r\n");
    if (written < 0 || (size_t)written >= remaining_capacity) {
        *response_buffer_capacity = current_len;
        return;
    }
    current_len += written;
    remaining_capacity -= written;

    // Write body
    if (resp->body != NULL && resp->body_len > 0) {
        if (resp->body_len > remaining_capacity) {
            // Body too large for remaining buffer, truncate or error
            // For now, we will copy what fits and update current_len
            memcpy(response_buffer_ptr + current_len, resp->body, remaining_capacity);
            current_len += remaining_capacity;
            *response_buffer_capacity = current_len; // Indicate actual written length
            return;
        }
        memcpy(response_buffer_ptr + current_len, resp->body, resp->body_len);
        current_len += resp->body_len;
        remaining_capacity -= resp->body_len;
    }

    // Ensure null-termination (for safety, though not strictly needed for binary copy)
    if (current_len < *response_buffer_capacity) {
        response_buffer_ptr[current_len] = '\0';
    } else {
        // If buffer is exactly full, cannot null-terminate.
        // This is fine as long as the receiver respects Content-Length.
    }

    *response_buffer_capacity = current_len; // Update actual length written
}

// Helper function to free Request struct's dynamically allocated members
void free_request_members(Request *req) {
    if (req == NULL) return;

    free(req->path_and_query);
    free(req->path);
    free(req->query_string);
    if (req->query) {
        for (int i = 0; i < req->query_count; ++i) {
            free(req->query[i].key);
            free(req->query[i].value); 
        }
        free(req->query);
    }
    free(req->host);
    free(req->user_agent);
    free(req->accept);
    free(req->content_type);
    if (req->cookies) {
        for (int i = 0; i < req->cookie_count; ++i) {
            free(req->cookies[i].key);
            free(req->cookies[i].value);
        }
        free(req->cookies);
    }
    if (req->headers) {
        for (int i = 0; i < req->header_count; ++i) {
            free(req->headers[i].key);
            free(req->headers[i].value);
        }
        free(req->headers);
    }
    free(req->body);
    if (req->form) {
        for (int i = 0; i < req->form_length; ++i) {
            free(req->form[i].key);
            free(req->form[i].value); 
        }
        free(req->form);
    }
}

// Helper function to free Response struct's dynamically allocated members
void free_response_members(Response *res) {
    if (res == NULL) return;

    free(res->content_type);
    free(res->status_msg);
    free(res->server);
    if (res->cookies) {
        for (int i = 0; i < res->cookie_count; ++i) {
            free(res->cookies[i].key);
            free(res->cookies[i].value);
        }
        free(res->cookies);
    }
    if (res->headers) {
        for (int i = 0; i < res->header_count; ++i) {
            free(res->headers[i].key);
            free(res->headers[i].value);
        }
        free(res->headers);
    }
    free(res->body);
}


/* the http request outer handler */
void HandleRequest(ServerInfo *server_info, size_t req_len, char request[], size_t *resp_len, char response[])
{
	*resp_len = 0;

	if (req_len == 0 || request == NULL) {
		return;
	}

    
    fprintf(stderr, "DEBUG: HandleRequest received - Total Length: %zu\n", req_len);
    /*
    fprintf(stderr, "DEBUG: HandleRequest received - Raw Request Buffer (Hex):\n");
    for (size_t k = 0; k < req_len; ++k) {
        fprintf(stderr, "%%%02X", (unsigned char)request[k]);
        if ((k + 1) % 16 == 0) fprintf(stderr, "\n"); // Newline every 16 bytes for readability
    }
    fprintf(stderr, "\n");
    */


	Request *req = (Request*)malloc(sizeof(Request));
	if (req == NULL) {
		perror("malloc failed for Request in HandleRequest");
		return; // Cannot proceed without request object
	}
	memset(req, 0, sizeof(Request));

	Response *resp=(Response*)malloc(sizeof(Response));
	if (resp == NULL) {
		perror("malloc failed for Response in HandleRequest");
		free(req); // Clean up request object
		return; // Cannot proceed without response object
	}
	memset(resp, 0, sizeof(Response));

    req->server_info = server_info;

	int ERR_PARSE=PacketToRequestObject(request, req_len, req);

	// Initialize response members with strdup to ensure they are on the heap
	resp->status_code = 200;
	resp->status_msg = strdup("OK");
	resp->content_type = strdup("text/html");
	resp->body_len = 0;
	resp->body = NULL;
	resp->server = strdup(SERVER_MOTD_TO_CLIENT);
	resp->keep_alive = false;
	resp->cookie_count = 0;
	resp->cookies = NULL;
	resp->header_count = 0;
	resp->headers = NULL;
	resp->content_length = 0;

    // Check for strdup failures during response initialization
    if (!resp->status_msg || !resp->content_type || !resp->server) {
        perror("strdup failed during response initialization in HandleRequest");
        // Attempt to clean up already strdup'd parts
        free(resp->status_msg);
        free(resp->content_type);
        free(resp->server);
        free_response_members(resp); // Free any other allocated parts of resp
        free(resp);
        free_request_members(req); // Free any allocated parts of req
        free(req);
        return; // Critical failure, cannot proceed
    }


	if(ERR_PARSE==0 && req->path != NULL)
	{
        bool match_found = false;
        HandlerMetadata *current_handler_meta = NULL;
        RequestHandler current_handler = NULL;

		for (int i = 0; handlers[i].metadata.path != NULL; i++)
        {
			//printf("Checking handler %d: %s %s\n", i, handlers[i].metadata.name,handlers[i].metadata.path);
            switch(handlers[i].metadata.type)
            {
                case HANDLER_STATIC:
                {
                    if (strcmp(handlers[i].metadata.path, req->path) == 0)
                    {
                        current_handler_meta = &handlers[i].metadata;
                        current_handler = handlers[i].handler;
                        match_found = true;
						//printf("Handler %s matched for path %s\n", handlers[i].metadata.name, req->path);
                        break;
                    }
                    break;
                }
                case HANDLER_PREFIX:
                {
                    size_t prefix_len = strlen(handlers[i].metadata.path);
                    
                    if (strncmp(req->path, handlers[i].metadata.path, prefix_len) == 0) {
                        
                        if (strcmp(handlers[i].metadata.path, "/") == 0) {
                            current_handler_meta = &handlers[i].metadata;
                            current_handler = handlers[i].handler;
                            match_found = true;
							//printf("Handler %s matched for path %s\n", handlers[i].metadata.name, req->path);
							break;
                        } else {
                            
                            
                            if (req->path[prefix_len] == '\0' || req->path[prefix_len] == '/') {
                                current_handler_meta = &handlers[i].metadata;
                                current_handler = handlers[i].handler;
                                match_found = true;
								//printf("Handler %s matched for path %s\n", handlers[i].metadata.name, req->path);
								break;
                            }
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
							//printf("Handler %s matched for path %s\n", handlers[i].metadata.name, req->path);
							break;
                        }

                    break;
                }
                case HANDLER_REGEX:
                {
                    pcre2_code *re;
                    PCRE2_SPTR pattern = (PCRE2_SPTR)handlers[i].metadata.path;
                    PCRE2_SPTR subject = (PCRE2_SPTR)req->path;
                    int errorcode;
                    PCRE2_SIZE erroroffset;
                    pcre2_match_data *match_data;
                    int rc;

                    re = pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroroffset, NULL);
                    if (re == NULL) {
                        PCRE2_UCHAR buffer[256];
                        pcre2_get_error_message(rc, buffer, sizeof(buffer));
                        fprintf(stderr, "PCRE2 compilation failed at offset %lu: %s\n", erroroffset, buffer);
                        break;
                    }

                    match_data = pcre2_match_data_create_from_pattern(re, NULL);
                    if (match_data == NULL) {
                        perror("PCRE2 match data creation failed");
                        pcre2_code_free(re);
                        break;
                    }

                    rc = pcre2_match(re, subject, strlen((char *)subject), 0, 0, match_data, NULL);

                    if (rc >= 0) {
                        match_found = true;
                        current_handler_meta = &handlers[i].metadata;
                        current_handler = handlers[i].handler;
                    } else if (rc == PCRE2_ERROR_NOMATCH) {
                    } else {
                        PCRE2_UCHAR buffer[256];
                        pcre2_get_error_message(rc, buffer, sizeof(buffer));
                        fprintf(stderr, "PCRE2 matching error: %s\n", buffer);
                    }

                    pcre2_match_data_free(match_data);
                    pcre2_code_free(re);
					//printf("Handler %s matched for path %s\n", handlers[i].metadata.name, req->path);
                    break;
                }
		    }

			if(match_found)
			{
				break;
			}
	    }

        if (match_found)
        {
            printf("Handler found for path %s with \"%s\"\n", req->path, current_handler_meta->name);
            req->handler = *current_handler_meta;
            current_handler(req, resp);
        } else {
            // If no handler matched, return 404 Not Found
            fprintf(stderr, "DEBUG: HandleRequest: No handler matched for path '%s'. Returning 404.\n", req->path ? req->path : "NULL");
            // FIX: Remove free() calls here. HandleRequest initializes and free_response_members cleans up.
            // if (resp->status_msg) free(resp->status_msg);
            // if (resp->content_type) free(resp->content_type);
            // if (resp->body) free(resp->body); // This one is fine as body is NULL initially

            resp->status_code = 404;
            resp->status_msg = strdup("Not Found");
            resp->content_type = strdup("text/html");
            resp->body = strdup("<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>");
            resp->body_len = strlen(resp->body);
        }
    }
    else
    {
		resp->status_code = 400;
		// If parsing failed or path is NULL, ensure status_msg and content_type are set
		// They are already strdup'd "OK" and "text/html" from initialization, so just update values.
		// FIX: Remove free() calls here. HandleRequest initializes and free_response_members cleans up.
		// free(resp->status_msg); // Free the default "OK"
		resp->status_msg = strdup("Bad Request");
		// free(resp->content_type); // Free the default "text/html"
		resp->content_type = strdup("text/html"); // Keep as text/html

		resp->body_len = 0;
		if (resp->body) { // If body was somehow allocated, free it
			free(resp->body);
			resp->body = NULL;
		}
	}

	size_t response_size = CACHE_SIZE; // Use CACHE_SIZE as initial buffer size
	char *response_body = (char *)malloc(response_size);
	if (response_body == NULL) {
		perror("malloc failed for response_body in HandleRequest");
		free_response_members(resp);
		free(resp);
		free_request_members(req);
		free(req);
		return;
	}

	ResponseObjectToPacket(resp, response_body, &response_size); // response_size will be updated with actual length

	memcpy(response, response_body, response_size);
	*resp_len = response_size; // Update the output length

	free(response_body);

    // Free dynamically allocated members of Request and Response
    free_request_members(req);
	free_response_members(resp);

	free(resp);
	free(req);
}
