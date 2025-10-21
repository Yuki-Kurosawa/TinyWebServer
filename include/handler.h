// include/handler.h
#ifndef HANDLER_H
#define HANDLER_H

#include <stddef.h> // For size_t
#include <stdbool.h> // For bool

// Constants for request/response limits (can be adjusted)
#define MAX_METHOD_LEN 10       // e.g., "GET", "POST"
#define MAX_URI_LEN 2048        // Max length of a URI
#define MAX_VERSION_LEN 10      // e.g., "HTTP/1.1"
#define MAX_KEY_LEN 64
#define MAX_VALUE_LEN 1024

typedef enum {
	HANDLER_UNDEFINED, // Undefined Handler
	HANDLER_STATIC, // Static Path Handler (example:/path/file.do)
	HANDLER_PREFIX, // Prefix Path Handler (example:/path/* , set path to /path/)
	HANDLER_SUFFIX, // Suffix Path Handler (example:/*/file.do , set path to file.do)
	HANDLER_REGEX,  // Regex Path Handler (example:/path/.* , set path to ^/path/(.*)$, pcre2 style regex)
} HandlerType;

// HttpRequestHandler Metadata
typedef struct {
	char* name; // HandlerName
	char *path; // Path, Not allowed characters: ',",\,/,;,:,?,@,#,$,%,^,*,(,),!,<,>,[,],{,},|,`,~,=,+ and whitespace
	HandlerType type; // HandlerType
} HandlerMetadata;

// Enums for HTTP methods and versions (can be expanded)
typedef enum {
    METHOD_UNKNOWN,
    METHOD_GET,
    METHOD_POST,
    // Add more methods as needed
} HttpMethod;

typedef enum {
    VERSION_UNKNOWN,
    HTTP_1_0,
    HTTP_1_1,
    // Add more versions as needed
} HttpVersion;

// Structure for a single HTTP header
typedef struct {
    char *key;
    char *value;
} KeyValuePair;

typedef struct {
	char* server_ip;
	int server_port; 
	char *remote_ip;
	int remote_port;
	char *root_dir; 
	char **default_page; 
	int num_default_page;
	char **server_name; 
	int num_server_names;
} ServerInfo;

// Structure to represent a parsed HTTP request
typedef struct {
    HttpMethod method;  // HttpMethod GET POST PUT DELETE INFO 
						// first version just do GET and POST
						// other will be added later
	HttpVersion version; // the HTTP/1.0 thing

	HandlerMetadata handler; // Handler metadata for this request, used to find the handler
						// it is used to find the handler for this request
						// it can be NULL if not set, but it is recommended to set it
						// so that we can check the handler for this request

	ServerInfo *server_info; // ServerInfo for this request, used to find the server info
						// it is used to find the server info for this request
						// it can be NULL if not set, but it is recommended to set it
						// so that we can check the server info for this request

    char *path_and_query; // Path and query string of the request, /index.html?q=1&b=2
	char *path; // Path of the request, e.g., /index.html

	int query_count; // Number of query parameters in the request, default 0
	char *query_string; // Query string of the request, e.g., "q=1&b=2"
						// this can be null if no query parameters are present
						// it is used to parse the query parameters into KeyValuePair
						// so that we can use it later
	KeyValuePair *query; // Query parameters in the request, e.g., "q=1&b=2"
						// this can be null if no query parameters are present

	

	/* common headers starts here */
    char *host; // Host header for virtual hosting
	char *user_agent; // User-Agent header
	char *accept; // Accept header
	char *content_type; // Content-Type header, for POST and PUT requests, otherwise it is NULL
	size_t content_length; // Content-Length header, for POST and PUT requests,otherwise it is 0
	/* common headers ends here */

	/* Cookies, first version may not need this */
	int cookie_count; // Number of cookies in the request, default 0
	int cookie_capacity; // Capacity of the cookies array, used for dynamic allocation
	KeyValuePair *cookies;  // cookies in the request, e.g., "sessionid=abc123; theme=dark"
							// this can be null if no cookies are present

    int header_count; // Number of non-common headers in the request
	int header_capacity; // Capacity of the headers array, used for dynamic allocation
    KeyValuePair *headers; //non-common headers in the request
    
	/* Request Body Data only for POST and PUT Requests */
	size_t body_len;    // Length of the request body
    char *body;         // request body data in bytes

	/* Form Data, only for POST Requests */
	// This is used when the Content-Type is application/x-www-form-urlencoded
	// It is not used for multipart/form-data or other types in this version
	int form_length; // Length of the form data, default 0
	size_t form_capacity;   // Current allocated capacity for form array
	KeyValuePair *form; // Form data in the request, e.g., "username=user&password=pass"
						// this can be null if no form data is present

	/* I don't want to do multipart data due to multipart is super complex */
   
} Request;

// Structure to represent an HTTP response
typedef struct {
    int status_code;    // e.g., 200, 404
    char *status_msg; // e.g., "OK", "Not Found"

	/* common headers starts here */
    char *content_type; // Content-Type header, for response
	size_t content_length; // Content-Length header, for response
	char *server; // Server header like "MyServer/1.0" , a constant string
	/* common headers ends here */

	/* Cookies, first version may not need this */
	int cookie_count; // Number of cookies in the response, default 0
	KeyValuePair *cookies;  // cookies in the response, e.g., "sessionid=abc123; theme=dark"
							// this can be null if no cookies are present


  	int header_count; // Number of non-common headers in the response
    KeyValuePair *headers; //non-common headers in the response

	bool keep_alive;    // Whether to keep the connection alive, but first version will not support this
    
	size_t body_len;    // Length of the response body
    char *body;         // the response body data in bytes
    
} Response;

// Function to process a parsed HTTP request and generate a response.
// This function will encapsulate the high-level application logic (e.g., serving files).
// It will take a Request object and fill in a Response object.
typedef void (*RequestHandler)(Request *req, Response *res);

// Check Page Usage Delegate
typedef bool (*CheckPageFunction)(Request *req, char *path);

// HttpRequestHandler
typedef struct {
	HandlerMetadata metadata;   // handler metadata
	RequestHandler handler; // Pointer to the handler function
	CheckPageFunction check_page; // Pointer to the function to check if the page exists
} Handler;

#endif // HANDLER_H