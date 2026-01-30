// Copyright (c) 2025 Yuki Kurosawa
// SPDX-License-Identifier: MIT
// include/handler.h
#ifndef HANDLER_H
#define HANDLER_H

#include <stddef.h> // For size_t
#include <stdbool.h> // For bool
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

inline static void PathRewrite(char* buffer,char* path,char* lextra,char* rextra)
{
	if (!path || !buffer) return;
	if (strlen(path) == 0) return;

    char* lastSlash = strrchr(path, '/');
    char* fileNameStart = (lastSlash) ? lastSlash + 1 : path;

    int dirLen = fileNameStart - path;
    if (dirLen > 0) {
        memcpy(buffer, path, dirLen);
    }
    char* p = buffer + dirLen;

    char* lastDot = strrchr(fileNameStart, '.');
    
    if (lextra && lastDot != fileNameStart) {
        strcpy(p, lextra);
        p += strlen(lextra);
    }

    if (lastDot) {
        int stemLen = lastDot - fileNameStart;
        memcpy(p, fileNameStart, stemLen);
        p += stemLen;
    } else {
        strcpy(p, fileNameStart);
        p += strlen(fileNameStart);
    }

    if (rextra) {
        strcpy(p, rextra);
        p += strlen(rextra);
    }

    *p = '\0'; 
}

inline static char* PathCombineExtend(char* left,char* right, int mode,char* mode_lextra,char* mode_rextra){
	char* buffer=malloc(MAX_URI_LEN);
    char* temp_right=malloc(MAX_URI_LEN);
	
    size_t len_l = strlen(left);
    int left_has_slash = (len_l > 0 && left[len_l - 1] == '/');
    int right_has_slash = (right[0] == '/');

	size_t len_r = strlen(right);

    /*if (mode == 1) {
        const char* r_start = right;
    	while (*r_start == '/') r_start++;
        const char* dot = strrchr(r_start, '.');
        int name_len = dot ? (int)(dot - r_start) : (int)strlen(r_start);
        snprintf(temp_right, MAX_URI_LEN, "%s%.*s%s", mode_lextra, name_len, r_start, mode_rextra);
		//printf("DEBUG: PathCombineExtend modified right to: %s\n", temp_right);
    } else {  */      
        strncpy(temp_right, right, MAX_URI_LEN);
	//}
	
	//printf("DEBUG: %s %d\n","/",'/');

	printf("DEBUG: PathCombine called with left: %s (%d,%d), right: %s (%d,%d)\n", left,left_has_slash,left[len_l - 1],
		 temp_right,right_has_slash,temp_right[0]);

    if(len_r >0 && len_l >0)
    {
		if (left_has_slash && right_has_slash) 
		{        
			snprintf(buffer, MAX_URI_LEN, "%s%s", left, temp_right + 1);
		}
		else if (!left_has_slash && right_has_slash) 
		{        
			snprintf(buffer, MAX_URI_LEN, "%s%s", left, temp_right);
		} 
		else if (!left_has_slash && !right_has_slash) 
		{        
			snprintf(buffer, MAX_URI_LEN, "%s/%s", left, temp_right);
		} 
		else
		{        
			snprintf(buffer, MAX_URI_LEN, "%s%s", left, temp_right);
		}
	}
	else if (len_l > 0 && len_r==0)
	{
		snprintf(buffer, MAX_URI_LEN, "%s", left);
	}
	else if (len_l == 0 && len_r >0)
	{
		snprintf(buffer, MAX_URI_LEN, "%s", temp_right);
	}
	else
	{
		snprintf(buffer, MAX_URI_LEN, "");
	}

	if(mode==1)
	{
		char* buffer1=malloc(MAX_URI_LEN);
		strncpy(buffer1,buffer,MAX_URI_LEN);
		PathRewrite(buffer,buffer1,mode_lextra,mode_rextra);		
		free(buffer1);
	}

	printf("DEBUG: PathCombineExtend result: %s\n", buffer);
	free(temp_right);
	return buffer;
}

inline static char* PathCombine(char* left,char* right) {
	return PathCombineExtend(left,right,0,"","");
}


#endif // HANDLER_H