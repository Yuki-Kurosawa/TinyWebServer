// test.c
#include "test.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For malloc, free

#define CACHE_SIZE 4096

// This function will be dynamically loaded and called by the web server.
void ProcessRequest(Request *req, Response *res)
{
    // Check if request and response objects are valid
    if (req == NULL || res == NULL) {
        fprintf(stderr, "ProcessRequest (libtest.so): Invalid request or response object.\n");
        return;
    }

    fprintf(stderr, "ProcessRequest (libtest.so): Handling request for path '%s'\n", req->path ? req->path : "NULL");

    // Allocate memory for the HTML response body
    // Using CACHE_SIZE from common.h for buffer size
    char *html_body = (char*)malloc(CACHE_SIZE);
    if (html_body == NULL) {
        perror("malloc failed for html_body in ProcessRequest (libtest.so)");
        // Set 500 Internal Server Error response
        res->status_code = 500;
        // FIX: Remove free() here. HandleRequest initializes and free_response_members cleans up.
        // if (res->status_msg) free(res->status_msg); 
        res->status_msg = strdup("Internal Server Error");
        // FIX: Remove free() here.
        // if (res->content_type) free(res->content_type); 
        res->content_type = strdup("text/plain");
        if (res->body) free(res->body);
        res->body = strdup("Internal Server Error: Could not allocate memory for response body in libtest.so.");
        res->body_len = strlen(res->body);
        return;
    }
    int body_len = 0;

	printf("%d\n",req);

    // Build the HTML response body
    body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
        "<html>\n"
        "<head>\n"
        "<title>libtest.so Dynamic Page</title>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<style>\n"
        "body { font-family: sans-serif; margin: 20px; background-color: #e6f7ff; color: #333; }\n"
        "h1 { color: #007bff; border-bottom: 2px solid #aaddff; padding-bottom: 5px; margin-top: 20px; }\n"
        "p { margin-bottom: 5px; }\n"
        "strong { color: #0056b3; }\n"
        ".success { color: #28a745; font-weight: bold; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Hello from libtest.so!</h1>\n"
        "<p class=\"success\">This content was generated by the dynamically loaded library.</p>\n"
        "<p><strong>Requested Path:</strong> %s</p>\n"
        "<p><strong>Method:</strong> %s</p>\n",
        req->path ? req->path : "N/A",
        req->method ? (req->method == METHOD_GET ? "GET" : "POST") : "N/A");

	fprintf(stderr,"after html\n");

    // Add query parameters if any
    if (req->query_count > 0 && req->query != NULL) {
        body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<h2>Query Parameters:</h2><ul>\n");
        for (int i = 0; i < req->query_count; ++i) {
            body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<li><strong>%s:</strong> %s</li>\n",
                                 req->query[i].key ? req->query[i].key : "N/A",
                                 req->query[i].value ? req->query[i].value : "N/A");
        }
        body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</ul>\n");
    }

    // End HTML body
    body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</body>\n</html>\n");

    // Free existing response members before re-assigning
    // FIX: Remove free() here. HandleRequest initializes and free_response_members cleans up.
    // if (res->status_msg) free(res->status_msg); 
    // if (res->content_type) free(res->content_type); 
    //if (res->body) free(res->body); // This one is fine as body is NULL initially

    // Set response parameters
    res->status_code = 200;
    res->status_msg = strdup("OK");
    res->content_type = strdup("text/html; charset=utf-8");
    res->body = html_body; // Assign the dynamically generated HTML
    res->body_len = body_len; // Set the body length

    fprintf(stderr, "ProcessRequest (libtest.so): Finished processing. Body length: %zu\n", res->body_len);
}
