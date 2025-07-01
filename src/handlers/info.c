#include "info.h" // This will include handler.h, which now has ServerInfo

#include <string.h> // For memcpy and strlen
#include <stdio.h>  // For printf (if needed for debugging)
#include <stdlib.h> // For malloc and free

#include "../common.h" 

#define CACHE_SIZE 131772 // Define a cache size for the HTML body

void DemoProcessRequest(Request *req, Response *res)
{	
	if (req == NULL || res == NULL) {
		printf("Invalid request or response object.\n");
		return;
	}

	printf("Processing request in DemoProcessRequest...\n");

	char *html_body=(char*)malloc(CACHE_SIZE);
	int body_len = 0;

	body_len+= snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<html>\n"
		"<head>\n"
		"<title>Server Info Page</title>\n"
		"<meta charset=\"UTF-8\">\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
		"<style>\n"
		"body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }\n"
		"h1, h2 { color: #0056b3; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 20px; }\n"
		"p { margin-bottom: 5px; }\n"
		"strong { color: #007bff; }\n"
		"table { width: 100%%; border-collapse: collapse; margin-top: 15px; }\n"
		"th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
		"th { background-color: #e9ecef; }\n"
		".section { background-color: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }\n"
		".warning { color: #dc3545; font-weight: bold; }\n"
		"</style>\n"
		"</head>\n"
		"<body>\n"
		"<h1>"
		SERVER_MOTD
		"Info Page"
		"</h1>\n"
		"<div class=\"section\">\n"
		"<h2>Request Details</h2>\n"
		"<p><strong>Request Method:</strong> %s</p>\n",
		req->method == METHOD_GET ? "GET" : "POST");

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Request Path And Query:</strong> %s</p>\n",req->path_and_query ? req->path_and_query : ""
	);

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Request Path:</strong> %s</p>\n",	
		req->path);

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Site Root:</strong> %s</p>\n",
		req->server_info->root_dir ? req->server_info->root_dir : "N/A");
	

	char file_path[1024]= {0};
	if (req->server_info->root_dir && req->path) {
		snprintf(file_path, sizeof(file_path), "%s%s", req->server_info->root_dir, req->path);
	} else {
		snprintf(file_path, sizeof(file_path), "N/A");
	}
	
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Handler File Path:</strong> %s</p>\n",
		file_path); 

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Request Handler Name:</strong> %s</p>\n",
		req->handler.name ? req->handler.name : "N/A");

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Request Handler Path:</strong> %s</p>\n",
		req->handler.path ? req->handler.path : "N/A");

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Request Handler Type:</strong> %s</p>\n",
		req->handler.type ? (req->handler.type==HANDLER_STATIC?"STATIC":
		(req->handler.type==HANDLER_PREFIX?"PREFIX":
		(req->handler.type==HANDLER_SUFFIX?"SUFFIX":"REGEX"))) : "N/A");


	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Query String:</strong> %s</p>\n",
		req->query_string ? req->query_string : "N/A");

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Query Count:</strong> %d</p>\n",
		req->query_count);

	if (req->query_count > 0) {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<table><thead><tr><th>#</th><th>Key</th><th>Value</th></tr></thead><tbody>\n");
		for (int i = 0; i < req->query_count; i++) {
			body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
				"<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n",
				i + 1,
				req->query[i].key ? req->query[i].key : "N/A",
				req->query[i].value ? req->query[i].value : "N/A");
		}
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</tbody></table>\n");
	} else {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p>No query parameters.</p>\n");
	}
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</div>\n"); // End Request Details section

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<div class=\"section\">\n<h2>HTTP Headers</h2>\n");
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Host:</strong> %s</p>\n",
		req->host ? req->host : "N/A");
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>User-Agent:</strong> %s</p>\n",
		req->user_agent ? req->user_agent : "N/A");
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Accept:</strong> %s</p>\n",
		req->accept ? req->accept : "*/*");
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Content-Type:</strong> %s</p>\n",
		req->content_type ? req->content_type : "N/A");
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Content-Length:</strong> %zu</p>\n",
		req->content_length);
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Body Length:</strong> %zu</p>\n",
		req->body_len);
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Body:</strong> %s</p>\n",
		req->body ? req->body : "N/A");
	
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Form Data Count:</strong> %d</p>\n",
		req->form_length);
	if (req->form_length > 0) {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<table><thead><tr><th>#</th><th>Key</th><th>Value</th></tr></thead><tbody>\n");
		for (int i = 0; i < req->form_length; i++) {
			body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
				"<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n",
				i + 1,
				req->form[i].key ? req->form[i].key : "N/A",
				req->form[i].value ? req->form[i].value : "N/A");
		}
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</tbody></table>\n");
	} else {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p>No form data.</p>\n");
	}

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Other Header Count:</strong> %d</p>\n",
		req->header_count);
	if (req->header_count > 0) {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<table><thead><tr><th>#</th><th>Key</th><th>Value</th></tr></thead><tbody>\n");
		for (int i = 0; i < req->header_count; i++) {
			body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
				"<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n",
				i + 1,
				req->headers[i].key ? req->headers[i].key : "N/A",
				req->headers[i].value ? req->headers[i].value : "N/A");
		}
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</tbody></table>\n");
	} else {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p>No other headers.</p>\n");
	}

	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"<p><strong>Cookie Count:</strong> %d</p>\n",
		req->cookie_count);
	if (req->cookie_count > 0) {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<table><thead><tr><th>#</th><th>Key</th><th>Value</th></tr></thead><tbody>\n");
		for (int i = 0; i < req->cookie_count; i++) {
			body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
				"<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n",
				i + 1,
				req->cookies[i].key ? req->cookies[i].key : "N/A",
				req->cookies[i].value ? req->cookies[i].value : "N/A");
		}
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</tbody></table>\n");
	} else {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p>No cookies.</p>\n");
	}
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</div>\n"); // End HTTP Headers section


	//--- NEW: Display Server Context Data from ServerInfo ---
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<div class=\"section\">\n<h2>Server Info</h2>\n");
	if (req->server_info != NULL) {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p><strong>Server IP:</strong> %s</p>\n",
			req->server_info->server_ip ? req->server_info->server_ip : "N/A");
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p><strong>Server Port:</strong> %d</p>\n",
			req->server_info->server_port);
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p><strong>Remote IP:</strong> %s</p>\n",
			req->server_info->remote_ip ? req->server_info->remote_ip : "N/A");
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p><strong>Remote Port:</strong> %d</p>\n",
			req->server_info->remote_port);
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p><strong>Site Root:</strong> %s</p>\n",
			req->server_info->root_dir ? req->server_info->root_dir : "N/A");
		// If you need more details from ListenSocket (like site_count, individual site details),
		// you would need to pass a pointer to ListenSocket directly or through a more complex ServerInfo.
		// For this version, we're only reflecting what's in ServerInfo struct.

	} else {
		body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "<p class=\"warning\">No server context data available.</p>\n");
	}
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</div>\n"); // End Server Context section
	// --- END NEW ---


		
	body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
		"</body>\n"
		"</html>\n");
		

	res->body = strdup(html_body);
	res->body_len = strlen(res->body);

	free(html_body);
}
