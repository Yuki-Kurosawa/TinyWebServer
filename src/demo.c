#include "demo.h"

#include <string.h> // For memcpy and strlen
#include <stdio.h>  // For printf (if needed for debugging)
#include <stdlib.h> // For malloc and free

void DemoProcessRequest(Request *req, Response *res)
{	
	if (req == NULL || res == NULL) {
		printf("Invalid request or response object.\n");
		return; // Invalid request or response object, do nothing
	}

	// Convert the request to a response
	char *html_body=(char*)malloc(16384);
	int body_len = 0;

	body_len+= snprintf(html_body + body_len, 16384 - body_len,
		"<html>\n"
		"<head>\n"
		"<title>Demo Response</title>\n"
		"<meta charset=\"UTF-8\">\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
		"</head>\n"
		"<body>\n"
		"<p>Request Method: %s</p>\n",
		req->method == METHOD_GET ? "GET" : "POST");

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Request Path And Query: %s</p>\n",req->path_and_query ? req->path_and_query : ""
	);

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Request Path: %s</p>\n",	
		req->path);

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Site Root: %s</p>\n",
		req->root_dir ? req->root_dir : "N/A");

	char file_path[1024]= {0};
	if (req->root_dir && req->path) {
		snprintf(file_path, sizeof(file_path), "%s%s", req->root_dir, req->path);
	} else {
		snprintf(file_path, sizeof(file_path), "N/A");
	}
	
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Handler File Path: %s</p>\n",
		req->root_dir ? file_path : "N/A");

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Query String: %s</p>\n",
		req->query_string ? req->query_string : "");

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Query Count: %d</p>\n",
		req->query_count);

	for (int i = 0; i < req->query_count; i++) {
		body_len += snprintf(html_body + body_len, 16384 - body_len,
			"<p>Query %d: %s: %s</p>\n",
			i + 1,
			req->query[i].key ? req->query[i].key : "N/A",
			req->query[i].value ? req->query[i].value : "N/A");
	}	

	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Host: %s</p>\n",
		req->host ? req->host : "N/A");
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>User-Agent: %s</p>\n",
		req->user_agent ? req->user_agent : "N/A");
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Accept: %s</p>\n",
		req->accept ? req->accept : "*/*");
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Content-Type: %s</p>\n",
		req->content_type ? req->content_type : "N/A");
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Content-Length: %zu</p>\n",
		req->content_length);
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Body Length: %zu</p>\n",
		req->body_len);
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Body: %s</p>\n",
		req->body ? req->body : "N/A");
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Form Length: %d</p>\n",
		req->form_length);
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Form Data: </p>\n");
	for (int i = 0; i < req->form_length; i++) {
		body_len += snprintf(html_body + body_len, 16384 - body_len,
			"<p>Form %d: %s: %s</p>\n",
			i + 1,
			req->form[i].key ? req->form[i].key : "N/A",
			req->form[i].value ? req->form[i].value : "N/A");
	}
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Header Count: %d</p>\n",
		req->header_count);
	for (int i = 0; i < req->header_count; i++) {
		body_len += snprintf(html_body + body_len, 16384 - body_len,
			"<p>Header %d: %s: %s</p>\n",
			i + 1,
			req->headers[i].key ? req->headers[i].key : "N/A",
			req->headers[i].value ? req->headers[i].value : "N/A");
	}
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"<p>Cookie Count: %d</p>\n",
		req->cookie_count);
	for (int i = 0; i < req->cookie_count; i++) {
		body_len += snprintf(html_body + body_len, 16384 - body_len,
			"<p>Cookie %d: %s=%s</p>\n",
			i + 1,
			req->cookies[i].key ? req->cookies[i].key : "N/A",
			req->cookies[i].value ? req->cookies[i].value : "N/A");
	}
	body_len += snprintf(html_body + body_len, 16384 - body_len,
		"</body>\n"
		"</html>\n");


	

	res->body = strdup(html_body); // Set the response body
	res->body_len = strlen(res->body); // Set the body length

	free(html_body); // Free the temporary HTML body buffer
}

