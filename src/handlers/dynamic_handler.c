// handlers/dynamic_handler.c
#include "dynamic_handler.h"
#include <string.h> // For strlen, strdup, snprintf, strrchr, strncpy, strcat
#include <stdio.h>  // For fprintf, snprintf, perror
#include <stdlib.h> // For malloc, free
#include <time.h>   // For time(), localtime(), strftime()
#include <sys/time.h> // For gettimeofday()
#include <sys/stat.h> // For stat() and S_ISREG()
#include <unistd.h>   // For access()
#include <errno.h>    // For errno
#include <dlfcn.h>    // NEW: For dynamic library loading (dlopen, dlsym, dlclose)

#include "../common.h" 

#define PATH_MAX_LEN 4096 

bool DynamicHandlerCheckPage(HandlerMetadata meta, char *path) {
    return true;
}


void DynamicHandlerProcessRequest(Request *req, Response *res) {
    
    if (req == NULL || res == NULL || req->server_info == NULL || req->path == NULL) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Invalid input parameters.\n");
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Invalid request or response objects.");
        res->body_len = strlen(res->body);
        return;
    }

    fprintf(stderr, "DynamicHandlerProcessRequest: Handling dynamic request for path '%s' with root_dir '%s'\n",
            req->path ? req->path : "NULL",
            req->server_info->root_dir ? req->server_info->root_dir : "NULL");

    char file_to_serve[PATH_MAX_LEN];
    char dynamic_path_base[PATH_MAX_LEN]; 

    const char *original_path = req->path;
    char *last_slash = strrchr(original_path, '/');
    const char *filename_start;
    char directory_path[PATH_MAX_LEN];
    memset(directory_path, 0, sizeof(directory_path));

    if (last_slash != NULL) {
        
        size_t dir_len = last_slash - original_path + 1;
        if (dir_len >= sizeof(directory_path)) {
            fprintf(stderr, "DynamicHandlerProcessRequest: Directory path too long.\n");
            if (res->status_msg) free(res->status_msg);
            if (res->content_type) free(res->content_type);
            if (res->body) free(res->body);

            res->status_code = 500;
            res->status_msg = strdup("Internal Server Error");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Dynamic script path too long (directory).</p></body></html>");
            res->body_len = strlen(res->body);
            return;
        }
        strncpy(directory_path, original_path, dir_len);
        directory_path[dir_len] = '\0';
        filename_start = last_slash + 1;
    } else {
        
        filename_start = original_path;
        
    }

    char base_filename[PATH_MAX_LEN]; 
    char *dot_in_filename = strrchr(filename_start, '.');

    if (dot_in_filename != NULL) {
        
        size_t base_filename_len = dot_in_filename - filename_start;
        if (base_filename_len >= sizeof(base_filename)) {
            fprintf(stderr, "DynamicHandlerProcessRequest: Base filename too long.\n");
            if (res->status_msg) free(res->status_msg);
            if (res->content_type) free(res->content_type);
            if (res->body) free(res->body);

            res->status_code = 500;
            res->status_msg = strdup("Internal Server Error");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Dynamic script path too long (base filename).</p></body></html>");
            res->body_len = strlen(res->body);
            return;
        }
        strncpy(base_filename, filename_start, base_filename_len);
        base_filename[base_filename_len] = '\0';
    } else {
        
        if (strlen(filename_start) >= sizeof(base_filename)) {
            fprintf(stderr, "DynamicHandlerProcessRequest: Filename (no dot) too long.\n");
            if (res->status_msg) free(res->status_msg);
            if (res->content_type) free(res->content_type);
            if (res->body) free(res->body);

            res->status_code = 500;
            res->status_msg = strdup("Internal Server Error");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Dynamic script path too long (filename no dot).</p></body></html>");
            res->body_len = strlen(res->body);
            return;
        }
        strcpy(base_filename, filename_start);
    }

    
    int snprintf_result = snprintf(dynamic_path_base, sizeof(dynamic_path_base), "%s%s%s.so",
                                   directory_path, "lib", base_filename);

    if (snprintf_result >= (int)sizeof(dynamic_path_base) || snprintf_result < 0) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Final dynamic_path_base too long or snprintf error.\n");
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Dynamic script path too long (final).</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    
    int path_snprintf_result = snprintf(file_to_serve, sizeof(file_to_serve), "%s%s",
                                        req->server_info->root_dir, dynamic_path_base);

    
    if (path_snprintf_result >= (int)sizeof(file_to_serve) || path_snprintf_result < 0) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Constructed path too long or snprintf error for '%s%s'\n",
                req->server_info->root_dir, dynamic_path_base);
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>File path too long.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    struct stat file_stat;
    
    if (stat(file_to_serve, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
        
        fprintf(stderr, "DynamicHandlerProcessRequest: Dynamic script '%s' not found or not a regular file. errno: %d (%s)\n",
                file_to_serve, errno, strerror(errno));

        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 404;
        res->status_msg = strdup("Not Found");
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>404 Not Found</h1><p>The requested dynamic script was not found on this server.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    
    void *handle = dlopen(file_to_serve, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Failed to open shared library '%s': %s\n", file_to_serve, dlerror());
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/html");
        char *error_body = (char*)malloc(CACHE_SIZE); // Re-use CACHE_SIZE for error body
        if (error_body) {
            snprintf(error_body, CACHE_SIZE,
                     "<html><body><h1>500 Internal Server Error</h1><p>Failed to load dynamic script: %s</p><p>Error: %s</p></body></html>",
                     file_to_serve, dlerror());
            res->body = error_body;
            res->body_len = strlen(res->body);
        } else {
            res->body = strdup("Internal Server Error: Failed to load dynamic script.");
            res->body_len = strlen(res->body);
        }
        return;
    }

    
    dlerror();
    RequestHandler dynamic_request_handler = (RequestHandler)dlsym(handle, "ProcessRequest");
    const char *dlsym_error = dlerror(); 

    if (dlsym_error) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Failed to find symbol 'ProcessRequest' in '%s': %s\n", file_to_serve, dlsym_error);
        dlclose(handle); 
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/html");
        char *error_body = (char*)malloc(CACHE_SIZE);
        if (error_body) {
             snprintf(error_body, CACHE_SIZE,
                     "<html><body><h1>500 Internal Server Error</h1><p>Dynamic script found but 'ProcessRequest' function not found: %s</p><p>Error: %s</p></body></html>",
                     file_to_serve, dlsym_error);
            res->body = error_body;
            res->body_len = strlen(res->body);
        } else {
            res->body = strdup("Internal Server Error: 'ProcessRequest' function not found.");
            res->body_len = strlen(res->body);
        }
        return;
    }

    
    fprintf(stderr, "DynamicHandlerProcessRequest: Calling dynamically loaded ProcessRequest from '%s'\n", file_to_serve);
    dynamic_request_handler(req, res); 

    
    dlclose(handle);
    fprintf(stderr, "DynamicHandlerProcessRequest: Closed shared library '%s'\n", file_to_serve);

    
}
