// Copyright (c) 2025 Yuki Kurosawa
// SPDX-License-Identifier: MIT
// handlers/static_file.c
#include "static_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> 
#include <unistd.h>   
#include <errno.h>      
#include "../common.h" 



bool StaticFileCheckPage(Request *req, char *path) {
    char file_to_serve[PATH_MAX_LEN];    
    
    int path_snprintf_result = snprintf(file_to_serve, sizeof(file_to_serve), "%s%s/%s",
                                        req->server_info->root_dir, req->path,path);
    printf("StaticFileCheckPage: Checking existence of file '%s'\n", file_to_serve);

    struct stat path_stat;
    
    if (stat(file_to_serve, &path_stat) == 0) {
        
        if (S_ISDIR(path_stat.st_mode)) {
            printf("DEBUG: StaticFileCheckPage: '%s' is a directory\n", req->path);
            return false; 
        }
    }

    FILE* fp=fopen(file_to_serve,"r");
    if(fp==NULL){
        printf("StaticFileCheckPage: Failed to open file '%s'\n", file_to_serve);
        return false;
    }
    return true;
}

void StaticFileProcessRequest(Request *req, Response *res) {
    fprintf(stderr, "StaticFileProcessRequest: Handling request for path '%s' with root_dir '%s'\n", 
            req->path ? req->path : "NULL", 
            req->server_info && req->server_info->root_dir ? req->server_info->root_dir : "NULL");

    
    if (req == NULL || res == NULL || req->server_info == NULL || req->path == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: Invalid input parameters.\n");
       
        if (res->body) free(res->body); 

        res->status_code = 500;
        
        if (res->status_msg) free(res->status_msg); // Free old one before strdup new one
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type); // Free old one before strdup new one
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Invalid input parameters.");
        res->body_len = strlen(res->body);
        return;
    }

    char file_to_serve[PATH_MAX_LEN];
    
    
    int path_snprintf_result = snprintf(file_to_serve, sizeof(file_to_serve), "%s%s",
                                        req->server_info->root_dir, req->path);

    
    if (path_snprintf_result >= (int)sizeof(file_to_serve) || path_snprintf_result < 0) {
        fprintf(stderr, "StaticFileProcessRequest: Constructed path too long or snprintf error for '%s%s'\n",
                req->server_info->root_dir, req->path);
        
        if (res->body) free(res->body);

        res->status_code = 500;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>File path too long.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    struct stat file_stat;
    
    if (stat(file_to_serve, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
        
        fprintf(stderr, "StaticFileProcessRequest: stat('%s') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        
        if (res->body) free(res->body);

        res->status_code = 404;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Not Found");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    // --- libmagic begin ---
    magic_t magic_cookie;
    const char *mime_type;

    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: magic_open failed: %s\\n", strerror(errno));
       
        if (res->body) free(res->body);

        res->status_code = 500;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Failed to initialize libmagic.");
        res->body_len = strlen(res->body);
        return;
    } else {
        
        if (magic_load(magic_cookie, NULL) != 0) {
            fprintf(stderr, "StaticFileProcessRequest: magic_load failed: %s\\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            
            if (res->status_msg) free(res->status_msg);
            res->status_msg = strdup("Internal Server Error");
            if (res->content_type) free(res->content_type);
            res->content_type = strdup("application/octet-stream"); 
            if (res->body) free(res->body);
            res->body = strdup("Internal Server Error: Failed to load libmagic database.");
            res->body_len = strlen(res->body);
            return;
        } else {
            
            mime_type = magic_file(magic_cookie, file_to_serve);
            if (mime_type == NULL) {
                fprintf(stderr, "StaticFileProcessRequest: magic_file failed for '%s': %s\\n", file_to_serve, magic_error(magic_cookie));
               
                if (res->status_msg) free(res->status_msg);
                res->status_msg = strdup("Internal Server Error");
                if (res->content_type) free(res->content_type);
                res->content_type = strdup("application/octet-stream"); 
                if (res->body) free(res->body);
                res->body = strdup("Internal Server Error: Failed to determine file type.");
                res->body_len = strlen(res->body);
                magic_close(magic_cookie);
                return;
            } else {
                
                if (res->content_type) free(res->content_type);
                res->content_type = strdup(mime_type); 
            }
            magic_close(magic_cookie); 
        }
    }
    // --- libmagic end ---

    
    FILE *file = fopen(file_to_serve, "rb"); 
    if (file == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: fopen('%s') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        
        if (res->body) free(res->body);

        res->status_code = 500;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Failed to open file.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    
    long file_size = file_stat.st_size;

    
    
    if (res->body) {
        free(res->body);
        res->body = NULL;
    }
    res->body = (char *)malloc(file_size);
    if (res->body == NULL) {
        perror("StaticFileProcessRequest: malloc failed for response body");
        fclose(file);
        
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Could not allocate memory for file content.");
        res->body_len = strlen(res->body);
        return;
    }

    
    size_t bytes_read = fread(res->body, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "StaticFileProcessRequest: fread failed to read all bytes from '%s'. Expected %ld, got %zu.\n",
                file_to_serve, file_size, bytes_read);
        free(res->body); 
        res->body = NULL;
        fclose(file);
        
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Failed to read file content.");
        res->body_len = strlen(res->body);
        return;
    }

    fclose(file); 

    
    res->status_code = 200;
    
    if (res->status_msg) {
        free(res->status_msg);
        res->status_msg = NULL;
    }
    res->status_msg = strdup("OK");
    
    res->body_len = bytes_read; 

    fprintf(stderr, "StaticFileProcessRequest: Successfully served '%s'. Content-Type: %s, Length: %zu\n",
            file_to_serve, res->content_type, res->body_len);
}
