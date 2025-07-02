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

#include "../common.h" // 包含通用定义和宏，例如 CACHE_SIZE

#define PATH_MAX_LEN 4096 // 定义一个最大路径长度

// 动态内容请求处理器占位符
void DynamicHandlerProcessRequest(Request *req, Response *res) {
    // 检查请求和响应对象是否有效
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
    char dynamic_path_base[PATH_MAX_LEN]; // 用于存储修改后的路径

    const char *original_path = req->path;
    char *last_slash = strrchr(original_path, '/');
    const char *filename_start;
    char directory_path[PATH_MAX_LEN];
    memset(directory_path, 0, sizeof(directory_path));

    if (last_slash != NULL) {
        // 复制目录部分（包括最后一个斜杠）
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
        // 没有斜杠，整个路径就是文件名
        filename_start = original_path;
        // directory_path 保持为空
    }

    char base_filename[PATH_MAX_LEN]; // 用于存储不带扩展名的文件名
    char *dot_in_filename = strrchr(filename_start, '.');

    if (dot_in_filename != NULL) {
        // 复制文件名中点之前的部分
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
        // 文件名中没有点，使用整个文件名
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

    // 构建新的 dynamic_path_base: 目录 + "lib" + 不带扩展名的文件名 + ".so"
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

    // 构建完整的文件路径
    int path_snprintf_result = snprintf(file_to_serve, sizeof(file_to_serve), "%s%s",
                                        req->server_info->root_dir, dynamic_path_base);

    // 检查路径是否过长
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
    // 检查文件是否存在且是常规文件
    if (stat(file_to_serve, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
        // 文件不存在或不是常规文件，返回 404 Not Found
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

    // 为HTML响应体分配内存
    char *html_body = (char*)malloc(CACHE_SIZE);
    if (html_body == NULL) {
        perror("malloc failed for html_body in DynamicHandlerProcessRequest");
        // 设置500 Internal Server Error响应
        res->status_code = 500;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);
        res->body = strdup("Internal Server Error: Could not allocate memory for response body.");
        res->body_len = strlen(res->body);
        return;
    }
    int body_len = 0;

    // 获取当前服务器时间
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t current_time = tv.tv_sec;
    struct tm *local_time = localtime(&current_time);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);

    // 构建HTML响应体
    body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len,
        "<html>\n"
        "<head>\n"
        "<title>Dynamic Content Placeholder</title>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "<style>\n"
        "body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }\n"
        "h1 { color: #0056b3; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 20px; }\n"
        "p { margin-bottom: 5px; }\n"
        "strong { color: #007bff; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<h1>Dynamic Content Placeholder</h1>\n"
        "<p>This page is served by a dynamic content handler.</p>\n"
        "<p><strong>Requested Path:</strong> %s</p>\n"
        "<p><strong>Resolved Script File:</strong> %s</p>\n" // NEW: 显示找到的脚本文件
        "<p><strong>Handler Type:</strong> Suffix Match (%s)</p>\n"
        "<p><strong>Current Server Time:</strong> %s</p>\n",
        req->path ? req->path : "N/A",
        file_to_serve, // 显示实际找到的文件路径
        dot_in_filename ? dot_in_filename : "N/A", // 提取后缀，如果存在
        time_str);

    // 结束HTML响应体
    body_len += snprintf(html_body + body_len, CACHE_SIZE - body_len, "</body>\n</html>\n");

    // 在重新分配之前，释放旧的响应字符串（如果存在）
    if (res->status_msg) free(res->status_msg);
    if (res->content_type) free(res->content_type);
    if (res->body) free(res->body);

    // 设置响应参数
    res->status_code = 200;
    res->status_msg = strdup("OK");
    res->content_type = strdup("text/html; charset=utf-8"); // 动态内容通常是HTML
    res->body = html_body; // 将动态生成的HTML赋值给响应体
    res->body_len = body_len; // 设置响应体长度

    fprintf(stderr, "DynamicHandlerProcessRequest: Finished processing. Body length: %zu\n", res->body_len);
}
