// handlers/static_file.c
#include "static_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // 用于 stat() 和 S_ISREG()
#include <unistd.h>   // 用于 access()
#include <errno.h>    // 用于 errno
#include <magic.h>    // 新增: 用于 libmagic 库
#include "../common.h" // 包含通用定义和宏
// 定义一个缓存大小，用于读取文件内容到内存
#define PATH_MAX_LEN 4096 // 定义一个最大路径长度

// 处理静态文件请求的函数
void StaticFileProcessRequest(Request *req, Response *res) {
    fprintf(stderr, "StaticFileProcessRequest: Handling request for path '%s' with root_dir '%s'\n", 
            req->path ? req->path : "NULL", 
            req->server_info && req->server_info->root_dir ? req->server_info->root_dir : "NULL");

    // 检查必要的输入参数是否有效
    if (req == NULL || res == NULL || req->server_info == NULL || req->path == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: Invalid input parameters.\n");
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()，因为它们由 HandleRequest 管理
        if (res->body) free(res->body); // 仅释放 body，如果它已被分配

        res->status_code = 500;
        // NEW: 直接 strdup 新值，替换 HandleRequest 中设置的默认值
        if (res->status_msg) free(res->status_msg); // Free old one before strdup new one
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type); // Free old one before strdup new one
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Invalid input parameters.");
        res->body_len = strlen(res->body);
        return;
    }

    char file_to_serve[PATH_MAX_LEN];
    // 构建完整的文件路径
    // snprintf 的返回值是写入的字符数（不包括终止符），如果缓冲区不足，则返回所需的字符数。
    int path_snprintf_result = snprintf(file_to_serve, sizeof(file_to_serve), "%s%s",
                                        req->server_info->root_dir, req->path);

    // 检查路径是否过长
    if (path_snprintf_result >= (int)sizeof(file_to_serve) || path_snprintf_result < 0) {
        fprintf(stderr, "StaticFileProcessRequest: Constructed path too long or snprintf error for '%s%s'\n",
                req->server_info->root_dir, req->path);
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
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
    // 检查文件是否存在且是常规文件
    if (stat(file_to_serve, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
        // 文件不存在或不是常规文件，返回 404 Not Found
        fprintf(stderr, "StaticFileProcessRequest: stat('%s') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
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

    // --- libmagic 部分开始 ---
    magic_t magic_cookie;
    const char *mime_type;

    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: magic_open failed: %s\\n", strerror(errno));
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
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
        // 加载默认的魔术数据库
        if (magic_load(magic_cookie, NULL) != 0) {
            fprintf(stderr, "StaticFileProcessRequest: magic_load failed: %s\\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
            if (res->status_msg) free(res->status_msg);
            res->status_msg = strdup("Internal Server Error");
            if (res->content_type) free(res->content_type);
            res->content_type = strdup("application/octet-stream"); // 默认值
            if (res->body) free(res->body);
            res->body = strdup("Internal Server Error: Failed to load libmagic database.");
            res->body_len = strlen(res->body);
            return;
        } else {
            // 使用 magic_file() 判断文件类型
            mime_type = magic_file(magic_cookie, file_to_serve);
            if (mime_type == NULL) {
                fprintf(stderr, "StaticFileProcessRequest: magic_file failed for '%s': %s\\n", file_to_serve, magic_error(magic_cookie));
                // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
                if (res->status_msg) free(res->status_msg);
                res->status_msg = strdup("Internal Server Error");
                if (res->content_type) free(res->content_type);
                res->content_type = strdup("application/octet-stream"); // 默认值
                if (res->body) free(res->body);
                res->body = strdup("Internal Server Error: Failed to determine file type.");
                res->body_len = strlen(res->body);
                magic_close(magic_cookie);
                return;
            } else {
                // NEW: 释放旧的 content_type (由 HandleRequest strdup), 然后 strdup 新的
                if (res->content_type) free(res->content_type);
                res->content_type = strdup(mime_type); // 复制 MIME 类型字符串
            }
            magic_close(magic_cookie); // 关闭 libmagic 句柄
        }
    }
    // --- libmagic 部分结束 ---

    // 尝试打开文件并读取内容
    FILE *file = fopen(file_to_serve, "rb"); // 以二进制读取模式打开
    if (file == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: fopen('%s') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
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

    // 获取文件大小
    long file_size = file_stat.st_size;

    // 为文件内容分配内存
    // 在重新分配之前，释放旧的 body (如果存在)
    if (res->body) {
        free(res->body);
        res->body = NULL;
    }
    res->body = (char *)malloc(file_size);
    if (res->body == NULL) {
        perror("StaticFileProcessRequest: malloc failed for response body");
        fclose(file);
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Could not allocate memory for file content.");
        res->body_len = strlen(res->body);
        return;
    }

    // 读取文件内容到内存
    size_t bytes_read = fread(res->body, 1, file_size, file);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "StaticFileProcessRequest: fread failed to read all bytes from '%s'. Expected %ld, got %zu.\n",
                file_to_serve, file_size, bytes_read);
        free(res->body); // 释放部分读取的 body
        res->body = NULL;
        fclose(file);
        // NEW: 移除对 res->status_msg 和 res->content_type 的 free()
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
        res->body = strdup("Internal Server Error: Failed to read file content.");
        res->body_len = strlen(res->body);
        return;
    }

    fclose(file); // 关闭文件

    // 设置响应参数
    res->status_code = 200;
    // NEW: 释放旧的 status_msg (由 HandleRequest strdup), 然后 strdup 新的
    if (res->status_msg) {
        free(res->status_msg);
        res->status_msg = NULL;
    }
    res->status_msg = strdup("OK");
    // res->content_type 已由 libmagic 设置
    res->body_len = bytes_read; // 设置响应体长度

    fprintf(stderr, "StaticFileProcessRequest: Successfully served '%s'. Content-Type: %s, Length: %zu\n",
            file_to_serve, res->content_type, res->body_len);
}
