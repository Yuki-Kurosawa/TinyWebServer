// handlers/static_file.c
#include "static_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> // 用于 stat() 和 S_ISREG()
#include <unistd.h>   // 用于 access()
#include <errno.h>    // 用于 errno

#define PATH_MAX_LEN 4096     // Max file path length

// 定义一个缓存大小，用于读取文件内容到内存
#define CACHE_SIZE 131772 

// 辅助函数：根据文件扩展名确定 Content-Type
const char* get_content_type(const char *file_path) {
    const char *dot = strrchr(file_path, '.');
    if (!dot || dot == file_path) return "application/octet-stream"; // 默认二进制流

    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0) return "text/html";
    if (strcmp(dot, ".css") == 0) return "text/css";
    if (strcmp(dot, ".js") == 0) return "application/javascript";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".txt") == 0) return "text/plain";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".png") == 0) return "image/png";
    if (strcmp(dot, ".gif") == 0) return "image/gif";
    if (strcmp(dot, ".ico") == 0) return "image/x-icon";
    if (strcmp(dot, ".svg") == 0) return "image/svg+xml";
    if (strcmp(dot, ".pdf") == 0) return "application/pdf";
    if (strcmp(dot, ".xml") == 0) return "application/xml";
    if (strcmp(dot, ".mp4") == 0) return "video/mp4";
    if (strcmp(dot, ".webm") == 0) return "video/webm";
    if (strcmp(dot, ".ogg") == 0) return "audio/ogg";
    if (strcmp(dot, ".mp3") == 0) return "audio/mpeg";
    if (strcmp(dot, ".wav") == 0) return "audio/wav";
    // 根据需要添加更多类型
    return "application/octet-stream";
}

// 处理静态文件请求的函数
void StaticFileProcessRequest(Request *req, Response *res) {
    // 检查必要的输入参数是否有效
    if (req == NULL || res == NULL || req->server_info == NULL || req->path == NULL) {
        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/plain");
        res->body = strdup("Server configuration error for static file handler.");
        res->body_len = strlen(res->body);
        return;
    }

    char full_path[PATH_MAX_LEN];
    // 通过检查 ".." 路径段来防止目录遍历攻击。
    // 更健壮的解决方案会使用 realpath 或类似函数进行路径规范化。
    if (strstr(req->path, "..") != NULL) {
        res->status_code = 403;
        res->status_msg = strdup("Forbidden");
        res->content_type = strdup("text/plain");
        res->body = strdup("Directory traversal detected.");
        res->body_len = strlen(res->body);
        return;
    }

    // 构建完整的文件路径：root_dir + req->path
    // 确保 root_dir 以斜杠结尾，如果它不是单独的 "/"
    char *root_dir_effective = req->server_info->root_dir;
    char temp_root_dir[PATH_MAX_LEN];
    if (strlen(root_dir_effective) > 0 && root_dir_effective[strlen(root_dir_effective) - 1] != '/') {
        snprintf(temp_root_dir, PATH_MAX_LEN, "%s/", root_dir_effective);
        root_dir_effective = temp_root_dir;
    } else if (strlen(root_dir_effective) == 0) { // 如果 root_dir 为空，则默认为当前目录
        root_dir_effective = "./";
    }

    // 处理根路径请求（例如，"/"），通过追加 "index.html"
    char *file_to_serve = (char*)req->path;
    char index_path[PATH_MAX_LEN];
    if (strcmp(req->path, "/") == 0) {
        snprintf(index_path, PATH_MAX_LEN, "%sindex.html", root_dir_effective);
        file_to_serve = index_path;
    } else {
        // 如果 req->path 以 '/' 开头且 root_dir_effective 已经以 '/' 结尾，则移除 req->path 的前导 '/'
        if (req->path[0] == '/' && root_dir_effective[strlen(root_dir_effective) - 1] == '/') {
            snprintf(full_path, PATH_MAX_LEN, "%s%s", root_dir_effective, req->path + 1);
        } else {
            snprintf(full_path, PATH_MAX_LEN, "%s%s", root_dir_effective, req->path);
        }
        file_to_serve = full_path;
    }


    struct stat st;
    // 检查文件是否存在并获取其信息
    if (stat(file_to_serve, &st) == -1) {
        // 文件未找到或其他 stat 错误
        if (errno == ENOENT) { // 文件或目录不存在
            res->status_code = 404;
            res->status_msg = strdup("Not Found");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>");
            res->body_len = strlen(res->body);
        } else if (errno == EACCES) { // 权限拒绝
            res->status_code = 403;
            res->status_msg = strdup("Forbidden");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>");
            res->body_len = strlen(res->body);
        } else { // 其他内部服务器错误
            res->status_code = 500;
            res->status_msg = strdup("Internal Server Error");
            res->content_type = strdup("text/html");
            res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred while trying to access the file.</p></body></html>");
            res->body_len = strlen(res->body);
        }
        return;
    }

    // 检查是否是常规文件（而不是目录或其他特殊文件）
    if (!S_ISREG(st.st_mode)) {
        res->status_code = 403; // 或者 404，取决于对目录请求的期望行为
        res->status_msg = strdup("Forbidden");
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>403 Forbidden</h1><p>Access to directories is forbidden.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    // 以二进制模式打开文件，适用于所有文件类型
    FILE *file = fopen(file_to_serve, "rb"); 
    if (file == NULL) {
        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/html");
        res->body = strdup("<html><body><h1>500 Internal Server Error</h1><p>Could not open file for reading.</p></body></html>");
        res->body_len = strlen(res->body);
        return;
    }

    // 确定文件大小并分配缓冲区
    long file_size = st.st_size;
    if (file_size > CACHE_SIZE) {
        fprintf(stderr, "Warning: File size %ld exceeds CACHE_SIZE %d. Truncating or erroring.\n", file_size, CACHE_SIZE);
        // 为了简单起见，我们只读取到 CACHE_SIZE。实际的服务器会流式传输或以其他方式处理大文件。
        file_size = CACHE_SIZE;
    }

    char *file_content = (char *)malloc(file_size + 1);
    if (file_content == NULL) {
        perror("malloc failed for file_content");
        fclose(file);
        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/plain");
        res->body = strdup("Server out of memory for file content.");
        res->body_len = strlen(res->body);
        return;
    }

    // 读取文件内容
    size_t bytes_read = fread(file_content, 1, file_size, file);
    fclose(file);

    // 检查文件读取是否发生错误
    if (bytes_read != file_size && ferror(file)) {
        perror("fread failed for file content");
        free(file_content);
        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/plain");
        res->body = strdup("Error reading file content.");
        res->body_len = strlen(res->body);
        return;
    }
    file_content[bytes_read] = '\0'; // 空终止符，适用于文本文件，对二进制文件也安全

    // 设置响应参数
    res->status_code = 200;
    res->status_msg = strdup("OK");
    res->content_type = strdup(get_content_type(file_to_serve));
    res->body = file_content;
    res->body_len = bytes_read;

    printf("Served static file: %s (Content-Type: %s, Size: %zu bytes)\n", file_to_serve, res->content_type, res->body_len);
}
