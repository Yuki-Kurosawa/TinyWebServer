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
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
        fprintf(stderr, "StaticFileProcessRequest: Directory traversal attempt detected for path '%s'.\n", req->path);
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
    char *file_to_serve = NULL;
    char index_path[PATH_MAX_LEN];

    if (strcmp(req->path, "/") == 0) {
        snprintf(index_path, PATH_MAX_LEN, "%sindex.html", root_dir_effective);
        file_to_serve = index_path;
        fprintf(stderr, "StaticFileProcessRequest: Serving default index file: '%s'\n", file_to_serve);
    } else {
        // 如果 req->path 以 '/' 开头且 root_dir_effective 已经以 '/' 结尾，则移除 req->path 的前导 '/'
        // 否则直接拼接
        if (req->path[0] == '/' && root_dir_effective[strlen(root_dir_effective) - 1] == '/') {
            snprintf(full_path, PATH_MAX_LEN, "%s%s", root_dir_effective, req->path + 1);
        } else {
            snprintf(full_path, PATH_MAX_LEN, "%s%s", root_dir_effective, req->path);
        }
        file_to_serve = full_path;
        fprintf(stderr, "StaticFileProcessRequest: Attempting to serve file: '%s'\n", file_to_serve);
    }


    struct stat st;
    // 检查文件是否存在并获取其信息
    if (stat(file_to_serve, &st) == -1) {
        // 文件未找到或其他 stat 错误
        fprintf(stderr, "StaticFileProcessRequest: stat('%s') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
        fprintf(stderr, "StaticFileProcessRequest: Path '%s' is not a regular file.\n", file_to_serve);
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
        fprintf(stderr, "StaticFileProcessRequest: fopen('%s', 'rb') failed. errno: %d (%s)\n", file_to_serve, errno, strerror(errno));
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
        fprintf(stderr, "StaticFileProcessRequest: Warning: File size %ld exceeds CACHE_SIZE %d. Reading only up to CACHE_SIZE.\n", file_size, CACHE_SIZE);
        // 为了简单起见，我们只读取到 CACHE_SIZE。实际的服务器会流式传输或以其他方式处理大文件。
        file_size = CACHE_SIZE;
    }

    char *file_content = (char *)malloc(file_size + 1);
    if (file_content == NULL) {
        perror("StaticFileProcessRequest: malloc failed for file_content");
        fclose(file);
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

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
        perror("StaticFileProcessRequest: fread failed for file content");
        free(file_content);
        // Ensure existing allocated strings are freed before re-assigning
        if (res->status_msg) free(res->status_msg);
        if (res->content_type) free(res->content_type);
        if (res->body) free(res->body);

        res->status_code = 500;
        res->status_msg = strdup("Internal Server Error");
        res->content_type = strdup("text/plain");
        res->body = strdup("Error reading file content.");
        res->body_len = strlen(res->body);
        return;
    }
    file_content[bytes_read] = '\0'; // 空终止符，适用于文本文件，对二进制文件也安全

    // --- 使用 libmagic 判断 Content-Type ---
    magic_t magic_cookie;
    const char *mime_type;

    // 在重新分配之前，释放旧的 content_type
    if (res->content_type) {
        free(res->content_type);
        res->content_type = NULL;
    }

    // 打开 libmagic 数据库，指定获取 MIME 类型
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == NULL) {
        fprintf(stderr, "StaticFileProcessRequest: magic_open failed: %s\n", magic_error(magic_cookie));
        // 无法初始化 libmagic，回退到默认或错误处理
        res->content_type = strdup("application/octet-stream"); // 默认值
    } else {
        // 加载默认的魔术数据库
        if (magic_load(magic_cookie, NULL) != 0) {
            fprintf(stderr, "StaticFileProcessRequest: magic_load failed: %s\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            res->content_type = strdup("application/octet-stream"); // 默认值
        } else {
            // 使用 magic_file() 判断文件类型
            mime_type = magic_file(magic_cookie, file_to_serve);
            if (mime_type == NULL) {
                fprintf(stderr, "StaticFileProcessRequest: magic_file failed for '%s': %s\n", file_to_serve, magic_error(magic_cookie));
                res->content_type = strdup("application/octet-stream"); // 默认值
            } else {
                res->content_type = strdup(mime_type); // 复制 MIME 类型字符串
            }
            magic_close(magic_cookie); // 关闭 libmagic 句柄
        }
    }
    // --- libmagic 部分结束 ---

    // 设置响应参数
    res->status_code = 200;
    // 在重新分配之前，释放旧的 status_msg
    if (res->status_msg) {
        free(res->status_msg);
        res->status_msg = NULL;
    }
    res->status_msg = strdup("OK");
    // res->content_type 已由 libmagic 设置
    // 在重新分配之前，释放旧的 body
    if (res->body) {
        free(res->body);
        res->body = NULL;
    }
    res->body = file_content; // 接管 file_content 的所有权
    res->body_len = bytes_read;

    fprintf(stderr, "StaticFileProcessRequest: Successfully served static file: '%s' (Content-Type: %s, Size: %zu bytes)\n", file_to_serve, res->content_type, res->body_len);
}
