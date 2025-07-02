// handlers/dynamic_handler.c
#include "dynamic_handler.h"
#include <string.h> // For strlen, strdup, snprintf
#include <stdio.h>  // For fprintf, snprintf
#include <stdlib.h> // For malloc, free
#include <time.h>   // For time(), localtime(), strftime()
#include <sys/time.h> // For gettimeofday()

#include "../common.h" // 包含通用定义和宏，例如 CACHE_SIZE

// 动态内容请求处理器占位符
void DynamicHandlerProcessRequest(Request *req, Response *res) {
    // 检查请求和响应对象是否有效
    if (req == NULL || res == NULL) {
        fprintf(stderr, "DynamicHandlerProcessRequest: Invalid request or response object.\n");
        return;
    }

    fprintf(stderr, "DynamicHandlerProcessRequest: Handling dynamic request for path '%s'\n", req->path ? req->path : "NULL");

    // 为HTML响应体分配内存
    char *html_body = (char*)malloc(CACHE_SIZE);
    if (html_body == NULL) {
        perror("malloc failed for html_body in DynamicHandlerProcessRequest");
        // 设置500 Internal Server Error响应
        res->status_code = 500;
        if (res->status_msg) free(res->status_msg);
        res->status_msg = strdup("Internal Server Error");
        if (res->content_type) free(res->content_type);
        res->content_type = strdup("text/plain");
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
        "<p><strong>Handler Type:</strong> Suffix Match (.%s)</p>\n"
        "<p><strong>Current Server Time:</strong> %s</p>\n",
        req->path ? req->path : "N/A",
        req->path ? strrchr(req->path, '.') + 1 : "N/A", // 提取后缀
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
