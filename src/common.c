#include "common.h"
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>

void show_help(char *prog)
{
    printf("small web server with TLS support and automatic MIME type detection\n\n");
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("OPTIONS:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --version  Show program version information\n");

}

void show_version(char *prog)
{
    printf("%s version %s\n", prog, YUKI_VERSION_STR);
    printf("\n");
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_STR);
    printf("libssl ABI version: %d\n",OPENSSL_SHLIB_VERSION);
    printf("PCRE2 version: %d.%d (%s)\n", PCRE2_MAJOR, PCRE2_MINOR, STR(PCRE2_DATE));
    printf("PCRE2 Bit Mode: %d\n", PCRE2_CODE_UNIT_WIDTH);
    printf("libmagic version: %d.%d\n", MAGIC_VERSION / 100,MAGIC_VERSION % 100);
    printf("magic database version (from kernel): %d.%d.%d\n", LINUX_VERSION_MAJOR,LINUX_VERSION_PATCHLEVEL,LINUX_VERSION_SUBLEVEL);
}
int NormalizeRequestPath(const char *path, char *out, size_t out_size) {
    if (path == NULL || out == NULL || out_size == 0) {
        return -1;
    }
    if (path[0] != '/') {
        return -1; // Require an absolute path
    }

    size_t o = 0;
    size_t seg_starts[2048]; // One entry per path segment
    int depth = 0;
    const char *p = path;

    out[0] = '\0';

    while (*p != '\0') {
        while (*p == '/') p++; // Skip slashes
        if (*p == '\0') break;

        const char *seg = p;
        while (*p != '\0' && *p != '/') p++;
        size_t seg_len = (size_t)(p - seg);

        if (seg_len == 1 && seg[0] == '.') {
            continue; // Current directory
        }
        if (seg_len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (depth == 0) {
                return -1; // Escaping above root -> reject
            }
            depth--;
            o = seg_starts[depth];
            out[o] = '\0';
            continue;
        }

        // Normal segment: append "/segment"
        if (depth >= 2048) {
            return -1; // Too many segments
        }
        if (o + seg_len + 2 > out_size) {
            return -1; // Buffer too small
        }
        if (o != 0) {
            out[o++] = '/';
        }
        seg_starts[depth++] = o;
        memcpy(out + o, seg, seg_len);
        o += seg_len;
        out[o] = '\0';
    }

    if (o == 0) {
        // Root path ("/" or empty)
        if (out_size < 2) return -1;
        out[0] = '/';
        out[1] = '\0';
        return 0;
    }
    return 0;
}

