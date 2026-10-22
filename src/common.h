// Copyright (c) 2025-2026 Yuki Kurosawa
// SPDX-License-Identifier: MIT
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h> // For size_t
#include "version.h"
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> // For PCRE2 regex matching
 
#include <linux/magic.h> 
#include <linux/version.h>
#include "/usr/include/magic.h" // For libmagic file type detection

#define SERVER_MOTD "Yuki Web Server"
#define SERVER_MOTD_TO_CLIENT "YukiWebServer/" YUKI_VERSION_STR
#define CACHE_SIZE 131072 // 128KiB initial response buffer (grown on demand)

#define MAX_STATIC_FILE_SIZE (64 * 1024 * 1024) // 64MiB hard cap for static files buffered fully in memory (M2)

#define PATH_MAX_LEN 4096 

#define XSTR(x) #x
#define STR(x) XSTR(x)

void show_help(char *prog);
void show_version(char *prog);

// Normalize a request path: resolve "." and ".." segments and reject any
// attempt to escape above the root. Returns 0 on success (out is NUL-terminated)
// or -1 if the path escapes the root (caller should treat it as 404).
int NormalizeRequestPath(const char *path, char *out, size_t out_size);

#endif // COMMON_H
