// Copyright (c) 2025-2026 Yuki Kurosawa
// SPDX-License-Identifier: MIT
#ifndef COMMON_H
#define COMMON_H

#include "version.h"
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h> // For PCRE2 regex matching
 
#include <linux/magic.h> 
#include <linux/version.h>
#include "/usr/include/magic.h" // For libmagic file type detection

#define SERVER_MOTD "Yuki Web Server"
#define SERVER_MOTD_TO_CLIENT "YukiWebServer/" YUKI_VERSION_STR
#define CACHE_SIZE 131072*1024 // 128MiB

#define PATH_MAX_LEN 4096 

#define XSTR(x) #x
#define STR(x) XSTR(x)

void show_help(char *prog);
void show_version(char *prog);

#endif // COMMON_H
