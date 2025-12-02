// Copyright (c) 2025 Yuki Kurosawa
// SPDX-License-Identifier: MIT
#ifndef COMMON_H
#define COMMON_H

#define SERVER_MOTD "Yuki's Tiny Web Server"
#define SERVER_MOTD_TO_CLIENT "YukiWebServer/1.0"
#define CACHE_SIZE 131072*1024 // 128MiB

#define PATH_MAX_LEN 4096 

void show_help(char *prog);
void show_version(char *prog);

#endif // COMMON_H
