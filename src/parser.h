// Copyright (c) 2025-2026 Yuki Kurosawa
// SPDX-License-Identifier: MIT
#ifndef PARSER_H
#define PARSER_H

#include <stddef.h> // For size_t
#include <stdbool.h> // For bool
#include "common.h" 
#include "../include/handler.h"

void HandleRequest(ServerInfo *server_info, size_t req_len, char request[], char **response_out, size_t *response_len_out);

#endif // PARSER_H