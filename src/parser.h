#ifndef PARSER_H
#define PARSER_H

#include <stddef.h> // For size_t
#include <stdbool.h> // For bool
#include "common.h" 
#include "../include/handler.h"

void HandleRequest(ServerInfo *server_info, size_t req_len, char request[], size_t *resp_len, char response[]);

#endif // PARSER_H