// Copyright (c) 2025 Yuki Kurosawa
// SPDX-License-Identifier: MIT
// handlers/dynamic_handler.h
#ifndef DYNAMIC_HANDLER_H
#define DYNAMIC_HANDLER_H

#include "../../include/handler.h"

bool DynamicHandlerCheckPage(Request *req, char *path);
void DynamicHandlerProcessRequest(Request *req, Response *res);

#endif // DYNAMIC_HANDLER_H