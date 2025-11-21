// Copyright (c) 2025 Yuki Kurosawa
// SPDX-License-Identifier: MIT
#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#include "../../include/handler.h"

bool StaticFileCheckPage(Request *req, char *path);
void StaticFileProcessRequest(Request *req, Response *res);

#endif