#ifndef STATIC_FILE_H
#define STATIC_FILE_H

#include "../../include/handler.h"

bool StaticFileCheckPage(HandlerMetadata meta, char *path);
void StaticFileProcessRequest(Request *req, Response *res);

#endif