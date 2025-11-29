#include "common.h"
#include <stdio.h>

void show_help(char *prog)
{
    printf("Usage: %s [OPTIONS]\n", prog);
}

void show_version(char *prog)
{
    printf("%s version 1.0.0\n", prog);
}
