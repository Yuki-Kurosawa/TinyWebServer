#include "common.h"
#include <stdio.h>

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
    printf("%s version 1.0.0\n", prog);
}
