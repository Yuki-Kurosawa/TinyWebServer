#include "common.h"
#include <stdio.h>
#include <openssl/opensslv.h>

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
    printf("%s version %s\n", prog, YUKI_VERSION_STR);
    printf("\n");
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_STR);
    printf("libssl ABI version: %d\n",OPENSSL_SHLIB_VERSION);
    printf("PCRE2 version: %d.%d (%s)\n", PCRE2_MAJOR, PCRE2_MINOR, STR(PCRE2_DATE));
    printf("PCRE2 Bit Mode: %d\n", PCRE2_CODE_UNIT_WIDTH);
    printf("libmagic version: %d.%d\n", MAGIC_VERSION / 100,MAGIC_VERSION % 100);
    printf("magic database version (from kernel): %d.%d.%d\n", LINUX_VERSION_MAJOR,LINUX_VERSION_PATCHLEVEL,LINUX_VERSION_SUBLEVEL);
}
