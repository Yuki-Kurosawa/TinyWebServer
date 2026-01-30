#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <handler.h>

int main(int argc, char *argv[]) {
    
    printf("---------------------------------\n");
    printf("Path Combine Example\n");
    {
        char* lpath = "/api/v1";
        char* rpath = "index.html";
        printf("Expected: /api/v1/index.html\n");
        printf("Test 1: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }
    {
        char* lpath = "/api/v1/";
        char* rpath = "index.html";
        printf("Expected: /api/v1/index.html\n");
        printf("Test 2: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }
    {
        char* lpath = "/api/v1";
        char* rpath = "/index.html";
        printf("Expected: /api/v1/index.html\n");
        printf("Test 3: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }
    {
        char* lpath = "/api/v1/";
        char* rpath = "/index.html";
        printf("Expected: /api/v1/index.html\n");
        printf("Test 4: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/api/v1";
        char* rpath = "index.lib";
        printf("Expected: /api/v1/libindex.so\n");
        printf("Test 5: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"lib",".so"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "";
        char* rpath = "/index.html";
        printf("Expected: /index.html\n");
        printf("Test 6: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "";
        char* rpath = "index.html";
        printf("Expected: index.html\n");
        printf("Test 7: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "index.html";
        char* rpath = "";
        printf("Expected: index.html\n");
        printf("Test 8: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/index.html";
        char* rpath = "";
        printf("Expected: /index.html\n");
        printf("Test 9: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/var/www/html";
        char* rpath = "page/index.html";
        printf("Expected: /var/www/html/page/index.html\n");
        printf("Test 10: left: %s right:%s result: %s\n",lpath,rpath,PathCombine(lpath,rpath));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/var/www/html";
        char* rpath = "page/index.do";
        printf("Expected: /var/www/html/page/libindex.so\n");
        printf("Test 11: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"lib",".so"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "";
        char* rpath = "";
        printf("Expected: \n");
        printf("Test 12: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"lib",".so"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/var/.gitignore";
        char* rpath = "";
        printf("Expected: /var/.svnignore\n");
        printf("Test 13: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"scm",".svnignore"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = ".gitignore";
        char* rpath = "";
        printf("Expected: .svnignore\n");
        printf("Test 14: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"scm",".svnignore"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = ".tar.gz";
        char* rpath = "";
        printf("Expected: archive.tar.xz\n");
        printf("Test 15: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"archive",".xz"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "1.tar.gz";
        char* rpath = "";
        printf("Expected: archive1.tar.xz\n");
        printf("Test 16: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"archive",".xz"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/var/.tar.gz";
        char* rpath = "";
        printf("Expected: /var/archive.tar.xz\n");
        printf("Test 17: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"archive",".xz"));
        printf("---------------------------------\n");
    }

    {
        char* lpath = "/var/1.tar.gz";
        char* rpath = "";
        printf("Expected: /var/archive1.tar.xz\n");
        printf("Test 18: left: %s right:%s result: %s\n",lpath,rpath,PathCombineExtend(lpath,rpath,1,"archive",".xz"));
        printf("---------------------------------\n");
    }

    printf("---------------------------------\n");
    return 0;
}