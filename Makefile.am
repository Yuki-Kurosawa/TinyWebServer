bin_PROGRAMS = yuki

yuki_SOURCES = src/www.c src/client.c src/handlers/info.c src/parser.c src/handlers/static_file.c src/handlers/dynamic_handler.c

yuki_LDFLAGS = -pthread 

yuki_LDADD = -lssl -lcrypto -lpcre2-8 -lmagic