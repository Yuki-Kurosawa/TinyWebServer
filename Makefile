.PHONY: all clean

CC=gcc
CFLAGS=-DGLOBAL_CONFIG_PATH="\"./www.conf\"" -DSITES_DIR_PATH="\"./sites\""
LDFLAGS=-pthread -lssl -lcrypto -lpcre2-8 -lmagic

all: www
	@echo Done
www: src/www.o src/client.o src/handlers/info.o src/parser.o src/handlers/static_file.o src/handlers/dynamic_handler.o
	@$(CC) $(CFLAGS) -o www src/www.o src/client.o src/handlers/info.o src/parser.o \
	src/handlers/static_file.o src/handlers/dynamic_handler.o $(LDFLAGS)
%.o: %.c
	@echo Compiling $<
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf www src/*.o src/handlers/*.o