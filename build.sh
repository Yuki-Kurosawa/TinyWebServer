#!/bin/bash

clear 

rm -rf www

gcc -DGLOBAL_CONFIG_PATH="\"./www.conf\"" -DSITES_DIR_PATH="\"./sites\"" \
-o www \
src/www.c src/client.c src/parser.c src/handlers/info.c \
-pthread -lssl -lcrypto \
-lpcre2-8


./www