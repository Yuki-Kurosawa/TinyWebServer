# Copyright (c) 2025 Yuki Kurosawa
# SPDX-License-Identifier: MIT
#!/bin/bash

clear 

rm -rf www

gcc -DGLOBAL_CONFIG_PATH="\"./yuki.conf\"" -DSITES_DIR_PATH="\"./sites\"" \
-o yuki \
src/www.c src/common.c src/client.c src/handlers/info.c \
 src/parser.c src/handlers/static_file.c \
 src/handlers/dynamic_handler.c \
-pthread -lssl -lcrypto \
-lpcre2-8 -lmagic

help2man --no-discard-stderr ./yuki > ./yuki.1
#man ./yuki.1

#gcc -o libtest.so -shared -fPIC \
#tests/test.c \
#-I./include

#file libtest.so
#sudo cp libtest.so /var/www/html/libtest.so


#./yuki
