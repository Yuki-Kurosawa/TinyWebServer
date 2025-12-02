# Copyright (c) 2025 Yuki Kurosawa
# SPDX-License-Identifier: MIT
bin_PROGRAMS = yuki

yuki_SOURCES = src/www.c src/common.c src/client.c src/handlers/info.c src/parser.c src/handlers/static_file.c src/handlers/dynamic_handler.c

yuki_LDFLAGS = -pthread 

yuki_LDADD = -lssl -lcrypto -lpcre2-8 -lmagic

globalconfdir = $(sysconfdir)/yuki
globalconf_DATA = yuki.conf

defaultsitedir = $(prefix)/share/yuki/html
defaultsite_DATA = html/index.html

defaultsiteconfdir = $(prefix)/share/yuki/sites
defaultsiteconf_DATA = sites/default

