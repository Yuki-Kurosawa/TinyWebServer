#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([src/common.h])
AC_CONFIG_HEADERS([config.h])
PKG_PROG_PKG_CONFIG

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES([OPENSSL], [openssl >= 3.0.0], [],
                  [AC_MSG_ERROR([OpenSSL 3.0.0 is needed to build this package.])])

PKG_CHECK_MODULES([PCRE2], [libpcre2-8 >= 10.0], [],
                  [AC_MSG_ERROR([PCRE2 (8bit version) 10.0 is needed to build this package.])])

PKG_CHECK_MODULES([LIBMAGIC], [libmagic >= 1:5.0], [],
                  [AC_MSG_ERROR([libmagic 1:5.0 is needed to build this package.])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strcasecmp strchr strdup strerror strrchr strstr strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
