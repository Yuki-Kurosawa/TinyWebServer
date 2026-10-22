// Copyright (c) 2025-2026 Yuki Kurosawa
// SPDX-License-Identifier: MIT
// client.c
#include "client.h" // Include our own header (which now includes parser.h)
#include <stdio.h>
#include <stdlib.h> // For malloc, free, perror
#include <string.h> // For memset, strlen, strstr, strchr, strncpy, strcmp, strcpy
#include <strings.h> // For strncasecmp (case-insensitive, POSIX)
#include <unistd.h> // For close, read, write
#include <pthread.h> // For pthread_exit
#include <errno.h>        // For errno
#include <fcntl.h>        // For fcntl (setting non-blocking) - though select is used for timeout
#include <sys/time.h>     // For struct timeval
#include <openssl/err.h>  // For SSL_get_error and ERR_print_errors_fp
#include <limits.h>        // For INT_MAX (write_all chunking)
#include <arpa/inet.h>    // For inet_ntop
#include <netinet/in.h>   // For sockaddr_in, sockaddr_in6
#include <sys/socket.h>   // For getsockname, setsockopt, SOL_SOCKET, SO_RCVTIMEO

// How long an idle keep-alive connection is kept before it is closed (s).
// The initial read / TLS handshake uses the shorter 5s socket timeout; once a
// response is sent and the connection will persist, the read timeout is
// re-armed to this value so an idle client cannot pin a worker thread forever.
#define KEEP_ALIVE_IDLE_SEC 30


// Function to find a site based on hostname
// This will be used by both SNI callback and HTTP Host header parsing
SiteConfig* find_site_for_hostname(ListenSocket *listener, const char *hostname) {
    SiteConfig *default_site = NULL;

    for (int i = 0; i < listener->site_count; ++i) {
        SiteConfig *current_site = listener->sites[i];
        for (int j = 0; j < current_site->num_server_names; ++j) {
            // Exact match
            if (strcmp(current_site->server_name[j], hostname) == 0) {
                return current_site;
            }
            // Default site fallback (the "_" server_name)
            if (strcmp(current_site->server_name[j], "_") == 0) {
                default_site = current_site;
            }
        }
    }
    // No exact match found, return default site if available
    return default_site;
}


// SNI callback for OpenSSL
// This function is called by OpenSSL during the TLS handshake when a server name is received.
int sni_callback(SSL *ssl, int *ad, void *arg) {
    ListenSocket *listener = (ListenSocket *)arg; // Retrieve the ListenSocket pointer passed during setup
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    if (servername) {
        fprintf(stderr, "SNI callback: Client requested server name: %s\n", servername);
        SiteConfig *matched_site = find_site_for_hostname(listener, servername);

        if (matched_site && matched_site->ssl_ctx) {
            // Successfully found a site with a loaded SSL context for this hostname
            SSL_set_SSL_CTX(ssl, matched_site->ssl_ctx); // Set the correct SSL_CTX for this connection
            fprintf(stderr, "SNI callback: Switched SSL_CTX for hostname %s.\n", servername);
            return SSL_TLSEXT_ERR_OK; // Indicate success
        } else {
            fprintf(stderr, "SNI callback: No matching site or SSL_CTX found for hostname %s. Using default or failing.\n", servername);
            return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context
        }
    }
    // No server name provided by client, or an error from SSL_get_servername
    return SSL_TLSEXT_ERR_NOACK; // Let OpenSSL use the default context
}



// Write the entire buffer to the peer, retrying partial writes and
// EINTR/EAGAIN. On plain sockets a blocking write loops until everything
// is flushed (or the peer closes -> error). With SO_SNDTIMEO (5s) a stalled
// client surfaces as EAGAIN; we retry a bounded number of times so a
// permanently stalled peer cannot pin a worker thread forever.
// Returns 0 on full success, -1 on failure.
static int write_all(int sock, SSL *ssl, const char *buf, size_t len) {
    size_t off = 0;
    int stall_count = 0; // consecutive EAGAIN/WANT_* attempts
    while (off < len) {
        size_t remain = len - off;
        int chunk = (remain > (size_t)INT_MAX) ? INT_MAX : (int)remain;
        if (ssl) {
            int n = SSL_write(ssl, buf + off, chunk);
            if (n > 0) { off += (size_t)n; stall_count = 0; continue; }
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if (++stall_count > 3) {
                    fprintf(stderr, "SSL_write stalled for socket %d.\n", sock);
                    return -1;
                }
                usleep(1000); // 1ms backoff, bounded
                continue;
            }
            if (err == SSL_ERROR_SYSCALL && errno == EINTR) continue;
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "SSL_write error for socket %d.\n", sock);
            return -1;
        } else {
            ssize_t n = write(sock, buf + off, (size_t)chunk);
            if (n > 0) { off += (size_t)n; stall_count = 0; continue; }
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (++stall_count > 3) {
                        perror("write stalled (send timeout)");
                        return -1;
                    }
                    usleep(1000);
                    continue;
                }
                perror("write error");
                return -1;
            }
            fprintf(stderr, "write returned 0 for socket %d.\n", sock);
            return -1;
        }
    }
    return 0;
}

// ---- HTTP keep-alive connection helpers ----

// Locate the end-of-headers marker "\r\n\r\n" within [buf, buf+len).
// Returns a pointer to the marker or NULL if not present.
static char *find_header_terminator(char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return buf + i;
    }
    return NULL;
}

// Find the value of a header field within a header block (case-insensitive).
// Leading/trailing whitespace is trimmed; *value_len is the value length and
// the returned pointer points at the first value character. Returns NULL if
// the field is absent. Every header line (including the first) is preceded by
// "\r\n" after the request line, so scanning for "\r\n" + field + ":" covers
// all of them. The header block need not be NUL-terminated (bounded by hdr_len).
static const char *find_header_value(const char *hdr, size_t hdr_len,
                                     const char *field, size_t *value_len) {
    size_t flen = strlen(field);
    size_t needle_len = 2 + flen + 1; // "\r\n" + field + ":"
    if (needle_len > hdr_len) return NULL;
    for (size_t i = 0; i + needle_len <= hdr_len; i++) {
        if (hdr[i] == '\r' && hdr[i+1] == '\n' &&
            strncasecmp(hdr + i + 2, field, flen) == 0 &&
            hdr[i + 2 + flen] == ':') {
            const char *v = hdr + i + needle_len;
            const char *e = hdr + hdr_len;
            while (v < e && (*v == ' ' || *v == '\t')) v++;
            const char *vend = v;
            while (vend < e && *vend != '\r' && *vend != '\n') vend++;
            *value_len = (size_t)(vend - v);
            return v;
        }
    }
    return NULL;
}

// Parse Content-Length from a header block. Returns 0 on success (with *out
// set), or -1 if the header is absent or malformed (caller treats as "no body").
static int header_content_length(const char *hdr, size_t hdr_len, size_t *out) {
    size_t vlen = 0;
    const char *v = find_header_value(hdr, hdr_len, "Content-Length", &vlen);
    if (!v) return -1;
    char tmp[32];
    if (vlen >= sizeof(tmp)) vlen = sizeof(tmp) - 1;
    memcpy(tmp, v, vlen); tmp[vlen] = '\0';
    char *endp = NULL;
    unsigned long n = strtoul(tmp, &endp, 10);
    if (endp == tmp) return -1;
    *out = (size_t)n;
    return 0;
}

// Read from the socket until at least `need` bytes are buffered, growing the
// buffer as necessary. conn_buf[conn_len] is kept NUL-terminated.
// Returns 0 on success, 1 on peer close (EOF), -1 on read timeout,
// -2 on fatal read error, -3 on out-of-memory growing the buffer.
static int conn_fill(int sock, SSL *ssl, char **conn_buf, size_t *conn_cap,
                     size_t *conn_len, size_t need, bool use_ssl) {
    while (*conn_len < need) {
        // Grow so there is always a free byte to read into plus room for NUL.
        if (*conn_cap < *conn_len + 2) {
            size_t newcap = *conn_cap * 2;
            if (newcap < need + 1) newcap = need + 1;
            char *nb = (char *)realloc(*conn_buf, newcap);
            if (!nb) return -3;
            *conn_buf = nb;
            *conn_cap = newcap;
        }
        size_t space = *conn_cap - 1 - *conn_len;
        ssize_t n;
        if (use_ssl) {
            n = SSL_read(ssl, *conn_buf + *conn_len, (int)space);
            if (n <= 0) {
                int err = SSL_get_error(ssl, (int)n);
                if (err == SSL_ERROR_ZERO_RETURN) return 1;      // clean EOF
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    return -1;                                    // stalled/timeout
                if (err == SSL_ERROR_SYSCALL) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                        return -1;                                // timeout
                    if (errno == 0) return 1;                     // unexpected EOF
                    return -2;
                }
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "SSL_read error on socket %d.\n", sock);
                return -2;
            }
        } else {
            n = read(sock, *conn_buf + *conn_len, space);
            if (n == 0) return 1;                                 // EOF
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT)
                    return -1;                                    // timeout
                perror("read error");
                return -2;
            }
        }
        *conn_len += (size_t)n;
        (*conn_buf)[*conn_len] = '\0';
    }
    return 0;
}

// Select the active site for this request from its Host header, falling back
// to the listener's default site. Returns NULL when no site can serve it.
static SiteConfig *select_active_site(ListenSocket *listener,
                                      const char *request_buf, size_t hdr_len) {
    char hostname[MAX_LINE_SIZE] = {0};
    size_t vlen = 0;
    const char *hv = find_header_value(request_buf, hdr_len, "Host", &vlen);
    if (hv) {
        if (vlen >= MAX_LINE_SIZE) vlen = MAX_LINE_SIZE - 1;
        memcpy(hostname, hv, vlen);
        hostname[vlen] = '\0';
    }
    SiteConfig *site = NULL;
    if (strlen(hostname) > 0) {
        site = find_site_for_hostname(listener, hostname);
    }
    if (site == NULL && listener->site_count > 0) {
        site = listener->sites[0]; // default site fallback
    }
    return site;
}

// Build a fresh per-request ServerInfo (server_ip/remote_ip are strdup'd and
// freed by free_request_members in parser.c; root_dir/default_page/server_name
// are borrowed pointers owned by the site config). Returns NULL on allocation
// failure. The caller must pass the resulting pointer to HandleRequest, which
// owns its lifetime.
static ServerInfo *build_server_info(ListenSocket *listener,
                                     struct sockaddr_storage *remote_addr,
                                     socklen_t remote_addr_len,
                                     SiteConfig *active_site) {
    ServerInfo *si = (ServerInfo *)calloc(1, sizeof(ServerInfo));
    if (!si) { perror("calloc ServerInfo"); return NULL; }

    char server_ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = sizeof(local_addr);
    if (getsockname(listener->sock_fd, (struct sockaddr *)&local_addr, &local_addr_len) == 0) {
        if (local_addr.ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)&local_addr)->sin_addr,
                      server_ip_str, sizeof(server_ip_str));
            si->server_port = ntohs(((struct sockaddr_in *)&local_addr)->sin_port);
        } else if (local_addr.ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&local_addr)->sin6_addr,
                      server_ip_str, sizeof(server_ip_str));
            si->server_port = ntohs(((struct sockaddr_in6 *)&local_addr)->sin6_port);
        } else {
            strcpy(server_ip_str, "N/A");
            si->server_port = 0;
        }
    } else {
        perror("getsockname failed for server IP");
        strcpy(server_ip_str, "N/A");
        si->server_port = 0;
    }
    si->server_ip = strdup(server_ip_str);
    if (!si->server_ip) { perror("strdup server_ip"); free(si); return NULL; }

    char remote_ip_str[INET6_ADDRSTRLEN];
    if (remote_addr_len > 0) {
        if (remote_addr->ss_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)remote_addr)->sin_addr,
                      remote_ip_str, sizeof(remote_ip_str));
            si->remote_port = ntohs(((struct sockaddr_in *)remote_addr)->sin_port);
        } else if (remote_addr->ss_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)remote_addr)->sin6_addr,
                      remote_ip_str, sizeof(remote_ip_str));
            si->remote_port = ntohs(((struct sockaddr_in6 *)remote_addr)->sin6_port);
        } else {
            strcpy(remote_ip_str, "N/A");
            si->remote_port = 0;
        }
    } else {
        strcpy(remote_ip_str, "N/A");
        si->remote_port = 0;
    }
    si->remote_ip = strdup(remote_ip_str);
    if (!si->remote_ip) {
        perror("strdup remote_ip");
        free(si->server_ip);
        free(si);
        return NULL;
    }

    si->root_dir = active_site->root_dir;
    si->default_page = active_site->default_page;
    si->num_default_page = active_site->num_default_page;
    si->server_name = active_site->server_name;
    si->num_server_names = active_site->num_server_names;
    return si;
}

// Send a minimal text error response that always closes the connection.
static void send_error_close(int sock, SSL *ssl, int code,
                             const char *reason, const char *body) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
        code, reason, strlen(body), body);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    write_all(sock, ssl, buf, (size_t)n);
}

// Function to handle a single client connection
void *handle_client(void *thread_args_ptr) {
    ClientThreadArgs *args = (ClientThreadArgs*) thread_args_ptr;
    int sock = args->sock;
    ListenSocket *listener = args->listener_socket; // Pointer to the ListenSocket this connection came from
    struct sockaddr_storage remote_addr = args->remote_addr; // Copy remote address
    socklen_t remote_addr_len = args->remote_addr_len; // Copy remote address length
    free(thread_args_ptr); // Free the dynamically allocated thread arguments

    SSL *ssl = NULL;
    bool use_ssl = listener->config.ssl_enabled;

    // --- Persistent connection read buffer ---
    // Holds header + body + any pipelined bytes across keep-alive requests.
    // Grown on demand; always NUL-terminated at buf_len.
    size_t conn_cap = MAX_REQUEST_SIZE + 1;
    char *conn_buf = (char *)malloc(conn_cap);
    if (!conn_buf) {
        perror("Failed to allocate conn_buf in handle_client");
        close(sock);
        pthread_exit(NULL);
    }
    conn_buf[0] = '\0';
    size_t buf_len = 0; // valid bytes buffered

    // --- Set socket timeouts BEFORE the TLS handshake so a slow or stalled
    //     handshake cannot pin a worker thread forever (H2). ---
    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 second timeout (initial request / handshake)
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof timeout);

    // --- PERFORM SSL HANDSHAKE IMMEDIATELY IF SSL IS ENABLED ---
    if (use_ssl) {
        // Use the listener's SSL_CTX for the initial handshake.
        // SNI callback will switch to site-specific SSL_CTX if needed.
        ssl = SSL_new(listener->listener_ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Error creating SSL object for socket %d.\n", sock);
            close(sock);
            free(conn_buf); // Clean up
            pthread_exit(NULL);
        }
        SSL_set_fd(ssl, sock);

        if (SSL_accept(ssl) <= 0) {
            // Handle SSL handshake failure (e.g., client sent plain HTTP to HTTPS port, or bad certificate negotiation)
            int ssl_err = SSL_get_error(ssl, -1);
            fprintf(stderr, "SSL handshake failed for socket %d. Error: %d\n", sock, ssl_err);
            ERR_print_errors_fp(stderr); // Print OpenSSL error stack
            close(sock);
            SSL_free(ssl);
            free(conn_buf); // Clean up
            pthread_exit(NULL);
        }
        fprintf(stderr, "SSL handshake successful for socket %d.\n", sock);
    }
    // --- END SSL HANDSHAKE ---


    // --- Keep-alive request loop ---
    // Serve many requests on the same socket until the client asks to close
    // ("Connection: close"), an idle timeout fires, or a framing error makes
    // the request boundary unknowable (in which case we must close to avoid
    // desynchronising the stream).
    for (;;) {
        // 1) Accumulate the full HTTP headers (terminated by "\r\n\r\n").
        size_t hdr_len = 0; // header block length, including the terminator
        char *hdr_end = NULL;
        for (;;) {
            hdr_end = find_header_terminator(conn_buf, buf_len);
            if (hdr_end) {
                hdr_len = (size_t)(hdr_end - conn_buf) + 4;
                break;
            }
            if (buf_len >= MAX_REQUEST_SIZE) {
                fprintf(stderr, "Request headers too large on socket %d.\n", sock);
                send_error_close(sock, ssl, 431, "Request Header Fields Too Large",
                                 "Request header fields too large.");
                goto conn_close;
            }
            int rr = conn_fill(sock, ssl, &conn_buf, &conn_cap, &buf_len,
                               buf_len + 1, use_ssl);
            if (rr != 0) goto conn_close; // EOF / timeout / error -> close
        }

        // 2) Determine the body length from Content-Length to find the request
        //    boundary, so leftover body bytes never desync the next request.
        size_t content_length = 0;
        if (header_content_length(conn_buf, hdr_len, &content_length) != 0) {
            content_length = 0; // absent/invalid -> no body
        }
        size_t req_len = hdr_len + content_length;
        if (req_len > MAX_REQUEST_SIZE) {
            fprintf(stderr, "Request too large on socket %d (Content-Length %zu).\n",
                    sock, content_length);
            send_error_close(sock, ssl, 413, "Payload Too Large",
                             "Request entity too large.");
            goto conn_close;
        }

        // 3) Read the remainder of the body, if any.
        while (buf_len < req_len) {
            int rr = conn_fill(sock, ssl, &conn_buf, &conn_cap, &buf_len,
                               req_len, use_ssl);
            if (rr != 0) {
                fprintf(stderr, "Truncated request body on socket %d; closing.\n", sock);
                goto conn_close; // cannot keep alive without a known boundary
            }
        }

        // 4) Select the active site for THIS request (Host header + fallback).
        SiteConfig *active_site = select_active_site(listener, conn_buf, hdr_len);
        if (active_site == NULL) {
            fprintf(stderr, "Error: No site configured for this listener.\n");
            send_error_close(sock, ssl, 500, "Internal Server Error",
                             "No site configured for this port.");
            goto conn_close;
        }

        // 5) Build a fresh ServerInfo for this request (freed by parser.c).
        ServerInfo *server_info = build_server_info(listener, &remote_addr,
                                                    remote_addr_len, active_site);
        if (server_info == NULL) {
            send_error_close(sock, ssl, 500, "Internal Server Error",
                             "Server out of memory.");
            goto conn_close;
        }

        // 6) Dispatch to the request pipeline.
        char *response_buffer = NULL;
        size_t response_len = 0;
        bool keep_alive = false;
        HandleRequest(server_info, req_len, conn_buf,
                      &response_buffer, &response_len, &keep_alive);
        // HandleRequest frees server_info (via free_request_members).

        // 7) Write the response.
        if (response_buffer == NULL) {
            fprintf(stderr, "No response produced for socket %d.\n", sock);
            goto conn_close;
        }
        if (write_all(sock, ssl, response_buffer, response_len) < 0) {
            fprintf(stderr, "Response write failed for socket %d.\n", sock);
            free(response_buffer);
            goto conn_close;
        }
        free(response_buffer);

        // 8) Consume the request from the buffer (supports pipelining).
        buf_len -= req_len;
        if (buf_len > 0) memmove(conn_buf, conn_buf + req_len, buf_len);
        conn_buf[buf_len] = '\0';

        // 9) Keep alive only if the parser says the connection may persist.
        if (!keep_alive) goto conn_close;

        // Re-arm the longer idle timeout for the next keep-alive request.
        struct timeval ka_timeout;
        ka_timeout.tv_sec = KEEP_ALIVE_IDLE_SEC;
        ka_timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&ka_timeout, sizeof ka_timeout);
    }

conn_close:
    // --- Shutdown and Cleanup ---
    if (use_ssl) {
        SSL_shutdown(ssl); // Perform graceful SSL shutdown
        SSL_free(ssl);     // Free the SSL object
    }
    close(sock); // Close the underlying socket
    free(conn_buf);

    pthread_exit(NULL); // Exit the thread
}
