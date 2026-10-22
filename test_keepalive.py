# Copyright (c) 2025-2026 Yuki Kurosawa
# SPDX-License-Identifier: MIT
#!/usr/bin/env python3

"""Keep-alive behavior regression test for the TinyWebServer HTTP layer.

Usage:
  - Start the server with a site listening on 127.0.0.1:18080 whose root
    contains index.html and page2.html (any static content works).
  - Run: python3 test_keepalive.py [--skip-idle]

Exit code 0 if all checks pass. `--skip-idle` skips the ~30s idle-timeout check
so the suite runs in a couple of seconds.
"""
import socket, sys, time

HOST, PORT = '127.0.0.1', 18080
SKIP_IDLE = '--skip-idle' in sys.argv

failures = []
passed = []

def log(*a):
    print(*a)

def check(name, cond, detail=''):
    if cond:
        passed.append(name); log(f"[PASS] {name} {detail}")
    else:
        failures.append(name); log(f"[FAIL] {name} {detail}")

def recv_until(sock, marker):
    data = b''
    while marker not in data:
        b = sock.recv(65536)
        if not b: break
        data += b
    return data

def read_response(sock):
    """Read one full HTTP response (headers + body by Content-Length)."""
    data = b''
    while b'\r\n\r\n' not in data:
        b = sock.recv(65536)
        if not b: break
        data += b
    if b'\r\n\r\n' not in data:
        return data, b'', None, None
    head, rest = data.split(b'\r\n\r\n', 1)
    cl, conn, status = None, None, None
    for line in head.split(b'\r\n'):
        low = line.lower()
        if low.startswith(b'content-length:'):
            cl = int(line.split(b':', 1)[1].strip())
        elif low.startswith(b'connection:'):
            conn = line.split(b':', 1)[1].strip().decode('latin1')
        elif low.startswith(b'http/'):
            parts = line.split()
            status = parts[1].decode('latin1') if len(parts) >= 2 else None
    body = b''
    if cl is not None:
        while len(rest) < cl:
            b = sock.recv(65536)
            if not b: break
            rest += b
        body = rest[:cl]
    return head, body, status, conn

def is_open(sock):
    try:
        sock.setblocking(False)
        d = sock.recv(1)
        return len(d) > 0
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        sock.setblocking(True)

def connect():
    return socket.create_connection((HOST, PORT), timeout=5)

def close_grace(sock):
    try: sock.shutdown(socket.SHUT_RDWR)
    except OSError: pass
    sock.close()

def wait_closed(sock, timeout=3.0):
    end = time.time() + timeout
    sock.settimeout(timeout)
    while time.time() < end:
        if not is_open(sock):
            sock.settimeout(5); return True
        time.sleep(0.05)
    sock.settimeout(5)
    return False

log("===== A: HTTP/1.1 keep-alive (no Connection header) =====")
s = connect(); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
_, _, st, cn = read_response(s)
check("A1 status 200", st == "200", str(st)); check("A1 keep-alive", cn and cn.lower().startswith("keep-alive"), str(cn))
time.sleep(0.4); check("A1 open", is_open(s))
s.sendall(b"GET /page2.html HTTP/1.1\r\nHost: x\r\n\r\n")
_, _, st2, _ = read_response(s)
check("A2 status 200", st2 == "200", str(st2)); check("A2 open", is_open(s))
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
_, _, st3, cn3 = read_response(s)
check("A3 status 200", st3 == "200", str(st3)); check("A3 Connection: close", cn3 and cn3.lower() == "close", str(cn3))
check("A3 closed by server", wait_closed(s)); close_grace(s)

log("===== B: HTTP/1.0 semantics =====")
s = connect(); s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
_, _, st, cn = read_response(s)
check("B1 status 200", st == "200", str(st)); check("B1 close (1.0 default)", cn and cn.lower() == "close", str(cn))
check("B1 closed", wait_closed(s)); close_grace(s)
s = connect(); s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
_, _, st, cn = read_response(s)
check("B2 status 200", st == "200", str(st)); check("B2 keep-alive (explicit)", cn and cn.lower().startswith("keep-alive"), str(cn))
time.sleep(0.4); check("B2 open", is_open(s))
s.sendall(b"GET /page2.html HTTP/1.0\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")
_, _, st2, _ = read_response(s)
check("B2 second 200", st2 == "200", str(st2)); close_grace(s)

log("===== C: HTTP/1.1 pipelining (3 requests at once) =====")
s = connect()
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
          b"GET /page2.html HTTP/1.1\r\nHost: x\r\n\r\n"
          b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")
r = [read_response(s) for _ in range(3)]
check("C r1 200", r[0][2] == "200", str(r[0][2]))
check("C r2 200", r[1][2] == "200", str(r[1][2]))
check("C r3 200", r[2][2] == "200", str(r[2][2]))
check("C order preserved", b"keep-alive index" in r[0][1] and b"page two" in r[1][1] and b"keep-alive index" in r[2][1])
time.sleep(0.4); check("C open", is_open(s)); close_grace(s)

log("===== D: POST body then keep-alive GET =====")
s = connect()
body = b"hello=world&x=1"
s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n"
          b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
_, _, st, cn = read_response(s)
check("D1 POST 200", st == "200", str(st)); check("D1 keep-alive", cn and cn.lower().startswith("keep-alive"), str(cn))
s.sendall(b"GET /page2.html HTTP/1.1\r\nHost: x\r\n\r\n")
_, _, st2, _ = read_response(s)
check("D2 GET-after-POST 200", st2 == "200", str(st2)); check("D2 open", is_open(s)); close_grace(s)

log("===== E: Connection token list =====")
s = connect(); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Upgrade\r\n\r\n")
_, _, st, _ = read_response(s)
check("E1 status 200", st == "200", str(st)); check("E1 open (token list)", is_open(s)); close_grace(s)
s = connect(); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, close\r\n\r\n")
_, _, st, cn = read_response(s)
check("E2 status 200", st == "200", str(st)); check("E2 close wins", cn and cn.lower() == "close", str(cn))
check("E2 closed", wait_closed(s)); close_grace(s)

log("===== F: 404 keep-alive =====")
s = connect(); s.sendall(b"GET /nope.html HTTP/1.1\r\nHost: x\r\n\r\n")
_, _, st, cn = read_response(s)
check("F1 404", st == "404", str(st)); check("F1 keep-alive", cn and cn.lower().startswith("keep-alive"), str(cn))
time.sleep(0.4); check("F1 open after 404", is_open(s)); close_grace(s)

if not SKIP_IDLE:
    log("===== G: idle keep-alive timeout closes connection (expect ~30s) =====")
    s = connect(); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    _, _, st, _ = read_response(s)
    check("G1 status 200", st == "200", str(st))
    t0 = time.time(); closed = wait_closed(s, timeout=40.0); elapsed = time.time() - t0
    check("G1 closed by idle timeout", closed, f"after {elapsed:.1f}s (expect ~30s)")
    check("G1 timeout >= 25s", elapsed >= 25, f"elapsed={elapsed:.1f}")
    close_grace(s)
else:
    log("===== G skipped (--skip-idle) =====")

log(f"\n===== {len(passed)} passed, {len(failures)} failed =====")
if failures:
    log("FAILED: " + ", ".join(failures)); sys.exit(1)
log("ALL PASS"); sys.exit(0)
