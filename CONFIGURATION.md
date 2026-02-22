
# Yuki Web Server Configuration Manual

## Overview
Yuki is a threaded HTTP/HTTPS web server supporting multiple sites on configurable listen addresses and ports.

## Configuration Files

### Global Configuration
**Location:** `/etc/yuki/yuki.conf`

Controls server-wide settings:

```
ipv4 on|off              # Enable/disable IPv4 support (default: on)
ipv6 on|off              # Enable/disable IPv6 support (default: on)
worker_user nobody       # User to drop privileges to (default: nobody)
```

### Site Configuration
**Location:** `/etc/yuki/sites-available/` (filename.conf)

Each site has its own configuration file:

```
listen ADDRESS:PORT [ssl]        # Address and port to listen on
server_name example.com www.*    # Virtual hostnames (space-separated)
root /var/www/html               # Document root directory
default_page index.html home.html # Default pages in order
ssl_certificate /path/to/cert    # SSL certificate (PEM format)
ssl_key /path/to/key             # SSL private key (PEM format)
ssl_chain /path/to/chain         # Intermediate certificate chain
```

## Listen Directive Examples

```
listen 8080                       # Port only, defaults to 0.0.0.0:8080
listen 192.168.1.1:8080          # IPv4 address:port
listen [::1]:8080                 # IPv6 address:port (brackets required)
listen 0.0.0.0:443 ssl           # HTTPS on IPv4
listen [::]:443 ssl               # HTTPS on all IPv6 addresses
```

## Site Configuration Example

**File:** `/etc/yuki/sites-available/example.conf`

```
listen 0.0.0.0:80
listen [::]:80
listen 0.0.0.0:443 ssl
listen [::]:443 ssl

server_name example.com www.example.com

root /var/www/example.com

default_page index.html index.htm

ssl_certificate /etc/yuki/certs/example.com.crt
ssl_key /etc/yuki/certs/example.com.key
ssl_chain /etc/yuki/certs/example.com.chain
```

> [!TIP]
> if SSL certificates are ECDSA certs, please put fullchain of certs in one file and set with `ssl_certificate` command.

## Port Reuse
Multiple sites can share the same listen address:port combination. Yuki uses SNI (Server Name Indication) to route HTTPS requests to correct certificates.
