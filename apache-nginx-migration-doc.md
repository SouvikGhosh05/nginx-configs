# Comprehensive Apache to Nginx Configuration Migration Guide

This is an in-depth guide providing exhaustive mapping of Apache configuration directives to their Nginx equivalents, with advanced variations, real-world examples, and extensive online references.

## Table of Contents
1. [Architecture and Philosophy Differences](#architecture-and-philosophy-differences)
2. [Basic Configuration Structure](#basic-configuration-structure)
3. [SSL/TLS Configuration Variants](#ssltls-configuration-variants)
4. [Proxy Configuration Patterns](#proxy-configuration-patterns)
5. [URL Rewriting and Redirects](#url-rewriting-and-redirects)
6. [Authentication Methods](#authentication-methods)
7. [Load Balancing and Upstream Configuration](#load-balancing-and-upstream-configuration)
8. [Rate Limiting and Security Controls](#rate-limiting-and-security-controls)
9. [Caching Strategies](#caching-strategies)
10. [WebSocket and Real-Time Features](#websocket-and-real-time-features)
11. [Error Handling and Custom Pages](#error-handling-and-custom-pages)
12. [Performance Tuning](#performance-tuning)
13. [Advanced Configuration Patterns](#advanced-configuration-patterns)
14. [Migration Best Practices](#migration-best-practices)
15. [Troubleshooting Guide](#troubleshooting-guide)
16. [References and Resources](#references-and-resources)

---

## Architecture and Philosophy Differences

### Apache Architecture
- **Process-based**: Creates new processes/threads for each request
- **Modular**: Uses loadable modules (mod_rewrite, mod_ssl, etc.)
- **Directory-based**: .htaccess files allow per-directory configuration
- **Flexible**: Highly configurable but can be resource-intensive

### Nginx Architecture
- **Event-driven**: Single-threaded event loop handling thousands of connections
- **Monolithic**: Most features are compiled-in
- **Block-based**: Configuration organized in nested blocks
- **Performance-focused**: Optimized for high concurrency and low resource usage

---

## Basic Configuration Structure

### 1. Simple Virtual Host Migration

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    DirectoryIndex index.html index.php
    
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/example-error.log
    CustomLog ${APACHE_LOG_DIR}/example-access.log combined
</VirtualHost>
```

#### Nginx Equivalent (Basic)
```nginx
server {
    listen 80;
    listen [::]:80;  # IPv6 support
    server_name example.com www.example.com;
    root /var/www/html;
    index index.html index.php;
    
    # Directory listing (equivalent to Options Indexes)
    location / {
        try_files $uri $uri/ =404;
        autoindex on;  # Enable directory listing
    }
    
    # Logging
    error_log /var/log/nginx/example-error.log;
    access_log /var/log/nginx/example-access.log combined;
}
```

#### Nginx Equivalent (Advanced)
```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name example.com www.example.com;
    root /var/www/html;
    index index.html index.htm index.php;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Gzip compression
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        gzip_static on;
    }
    
    # PHP handling
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    # Logging with additional format
    log_format detailed '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" '
                       '"$http_user_agent" "$http_x_forwarded_for"';
    
    error_log /var/log/nginx/example-error.log warn;
    access_log /var/log/nginx/example-access.log detailed;
}
```

### 2. Multiple Domain Handling

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName primary.com
    ServerAlias secondary.com tertiary.com
    DocumentRoot /var/www/primary
    
    <Directory /var/www/primary>
        AllowOverride All
    </Directory>
</VirtualHost>
```

#### Nginx Equivalent
```nginx
server {
    listen 80;
    server_name primary.com secondary.com tertiary.com;
    root /var/www/primary;
    
    # Different handling based on domain
    if ($host = secondary.com) {
        set $subdirectory /secondary;
    }
    if ($host = tertiary.com) {
        set $subdirectory /tertiary;
    }
    
    location / {
        try_files $uri $uri/ $subdirectory$uri $subdirectory$uri/ =404;
    }
}

# Alternative: Separate server blocks for different domains
server {
    listen 80;
    server_name secondary.com;
    root /var/www/secondary;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

---

## SSL/TLS Configuration Variants

### 1. Basic SSL Configuration

#### Apache Configuration
```apache
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt
    
    # Security settings
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
    
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

#### Nginx Equivalent (Modern SSL)
```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;
    
    # Modern SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    
    # SSL session settings
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/ca-chain.crt;
    resolver 1.1.1.1 1.0.0.1 valid=300s;
    resolver_timeout 5s;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
}
```

### 2. Client Certificate Authentication

#### Apache Configuration
```apache
<VirtualHost *:443>
    ServerName secure.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    
    # Client certificate verification
    SSLVerifyClient require
    SSLVerifyDepth 2
    SSLCACertificateFile /etc/ssl/certs/ca.crt
    SSLCARevocationFile /etc/ssl/crl/ca.crl
    
    <Location /admin>
        SSLRequireSSL
        SSLRequire %{SSL_CLIENT_S_DN_CN} eq "admin"
    </Location>
</VirtualHost>
```

#### Nginx Equivalent (Client Certificate)
```nginx
server {
    listen 443 ssl;
    server_name secure.example.com;
    
    # Server SSL configuration
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Client certificate verification
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_crl /etc/ssl/crl/ca.crl;
    ssl_verify_client on;
    ssl_verify_depth 2;
    
    # Basic client cert validation
    location / {
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        proxy_pass http://backend;
    }
    
    # Advanced client cert validation
    location /admin {
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        if ($ssl_client_s_dn_cn != "admin") {
            return 403;
        }
        proxy_pass http://admin_backend;
    }
    
    # Fingerprint-based validation
    location /secure {
        # Map specific certificate fingerprints
        if ($ssl_client_fingerprint !~ ^(abcdef123456|fedcba654321)$) {
            return 403;
        }
        proxy_pass http://secure_backend;
    }
}

# Alternative: Optional client certificates with fallback
server {
    listen 443 ssl;
    server_name flexible.example.com;
    
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client optional;
    
    location / {
        # Different behavior based on client cert
        if ($ssl_client_verify = SUCCESS) {
            set $auth_type "cert";
        }
        if ($ssl_client_verify != SUCCESS) {
            set $auth_type "basic";
        }
        
        # Basic auth for non-cert users
        if ($auth_type = "basic") {
            auth_basic "Restricted Area";
            auth_basic_user_file /etc/nginx/.htpasswd;
        }
        
        proxy_pass http://backend;
        proxy_set_header X-Auth-Type $auth_type;
        proxy_set_header X-Client-DN $ssl_client_s_dn;
    }
}
```

### 3. Multi-Certificate Setup (RSA + ECDSA)

#### Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # RSA Certificate
    ssl_certificate /etc/ssl/certs/example.com.rsa.crt;
    ssl_certificate_key /etc/ssl/private/example.com.rsa.key;
    
    # ECDSA Certificate (preferred for modern clients)
    ssl_certificate /etc/ssl/certs/example.com.ecdsa.crt;
    ssl_certificate_key /etc/ssl/private/example.com.ecdsa.key;
    
    # SSL settings optimized for dual certificates
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
}
```

---

## Proxy Configuration Patterns

### 1. Basic Reverse Proxy

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName api.example.com
    
    ProxyRequests Off
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    
    <Proxy *>
        Require all granted
    </Proxy>
    
    ProxyTimeout 300
    ProxyPassReverse / http://127.0.0.1:8080/
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
</VirtualHost>
```

#### Nginx Equivalent (Basic)
```nginx
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
```

#### Nginx Equivalent (Advanced)
```nginx
# Upstream definition for load balancing
upstream backend_pool {
    least_conn;
    server 127.0.0.1:8080 weight=3 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8081 weight=2 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:8082 backup;
    
    # Keep-alive connections
    keepalive 32;
}

server {
    listen 80;
    server_name api.example.com;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    
    location / {
        # Apply rate limiting
        limit_req zone=api burst=200 nodelay;
        
        # Proxy configuration
        proxy_pass http://backend_pool;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Error handling
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
        proxy_next_upstream_tries 3;
        proxy_next_upstream_timeout 30s;
        
        # Custom error pages
        error_page 502 503 504 /maintenance.html;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Maintenance page
    location = /maintenance.html {
        root /usr/share/nginx/html;
        internal;
    }
}
```

### 2. Path-Based Routing

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName app.example.com
    
    ProxyPass /api/ http://api-server:3000/
    ProxyPassReverse /api/ http://api-server:3000/
    
    ProxyPass /auth/ http://auth-server:4000/
    ProxyPassReverse /auth/ http://auth-server:4000/
    
    ProxyPass /uploads/ http://file-server:5000/
    ProxyPassReverse /uploads/ http://file-server:5000/
    
    # Default to web frontend
    ProxyPass / http://frontend-server:8080/
    ProxyPassReverse / http://frontend-server:8080/
</VirtualHost>
```

#### Nginx Equivalent
```nginx
# Define upstream servers
upstream api_backend {
    server api-server:3000;
    keepalive 16;
}

upstream auth_backend {
    server auth-server:4000;
    keepalive 8;
}

upstream file_backend {
    server file-server:5000;
    keepalive 8;
}

upstream frontend_backend {
    server frontend-server:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name app.example.com;
    
    # API endpoints (most specific first)
    location /api/ {
        proxy_pass http://api_backend/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        include proxy_params;
        
        # API-specific settings
        proxy_read_timeout 300s;
        client_max_body_size 10m;
    }
    
    # Authentication service
    location /auth/ {
        proxy_pass http://auth_backend/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        include proxy_params;
        
        # Disable caching for auth
        proxy_no_cache 1;
        proxy_cache_bypass 1;
    }
    
    # File uploads (large files)
    location /uploads/ {
        proxy_pass http://file_backend/;
        include proxy_params;
        
        # Large file settings
        client_max_body_size 100m;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    
    # Static files (served directly by Nginx)
    location /static/ {
        root /var/www/app;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Default location (frontend)
    location / {
        proxy_pass http://frontend_backend/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        include proxy_params;
        
        # Frontend-specific caching
        proxy_cache frontend_cache;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
    }
}

# Proxy parameters file: /etc/nginx/proxy_params
# proxy_set_header Host $http_host;
# proxy_set_header X-Real-IP $remote_addr;
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
# proxy_set_header X-Forwarded-Proto $scheme;
```

---

## Authentication Methods

### 1. Basic Authentication

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName admin.example.com
    DocumentRoot /var/www/admin
    
    <Directory /var/www/admin>
        AuthType Basic
        AuthName "Admin Area"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Directory>
    
    <Directory /var/www/admin/public>
        AuthType None
        Require all granted
    </Directory>
</VirtualHost>
```

#### Nginx Equivalent
```nginx
server {
    listen 80;
    server_name admin.example.com;
    root /var/www/admin;
    
    # Default authentication
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    # Public area without authentication
    location /public/ {
        auth_basic off;
        try_files $uri $uri/ =404;
    }
    
    # Different auth for different areas
    location /super-admin/ {
        auth_basic "Super Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd-super;
        try_files $uri $uri/ =404;
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 2. IP-Based Access Control

#### Apache Configuration
```apache
<VirtualHost *:80>
    ServerName internal.example.com
    
    <Directory /var/www/internal>
        Require ip 192.168.1.0/24
        Require ip 10.0.0.0/8
        Require ip 127.0.0.1
    </Directory>
    
    <Directory /var/www/internal/restricted>
        Require ip 192.168.1.100
        Require ip 192.168.1.101
    </Directory>
</VirtualHost>
```

#### Nginx Equivalent
```nginx
server {
    listen 80;
    server_name internal.example.com;
    root /var/www/internal;
    
    # Default IP restrictions
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    allow 127.0.0.1;
    deny all;
    
    location /restricted/ {
        # More restrictive IP access
        allow 192.168.1.100;
        allow 192.168.1.101;
        deny all;
        try_files $uri $uri/ =404;
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}

# Using geo module for complex IP logic
geo $allowed_ip {
    default 0;
    192.168.1.0/24 1;
    10.0.0.0/8 1;
    127.0.0.1/32 1;
}

server {
    listen 80;
    server_name geo.example.com;
    
    if ($allowed_ip = 0) {
        return 403;
    }
    
    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 3. Combined Authentication Methods

#### Nginx Advanced Authentication
```nginx
server {
    listen 443 ssl;
    server_name secure.example.com;
    
    # SSL settings
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client optional;
    
    # Multi-factor authentication location
    location /secure/ {
        # Require BOTH IP allowlist AND (client cert OR basic auth)
        satisfy all;
        
        # IP restriction
        allow 192.168.1.0/24;
        deny all;
        
        # Client cert OR basic auth
        set $auth_type "";
        if ($ssl_client_verify = SUCCESS) {
            set $auth_type "cert";
        }
        if ($auth_type != "cert") {
            auth_basic "Secure Area";
            auth_basic_user_file /etc/nginx/.htpasswd;
        }
        
        proxy_pass http://secure_backend;
        proxy_set_header X-Auth-Method $auth_type;
        proxy_set_header X-Client-CN $ssl_client_s_dn_cn;
    }
    
    # Time-based access control
    location /business-hours/ {
        # Only allow access during business hours (9 AM - 5 PM)
        if ($time_iso8601 ~ "T(0[0-8]|1[7-9]|2[0-3])") {
            return 403 "Access only allowed during business hours (9 AM - 5 PM)";
        }
        
        auth_basic "Business Hours Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://backend;
    }
}
```

---

## Load Balancing and Upstream Configuration

### 1. Basic Load Balancing

#### Apache Configuration (mod_proxy_balancer)
```apache
<Proxy "balancer://mycluster">
    BalancerMember http://server1.example.com:8080
    BalancerMember http://server2.example.com:8080
    BalancerMember http://server3.example.com:8080
    ProxySet lbmethod=byrequests
</Proxy>

<VirtualHost *:80>
    ServerName balanced.example.com
    ProxyPass / balancer://mycluster/
    ProxyPassReverse / balancer://mycluster/
</VirtualHost>
```

#### Nginx Equivalent (Multiple Methods)
```nginx
# Method 1: Round Robin (default)
upstream backend_rr {
    server server1.example.com:8080;
    server server2.example.com:8080;
    server server3.example.com:8080;
}

# Method 2: Weighted Round Robin
upstream backend_weighted {
    server server1.example.com:8080 weight=3;
    server server2.example.com:8080 weight=2;
    server server3.example.com:8080 weight=1;
}

# Method 3: Least Connections
upstream backend_lc {
    least_conn;
    server server1.example.com:8080;
    server server2.example.com:8080;
    server server3.example.com:8080;
}

# Method 4: IP Hash (session persistence)
upstream backend_ip_hash {
    ip_hash;
    server server1.example.com:8080;
    server server2.example.com:8080;
    server server3.example.com:8080;
}

# Method 5: Consistent Hash
upstream backend_hash {
    hash $request_uri consistent;
    server server1.example.com:8080;
    server server2.example.com:8080;
    server server3.example.com:8080;
}

# Method 6: Random (Nginx Plus or 1.15.1+)
upstream backend_random {
    random two least_conn;
    server server1.example.com:8080;
    server server2.example.com:8080;
    server server3.example.com:8080;
}

server {
    listen 80;
    server_name balanced.example.com;
    
    location / {
        proxy_pass http://backend_rr;
        include proxy_params;
    }
}
```

### 2. Advanced Upstream Configuration

#### Nginx Advanced Upstream
```nginx
upstream backend_advanced {
    # Load balancing method
    least_conn;
    
    # Primary servers
    server app1.example.com:8080 weight=3 max_fails=3 fail_timeout=30s;
    server app2.example.com:8080 weight=2 max_fails=3 fail_timeout=30s;
    server app3.example.com:8080 weight=1 max_fails=3 fail_timeout=30s;
    
    # Backup server (only used when all primary servers fail)
    server backup.example.com:8080 backup;
    
    # Server marked as down for maintenance
    server maintenance.example.com:8080 down;
    
    # Connection settings
    keepalive 32;
    keepalive_requests 1000;
    keepalive_timeout 60s;
    
    # Health checks (Nginx Plus only)
    # zone backend 64k;
}

server {
    listen 80;
    server_name app.example.com;
    
    location / {
        proxy_pass http://backend_advanced;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        
        # Load balancer headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
        
        # Retry logic
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
        proxy_next_upstream_tries 3;
        proxy_next_upstream_timeout 10s;
    }
}
```

### 3. Dynamic Upstream with Resolver

#### Nginx Dynamic Upstream
```nginx
server {
    listen 80;
    server_name dynamic.example.com;
    
    # DNS resolver for dynamic upstream
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    location / {
        # Dynamic upstream resolution
        set $upstream_endpoint "http://backend.example.com:8080";
        proxy_pass $upstream_endpoint;
        
        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important: Don't resolve at startup
        proxy_pass_request_body on;
        proxy_pass_request_headers on;
    }
}
```

---

## Rate Limiting and Security Controls

### 1. Request Rate Limiting

#### Apache Configuration (mod_reqtimeout)
```apache
<VirtualHost *:80>
    ServerName api.example.com
    
    # Basic rate limiting with mod_reqtimeout
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
    
    # Using mod_evasive (if available)
    DOSHashTableSize 4096
    DOSPageCount 3
    DOSSiteCount 50
    DOSPageInterval 1
    DOSSiteInterval 1
    DOSBlockingPeriod 600
</VirtualHost>
```

#### Nginx Rate Limiting (Comprehensive)
```nginx
# Define rate limiting zones
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=global:10m rate=1000r/s;
limit_req_zone $server_name zone=perserver:10m rate=1000r/s;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
limit_conn_zone $server_name zone=conn_limit_per_server:10m;

server {
    listen 80;
    server_name api.example.com;
    
    # Global connection limits
    limit_conn conn_limit_per_ip 20;
    limit_conn conn_limit_per_server 1000;
    
    # Login endpoint (very restrictive)
    location /login {
        limit_req zone=login burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://auth_backend;
    }
    
    # API endpoints (moderate limiting)
    location /api/ {
        limit_req zone=api burst=200 nodelay;
        limit_req zone=global burst=1000 nodelay;
        limit_req_status 429;
        
        # Custom error page for rate limiting
        error_page 429 /rate_limit.html;
        
        proxy_pass http://api_backend;
    }
    
    # Static content (minimal limiting)
    location /static/ {
        limit_req zone=global burst=1000 nodelay;
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }
    
    # Rate limit error page
    location = /rate_limit.html {
        root /usr/share/nginx/html;
        internal;
    }
}

# Whitelist certain IPs from rate limiting
geo $limit {
    default 1;
    10.0.0.0/8 0;      # Internal networks
    192.168.0.0/16 0;  # Private networks
    127.0.0.1/32 0;    # Localhost
}

map $limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=whitelisted:10m rate=100r/s;

server {
    listen 80;
    server_name whitelisted.example.com;
    
    location / {
        limit_req zone=whitelisted burst=200 nodelay;
        proxy_pass http://backend;
    }
}
```

### 2. DDoS Protection

#### Nginx Anti-DDoS Configuration
```nginx
# Define security zones
limit_req_zone $binary_remote_addr zone=ddos:20m rate=20r/s;
limit_conn_zone $binary_remote_addr zone=ddos_conn:20m;

# Geo-blocking (example)
geo $blocked_country {
    default 0;
    # Add country IP ranges that should be blocked
    # 1.2.3.0/24 1;  # Example blocked range
}

# User agent filtering
map $http_user_agent $blocked_agent {
    default 0;
    ~*malicious 1;
    ~*bot 1;
    ~*scanner 1;
    ~*crawler 1;
    "" 1;  # Empty user agent
}

server {
    listen 80;
    server_name protected.example.com;
    
    # Block by country
    if ($blocked_country) {
        return 403 "Access from your country is not allowed";
    }
    
    # Block by user agent
    if ($blocked_agent) {
        return 403 "Blocked user agent";
    }
    
    # Connection and request limits
    limit_conn ddos_conn 50;
    limit_req zone=ddos burst=100 nodelay;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Block common exploit attempts
    location ~* \.(php|asp|aspx|jsp)$ {
        return 403 "Access denied";
    }
    
    # Block access to sensitive files
    location ~* \.(htaccess|htpasswd|ini|log|sh|sql|conf)$ {
        return 403 "Access denied";
    }
    
    # Main application
    location / {
        proxy_pass http://backend;
        include proxy_params;
    }
}
```

---

## Caching Strategies

### 1. Proxy Caching

#### Apache Configuration (mod_cache)
```apache
<VirtualHost *:80>
    ServerName cached.example.com
    
    CacheEnable disk /
    CacheRoot /var/cache/apache2/mod_cache_disk
    CacheDirLevels 2
    CacheDirLength 1
    CacheDefaultExpire 3600
    CacheMaxExpire 86400
    
    ProxyPass / http://backend:8080/
    ProxyPassReverse / http://backend:8080/
</VirtualHost>
```

#### Nginx Proxy Caching
```nginx
# Cache configuration
proxy_cache_path /var/cache/nginx/proxy 
                levels=1:2 
                keys_zone=app_cache:100m 
                max_size=10g 
                inactive=60m 
                use_temp_path=off;

# Cache for static content
proxy_cache_path /var/cache/nginx/static 
                levels=1:2 
                keys_zone=static_cache:50m 
                max_size=5g 
                inactive=30d 
                use_temp_path=off;

server {
    listen 80;
    server_name cached.example.com;
    
    # API endpoints (short cache)
    location /api/ {
        proxy_cache app_cache;
        proxy_cache_key "$scheme$request_method$host$request_uri";
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_valid any 5m;
        
        # Cache control headers
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        proxy_cache_lock on;
        proxy_cache_lock_timeout 5s;
        
        # Bypass cache for certain conditions
        proxy_cache_bypass $http_pragma $http_authorization;
        proxy_no_cache $http_pragma $http_authorization;
        
        # Add cache status header
        add_header X-Cache-Status $upstream_cache_status;
        
        proxy_pass http://api_backend;
    }
    
    # Static content (long cache)
    location /static/ {
        proxy_cache static_cache;
        proxy_cache_valid 200 30d;
        proxy_cache_valid 404 1h;
        
        # Ignore cache control from backend
        proxy_ignore_headers Cache-Control Expires;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        
        add_header X-Cache-Status $upstream_cache_status;
        add_header Cache-Control "public, max-age=2592000";
        
        proxy_pass http://static_backend;
    }
    
    # Cache purge endpoint (admin only)
    location /cache-purge/ {
        allow 192.168.1.0/24;
        deny all;
        
        proxy_cache_purge app_cache "$scheme$request_method$host$request_uri";
    }
}
```

### 2. Microcaching

#### Nginx Microcaching
```nginx
# Microcache for dynamic content
proxy_cache_path /var/cache/nginx/micro 
                levels=1:2 
                keys_zone=microcache:10m 
                max_size=1g 
                inactive=1h 
                use_temp_path=off;

server {
    listen 80;
    server_name dynamic.example.com;
    
    # Set cache bypass conditions
    set $no_cache 0;
    
    # Bypass cache for logged-in users
    if ($http_cookie ~* "logged_in") {
        set $no_cache 1;
    }
    
    # Bypass cache for specific paths
    if ($request_uri ~* "/(admin|login|api/user)") {
        set $no_cache 1;
    }
    
    # Bypass cache for POST requests
    if ($request_method = POST) {
        set $no_cache 1;
    }
    
    location / {
        # Microcache configuration
        proxy_cache microcache;
        proxy_cache_key "$scheme$request_method$host$request_uri";
        proxy_cache_valid 200 1s;
        proxy_cache_valid 404 10s;
        
        # Cache bypass
        proxy_cache_bypass $no_cache;
        proxy_no_cache $no_cache;
        
        # Cache even with cookies (for microcaching)
        proxy_ignore_headers Set-Cookie;
        proxy_hide_header Set-Cookie;
        
        # Use stale content if backend is down
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        
        # Headers
        add_header X-Cache-Status $upstream_cache_status;
        add_header X-Cache-Date $upstream_http_date;
        
        proxy_pass http://dynamic_backend;
    }
}
```

---

## Advanced Configuration Patterns

### 1. Multi-Site Setup with Shared Configuration

#### Nginx Multi-Site Configuration
```nginx
# /etc/nginx/conf.d/shared.conf
# Shared upstream definitions
upstream php_backend {
    server unix:/var/run/php/php8.1-fpm.sock;
}

upstream node_backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

# Shared SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# Shared security headers
map $sent_http_content_type $security_headers {
    default "X-Frame-Options: DENY; X-Content-Type-Options: nosniff; X-XSS-Protection: 1; mode=block";
}

# Site 1: WordPress
server {
    listen 443 ssl http2;
    server_name site1.example.com;
    root /var/www/site1;
    index index.php;
    
    ssl_certificate /etc/ssl/certs/site1.crt;
    ssl_certificate_key /etc/ssl/private/site1.key;
    
    # WordPress-specific configuration
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass php_backend;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
    
    # WordPress security
    location ~ /\. {
        deny all;
    }
    
    location ~* /(?:uploads|files)/.*\.php$ {
        deny all;
    }
}

# Site 2: Node.js Application
server {
    listen 443 ssl http2;
    server_name site2.example.com;
    
    ssl_certificate /etc/ssl/certs/site2.crt;
    ssl_certificate_key /etc/ssl/private/site2.key;
    
    location / {
        proxy_pass http://node_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    # Static files served by Nginx
    location /static/ {
        root /var/www/site2;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# Site 3: Static Site with Custom Routing
server {
    listen 443 ssl http2;
    server_name site3.example.com;
    root /var/www/site3;
    index index.html;
    
    ssl_certificate /etc/ssl/certs/site3.crt;
    ssl_certificate_key /etc/ssl/private/site3.key;
    
    # Custom routing for SPA
    location / {
        try_files $uri $uri/ @fallback;
    }
    
    location @fallback {
        rewrite ^.*$ /index.html last;
    }
    
    # API proxy for SPA
    location /api/ {
        proxy_pass http://api_backend/;
        include proxy_params;
    }
}
```

### 2. Development vs Production Configurations

#### Nginx Environment-Specific Configuration
```nginx
# /etc/nginx/conf.d/environment.conf
# Environment detection
map $host $environment {
    ~*dev\. "development";
    ~*staging\. "staging";
    default "production";
}

# Environment-specific upstream
map $environment $backend_pool {
    development "dev_backend";
    staging "staging_backend";
    production "prod_backend";
}

# Development backend
upstream dev_backend {
    server dev.internal:3000;
}

# Staging backend
upstream staging_backend {
    server staging1.internal:3000;
    server staging2.internal:3000;
}

# Production backend (with load balancing)
upstream prod_backend {
    least_conn;
    server prod1.internal:3000 weight=3;
    server prod2.internal:3000 weight=3;
    server prod3.internal:3000 weight=2;
    server prod4.internal:3000 backup;
    keepalive 32;
}

server {
    listen 80;
    server_name ~^(?<subdomain>.+)\.example\.com$;
    
    # Development-specific settings
    if ($environment = "development") {
        add_header X-Debug-Info "Development Environment" always;
        error_log /var/log/nginx/dev-error.log debug;
    }
    
    # Staging-specific settings
    if ($environment = "staging") {
        add_header X-Robots-Tag "noindex, nofollow" always;
        auth_basic "Staging Environment";
        auth_basic_user_file /etc/nginx/.htpasswd-staging;
    }
    
    # Production-specific settings
    if ($environment = "production") {
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header X-Frame-Options "DENY" always;
    }
    
    location / {
        proxy_pass http://$backend_pool;
        proxy_set_header Host $host;
        proxy_set_header X-Environment $environment;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## References and Resources

### Official Documentation
1. **Nginx Official Documentation**: https://nginx.org/en/docs/
2. **Apache HTTP Server Documentation**: https://httpd.apache.org/docs/
3. **Nginx Admin Guide**: https://docs.nginx.com/nginx/admin-guide/
4. **Let's Encrypt Documentation**: https://letsencrypt.org/docs/

### Migration Guides and Tutorials
1. **DigitalOcean Apache to Nginx Migration**: https://www.digitalocean.com/community/tutorials/how-to-migrate-from-an-apache-web-server-to-nginx-on-an-ubuntu-vps
2. **Ultimate Guide to Migrating From Apache to Nginx (Part 1)**: https://www.airpair.com/nginx/posts/ultimate-guide-migrating-apache-to-nginx-1
3. **Ultimate Guide to Migrating From Apache to Nginx (Part 2)**: https://www.airpair.com/nginx/posts/ultimate-guide-migrating-apache-to-nginx-2
4. **LinuxConfig Migration Guide**: https://linuxconfig.org/how-to-migrate-apache-to-nginx-by-converting-virtualhosts-to-server-blocks

### Load Balancing and Performance
1. **Nginx Load Balancing Documentation**: http://nginx.org/en/docs/http/load_balancing.html
2. **HTTP Load Balancing with Nginx**: https://docs.nginx.com/nginx/admin-guide/load-balancer/http-load-balancer/
3. **Advanced Nginx Load Balancing**: https://www.webhi.com/how-to/advanced-nginx-configuration-load-balancer/
4. **TCP/UDP Load Balancing**: https://blog.nginx.org/blog/tcp-load-balancing-udp-load-balancing-nginx-tips-tricks

### Security and Rate Limiting
1. **Nginx Rate Limiting Guide**: https://blog.nginx.org/blog/rate-limiting-nginx
2. **Nginx Rate Limiting Documentation**: https://nginx.org/en/docs/http/ngx_http_limit_req_module.html
3. **Nginx Security Controls**: https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-proxied-http/
4. **Basic Authentication with Nginx**: https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/

### SSL/TLS and Authentication
1. **Nginx SSL Module Documentation**: https://nginx.org/en/docs/http/ngx_http_ssl_module.html
2. **Client Certificate Authentication**: https://fardog.io/blog/2017/12/30/client-side-certificate-authentication-with-nginx/
3. **SSL Client Certificate Authentication**: https://www.ssltrust.com.au/help/setup-guides/client-certificate-authentication
4. **Nginx SSL Configuration Examples**: https://github.com/h5bp/server-configs-nginx

### Community Resources
1. **Nginx Community**: https://community.nginx.org/
2. **Stack Overflow Nginx Tag**: https://stackoverflow.com/questions/tagged/nginx
3. **Reddit r/nginx**: https://www.reddit.com/r/nginx/
4. **GitHub Nginx Configurations**: https://github.com/nginxinc/nginx-plus-demos

### Tools and Utilities
1. **Nginx Configuration Tester**: https://nginx.org/en/docs/switches.html
2. **SSL Labs SSL Test**: https://www.ssllabs.com/ssltest/
3. **Apache2Nginx Converter**: https://github.com/nhnc-nginx/apache2nginx
4. **Nginx Configuration Generator**: https://nginxconfig.io/

### Books and In-Depth Resources
1. **"Nginx Cookbook" by Derek DeJonghe** (O'Reilly)
2. **"Mastering Nginx" by Dimitri Aivaliotis** (Packt)
3. **"Nginx HTTP Server" by Clément Nedelcu** (Packt)
4. **"Complete Nginx Cookbook"** (Nginx Inc.)

---

## Migration Checklist

### Pre-Migration
- [ ] Document current Apache configuration
- [ ] Identify all virtual hosts and their purposes
- [ ] List all custom modules and their Nginx equivalents
- [ ] Test Nginx configuration in staging environment
- [ ] Backup all configuration files and SSL certificates

### During Migration
- [ ] Install and configure Nginx
- [ ] Migrate virtual hosts one by one
- [ ] Test each configuration thoroughly
- [ ] Verify SSL certificates and security settings
- [ ] Check log file locations and formats

### Post-Migration
- [ ] Monitor performance and error logs
- [ ] Verify all sites are functioning correctly
- [ ] Update monitoring and alerting systems
- [ ] Train team on Nginx configuration and troubleshooting
- [ ] Document the new configuration for future reference

This comprehensive guide provides a thorough foundation for migrating from Apache to Nginx, covering common scenarios and advanced use cases encountered in real-world deployments.