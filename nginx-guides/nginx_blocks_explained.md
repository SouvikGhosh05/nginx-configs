# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive) - ONLY at end of URI
location ~ \.(CSS|JS|PNG)$ {
    # $ means "end of string" - IMPORTANT for security!
    # ✓ Matches: /assets/style.CSS, /scripts/app.JS, /images/logo.PNG
    # ✗ Doesn't match: /assets/style.css (lowercase), /images/file.CSS.backup
    # ✗ Doesn't match: /malicious.CSS/../../etc/passwd ($ prevents path traversal)
    expires 1h;                          # Cache for 1 hour
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # ^ means "start of string", [0-9]+ means "one or more digits"
    # ✓ Matches: /api/v1/, /api/v2/users, /api/v123/orders
    # ✗ Doesn't match: /old/api/v1/, /api/version1/, /api/v/
    proxy_pass http://versioned_api_backend;    # Route to versioned API backend
}

# Matches specific date-based file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # [0-9]{4} means "exactly 4 digits", [0-9]{2} means "exactly 2 digits"
    # ✓ Matches: /reports/2024/03/, /reports/2023/12/sales
    # ✗ Doesn't match: /reports/24/3/, /reports/2024/3/, /old/reports/2024/03/
    auth_required on;                    # Require authentication
    proxy_pass http://reports_backend;   # Route to reports service
}
```

#### **Case-Insensitive Regex (~*) - WITH End Anchor ($)**
```nginx
# Matches common image formats (any case) - SECURE with end anchor
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    # ~* = case-insensitive, $ = end of URI (SECURITY CRITICAL)
    # ✓ Matches: /image.JPG, /photo.jpeg, /logo.PNG, /icon.GIF
    # ✓ Matches: /path/to/file.jpg, /assets/images/photo.WEBP
    # ✗ Doesn't match: /image.jpg.backup, /photo.png/../../etc/passwd
    # ✗ Doesn't match: /malicious.jpg.php (prevents double extension attacks)
    expires 1y;                                 # Cache images for 1 year
    add_header Cache-Control "public, immutable";  # Immutable cache header
    access_log off;                             # Don't log image requests
}

# Matches CSS and JavaScript files - SECURE
location ~* \.(css|js)$ {
    # ✓ Matches: /style.css, /app.JS, /main.CSS, /script.js
    # ✗ Doesn't match: /style.css.backup, /app.js.old, /script.js/malicious
    expires 1month;                     # Cache for 1 month
    gzip_static on;                     # Serve pre-compressed files if available
    add_header Cache-Control "public";  # Public cache header
}

# Matches documentation files for download - SECURE
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Matches: /manual.PDF, /report.doc, /data.ZIP, /readme.TXT
    # ✗ Doesn't match: /document.pdf.exe, /file.zip/malicious, /report.doc.backup
    add_header Content-Disposition "attachment";  # Force download
    root /var/www/downloads;                      # Downloads directory
}
```

#### **Case-Insensitive Regex (~*) - WITHOUT End Anchor (DANGEROUS!)**
```nginx
# DANGEROUS PATTERN - Without $ end anchor
location ~* \.(pdf|doc|docx|txt|zip) {
    # ⚠️  NO $ at end - SECURITY RISK!
    # ✓ Matches: /document.pdf (intended)
    # ⚠️  ALSO Matches: /document.pdf.php (DANGEROUS!)
    # ⚠️  ALSO Matches: /file.zip/../../etc/passwd (PATH TRAVERSAL!)
    # ⚠️  ALSO Matches: /malicious.txt.exe (DOUBLE EXTENSION ATTACK!)
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# CORRECT VERSION - Always use $ for file extensions
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Secure: Only matches files ending with these extensions
    # ✗ Blocks: /document.pdf.php, /file.zip.backup, /malicious.txt.exe
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}
```

#### **Advanced Regex Examples with Path Behavior**
```nginx
# User profile URLs with capture groups - SECURE
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # ^ = start, ([a-zA-Z0-9_-]+) = capture username, /? = optional slash, $ = end
    # ✓ Matches: /user/john_doe, /user/ADMIN/, /user/test123/
    # ✗ Doesn't match: /user/, /user/john../malicious, /old/user/john
    # ✗ Doesn't match: /user/john/posts ($ prevents extra path segments)
    proxy_pass http://user_backend/profile/$1;    # $1 refers to captured username
}

# API versioning with alternatives - SECURE
location ~* ^/api/(v[0-9]+|beta|alpha)/?$ {
    # (v[0-9]+|beta|alpha) = version pattern with alternatives, $ = end
    # ✓ Matches: /api/v1, /api/v2/, /API/BETA/, /api/alpha
    # ✗ Doesn't match: /api/v1/users ($ prevents sub-paths)
    # ✗ Doesn't match: /old/api/v1/, /api/v1beta (strict pattern)
    limit_req zone=api burst=50;        # Apply rate limiting
    proxy_pass http://api_backend;       # Route to API backend
}

# File upload paths - DANGEROUS without proper anchoring
location ~* /uploads/.*\.(jpg|png|gif) {
    # ⚠️  No ^ or $ anchors - can match anywhere in path!
    # ✓ Matches: /uploads/photo.jpg (intended)
    # ⚠️  ALSO Matches: /malicious/uploads/photo.jpg/../../../etc/passwd
    # ⚠️  ALSO Matches: /uploads/safe.jpg.php (missing $ anchor)
    expires 1M;
}

# SECURE VERSION with proper anchoring
location ~* ^/uploads/[^/]+\.(jpg|png|gif)$ {
    # ^ = start, [^/]+ = filename without slashes, $ = end
    # ✓ Matches: /uploads/photo.jpg, /uploads/image.PNG
    # ✗ Doesn't match: /uploads/../../etc/passwd, /uploads/photo.jpg.php
    # ✗ Doesn't match: /uploads/subdir/photo.jpg (prevents subdirectory access)
    expires 1M;
    root /var/www/uploads;
}
```

#### **Security-Focused Examples for Interview Discussion**
```nginx
# SECURE: Block executable files with proper anchoring
location ~* \.(php|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
    # $ anchor CRITICAL - prevents /script.php.txt bypasses
    # ✓ Blocks: /malicious.php, /script.PHP, /backdoor.phtml
    # ✓ Blocks: /upload.php (even if uploaded to wrong directory)
    # ✗ Doesn't block: /legitimate.php.backup (ends with .backup, not .php)
    deny all;                            # Block all executable files
    access_log /var/log/nginx/blocked.log;  # Log blocking attempts
}

# SECURE: Media files with size validation
location ~* ^/media/[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif|webp)$ {
    # ^/media/ = must start with /media/, [a-zA-Z0-9_-]+ = safe filename chars only
    # $ = must end with allowed extension (prevents .php appends)
    # ✓ Matches: /media/photo_123.jpg, /media/image-2024.PNG
    # ✗ Doesn't match: /media/../../../etc/passwd, /media/photo.jpg.php
    # ✗ Doesn't match: /media/subdir/photo.jpg (prevents directory traversal)
    expires 6M;                          # Cache media for 6 months
    add_header Cache-Control "public, immutable";
    
    # Optional: Add security headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type confusion
}

# DANGEROUS vs SECURE comparison
location ~* \.txt {
    # ⚠️  DANGEROUS: /malicious.txt.php would match!
    return 200 "Text file";
}

location ~* \.txt$ {
    # ✅ SECURE: Only files actually ending in .txt
    return 200 "Text file";
}
```

**When to Use:**
- **File extension matching** - ALWAYS use `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor for security
- **Dynamic URL patterns** - Use `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 for precise matching
- **Flexible matching** - Case-insensitive with proper boundaries
- **Security-critical paths** - Multiple validation layers with anchors

#### **Interview Key Points:**

**Q: "What's the difference between `~* \.pdf` and `~* \.pdf# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

?"**
**A:** "The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor is crucial for security. Without it, `~* \.pdf` would match `/document.pdf.php` which could be a security vulnerability. The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 ensures the URI actually ends with `.pdf`, preventing double extension attacks and path traversal attempts."

**Q: "Why do you anchor your regex patterns?"**
**A:** "Anchoring with `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 is a security best practice. It prevents unintended matches that could allow attackers to bypass restrictions. For example, without `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

, a pattern for images might match `/photo.jpg.php`, potentially serving executable files instead of images."

**Q: "How do you secure file upload locations?"**
**A:** "I use strict regex patterns with anchors like `^/uploads/[^/]+\.(jpg|png)# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 to ensure files are in the correct directory, have safe filenames without path separators, and end with allowed extensions. This prevents directory traversal and executable file uploads."

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier) - "Longest Match Wins"**

```nginx
# Multiple prefix patterns - nginx chooses the LONGEST matching prefix
location /api/ {
    # ✓ Matches: /api/, /api/users, /api/orders/123
    # This is a SHORTER prefix - lower priority
    return 200 "General API endpoint";
    proxy_pass http://api_backend;
}

location /api/v1/ {
    # ✓ Matches: /api/v1/, /api/v1/users, /api/v1/orders/123
    # This is a LONGER prefix - HIGHER priority than /api/
    return 200 "API Version 1";
    proxy_pass http://api_v1_backend;
}

location /api/v1/admin/ {
    # ✓ Matches: /api/v1/admin/, /api/v1/admin/users, /api/v1/admin/settings
    # This is the LONGEST prefix - HIGHEST priority among these three
    auth_basic "Admin Required";
    return 200 "Admin API";
    proxy_pass http://admin_backend;
}

# REQUEST BEHAVIOR EXAMPLES:
# /api/users           → Matches /api/ (returns "General API endpoint")
# /api/v1/users        → Matches /api/v1/ (returns "API Version 1") 
# /api/v1/admin/users  → Matches /api/v1/admin/ (returns "Admin API")
```

#### **Longest Match Priority Demonstration:**
```nginx
# Order doesn't matter - nginx finds longest match automatically
location / {
    # ✓ Matches: EVERYTHING not matched by more specific patterns
    # SHORTEST prefix (1 character) - LOWEST priority
    try_files $uri $uri/ /index.html;
}

location /app {
    # ✓ Matches: /app, /app-data, /application (anything starting with /app)
    # ✗ Doesn't match: /ap, /app/ (exact: /app doesn't have trailing slash)
    return 200 "App prefix (no slash)";
}

location /app/ {
    # ✓ Matches: /app/, /app/dashboard, /app/settings/profile
    # LONGER than /app - takes priority over /app for /app/anything
    try_files $uri $uri/ /app/index.html;
}

location /app/admin {
    # ✓ Matches: /app/admin, /app/admin-panel, /app/administration  
    # LONGER than /app/ - takes priority for /app/admin*
    auth_basic "Admin Access";
    return 200 "App admin (no slash)";
}

location /app/admin/ {
    # ✓ Matches: /app/admin/, /app/admin/users, /app/admin/settings
    # LONGEST prefix - HIGHEST priority for /app/admin/ paths
    auth_basic "Admin Access";
    proxy_pass http://admin_backend;
}

# REQUEST EXAMPLES with longest match logic:
# /app                 → Matches /app (exact match, no slash)
# /app/                → Matches /app/ (longer than /app for this path)
# /app/dashboard       → Matches /app/ (longest match)
# /app/admin           → Matches /app/admin (longer than /app/)
# /app/admin/          → Matches /app/admin/ (longest match)
# /app/admin/users     → Matches /app/admin/ (longest match)
# /anything-else       → Matches / (catch-all)
```

#### **Real-World Multi-Service Example:**
```nginx
server {
    # Microservices routing with longest match prioritization
    
    location /api/ {
        # FALLBACK: General API gateway for unspecified services
        # ✓ Matches: /api/unknown, /api/legacy, /api/test
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://default_api_backend;
        proxy_set_header X-Service "default";
    }
    
    location /api/auth/ {
        # LONGER: Authentication service
        # ✓ Matches: /api/auth/login, /api/auth/logout, /api/auth/refresh
        limit_req zone=auth burst=10;           # Stricter rate limiting
        proxy_pass http://auth_service_backend;
        proxy_set_header X-Service "auth";
    }
    
    location /api/user/ {
        # LONGER: User management service  
        # ✓ Matches: /api/user/profile, /api/user/settings, /api/user/123
        limit_req zone=users burst=100 nodelay;
        proxy_pass http://user_service_backend;
        proxy_set_header X-Service "users";
    }
    
    location /api/user/admin/ {
        # LONGEST: User admin operations
        # ✓ Matches: /api/user/admin/list, /api/user/admin/ban, /api/user/admin/roles
        auth_basic "User Admin";                 # Requires authentication
        limit_req zone=admin burst=20;          # Different rate limits
        proxy_pass http://user_admin_backend;
        proxy_set_header X-Service "user-admin";
    }
    
    # PROCESSING EXAMPLES:
    # /api/test            → /api/ (fallback)
    # /api/auth/login      → /api/auth/ (longer than /api/)
    # /api/user/profile    → /api/user/ (longer than /api/)  
    # /api/user/admin/ban  → /api/user/admin/ (longest match)
}
```

#### **Directory-Based Organization Example:**
```nginx
server {
    # Static file serving with longest match logic
    
    location /static/ {
        # GENERAL: All static assets
        # ✓ Matches: /static/css/main.css, /static/js/app.js, /static/images/logo.png
        expires 1M;                              # 1 month cache
        root /var/www/assets;
        add_header Cache-Control "public";
    }
    
    location /static/images/ {
        # LONGER: Image-specific handling
        # ✓ Matches: /static/images/photo.jpg, /static/images/icons/home.png
        expires 1y;                              # Longer cache for images
        root /var/www/assets;
        add_header Cache-Control "public, immutable";
        
        # Image-specific optimizations
        add_header Vary Accept;                  # For WebP serving
        access_log off;                          # Don't log image requests
    }
    
    location /static/images/profile/ {
        # LONGEST: Profile images with special handling
        # ✓ Matches: /static/images/profile/user123.jpg, /static/images/profile/avatars/default.png
        expires 6M;                              # Medium cache (profiles change)
        root /var/www/assets;
        
        # Profile-specific security
        add_header X-Content-Type-Options nosniff;
        auth_request /auth;                      # Require authentication
    }
    
    # PROCESSING EXAMPLES:
    # /static/css/main.css              → /static/ (general static)
    # /static/images/logo.png           → /static/images/ (longer match)
    # /static/images/profile/user.jpg   → /static/images/profile/ (longest match)
}
```

#### **API Versioning with Longest Match:**
```nginx
server {
    # API versioning where longest match determines routing
    
    location /api/ {
        # DEFAULT: Unversioned or latest API
        # ✓ Matches: /api/status, /api/docs, /api/health
        proxy_pass http://api_latest_backend;
        proxy_set_header X-API-Version "latest";
    }
    
    location /api/v1/ {
        # VERSION 1: Legacy API
        # ✓ Matches: /api/v1/users, /api/v1/orders, /api/v1/products
        proxy_pass http://api_v1_backend;
        proxy_set_header X-API-Version "v1";
        
        # Legacy API warnings
        add_header X-API-Deprecated "true";
        add_header X-API-Sunset "2024-12-31";
    }
    
    location /api/v2/ {
        # VERSION 2: Current stable API
        # ✓ Matches: /api/v2/users, /api/v2/orders, /api/v2/products
        proxy_pass http://api_v2_backend;
        proxy_set_header X-API-Version "v2";
    }
    
    location /api/v2/admin/ {
        # ADMIN V2: Administrative endpoints  
        # ✓ Matches: /api/v2/admin/users, /api/v2/admin/reports, /api/v2/admin/config
        auth_basic "API Admin";                  # Require authentication
        proxy_pass http://api_v2_admin_backend;
        proxy_set_header X-API-Version "v2-admin";
        
        # Admin-specific rate limiting
        limit_req zone=admin burst=10;
    }
    
    # PROCESSING EXAMPLES:
    # /api/health          → /api/ (general API)
    # /api/v1/users        → /api/v1/ (legacy version)
    # /api/v2/users        → /api/v2/ (current version)
    # /api/v2/admin/users  → /api/v2/admin/ (longest, most specific)
}
```

**When to Use Prefix Match:**
- **API routing** - Simple, clean URL patterns for REST APIs
- **Directory-based organization** - Different backends for different URL paths  
- **Service routing** - Route to different microservices based on path
- **Content organization** - Different handling for different content types
- **Progressive enhancement** - More specific paths get special treatment

**Why Longest Match Wins:**
- **Specificity** - More specific patterns should take priority
- **Predictable behavior** - Always chooses the most specific match
- **Flexible organization** - Can add more specific patterns without breaking existing ones
- **Performance** - nginx can efficiently find longest match without regex processing

**Significance for DevOps:**
- **Service isolation** - Each service gets its own path prefix
- **Configuration management** - Can organize configs by service boundaries
- **Monitoring** - Easy to track metrics per service path
- **Security** - Apply different security policies to different path hierarchies
- **Scalability** - Easy to add new services with new path prefixes

**Interview Key Points:**

**Q: "How does nginx choose between multiple prefix matches?"**
**A:** "Nginx uses longest match wins. For `/api/v1/admin/users`, if I have `/api/`, `/api/v1/`, and `/api/v1/admin/` locations, nginx chooses `/api/v1/admin/` because it's the longest matching prefix. This allows hierarchical configuration where more specific paths can have different behaviors."

**Q: "When would you use prefix match vs exact match?"**
**A:** "I use exact match (`=`) for specific endpoints like `/health` that need maximum performance and security. I use prefix match for hierarchical routing like `/api/users/`, `/api/orders/` where I want to handle all sub-paths under that prefix. Prefix gives flexibility for RESTful APIs where `/api/users/123` and `/api/users/123/posts` should go to the same backend."

**Q: "How do you organize microservices routing with prefix matches?"**
**A:** "I create a hierarchy: `/api/` as fallback, `/api/users/` for user service, `/api/users/admin/` for user admin operations. Longest match ensures the most specific service handles the request, while the hierarchy provides logical organization and fallback routing."

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    # (?<tenant_name>[a-z0-9]+): Named capture group for tenant
    # (?<path>.*): Named capture group for remaining path
    proxy_pass http://$tenant_name_backend/$path$is_args$args;  # Dynamic backend routing
    proxy_set_header X-Tenant $tenant_name;                    # Pass tenant info to backend
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";    # Create dynamic zone name
    limit_req zone=$tenant_zone burst=20;   # Apply tenant-specific rate limiting
    proxy_pass http://tenant_backend;       # Route to tenant backend
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;                                      # Extract language code
    set $path $2;                                      # Extract remaining path
    proxy_pass http://i18n_backend/$path$is_args$args; # Route to internationalization backend
    proxy_set_header X-Language $lang;                 # Pass language to backend
}

# Specific language handling
location /en/ {
    alias /var/www/english/;              # Serve English content from specific directory
    try_files $uri $uri/ /en/index.html;  # English-specific fallback
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;     # Route v1 API to legacy backend
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;     # Route v2 API to current backend
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend; # Default to latest API version
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";                                    # Initialize variable
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {  # Check user agent
        set $mobile_backend "_mobile";                         # Set mobile suffix
    }
    proxy_pass http://web${mobile_backend}_backend;            # Route to appropriate backend
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { 
        expires 1y;         # Cache favicon for 1 year
        access_log off;     # Don't log favicon requests
    }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { 
        expires 1y;                           # Long-term caching for static assets
        root /var/www/assets;                 # Static files directory
    }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M;                           # Cache product images for 6 months
        root /var/www/media;                  # Media files directory
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10;         # Cart-specific rate limiting
        proxy_pass http://cart_service;       # Route to cart microservice
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5;       # Strict rate limiting for payments
        proxy_pass https://secure_payment;    # Route to secure payment processor
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1;  # Route with captured username
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html;     # Single Page Application fallback
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { 
        return 301 /admin/;                   # Redirect to trailing slash
    }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";                    # Basic authentication
        auth_basic_user_file /etc/nginx/.htpasswd;   # Admin credentials file
        proxy_pass http://admin_backend;              # Route to admin backend
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;            # Allow 50MB uploads
        root /var/www/media;                  # Media storage directory
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;                           # Cache plugin assets for 1 month
        root /var/www/plugins;                # Plugin directory
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;       # Route to blog service
        proxy_set_header X-Year $1;          # Pass year to backend
        proxy_set_header X-Month $2;         # Pass month to backend
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { 
        return 200 "OK";                      # Simple health check response
    }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;      # User service rate limiting
        proxy_pass http://user_service/;     # Route to user microservice
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;      # Order service rate limiting
        proxy_pass http://order_service/;    # Route to order microservice
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;  # Inventory service rate limiting
        proxy_pass http://inventory_service/; # Route to inventory microservice
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;  # Route to WebSocket service
        proxy_http_version 1.1;              # Required for WebSockets
        proxy_set_header Upgrade $http_upgrade;     # WebSocket upgrade header
        proxy_set_header Connection "upgrade";      # WebSocket connection header
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;                            # Only accessible via internal redirect
        alias /var/secure/files/;            # Secure file storage
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;   # Dynamic routing to versioned service
    }
}
```

### **8. Location Matching Comparison: /health Examples**

Let's compare different ways to match `/health` and understand their behavior:

#### **Comparison Table:**

| Pattern | Type | Priority | Matches | Use Case |
|---------|------|----------|---------|-----------|
| `location /health` | Prefix Match | 4 (Lowest) | `/health`, `/health123`, `/health/status` | General routing |
| `location = /health` | Exact Match | 1 (Highest) | `/health` ONLY | High-performance endpoints |
| `location ^~ /health` | Prefix + Modifier | 2 | `/health`, `/health123`, `/health/status` | Performance optimization |
| `location ~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-sensitive) | 3 | `/health` ONLY | Complex pattern matching |
| `location ~* ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-insensitive) | 3 | `/health`, `/HEALTH`, `/Health` | Flexible matching |

#### **Detailed Examples with Behavior:**

```nginx
# 1. Prefix Match - /health
location /health {
    return 200 "Prefix match: $uri";
}
# Matches:
# ✓ /health → "Prefix match: /health"
# ✓ /health123 → "Prefix match: /health123"  
# ✓ /health/status → "Prefix match: /health/status"
# ✓ /health/ → "Prefix match: /health/"
# ✗ /api/health → No match (doesn't start with /health)
```

```nginx
# 2. Exact Match - = /health
location = /health {
    return 200 "Exact match: $uri";
}
# Matches:
# ✓ /health → "Exact match: /health"
# ✗ /health123 → No match
# ✗ /health/status → No match  
# ✗ /health/ → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 3. Prefix Match with Modifier - ^~ /health
location ^~ /health {
    return 200 "Prefix with modifier: $uri";
}
# Matches:
# ✓ /health → "Prefix with modifier: /health"
# ✓ /health123 → "Prefix with modifier: /health123"
# ✓ /health/status → "Prefix with modifier: /health/status"
# ✓ /health/ → "Prefix with modifier: /health/"
# ✗ /api/health → No match
# 
# IMPORTANT: Stops processing regex locations!
```

```nginx
# 4. Regex Match (case-sensitive) - ~ ^/health$
location ~ ^/health$ {
    return 200 "Regex match: $uri";
}
# Matches:
# ✓ /health → "Regex match: /health"
# ✗ /health123 → No match ($ means end of string)
# ✗ /health/status → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 5. Regex Match (case-insensitive) - ~* ^/health$
location ~* ^/health$ {
    return 200 "Case-insensitive regex: $uri";
}
# Matches:
# ✓ /health → "Case-insensitive regex: /health"
# ✓ /HEALTH → "Case-insensitive regex: /HEALTH"
# ✓ /Health → "Case-insensitive regex: /Health"
# ✗ /health123 → No match ($ means end of string)
```

#### **Processing Priority Example:**

```nginx
server {
    # Multiple location blocks for /health
    
    # Priority 1: Exact match (processed first)
    location = /health {
        return 200 "Exact match";
    }
    
    # Priority 2: Prefix with modifier (processed second)
    location ^~ /health {
        return 200 "Prefix with modifier";
    }
    
    # Priority 3: Regex (processed third)
    location ~ ^/health {
        return 200 "Regex match";
    }
    
    # Priority 4: Prefix (processed last)
    location /health {
        return 200 "Prefix match";
    }
}

# Request Results:
# GET /health → "Exact match" (stops processing here)
# GET /health/status → "Prefix with modifier" (exact doesn't match, this does and stops regex)
```

#### **Real-World Scenarios:**

##### **Scenario 1: High-Performance Health Check**
```nginx
# Use exact match for maximum performance
location = /health {
    access_log off;
    return 200 "OK";
}
# Why: Health checks happen frequently, exact match is fastest
```

##### **Scenario 2: Health Check with Sub-paths**
```nginx
# Use prefix with modifier to include health sub-endpoints
location ^~ /health {
    # Matches /health, /health/detailed, /health/db, etc.
    proxy_pass http://health_service;
}
# Why: Covers all health-related endpoints, skips regex processing
```

##### **Scenario 3: Strict Health Check Only**
```nginx
# Use regex to match only /health (not sub-paths)
location ~* ^/health/?$ {
    # Matches /health and /health/ only
    return 200 "Health OK";
}
# Why: Prevents matching /health/anything-else
```

##### **Scenario 4: Multiple Health Endpoints**
```nginx
# Combine different approaches
location = /health {
    # Quick health check
    return 200 "OK";
}

location = /health/detailed {
    # Detailed health check
    proxy_pass http://detailed_health_service;
}

location ^~ /health/ {
    # All other health sub-paths
    proxy_pass http://health_service;
}
```

#### **Performance Comparison:**

| Match Type | Performance | Processing | Best For |
|------------|-------------|------------|----------|
| `= /health` | **Fastest** | No regex, immediate match | High-frequency endpoints |
| `^~ /health` | **Fast** | Skips regex processing | Static asset paths |
| `~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | **Slower** | Regex compilation needed | Complex patterns only |
| `/health` | **Medium** | Longest prefix comparison | General routing |

#### **Common Mistakes:**

```nginx
# WRONG: This is not valid nginx syntax
location ^/health {  # Missing ~ for regex or = for exact
    return 200 "Invalid";
}

# WRONG: Overlapping without consideration
location /health {
    return 200 "This will never execute";
}
location = /health {
    return 200 "This executes first";
}

# CORRECT: Order matters for prefix matches
location /health/detailed {  # More specific first
    return 200 "Detailed health";
}
location /health {           # General match second
    return 200 "General health";
}
```

#### **Interview Question Examples:**

**Q: "What's the difference between `location /health` and `location = /health`?"**

**A:** "`location /health` is a prefix match that matches `/health` and anything starting with `/health` like `/health123` or `/health/status`. `location = /health` is an exact match that only matches `/health` exactly - it's faster and has the highest priority in nginx processing."

**Q: "When would you use `^~ /health` instead of `/health`?"**

**A:** "I'd use `^~ /health` when I want prefix matching but need to skip regex processing for performance. It's useful for high-traffic paths like static assets or API endpoints where I know regex locations aren't needed."

**Q: "How does nginx decide which location block to use?"**

**A:** "Nginx follows a specific priority: 1) Exact matches (`=`) first, 2) Prefix with modifier (`^~`) second, 3) Regex matches (`~` or `~*`) third, and 4) Regular prefix matches last, where the longest match wins."

This comparison shows exactly how different location patterns behave and when to use each one!

---

## 9. Critical Security: Regex Anchoring in Location Blocks

### **The $ Anchor Security Issue - Essential for Interviews**

This is one of the most important security concepts in nginx configuration that interviewers often test:

```nginx
# ⚠️  SECURITY VULNERABILITY - Missing $ anchor
location ~* \.(pdf|doc|txt|zip) {
    # DANGEROUS: Matches these unexpected paths:
    # ✓ /document.pdf (intended)
    # ⚠️  /document.pdf.php (EXECUTABLE PHP FILE!)
    # ⚠️  /file.zip.backup (BACKUP FILE EXPOSURE!)
    # ⚠️  /malicious.txt.exe (EXECUTABLE MASQUERADING!)
    # ⚠️  /safe.pdf/../../etc/passwd (PATH TRAVERSAL!)
    
    root /var/www/downloads;
    # This could serve executable files or allow path traversal!
}

# ✅ SECURE VERSION - With $ anchor
location ~* \.(pdf|doc|txt|zip)$ {
    # SECURE: Only matches files that END with these extensions
    # ✓ /document.pdf (allowed)
    # ✗ /document.pdf.php (blocked - doesn't end with .pdf)
    # ✗ /file.zip.backup (blocked - ends with .backup, not .zip)
    # ✗ /malicious.txt.exe (blocked - ends with .exe, not .txt)
    
    root /var/www/downloads;
    add_header Content-Disposition "attachment";
}
```

### **Real-World Attack Scenarios (Interview Examples)**

#### **Scenario 1: Double Extension Attack**
```nginx
# VULNERABLE configuration
location ~* \.(jpg|png|gif) {
    root /var/www/uploads;
}

# Attacker uploads: malicious.jpg.php
# ✅ Matches the regex (contains .jpg)
# ⚠️  Gets served as PHP and executed!

# SECURE configuration
location ~* \.(jpg|png|gif)$ {
    root /var/www/uploads;
}
# ✗ malicious.jpg.php blocked (doesn't END with image extension)
```

#### **Scenario 2: Path Traversal via Regex**
```nginx
# VULNERABLE configuration  
location ~* \.log {
    root /var/log/nginx;
}

# Attacker requests: /application.log/../../etc/passwd
# ✅ Matches regex (contains .log)
# ⚠️  Serves /etc/passwd due to path traversal!

# SECURE configuration
location ~* \.log$ {
    root /var/log/nginx;
}
# ✗ Path traversal blocked (doesn't END with .log)
```

#### **Scenario 3: Config File Exposure**
```nginx
# VULNERABLE - Trying to serve documentation
location ~* \.(txt|md|doc) {
    root /var/www/docs;
}

# Attacker requests: /config.txt.backup
# ✅ Matches regex (contains .txt)  
# ⚠️  Exposes configuration backup files!

# SECURE VERSION
location ~* \.(txt|md|doc)$ {
    root /var/www/docs;
}
# ✗ Backup files blocked (don't END with allowed extensions)
```

### **Interview Questions & Expert Answers**

#### **Q: "What's wrong with `location ~* \.php` vs `location ~* \.php# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive) - ONLY at end of URI
location ~ \.(CSS|JS|PNG)$ {
    # $ means "end of string" - IMPORTANT for security!
    # ✓ Matches: /assets/style.CSS, /scripts/app.JS, /images/logo.PNG
    # ✗ Doesn't match: /assets/style.css (lowercase), /images/file.CSS.backup
    # ✗ Doesn't match: /malicious.CSS/../../etc/passwd ($ prevents path traversal)
    expires 1h;                          # Cache for 1 hour
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # ^ means "start of string", [0-9]+ means "one or more digits"
    # ✓ Matches: /api/v1/, /api/v2/users, /api/v123/orders
    # ✗ Doesn't match: /old/api/v1/, /api/version1/, /api/v/
    proxy_pass http://versioned_api_backend;    # Route to versioned API backend
}

# Matches specific date-based file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # [0-9]{4} means "exactly 4 digits", [0-9]{2} means "exactly 2 digits"
    # ✓ Matches: /reports/2024/03/, /reports/2023/12/sales
    # ✗ Doesn't match: /reports/24/3/, /reports/2024/3/, /old/reports/2024/03/
    auth_required on;                    # Require authentication
    proxy_pass http://reports_backend;   # Route to reports service
}
```

#### **Case-Insensitive Regex (~*) - WITH End Anchor ($)**
```nginx
# Matches common image formats (any case) - SECURE with end anchor
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    # ~* = case-insensitive, $ = end of URI (SECURITY CRITICAL)
    # ✓ Matches: /image.JPG, /photo.jpeg, /logo.PNG, /icon.GIF
    # ✓ Matches: /path/to/file.jpg, /assets/images/photo.WEBP
    # ✗ Doesn't match: /image.jpg.backup, /photo.png/../../etc/passwd
    # ✗ Doesn't match: /malicious.jpg.php (prevents double extension attacks)
    expires 1y;                                 # Cache images for 1 year
    add_header Cache-Control "public, immutable";  # Immutable cache header
    access_log off;                             # Don't log image requests
}

# Matches CSS and JavaScript files - SECURE
location ~* \.(css|js)$ {
    # ✓ Matches: /style.css, /app.JS, /main.CSS, /script.js
    # ✗ Doesn't match: /style.css.backup, /app.js.old, /script.js/malicious
    expires 1month;                     # Cache for 1 month
    gzip_static on;                     # Serve pre-compressed files if available
    add_header Cache-Control "public";  # Public cache header
}

# Matches documentation files for download - SECURE
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Matches: /manual.PDF, /report.doc, /data.ZIP, /readme.TXT
    # ✗ Doesn't match: /document.pdf.exe, /file.zip/malicious, /report.doc.backup
    add_header Content-Disposition "attachment";  # Force download
    root /var/www/downloads;                      # Downloads directory
}
```

#### **Case-Insensitive Regex (~*) - WITHOUT End Anchor (DANGEROUS!)**
```nginx
# DANGEROUS PATTERN - Without $ end anchor
location ~* \.(pdf|doc|docx|txt|zip) {
    # ⚠️  NO $ at end - SECURITY RISK!
    # ✓ Matches: /document.pdf (intended)
    # ⚠️  ALSO Matches: /document.pdf.php (DANGEROUS!)
    # ⚠️  ALSO Matches: /file.zip/../../etc/passwd (PATH TRAVERSAL!)
    # ⚠️  ALSO Matches: /malicious.txt.exe (DOUBLE EXTENSION ATTACK!)
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# CORRECT VERSION - Always use $ for file extensions
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Secure: Only matches files ending with these extensions
    # ✗ Blocks: /document.pdf.php, /file.zip.backup, /malicious.txt.exe
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}
```

#### **Advanced Regex Examples with Path Behavior**
```nginx
# User profile URLs with capture groups - SECURE
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # ^ = start, ([a-zA-Z0-9_-]+) = capture username, /? = optional slash, $ = end
    # ✓ Matches: /user/john_doe, /user/ADMIN/, /user/test123/
    # ✗ Doesn't match: /user/, /user/john../malicious, /old/user/john
    # ✗ Doesn't match: /user/john/posts ($ prevents extra path segments)
    proxy_pass http://user_backend/profile/$1;    # $1 refers to captured username
}

# API versioning with alternatives - SECURE
location ~* ^/api/(v[0-9]+|beta|alpha)/?$ {
    # (v[0-9]+|beta|alpha) = version pattern with alternatives, $ = end
    # ✓ Matches: /api/v1, /api/v2/, /API/BETA/, /api/alpha
    # ✗ Doesn't match: /api/v1/users ($ prevents sub-paths)
    # ✗ Doesn't match: /old/api/v1/, /api/v1beta (strict pattern)
    limit_req zone=api burst=50;        # Apply rate limiting
    proxy_pass http://api_backend;       # Route to API backend
}

# File upload paths - DANGEROUS without proper anchoring
location ~* /uploads/.*\.(jpg|png|gif) {
    # ⚠️  No ^ or $ anchors - can match anywhere in path!
    # ✓ Matches: /uploads/photo.jpg (intended)
    # ⚠️  ALSO Matches: /malicious/uploads/photo.jpg/../../../etc/passwd
    # ⚠️  ALSO Matches: /uploads/safe.jpg.php (missing $ anchor)
    expires 1M;
}

# SECURE VERSION with proper anchoring
location ~* ^/uploads/[^/]+\.(jpg|png|gif)$ {
    # ^ = start, [^/]+ = filename without slashes, $ = end
    # ✓ Matches: /uploads/photo.jpg, /uploads/image.PNG
    # ✗ Doesn't match: /uploads/../../etc/passwd, /uploads/photo.jpg.php
    # ✗ Doesn't match: /uploads/subdir/photo.jpg (prevents subdirectory access)
    expires 1M;
    root /var/www/uploads;
}
```

#### **Security-Focused Examples for Interview Discussion**
```nginx
# SECURE: Block executable files with proper anchoring
location ~* \.(php|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
    # $ anchor CRITICAL - prevents /script.php.txt bypasses
    # ✓ Blocks: /malicious.php, /script.PHP, /backdoor.phtml
    # ✓ Blocks: /upload.php (even if uploaded to wrong directory)
    # ✗ Doesn't block: /legitimate.php.backup (ends with .backup, not .php)
    deny all;                            # Block all executable files
    access_log /var/log/nginx/blocked.log;  # Log blocking attempts
}

# SECURE: Media files with size validation
location ~* ^/media/[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif|webp)$ {
    # ^/media/ = must start with /media/, [a-zA-Z0-9_-]+ = safe filename chars only
    # $ = must end with allowed extension (prevents .php appends)
    # ✓ Matches: /media/photo_123.jpg, /media/image-2024.PNG
    # ✗ Doesn't match: /media/../../../etc/passwd, /media/photo.jpg.php
    # ✗ Doesn't match: /media/subdir/photo.jpg (prevents directory traversal)
    expires 6M;                          # Cache media for 6 months
    add_header Cache-Control "public, immutable";
    
    # Optional: Add security headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type confusion
}

# DANGEROUS vs SECURE comparison
location ~* \.txt {
    # ⚠️  DANGEROUS: /malicious.txt.php would match!
    return 200 "Text file";
}

location ~* \.txt$ {
    # ✅ SECURE: Only files actually ending in .txt
    return 200 "Text file";
}
```

**When to Use:**
- **File extension matching** - ALWAYS use `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor for security
- **Dynamic URL patterns** - Use `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 for precise matching
- **Flexible matching** - Case-insensitive with proper boundaries
- **Security-critical paths** - Multiple validation layers with anchors

#### **Interview Key Points:**

**Q: "What's the difference between `~* \.pdf` and `~* \.pdf# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

?"**
**A:** "The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor is crucial for security. Without it, `~* \.pdf` would match `/document.pdf.php` which could be a security vulnerability. The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 ensures the URI actually ends with `.pdf`, preventing double extension attacks and path traversal attempts."

**Q: "Why do you anchor your regex patterns?"**
**A:** "Anchoring with `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 is a security best practice. It prevents unintended matches that could allow attackers to bypass restrictions. For example, without `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

, a pattern for images might match `/photo.jpg.php`, potentially serving executable files instead of images."

**Q: "How do you secure file upload locations?"**
**A:** "I use strict regex patterns with anchors like `^/uploads/[^/]+\.(jpg|png)# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 to ensure files are in the correct directory, have safe filenames without path separators, and end with allowed extensions. This prevents directory traversal and executable file uploads."

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;  # Rate limiting with immediate processing
    proxy_pass http://api_backend;        # Forward to API backend
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;  # Try file, then directory, then fallback
    # try_files: $uri (exact file), $uri/ (as directory), fallback
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";                    # Basic authentication prompt
    auth_basic_user_file /etc/nginx/.htpasswd;     # User credentials file
    try_files $uri $uri/ /app/admin/index.html;    # Admin-specific fallback
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;           # Allow large file uploads (100MB)
    proxy_pass http://file_storage_backend;  # Route to file storage service
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;    # SPA fallback pattern
    # First try exact file, then as directory, finally serve index.html
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    # (?<tenant_name>[a-z0-9]+): Named capture group for tenant
    # (?<path>.*): Named capture group for remaining path
    proxy_pass http://$tenant_name_backend/$path$is_args$args;  # Dynamic backend routing
    proxy_set_header X-Tenant $tenant_name;                    # Pass tenant info to backend
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";    # Create dynamic zone name
    limit_req zone=$tenant_zone burst=20;   # Apply tenant-specific rate limiting
    proxy_pass http://tenant_backend;       # Route to tenant backend
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;                                      # Extract language code
    set $path $2;                                      # Extract remaining path
    proxy_pass http://i18n_backend/$path$is_args$args; # Route to internationalization backend
    proxy_set_header X-Language $lang;                 # Pass language to backend
}

# Specific language handling
location /en/ {
    alias /var/www/english/;              # Serve English content from specific directory
    try_files $uri $uri/ /en/index.html;  # English-specific fallback
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;     # Route v1 API to legacy backend
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;     # Route v2 API to current backend
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend; # Default to latest API version
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";                                    # Initialize variable
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {  # Check user agent
        set $mobile_backend "_mobile";                         # Set mobile suffix
    }
    proxy_pass http://web${mobile_backend}_backend;            # Route to appropriate backend
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { 
        expires 1y;         # Cache favicon for 1 year
        access_log off;     # Don't log favicon requests
    }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { 
        expires 1y;                           # Long-term caching for static assets
        root /var/www/assets;                 # Static files directory
    }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M;                           # Cache product images for 6 months
        root /var/www/media;                  # Media files directory
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10;         # Cart-specific rate limiting
        proxy_pass http://cart_service;       # Route to cart microservice
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5;       # Strict rate limiting for payments
        proxy_pass https://secure_payment;    # Route to secure payment processor
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1;  # Route with captured username
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html;     # Single Page Application fallback
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { 
        return 301 /admin/;                   # Redirect to trailing slash
    }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";                    # Basic authentication
        auth_basic_user_file /etc/nginx/.htpasswd;   # Admin credentials file
        proxy_pass http://admin_backend;              # Route to admin backend
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;            # Allow 50MB uploads
        root /var/www/media;                  # Media storage directory
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;                           # Cache plugin assets for 1 month
        root /var/www/plugins;                # Plugin directory
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;       # Route to blog service
        proxy_set_header X-Year $1;          # Pass year to backend
        proxy_set_header X-Month $2;         # Pass month to backend
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { 
        return 200 "OK";                      # Simple health check response
    }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;      # User service rate limiting
        proxy_pass http://user_service/;     # Route to user microservice
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;      # Order service rate limiting
        proxy_pass http://order_service/;    # Route to order microservice
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;  # Inventory service rate limiting
        proxy_pass http://inventory_service/; # Route to inventory microservice
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;  # Route to WebSocket service
        proxy_http_version 1.1;              # Required for WebSockets
        proxy_set_header Upgrade $http_upgrade;     # WebSocket upgrade header
        proxy_set_header Connection "upgrade";      # WebSocket connection header
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;                            # Only accessible via internal redirect
        alias /var/secure/files/;            # Secure file storage
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;   # Dynamic routing to versioned service
    }
}
```

### **8. Location Matching Comparison: /health Examples**

Let's compare different ways to match `/health` and understand their behavior:

#### **Comparison Table:**

| Pattern | Type | Priority | Matches | Use Case |
|---------|------|----------|---------|-----------|
| `location /health` | Prefix Match | 4 (Lowest) | `/health`, `/health123`, `/health/status` | General routing |
| `location = /health` | Exact Match | 1 (Highest) | `/health` ONLY | High-performance endpoints |
| `location ^~ /health` | Prefix + Modifier | 2 | `/health`, `/health123`, `/health/status` | Performance optimization |
| `location ~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-sensitive) | 3 | `/health` ONLY | Complex pattern matching |
| `location ~* ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-insensitive) | 3 | `/health`, `/HEALTH`, `/Health` | Flexible matching |

#### **Detailed Examples with Behavior:**

```nginx
# 1. Prefix Match - /health
location /health {
    return 200 "Prefix match: $uri";
}
# Matches:
# ✓ /health → "Prefix match: /health"
# ✓ /health123 → "Prefix match: /health123"  
# ✓ /health/status → "Prefix match: /health/status"
# ✓ /health/ → "Prefix match: /health/"
# ✗ /api/health → No match (doesn't start with /health)
```

```nginx
# 2. Exact Match - = /health
location = /health {
    return 200 "Exact match: $uri";
}
# Matches:
# ✓ /health → "Exact match: /health"
# ✗ /health123 → No match
# ✗ /health/status → No match  
# ✗ /health/ → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 3. Prefix Match with Modifier - ^~ /health
location ^~ /health {
    return 200 "Prefix with modifier: $uri";
}
# Matches:
# ✓ /health → "Prefix with modifier: /health"
# ✓ /health123 → "Prefix with modifier: /health123"
# ✓ /health/status → "Prefix with modifier: /health/status"
# ✓ /health/ → "Prefix with modifier: /health/"
# ✗ /api/health → No match
# 
# IMPORTANT: Stops processing regex locations!
```

```nginx
# 4. Regex Match (case-sensitive) - ~ ^/health$
location ~ ^/health$ {
    return 200 "Regex match: $uri";
}
# Matches:
# ✓ /health → "Regex match: /health"
# ✗ /health123 → No match ($ means end of string)
# ✗ /health/status → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 5. Regex Match (case-insensitive) - ~* ^/health$
location ~* ^/health$ {
    return 200 "Case-insensitive regex: $uri";
}
# Matches:
# ✓ /health → "Case-insensitive regex: /health"
# ✓ /HEALTH → "Case-insensitive regex: /HEALTH"
# ✓ /Health → "Case-insensitive regex: /Health"
# ✗ /health123 → No match ($ means end of string)
```

#### **Processing Priority Example:**

```nginx
server {
    # Multiple location blocks for /health
    
    # Priority 1: Exact match (processed first)
    location = /health {
        return 200 "Exact match";
    }
    
    # Priority 2: Prefix with modifier (processed second)
    location ^~ /health {
        return 200 "Prefix with modifier";
    }
    
    # Priority 3: Regex (processed third)
    location ~ ^/health {
        return 200 "Regex match";
    }
    
    # Priority 4: Prefix (processed last)
    location /health {
        return 200 "Prefix match";
    }
}

# Request Results:
# GET /health → "Exact match" (stops processing here)
# GET /health/status → "Prefix with modifier" (exact doesn't match, this does and stops regex)
```

#### **Real-World Scenarios:**

##### **Scenario 1: High-Performance Health Check**
```nginx
# Use exact match for maximum performance
location = /health {
    access_log off;
    return 200 "OK";
}
# Why: Health checks happen frequently, exact match is fastest
```

##### **Scenario 2: Health Check with Sub-paths**
```nginx
# Use prefix with modifier to include health sub-endpoints
location ^~ /health {
    # Matches /health, /health/detailed, /health/db, etc.
    proxy_pass http://health_service;
}
# Why: Covers all health-related endpoints, skips regex processing
```

##### **Scenario 3: Strict Health Check Only**
```nginx
# Use regex to match only /health (not sub-paths)
location ~* ^/health/?$ {
    # Matches /health and /health/ only
    return 200 "Health OK";
}
# Why: Prevents matching /health/anything-else
```

##### **Scenario 4: Multiple Health Endpoints**
```nginx
# Combine different approaches
location = /health {
    # Quick health check
    return 200 "OK";
}

location = /health/detailed {
    # Detailed health check
    proxy_pass http://detailed_health_service;
}

location ^~ /health/ {
    # All other health sub-paths
    proxy_pass http://health_service;
}
```

#### **Performance Comparison:**

| Match Type | Performance | Processing | Best For |
|------------|-------------|------------|----------|
| `= /health` | **Fastest** | No regex, immediate match | High-frequency endpoints |
| `^~ /health` | **Fast** | Skips regex processing | Static asset paths |
| `~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | **Slower** | Regex compilation needed | Complex patterns only |
| `/health` | **Medium** | Longest prefix comparison | General routing |

#### **Common Mistakes:**

```nginx
# WRONG: This is not valid nginx syntax
location ^/health {  # Missing ~ for regex or = for exact
    return 200 "Invalid";
}

# WRONG: Overlapping without consideration
location /health {
    return 200 "This will never execute";
}
location = /health {
    return 200 "This executes first";
}

# CORRECT: Order matters for prefix matches
location /health/detailed {  # More specific first
    return 200 "Detailed health";
}
location /health {           # General match second
    return 200 "General health";
}
```

#### **Interview Question Examples:**

**Q: "What's the difference between `location /health` and `location = /health`?"**

**A:** "`location /health` is a prefix match that matches `/health` and anything starting with `/health` like `/health123` or `/health/status`. `location = /health` is an exact match that only matches `/health` exactly - it's faster and has the highest priority in nginx processing."

**Q: "When would you use `^~ /health` instead of `/health`?"**

**A:** "I'd use `^~ /health` when I want prefix matching but need to skip regex processing for performance. It's useful for high-traffic paths like static assets or API endpoints where I know regex locations aren't needed."

**Q: "How does nginx decide which location block to use?"**

**A:** "Nginx follows a specific priority: 1) Exact matches (`=`) first, 2) Prefix with modifier (`^~`) second, 3) Regex matches (`~` or `~*`) third, and 4) Regular prefix matches last, where the longest match wins."

This comparison shows exactly how different location patterns behave and when to use each one!

---

?"**

**Expert Answer:**
"The missing `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive) - ONLY at end of URI
location ~ \.(CSS|JS|PNG)$ {
    # $ means "end of string" - IMPORTANT for security!
    # ✓ Matches: /assets/style.CSS, /scripts/app.JS, /images/logo.PNG
    # ✗ Doesn't match: /assets/style.css (lowercase), /images/file.CSS.backup
    # ✗ Doesn't match: /malicious.CSS/../../etc/passwd ($ prevents path traversal)
    expires 1h;                          # Cache for 1 hour
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # ^ means "start of string", [0-9]+ means "one or more digits"
    # ✓ Matches: /api/v1/, /api/v2/users, /api/v123/orders
    # ✗ Doesn't match: /old/api/v1/, /api/version1/, /api/v/
    proxy_pass http://versioned_api_backend;    # Route to versioned API backend
}

# Matches specific date-based file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # [0-9]{4} means "exactly 4 digits", [0-9]{2} means "exactly 2 digits"
    # ✓ Matches: /reports/2024/03/, /reports/2023/12/sales
    # ✗ Doesn't match: /reports/24/3/, /reports/2024/3/, /old/reports/2024/03/
    auth_required on;                    # Require authentication
    proxy_pass http://reports_backend;   # Route to reports service
}
```

#### **Case-Insensitive Regex (~*) - WITH End Anchor ($)**
```nginx
# Matches common image formats (any case) - SECURE with end anchor
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    # ~* = case-insensitive, $ = end of URI (SECURITY CRITICAL)
    # ✓ Matches: /image.JPG, /photo.jpeg, /logo.PNG, /icon.GIF
    # ✓ Matches: /path/to/file.jpg, /assets/images/photo.WEBP
    # ✗ Doesn't match: /image.jpg.backup, /photo.png/../../etc/passwd
    # ✗ Doesn't match: /malicious.jpg.php (prevents double extension attacks)
    expires 1y;                                 # Cache images for 1 year
    add_header Cache-Control "public, immutable";  # Immutable cache header
    access_log off;                             # Don't log image requests
}

# Matches CSS and JavaScript files - SECURE
location ~* \.(css|js)$ {
    # ✓ Matches: /style.css, /app.JS, /main.CSS, /script.js
    # ✗ Doesn't match: /style.css.backup, /app.js.old, /script.js/malicious
    expires 1month;                     # Cache for 1 month
    gzip_static on;                     # Serve pre-compressed files if available
    add_header Cache-Control "public";  # Public cache header
}

# Matches documentation files for download - SECURE
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Matches: /manual.PDF, /report.doc, /data.ZIP, /readme.TXT
    # ✗ Doesn't match: /document.pdf.exe, /file.zip/malicious, /report.doc.backup
    add_header Content-Disposition "attachment";  # Force download
    root /var/www/downloads;                      # Downloads directory
}
```

#### **Case-Insensitive Regex (~*) - WITHOUT End Anchor (DANGEROUS!)**
```nginx
# DANGEROUS PATTERN - Without $ end anchor
location ~* \.(pdf|doc|docx|txt|zip) {
    # ⚠️  NO $ at end - SECURITY RISK!
    # ✓ Matches: /document.pdf (intended)
    # ⚠️  ALSO Matches: /document.pdf.php (DANGEROUS!)
    # ⚠️  ALSO Matches: /file.zip/../../etc/passwd (PATH TRAVERSAL!)
    # ⚠️  ALSO Matches: /malicious.txt.exe (DOUBLE EXTENSION ATTACK!)
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# CORRECT VERSION - Always use $ for file extensions
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Secure: Only matches files ending with these extensions
    # ✗ Blocks: /document.pdf.php, /file.zip.backup, /malicious.txt.exe
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}
```

#### **Advanced Regex Examples with Path Behavior**
```nginx
# User profile URLs with capture groups - SECURE
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # ^ = start, ([a-zA-Z0-9_-]+) = capture username, /? = optional slash, $ = end
    # ✓ Matches: /user/john_doe, /user/ADMIN/, /user/test123/
    # ✗ Doesn't match: /user/, /user/john../malicious, /old/user/john
    # ✗ Doesn't match: /user/john/posts ($ prevents extra path segments)
    proxy_pass http://user_backend/profile/$1;    # $1 refers to captured username
}

# API versioning with alternatives - SECURE
location ~* ^/api/(v[0-9]+|beta|alpha)/?$ {
    # (v[0-9]+|beta|alpha) = version pattern with alternatives, $ = end
    # ✓ Matches: /api/v1, /api/v2/, /API/BETA/, /api/alpha
    # ✗ Doesn't match: /api/v1/users ($ prevents sub-paths)
    # ✗ Doesn't match: /old/api/v1/, /api/v1beta (strict pattern)
    limit_req zone=api burst=50;        # Apply rate limiting
    proxy_pass http://api_backend;       # Route to API backend
}

# File upload paths - DANGEROUS without proper anchoring
location ~* /uploads/.*\.(jpg|png|gif) {
    # ⚠️  No ^ or $ anchors - can match anywhere in path!
    # ✓ Matches: /uploads/photo.jpg (intended)
    # ⚠️  ALSO Matches: /malicious/uploads/photo.jpg/../../../etc/passwd
    # ⚠️  ALSO Matches: /uploads/safe.jpg.php (missing $ anchor)
    expires 1M;
}

# SECURE VERSION with proper anchoring
location ~* ^/uploads/[^/]+\.(jpg|png|gif)$ {
    # ^ = start, [^/]+ = filename without slashes, $ = end
    # ✓ Matches: /uploads/photo.jpg, /uploads/image.PNG
    # ✗ Doesn't match: /uploads/../../etc/passwd, /uploads/photo.jpg.php
    # ✗ Doesn't match: /uploads/subdir/photo.jpg (prevents subdirectory access)
    expires 1M;
    root /var/www/uploads;
}
```

#### **Security-Focused Examples for Interview Discussion**
```nginx
# SECURE: Block executable files with proper anchoring
location ~* \.(php|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
    # $ anchor CRITICAL - prevents /script.php.txt bypasses
    # ✓ Blocks: /malicious.php, /script.PHP, /backdoor.phtml
    # ✓ Blocks: /upload.php (even if uploaded to wrong directory)
    # ✗ Doesn't block: /legitimate.php.backup (ends with .backup, not .php)
    deny all;                            # Block all executable files
    access_log /var/log/nginx/blocked.log;  # Log blocking attempts
}

# SECURE: Media files with size validation
location ~* ^/media/[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif|webp)$ {
    # ^/media/ = must start with /media/, [a-zA-Z0-9_-]+ = safe filename chars only
    # $ = must end with allowed extension (prevents .php appends)
    # ✓ Matches: /media/photo_123.jpg, /media/image-2024.PNG
    # ✗ Doesn't match: /media/../../../etc/passwd, /media/photo.jpg.php
    # ✗ Doesn't match: /media/subdir/photo.jpg (prevents directory traversal)
    expires 6M;                          # Cache media for 6 months
    add_header Cache-Control "public, immutable";
    
    # Optional: Add security headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type confusion
}

# DANGEROUS vs SECURE comparison
location ~* \.txt {
    # ⚠️  DANGEROUS: /malicious.txt.php would match!
    return 200 "Text file";
}

location ~* \.txt$ {
    # ✅ SECURE: Only files actually ending in .txt
    return 200 "Text file";
}
```

**When to Use:**
- **File extension matching** - ALWAYS use `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor for security
- **Dynamic URL patterns** - Use `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 for precise matching
- **Flexible matching** - Case-insensitive with proper boundaries
- **Security-critical paths** - Multiple validation layers with anchors

#### **Interview Key Points:**

**Q: "What's the difference between `~* \.pdf` and `~* \.pdf# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

?"**
**A:** "The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor is crucial for security. Without it, `~* \.pdf` would match `/document.pdf.php` which could be a security vulnerability. The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 ensures the URI actually ends with `.pdf`, preventing double extension attacks and path traversal attempts."

**Q: "Why do you anchor your regex patterns?"**
**A:** "Anchoring with `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 is a security best practice. It prevents unintended matches that could allow attackers to bypass restrictions. For example, without `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

, a pattern for images might match `/photo.jpg.php`, potentially serving executable files instead of images."

**Q: "How do you secure file upload locations?"**
**A:** "I use strict regex patterns with anchors like `^/uploads/[^/]+\.(jpg|png)# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 to ensure files are in the correct directory, have safe filenames without path separators, and end with allowed extensions. This prevents directory traversal and executable file uploads."

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;  # Rate limiting with immediate processing
    proxy_pass http://api_backend;        # Forward to API backend
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;  # Try file, then directory, then fallback
    # try_files: $uri (exact file), $uri/ (as directory), fallback
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";                    # Basic authentication prompt
    auth_basic_user_file /etc/nginx/.htpasswd;     # User credentials file
    try_files $uri $uri/ /app/admin/index.html;    # Admin-specific fallback
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;           # Allow large file uploads (100MB)
    proxy_pass http://file_storage_backend;  # Route to file storage service
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;    # SPA fallback pattern
    # First try exact file, then as directory, finally serve index.html
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    # (?<tenant_name>[a-z0-9]+): Named capture group for tenant
    # (?<path>.*): Named capture group for remaining path
    proxy_pass http://$tenant_name_backend/$path$is_args$args;  # Dynamic backend routing
    proxy_set_header X-Tenant $tenant_name;                    # Pass tenant info to backend
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";    # Create dynamic zone name
    limit_req zone=$tenant_zone burst=20;   # Apply tenant-specific rate limiting
    proxy_pass http://tenant_backend;       # Route to tenant backend
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;                                      # Extract language code
    set $path $2;                                      # Extract remaining path
    proxy_pass http://i18n_backend/$path$is_args$args; # Route to internationalization backend
    proxy_set_header X-Language $lang;                 # Pass language to backend
}

# Specific language handling
location /en/ {
    alias /var/www/english/;              # Serve English content from specific directory
    try_files $uri $uri/ /en/index.html;  # English-specific fallback
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;     # Route v1 API to legacy backend
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;     # Route v2 API to current backend
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend; # Default to latest API version
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";                                    # Initialize variable
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {  # Check user agent
        set $mobile_backend "_mobile";                         # Set mobile suffix
    }
    proxy_pass http://web${mobile_backend}_backend;            # Route to appropriate backend
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { 
        expires 1y;         # Cache favicon for 1 year
        access_log off;     # Don't log favicon requests
    }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { 
        expires 1y;                           # Long-term caching for static assets
        root /var/www/assets;                 # Static files directory
    }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M;                           # Cache product images for 6 months
        root /var/www/media;                  # Media files directory
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10;         # Cart-specific rate limiting
        proxy_pass http://cart_service;       # Route to cart microservice
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5;       # Strict rate limiting for payments
        proxy_pass https://secure_payment;    # Route to secure payment processor
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1;  # Route with captured username
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html;     # Single Page Application fallback
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { 
        return 301 /admin/;                   # Redirect to trailing slash
    }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";                    # Basic authentication
        auth_basic_user_file /etc/nginx/.htpasswd;   # Admin credentials file
        proxy_pass http://admin_backend;              # Route to admin backend
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;            # Allow 50MB uploads
        root /var/www/media;                  # Media storage directory
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;                           # Cache plugin assets for 1 month
        root /var/www/plugins;                # Plugin directory
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;       # Route to blog service
        proxy_set_header X-Year $1;          # Pass year to backend
        proxy_set_header X-Month $2;         # Pass month to backend
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { 
        return 200 "OK";                      # Simple health check response
    }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;      # User service rate limiting
        proxy_pass http://user_service/;     # Route to user microservice
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;      # Order service rate limiting
        proxy_pass http://order_service/;    # Route to order microservice
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;  # Inventory service rate limiting
        proxy_pass http://inventory_service/; # Route to inventory microservice
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;  # Route to WebSocket service
        proxy_http_version 1.1;              # Required for WebSockets
        proxy_set_header Upgrade $http_upgrade;     # WebSocket upgrade header
        proxy_set_header Connection "upgrade";      # WebSocket connection header
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;                            # Only accessible via internal redirect
        alias /var/secure/files/;            # Secure file storage
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;   # Dynamic routing to versioned service
    }
}
```

### **8. Location Matching Comparison: /health Examples**

Let's compare different ways to match `/health` and understand their behavior:

#### **Comparison Table:**

| Pattern | Type | Priority | Matches | Use Case |
|---------|------|----------|---------|-----------|
| `location /health` | Prefix Match | 4 (Lowest) | `/health`, `/health123`, `/health/status` | General routing |
| `location = /health` | Exact Match | 1 (Highest) | `/health` ONLY | High-performance endpoints |
| `location ^~ /health` | Prefix + Modifier | 2 | `/health`, `/health123`, `/health/status` | Performance optimization |
| `location ~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-sensitive) | 3 | `/health` ONLY | Complex pattern matching |
| `location ~* ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-insensitive) | 3 | `/health`, `/HEALTH`, `/Health` | Flexible matching |

#### **Detailed Examples with Behavior:**

```nginx
# 1. Prefix Match - /health
location /health {
    return 200 "Prefix match: $uri";
}
# Matches:
# ✓ /health → "Prefix match: /health"
# ✓ /health123 → "Prefix match: /health123"  
# ✓ /health/status → "Prefix match: /health/status"
# ✓ /health/ → "Prefix match: /health/"
# ✗ /api/health → No match (doesn't start with /health)
```

```nginx
# 2. Exact Match - = /health
location = /health {
    return 200 "Exact match: $uri";
}
# Matches:
# ✓ /health → "Exact match: /health"
# ✗ /health123 → No match
# ✗ /health/status → No match  
# ✗ /health/ → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 3. Prefix Match with Modifier - ^~ /health
location ^~ /health {
    return 200 "Prefix with modifier: $uri";
}
# Matches:
# ✓ /health → "Prefix with modifier: /health"
# ✓ /health123 → "Prefix with modifier: /health123"
# ✓ /health/status → "Prefix with modifier: /health/status"
# ✓ /health/ → "Prefix with modifier: /health/"
# ✗ /api/health → No match
# 
# IMPORTANT: Stops processing regex locations!
```

```nginx
# 4. Regex Match (case-sensitive) - ~ ^/health$
location ~ ^/health$ {
    return 200 "Regex match: $uri";
}
# Matches:
# ✓ /health → "Regex match: /health"
# ✗ /health123 → No match ($ means end of string)
# ✗ /health/status → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 5. Regex Match (case-insensitive) - ~* ^/health$
location ~* ^/health$ {
    return 200 "Case-insensitive regex: $uri";
}
# Matches:
# ✓ /health → "Case-insensitive regex: /health"
# ✓ /HEALTH → "Case-insensitive regex: /HEALTH"
# ✓ /Health → "Case-insensitive regex: /Health"
# ✗ /health123 → No match ($ means end of string)
```

#### **Processing Priority Example:**

```nginx
server {
    # Multiple location blocks for /health
    
    # Priority 1: Exact match (processed first)
    location = /health {
        return 200 "Exact match";
    }
    
    # Priority 2: Prefix with modifier (processed second)
    location ^~ /health {
        return 200 "Prefix with modifier";
    }
    
    # Priority 3: Regex (processed third)
    location ~ ^/health {
        return 200 "Regex match";
    }
    
    # Priority 4: Prefix (processed last)
    location /health {
        return 200 "Prefix match";
    }
}

# Request Results:
# GET /health → "Exact match" (stops processing here)
# GET /health/status → "Prefix with modifier" (exact doesn't match, this does and stops regex)
```

#### **Real-World Scenarios:**

##### **Scenario 1: High-Performance Health Check**
```nginx
# Use exact match for maximum performance
location = /health {
    access_log off;
    return 200 "OK";
}
# Why: Health checks happen frequently, exact match is fastest
```

##### **Scenario 2: Health Check with Sub-paths**
```nginx
# Use prefix with modifier to include health sub-endpoints
location ^~ /health {
    # Matches /health, /health/detailed, /health/db, etc.
    proxy_pass http://health_service;
}
# Why: Covers all health-related endpoints, skips regex processing
```

##### **Scenario 3: Strict Health Check Only**
```nginx
# Use regex to match only /health (not sub-paths)
location ~* ^/health/?$ {
    # Matches /health and /health/ only
    return 200 "Health OK";
}
# Why: Prevents matching /health/anything-else
```

##### **Scenario 4: Multiple Health Endpoints**
```nginx
# Combine different approaches
location = /health {
    # Quick health check
    return 200 "OK";
}

location = /health/detailed {
    # Detailed health check
    proxy_pass http://detailed_health_service;
}

location ^~ /health/ {
    # All other health sub-paths
    proxy_pass http://health_service;
}
```

#### **Performance Comparison:**

| Match Type | Performance | Processing | Best For |
|------------|-------------|------------|----------|
| `= /health` | **Fastest** | No regex, immediate match | High-frequency endpoints |
| `^~ /health` | **Fast** | Skips regex processing | Static asset paths |
| `~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | **Slower** | Regex compilation needed | Complex patterns only |
| `/health` | **Medium** | Longest prefix comparison | General routing |

#### **Common Mistakes:**

```nginx
# WRONG: This is not valid nginx syntax
location ^/health {  # Missing ~ for regex or = for exact
    return 200 "Invalid";
}

# WRONG: Overlapping without consideration
location /health {
    return 200 "This will never execute";
}
location = /health {
    return 200 "This executes first";
}

# CORRECT: Order matters for prefix matches
location /health/detailed {  # More specific first
    return 200 "Detailed health";
}
location /health {           # General match second
    return 200 "General health";
}
```

#### **Interview Question Examples:**

**Q: "What's the difference between `location /health` and `location = /health`?"**

**A:** "`location /health` is a prefix match that matches `/health` and anything starting with `/health` like `/health123` or `/health/status`. `location = /health` is an exact match that only matches `/health` exactly - it's faster and has the highest priority in nginx processing."

**Q: "When would you use `^~ /health` instead of `/health`?"**

**A:** "I'd use `^~ /health` when I want prefix matching but need to skip regex processing for performance. It's useful for high-traffic paths like static assets or API endpoints where I know regex locations aren't needed."

**Q: "How does nginx decide which location block to use?"**

**A:** "Nginx follows a specific priority: 1) Exact matches (`=`) first, 2) Prefix with modifier (`^~`) second, 3) Regex matches (`~` or `~*`) third, and 4) Regular prefix matches last, where the longest match wins."

This comparison shows exactly how different location patterns behave and when to use each one!

---

 anchor is a critical security vulnerability. Without it, `~* \.php` would match `/backdoor.php.txt`, potentially serving executable PHP files that bypass upload restrictions. The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive) - ONLY at end of URI
location ~ \.(CSS|JS|PNG)$ {
    # $ means "end of string" - IMPORTANT for security!
    # ✓ Matches: /assets/style.CSS, /scripts/app.JS, /images/logo.PNG
    # ✗ Doesn't match: /assets/style.css (lowercase), /images/file.CSS.backup
    # ✗ Doesn't match: /malicious.CSS/../../etc/passwd ($ prevents path traversal)
    expires 1h;                          # Cache for 1 hour
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # ^ means "start of string", [0-9]+ means "one or more digits"
    # ✓ Matches: /api/v1/, /api/v2/users, /api/v123/orders
    # ✗ Doesn't match: /old/api/v1/, /api/version1/, /api/v/
    proxy_pass http://versioned_api_backend;    # Route to versioned API backend
}

# Matches specific date-based file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # [0-9]{4} means "exactly 4 digits", [0-9]{2} means "exactly 2 digits"
    # ✓ Matches: /reports/2024/03/, /reports/2023/12/sales
    # ✗ Doesn't match: /reports/24/3/, /reports/2024/3/, /old/reports/2024/03/
    auth_required on;                    # Require authentication
    proxy_pass http://reports_backend;   # Route to reports service
}
```

#### **Case-Insensitive Regex (~*) - WITH End Anchor ($)**
```nginx
# Matches common image formats (any case) - SECURE with end anchor
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    # ~* = case-insensitive, $ = end of URI (SECURITY CRITICAL)
    # ✓ Matches: /image.JPG, /photo.jpeg, /logo.PNG, /icon.GIF
    # ✓ Matches: /path/to/file.jpg, /assets/images/photo.WEBP
    # ✗ Doesn't match: /image.jpg.backup, /photo.png/../../etc/passwd
    # ✗ Doesn't match: /malicious.jpg.php (prevents double extension attacks)
    expires 1y;                                 # Cache images for 1 year
    add_header Cache-Control "public, immutable";  # Immutable cache header
    access_log off;                             # Don't log image requests
}

# Matches CSS and JavaScript files - SECURE
location ~* \.(css|js)$ {
    # ✓ Matches: /style.css, /app.JS, /main.CSS, /script.js
    # ✗ Doesn't match: /style.css.backup, /app.js.old, /script.js/malicious
    expires 1month;                     # Cache for 1 month
    gzip_static on;                     # Serve pre-compressed files if available
    add_header Cache-Control "public";  # Public cache header
}

# Matches documentation files for download - SECURE
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Matches: /manual.PDF, /report.doc, /data.ZIP, /readme.TXT
    # ✗ Doesn't match: /document.pdf.exe, /file.zip/malicious, /report.doc.backup
    add_header Content-Disposition "attachment";  # Force download
    root /var/www/downloads;                      # Downloads directory
}
```

#### **Case-Insensitive Regex (~*) - WITHOUT End Anchor (DANGEROUS!)**
```nginx
# DANGEROUS PATTERN - Without $ end anchor
location ~* \.(pdf|doc|docx|txt|zip) {
    # ⚠️  NO $ at end - SECURITY RISK!
    # ✓ Matches: /document.pdf (intended)
    # ⚠️  ALSO Matches: /document.pdf.php (DANGEROUS!)
    # ⚠️  ALSO Matches: /file.zip/../../etc/passwd (PATH TRAVERSAL!)
    # ⚠️  ALSO Matches: /malicious.txt.exe (DOUBLE EXTENSION ATTACK!)
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# CORRECT VERSION - Always use $ for file extensions
location ~* \.(pdf|doc|docx|txt|zip)$ {
    # ✓ Secure: Only matches files ending with these extensions
    # ✗ Blocks: /document.pdf.php, /file.zip.backup, /malicious.txt.exe
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}
```

#### **Advanced Regex Examples with Path Behavior**
```nginx
# User profile URLs with capture groups - SECURE
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # ^ = start, ([a-zA-Z0-9_-]+) = capture username, /? = optional slash, $ = end
    # ✓ Matches: /user/john_doe, /user/ADMIN/, /user/test123/
    # ✗ Doesn't match: /user/, /user/john../malicious, /old/user/john
    # ✗ Doesn't match: /user/john/posts ($ prevents extra path segments)
    proxy_pass http://user_backend/profile/$1;    # $1 refers to captured username
}

# API versioning with alternatives - SECURE
location ~* ^/api/(v[0-9]+|beta|alpha)/?$ {
    # (v[0-9]+|beta|alpha) = version pattern with alternatives, $ = end
    # ✓ Matches: /api/v1, /api/v2/, /API/BETA/, /api/alpha
    # ✗ Doesn't match: /api/v1/users ($ prevents sub-paths)
    # ✗ Doesn't match: /old/api/v1/, /api/v1beta (strict pattern)
    limit_req zone=api burst=50;        # Apply rate limiting
    proxy_pass http://api_backend;       # Route to API backend
}

# File upload paths - DANGEROUS without proper anchoring
location ~* /uploads/.*\.(jpg|png|gif) {
    # ⚠️  No ^ or $ anchors - can match anywhere in path!
    # ✓ Matches: /uploads/photo.jpg (intended)
    # ⚠️  ALSO Matches: /malicious/uploads/photo.jpg/../../../etc/passwd
    # ⚠️  ALSO Matches: /uploads/safe.jpg.php (missing $ anchor)
    expires 1M;
}

# SECURE VERSION with proper anchoring
location ~* ^/uploads/[^/]+\.(jpg|png|gif)$ {
    # ^ = start, [^/]+ = filename without slashes, $ = end
    # ✓ Matches: /uploads/photo.jpg, /uploads/image.PNG
    # ✗ Doesn't match: /uploads/../../etc/passwd, /uploads/photo.jpg.php
    # ✗ Doesn't match: /uploads/subdir/photo.jpg (prevents subdirectory access)
    expires 1M;
    root /var/www/uploads;
}
```

#### **Security-Focused Examples for Interview Discussion**
```nginx
# SECURE: Block executable files with proper anchoring
location ~* \.(php|php5|phtml|pl|py|jsp|asp|sh|cgi)$ {
    # $ anchor CRITICAL - prevents /script.php.txt bypasses
    # ✓ Blocks: /malicious.php, /script.PHP, /backdoor.phtml
    # ✓ Blocks: /upload.php (even if uploaded to wrong directory)
    # ✗ Doesn't block: /legitimate.php.backup (ends with .backup, not .php)
    deny all;                            # Block all executable files
    access_log /var/log/nginx/blocked.log;  # Log blocking attempts
}

# SECURE: Media files with size validation
location ~* ^/media/[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif|webp)$ {
    # ^/media/ = must start with /media/, [a-zA-Z0-9_-]+ = safe filename chars only
    # $ = must end with allowed extension (prevents .php appends)
    # ✓ Matches: /media/photo_123.jpg, /media/image-2024.PNG
    # ✗ Doesn't match: /media/../../../etc/passwd, /media/photo.jpg.php
    # ✗ Doesn't match: /media/subdir/photo.jpg (prevents directory traversal)
    expires 6M;                          # Cache media for 6 months
    add_header Cache-Control "public, immutable";
    
    # Optional: Add security headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type confusion
}

# DANGEROUS vs SECURE comparison
location ~* \.txt {
    # ⚠️  DANGEROUS: /malicious.txt.php would match!
    return 200 "Text file";
}

location ~* \.txt$ {
    # ✅ SECURE: Only files actually ending in .txt
    return 200 "Text file";
}
```

**When to Use:**
- **File extension matching** - ALWAYS use `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor for security
- **Dynamic URL patterns** - Use `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 for precise matching
- **Flexible matching** - Case-insensitive with proper boundaries
- **Security-critical paths** - Multiple validation layers with anchors

#### **Interview Key Points:**

**Q: "What's the difference between `~* \.pdf` and `~* \.pdf# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

?"**
**A:** "The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 anchor is crucial for security. Without it, `~* \.pdf` would match `/document.pdf.php` which could be a security vulnerability. The `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 ensures the URI actually ends with `.pdf`, preventing double extension attacks and path traversal attempts."

**Q: "Why do you anchor your regex patterns?"**
**A:** "Anchoring with `^` and `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 is a security best practice. It prevents unintended matches that could allow attackers to bypass restrictions. For example, without `# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

, a pattern for images might match `/photo.jpg.php`, potentially serving executable files instead of images."

**Q: "How do you secure file upload locations?"**
**A:** "I use strict regex patterns with anchors like `^/uploads/[^/]+\.(jpg|png)# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;                    # Run nginx worker processes as 'nginx' user (security)
worker_processes auto;         # Number of worker processes (auto = match CPU cores)
worker_rlimit_nofile 65535;   # Maximum file descriptors per worker process
error_log /var/log/nginx/error.log warn;  # Global error log file and level
pid /var/run/nginx.pid;       # File to store nginx master process ID
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Event method for Linux (high performance I/O)
    worker_connections 1024;      # Maximum concurrent connections per worker process
    multi_accept on;              # Worker can accept multiple connections simultaneously
    accept_mutex off;             # Disable serialization of accept() calls (modern default)
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;        # Include MIME type definitions
    default_type application/octet-stream; # Default MIME type for unknown files
    
    # Performance optimizations
    sendfile on;                          # Use kernel sendfile() for serving files
    tcp_nopush on;                        # Send HTTP response headers in one packet
    tcp_nodelay on;                       # Don't buffer data (send immediately)
    keepalive_timeout 65;                 # How long to keep connections alive (seconds)
    
    # Security headers
    server_tokens off;                    # Hide nginx version in error pages/headers
    add_header X-Content-Type-Options nosniff;  # Prevent MIME type sniffing
    add_header X-Frame-Options DENY;            # Prevent embedding in frames
    
    # Rate limiting zones (global definitions)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;    # API rate limit zone
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;   # Login rate limit zone
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;             # Connection limit zone
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;                       # Use least connections algorithm
        server backend1:8080 weight=3;    # Backend server with weight 3
        server backend2:8080 weight=3;    # Backend server with weight 3
        keepalive 32;                     # Keep 32 idle connections to backends
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';  # Custom log format
    
    # Gzip compression
    gzip on;                              # Enable gzip compression
    gzip_vary on;                         # Add Vary: Accept-Encoding header
    gzip_min_length 1024;                 # Only compress files larger than 1KB
    gzip_types text/plain text/css application/json;  # File types to compress
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;   # Include all site configurations
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Use kernel's sendfile() syscall - efficient file serving
tcp_nopush on;         # Send HTTP response headers in one TCP packet with sendfile
tcp_nodelay on;        # Disable Nagle's algorithm - don't buffer small TCP packets
keepalive_timeout 65;  # Keep client connections alive for 65 seconds for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;  # Define rate limit zone
# $binary_remote_addr: Client IP in binary format (saves memory)
# zone=api:10m: Zone name "api" with 10MB memory allocation
# rate=10r/s: Allow 10 requests per second
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method - route to server with fewest connections
    server backend1:8080 weight=3; # Backend server with weight 3 (gets 3x more requests)
    keepalive 32;                  # Maintain 32 persistent connections to backends
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;                    # Listen on port 80 for HTTP traffic
    listen 443 ssl http2;         # Listen on port 443 for HTTPS with HTTP/2 enabled
    server_name myapp.example.com www.myapp.example.com;  # Domain names this server handles
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;      # Path to SSL certificate file
    ssl_certificate_key /path/to/private.key;  # Path to SSL private key file
    ssl_protocols TLSv1.2 TLSv1.3;         # Allowed SSL/TLS protocol versions
    
    # Document root and index
    root /var/www/myapp;          # Document root directory for static files
    index index.html index.php;   # Default files to serve when directory is requested
    
    # Client settings
    client_max_body_size 50M;     # Maximum size of client request body (file uploads)
    client_body_timeout 60s;      # Timeout for reading client request body
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;  # Access log file with 'main' format
    error_log /var/log/nginx/myapp_error.log;         # Error log file for this server
    
    # Include location blocks
    location / { ... }            # Location blocks define how to handle specific URL patterns
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;               # Disable access logging for this endpoint
    return 200 "OK";             # Return HTTP 200 status with "OK" body
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;                  # Set cache expiration to 1 year
    access_log off;              # Don't log favicon requests (reduces log noise)
    alias /var/www/static/favicon.ico;  # Serve specific file (alias vs root)
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;  # Apply rate limiting with burst allowance
    proxy_pass http://status_backend;         # Forward request to upstream backend
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;  # Try to serve request URI, fallback to index.html
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;                           # Cache static assets for 1 year
    add_header Cache-Control "public, immutable";  # Add cache control header
    root /var/www/assets;                 # Document root for static files
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;                         # Cache images for 30 days
    root /var/www/media;                 # Media files root directory
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;                           # Only accessible via nginx internal redirect
    root /var/secure/files;             # Secure file storage location
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";                    # Enable basic authentication
    auth_basic_user_file /etc/nginx/.htpasswd; # Password file location
    try_files $uri $uri/ /admin/index.php;     # Try files, fallback to PHP
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

 to ensure files are in the correct directory, have safe filenames without path separators, and end with allowed extensions. This prevents directory traversal and executable file uploads."

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;  # Rate limiting with immediate processing
    proxy_pass http://api_backend;        # Forward to API backend
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;  # Try file, then directory, then fallback
    # try_files: $uri (exact file), $uri/ (as directory), fallback
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";                    # Basic authentication prompt
    auth_basic_user_file /etc/nginx/.htpasswd;     # User credentials file
    try_files $uri $uri/ /app/admin/index.html;    # Admin-specific fallback
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;           # Allow large file uploads (100MB)
    proxy_pass http://file_storage_backend;  # Route to file storage service
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;    # SPA fallback pattern
    # First try exact file, then as directory, finally serve index.html
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    # (?<tenant_name>[a-z0-9]+): Named capture group for tenant
    # (?<path>.*): Named capture group for remaining path
    proxy_pass http://$tenant_name_backend/$path$is_args$args;  # Dynamic backend routing
    proxy_set_header X-Tenant $tenant_name;                    # Pass tenant info to backend
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";    # Create dynamic zone name
    limit_req zone=$tenant_zone burst=20;   # Apply tenant-specific rate limiting
    proxy_pass http://tenant_backend;       # Route to tenant backend
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;                                      # Extract language code
    set $path $2;                                      # Extract remaining path
    proxy_pass http://i18n_backend/$path$is_args$args; # Route to internationalization backend
    proxy_set_header X-Language $lang;                 # Pass language to backend
}

# Specific language handling
location /en/ {
    alias /var/www/english/;              # Serve English content from specific directory
    try_files $uri $uri/ /en/index.html;  # English-specific fallback
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;     # Route v1 API to legacy backend
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;     # Route v2 API to current backend
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend; # Default to latest API version
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";                                    # Initialize variable
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {  # Check user agent
        set $mobile_backend "_mobile";                         # Set mobile suffix
    }
    proxy_pass http://web${mobile_backend}_backend;            # Route to appropriate backend
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { 
        expires 1y;         # Cache favicon for 1 year
        access_log off;     # Don't log favicon requests
    }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { 
        expires 1y;                           # Long-term caching for static assets
        root /var/www/assets;                 # Static files directory
    }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M;                           # Cache product images for 6 months
        root /var/www/media;                  # Media files directory
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10;         # Cart-specific rate limiting
        proxy_pass http://cart_service;       # Route to cart microservice
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5;       # Strict rate limiting for payments
        proxy_pass https://secure_payment;    # Route to secure payment processor
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1;  # Route with captured username
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html;     # Single Page Application fallback
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { 
        return 301 /admin/;                   # Redirect to trailing slash
    }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";                    # Basic authentication
        auth_basic_user_file /etc/nginx/.htpasswd;   # Admin credentials file
        proxy_pass http://admin_backend;              # Route to admin backend
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;            # Allow 50MB uploads
        root /var/www/media;                  # Media storage directory
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;                           # Cache plugin assets for 1 month
        root /var/www/plugins;                # Plugin directory
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;       # Route to blog service
        proxy_set_header X-Year $1;          # Pass year to backend
        proxy_set_header X-Month $2;         # Pass month to backend
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { 
        return 200 "OK";                      # Simple health check response
    }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;      # User service rate limiting
        proxy_pass http://user_service/;     # Route to user microservice
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;      # Order service rate limiting
        proxy_pass http://order_service/;    # Route to order microservice
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;  # Inventory service rate limiting
        proxy_pass http://inventory_service/; # Route to inventory microservice
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;  # Route to WebSocket service
        proxy_http_version 1.1;              # Required for WebSockets
        proxy_set_header Upgrade $http_upgrade;     # WebSocket upgrade header
        proxy_set_header Connection "upgrade";      # WebSocket connection header
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;                            # Only accessible via internal redirect
        alias /var/secure/files/;            # Secure file storage
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;   # Dynamic routing to versioned service
    }
}
```

### **8. Location Matching Comparison: /health Examples**

Let's compare different ways to match `/health` and understand their behavior:

#### **Comparison Table:**

| Pattern | Type | Priority | Matches | Use Case |
|---------|------|----------|---------|-----------|
| `location /health` | Prefix Match | 4 (Lowest) | `/health`, `/health123`, `/health/status` | General routing |
| `location = /health` | Exact Match | 1 (Highest) | `/health` ONLY | High-performance endpoints |
| `location ^~ /health` | Prefix + Modifier | 2 | `/health`, `/health123`, `/health/status` | Performance optimization |
| `location ~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-sensitive) | 3 | `/health` ONLY | Complex pattern matching |
| `location ~* ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | Regex (case-insensitive) | 3 | `/health`, `/HEALTH`, `/Health` | Flexible matching |

#### **Detailed Examples with Behavior:**

```nginx
# 1. Prefix Match - /health
location /health {
    return 200 "Prefix match: $uri";
}
# Matches:
# ✓ /health → "Prefix match: /health"
# ✓ /health123 → "Prefix match: /health123"  
# ✓ /health/status → "Prefix match: /health/status"
# ✓ /health/ → "Prefix match: /health/"
# ✗ /api/health → No match (doesn't start with /health)
```

```nginx
# 2. Exact Match - = /health
location = /health {
    return 200 "Exact match: $uri";
}
# Matches:
# ✓ /health → "Exact match: /health"
# ✗ /health123 → No match
# ✗ /health/status → No match  
# ✗ /health/ → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 3. Prefix Match with Modifier - ^~ /health
location ^~ /health {
    return 200 "Prefix with modifier: $uri";
}
# Matches:
# ✓ /health → "Prefix with modifier: /health"
# ✓ /health123 → "Prefix with modifier: /health123"
# ✓ /health/status → "Prefix with modifier: /health/status"
# ✓ /health/ → "Prefix with modifier: /health/"
# ✗ /api/health → No match
# 
# IMPORTANT: Stops processing regex locations!
```

```nginx
# 4. Regex Match (case-sensitive) - ~ ^/health$
location ~ ^/health$ {
    return 200 "Regex match: $uri";
}
# Matches:
# ✓ /health → "Regex match: /health"
# ✗ /health123 → No match ($ means end of string)
# ✗ /health/status → No match
# ✗ /HEALTH → No match (case-sensitive)
```

```nginx
# 5. Regex Match (case-insensitive) - ~* ^/health$
location ~* ^/health$ {
    return 200 "Case-insensitive regex: $uri";
}
# Matches:
# ✓ /health → "Case-insensitive regex: /health"
# ✓ /HEALTH → "Case-insensitive regex: /HEALTH"
# ✓ /Health → "Case-insensitive regex: /Health"
# ✗ /health123 → No match ($ means end of string)
```

#### **Processing Priority Example:**

```nginx
server {
    # Multiple location blocks for /health
    
    # Priority 1: Exact match (processed first)
    location = /health {
        return 200 "Exact match";
    }
    
    # Priority 2: Prefix with modifier (processed second)
    location ^~ /health {
        return 200 "Prefix with modifier";
    }
    
    # Priority 3: Regex (processed third)
    location ~ ^/health {
        return 200 "Regex match";
    }
    
    # Priority 4: Prefix (processed last)
    location /health {
        return 200 "Prefix match";
    }
}

# Request Results:
# GET /health → "Exact match" (stops processing here)
# GET /health/status → "Prefix with modifier" (exact doesn't match, this does and stops regex)
```

#### **Real-World Scenarios:**

##### **Scenario 1: High-Performance Health Check**
```nginx
# Use exact match for maximum performance
location = /health {
    access_log off;
    return 200 "OK";
}
# Why: Health checks happen frequently, exact match is fastest
```

##### **Scenario 2: Health Check with Sub-paths**
```nginx
# Use prefix with modifier to include health sub-endpoints
location ^~ /health {
    # Matches /health, /health/detailed, /health/db, etc.
    proxy_pass http://health_service;
}
# Why: Covers all health-related endpoints, skips regex processing
```

##### **Scenario 3: Strict Health Check Only**
```nginx
# Use regex to match only /health (not sub-paths)
location ~* ^/health/?$ {
    # Matches /health and /health/ only
    return 200 "Health OK";
}
# Why: Prevents matching /health/anything-else
```

##### **Scenario 4: Multiple Health Endpoints**
```nginx
# Combine different approaches
location = /health {
    # Quick health check
    return 200 "OK";
}

location = /health/detailed {
    # Detailed health check
    proxy_pass http://detailed_health_service;
}

location ^~ /health/ {
    # All other health sub-paths
    proxy_pass http://health_service;
}
```

#### **Performance Comparison:**

| Match Type | Performance | Processing | Best For |
|------------|-------------|------------|----------|
| `= /health` | **Fastest** | No regex, immediate match | High-frequency endpoints |
| `^~ /health` | **Fast** | Skips regex processing | Static asset paths |
| `~ ^/health# Nginx Configuration Blocks - Deep Dive Explanation

## 1. Main Block (Global Context)

```nginx
# Global directives - affect entire nginx process
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;
```

### **Purpose:** 
Controls the nginx master process and global settings that affect all worker processes.

### **When to Use:**
- **Production servers** - Set worker processes, file limits, logging
- **Security hardening** - Define user context for nginx processes
- **Resource management** - Control memory and file descriptor limits

### **Key Directives Explained:**

| Directive | Purpose | Example Scenario |
|-----------|---------|------------------|
| `user nginx;` | Security - runs nginx as non-root user | Production environments to limit privilege escalation |
| `worker_processes auto;` | Performance - matches CPU cores | High-traffic servers needing optimal CPU utilization |
| `worker_rlimit_nofile 65535;` | Scale - increases file descriptor limit | Heavy traffic with many concurrent connections |
| `error_log` | Debugging - global error logging | Troubleshooting server-wide issues |

---

## 2. Events Block

```nginx
events {
    use epoll;                    # Linux-specific event method
    worker_connections 1024;      # Max connections per worker
    multi_accept on;              # Accept multiple connections at once
    accept_mutex off;             # Disable connection serialization
}
```

### **Purpose:** 
Controls how nginx handles connections and events at the network level.

### **When to Use:**
- **High-concurrency applications** - Optimize connection handling
- **Performance tuning** - Choose appropriate event model for your OS
- **Resource optimization** - Control memory usage vs connection capacity

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `use epoll;` | Linux performance - efficient event polling | High-traffic Linux servers |
| `worker_connections 1024;` | Capacity - max concurrent connections | Calculate: workers × connections = total capacity |
| `multi_accept on;` | Performance - accept multiple connections per event | High request rate scenarios |
| `accept_mutex off;` | Load balancing - modern nginx doesn't need this | High-traffic servers with multiple workers |

---

## 3. HTTP Block

```nginx
http {
    # MIME types and basic HTTP settings
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security headers
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    
    # Rate limiting zones (global)
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    # Load balancing groups
    upstream backend_pool {
        least_conn;
        server backend1:8080 weight=3;
        server backend2:8080 weight=3;
        keepalive 32;
    }
    
    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json;
    
    # Include server blocks
    include /etc/nginx/sites-enabled/*;
}
```

### **Purpose:** 
Contains all HTTP-related configurations that apply across all virtual hosts.

### **When to Use:**
- **Multi-site hosting** - Shared settings across all websites
- **Global security policies** - Rate limiting, headers applying everywhere
- **Performance optimizations** - Compression, caching settings
- **Load balancing** - Define upstream servers used by multiple sites

### **Key Sections Explained:**

#### **Performance Directives:**
```nginx
sendfile on;           # Efficient file serving
tcp_nopush on;         # Send headers in one packet
tcp_nodelay on;        # Don't buffer small packets
keepalive_timeout 65;  # Keep connections alive for reuse
```
**Scenario:** High-traffic websites serving static files and API responses

#### **Rate Limiting Zones:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```
**Scenario:** Protect all applications from DDoS attacks and abuse

#### **Upstream Definitions:**
```nginx
upstream backend_pool {
    least_conn;                    # Load balancing method
    server backend1:8080 weight=3; # Backend server with weight
    keepalive 32;                  # Connection pooling
}
```
**Scenario:** Microservices architecture with multiple backend instances

---

## 4. Server Block

```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name myapp.example.com www.myapp.example.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Document root and index
    root /var/www/myapp;
    index index.html index.php;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 60s;
    
    # Logging for this virtual host
    access_log /var/log/nginx/myapp_access.log main;
    error_log /var/log/nginx/myapp_error.log;
    
    # Include location blocks
    location / { ... }
}
```

### **Purpose:** 
Defines a virtual host - how nginx handles requests for specific domain(s).

### **When to Use:**
- **Multiple websites** - Each domain gets its own server block
- **SSL/TLS termination** - Handle HTTPS certificates
- **Domain-specific settings** - Different apps need different configurations
- **Load balancer frontend** - Route requests to backend services

### **Key Directives Explained:**

| Directive | Purpose | Scenario |
|-----------|---------|----------|
| `listen 80;` | Network - which port to listen on | HTTP traffic |
| `listen 443 ssl http2;` | Security/Performance - HTTPS with HTTP/2 | Modern web applications |
| `server_name myapp.example.com;` | Routing - which domain this serves | Multi-tenant applications |
| `ssl_certificate` | Security - SSL/TLS certificate | HTTPS-enabled applications |
| `client_max_body_size 50M;` | Capacity - maximum upload size | File upload applications |
| `root /var/www/myapp;` | File serving - document root | Static file hosting |

---

## 5. Location Block - Comprehensive Path Matching Examples

### **Location Matching Types and Priority Order:**

Nginx processes location blocks in this **exact priority order**:

1. **Exact Match** `= /path`
2. **Prefix Match with Modifier** `^~ /path`  
3. **Regular Expression Match** `~ /pattern` (case-sensitive) or `~* /pattern` (case-insensitive)
4. **Prefix Match** `/path` (longest match wins)

### **1. Exact Match (= modifier)**

```nginx
# Matches EXACTLY /health - highest priority
location = /health {
    access_log off;
    return 200 "OK";
}

# Matches EXACTLY /favicon.ico
location = /favicon.ico {
    expires 1y;
    access_log off;
    alias /var/www/static/favicon.ico;
}

# Matches EXACTLY /api/status
location = /api/status {
    limit_req zone=status burst=100 nodelay;
    proxy_pass http://status_backend;
}

# Matches EXACTLY / (root)
location = / {
    try_files $uri /index.html;
}
```

**When to Use:**
- **Health check endpoints** - `/health`, `/ping`, `/status`
- **Specific static files** - `/favicon.ico`, `/robots.txt`
- **Root path handling** - `/`
- **High-performance routes** - Fastest matching, no regex processing

### **2. Prefix Match with Modifier (^~ modifier)**

```nginx
# Matches /static/ and everything under it - stops regex processing
location ^~ /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    root /var/www/assets;
    # /static/css/style.css → /var/www/assets/static/css/style.css
}

# Matches /images/ - high priority for static assets
location ^~ /images/ {
    expires 30d;
    root /var/www/media;
    # /images/photo.jpg → /var/www/media/images/photo.jpg
}

# Matches /downloads/ - bypass regex for performance
location ^~ /downloads/ {
    internal;  # Only accessible via nginx redirect
    root /var/secure/files;
}

# Matches /admin/ - priority over regex
location ^~ /admin/ {
    auth_basic "Admin Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /admin/index.php;
}
```

**When to Use:**
- **Static asset directories** - Better performance than regex
- **High-traffic paths** - Skip regex processing
- **Security-sensitive paths** - Ensure exact matching
- **Large file downloads** - Optimize for performance

### **3. Regular Expression Match (~ and ~* modifiers)**

#### **Case-Sensitive Regex (~)**
```nginx
# Matches file extensions (case-sensitive)
location ~ \.(CSS|JS|PNG)$ {
    # Only matches uppercase extensions
    expires 1h;
}

# Matches API versioning pattern
location ~ ^/api/v[0-9]+/ {
    # Matches /api/v1/, /api/v2/, /api/v123/
    proxy_pass http://versioned_api_backend;
}

# Matches specific file patterns
location ~ ^/reports/[0-9]{4}/[0-9]{2}/ {
    # Matches /reports/2024/03/, /reports/2023/12/
    auth_required on;
    proxy_pass http://reports_backend;
}
```

#### **Case-Insensitive Regex (~*)**
```nginx
# Matches common image formats (any case)
location ~* \.(jpg|jpeg|png|gif|webp|svg|ico)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Matches CSS and JavaScript files
location ~* \.(css|js)$ {
    expires 1month;
    gzip_static on;
    add_header Cache-Control "public";
}

# Matches documentation files
location ~* \.(pdf|doc|docx|txt|zip)$ {
    add_header Content-Disposition "attachment";
    root /var/www/downloads;
}

# Matches user profile URLs
location ~* ^/user/([a-zA-Z0-9_-]+)/?$ {
    # Matches /user/john_doe/, /User/ADMIN/, /user/test123
    proxy_pass http://user_backend/profile/$1;
}

# Matches multiple API versions
location ~* ^/api/(v[0-9]+|beta|alpha)/ {
    # Matches /api/v1/, /API/BETA/, /api/alpha/
    limit_req zone=api burst=50;
    proxy_pass http://api_backend;
}
```

**When to Use:**
- **File extension matching** - Static assets, downloads
- **Dynamic URL patterns** - User profiles, date-based URLs
- **Flexible matching** - Case-insensitive requirements
- **Complex routing** - Multiple patterns in one location

### **4. Prefix Match (no modifier)**

```nginx
# Matches /api/ and everything under it
location /api/ {
    limit_req zone=api burst=50 nodelay;
    proxy_pass http://api_backend;
    # /api/users → http://api_backend/users
    # /api/users/123 → http://api_backend/users/123
}

# Matches /app/ - longest prefix wins
location /app/ {
    try_files $uri $uri/ /app/index.html;
}

# More specific prefix - takes priority over /app/
location /app/admin/ {
    auth_basic "Admin Required";
    auth_basic_user_file /etc/nginx/.htpasswd;
    try_files $uri $uri/ /app/admin/index.html;
}

# Matches anything starting with /files/
location /files/ {
    client_max_body_size 100M;
    proxy_pass http://file_storage_backend;
}

# Catch-all location - matches everything
location / {
    try_files $uri $uri/ /index.html;
}
```

**When to Use:**
- **API routing** - Simple prefix-based routing
- **Directory-based organization** - Different backends for different paths
- **Fallback handling** - Catch-all patterns
- **Simple proxy routing** - Straightforward URL forwarding

### **5. Advanced Path Matching Examples**

#### **Multi-tenant Applications**
```nginx
# Using named capture groups
location ~* ^/tenant/(?<tenant_name>[a-z0-9]+)/(?<path>.*)$ {
    proxy_pass http://$tenant_name_backend/$path$is_args$args;
    proxy_set_header X-Tenant $tenant_name;
}

# Tenant-specific rate limiting
location ~* ^/tenant/(?<tenant>[a-z0-9]+)/ {
    set $tenant_zone "tenant_${tenant}";
    limit_req zone=$tenant_zone burst=20;
    proxy_pass http://tenant_backend;
}
```

#### **Language/Locale Routing**
```nginx
# Matches /en/, /fr/, /de/, etc.
location ~* ^/([a-z]{2})/(.*)$ {
    set $lang $1;
    set $path $2;
    proxy_pass http://i18n_backend/$path$is_args$args;
    proxy_set_header X-Language $lang;
}

# Specific language handling
location /en/ {
    alias /var/www/english/;
    try_files $uri $uri/ /en/index.html;
}
```

#### **API Version Routing**
```nginx
# Version-specific backends
location ~ ^/api/v1/ {
    proxy_pass http://api_v1_backend;
}

location ~ ^/api/v2/ {
    proxy_pass http://api_v2_backend;
}

# Latest version default
location /api/ {
    proxy_pass http://api_latest_backend;
}
```

#### **Mobile vs Desktop**
```nginx
# Mobile detection and routing
location / {
    set $mobile_backend "";
    if ($http_user_agent ~* "(iPhone|iPad|Android|Mobile)") {
        set $mobile_backend "_mobile";
    }
    proxy_pass http://web${mobile_backend}_backend;
}
```

### **6. Location Matching Examples with Real Scenarios**

#### **E-commerce Application**
```nginx
server {
    # Product images - exact matching for performance
    location = /favicon.ico { expires 1y; access_log off; }
    
    # Static assets - prefix with modifier for performance
    location ^~ /static/ { expires 1y; root /var/www/assets; }
    
    # Product images - regex for file types
    location ~* /products/.*\.(jpg|jpeg|png|webp)$ { 
        expires 6M; 
        root /var/www/media; 
    }
    
    # API endpoints - prefix matching
    location /api/cart/ { 
        limit_req zone=cart burst=10; 
        proxy_pass http://cart_service; 
    }
    
    location /api/payment/ { 
        limit_req zone=payment burst=5; 
        proxy_pass https://secure_payment; 
    }
    
    # User profiles - regex with capture
    location ~* ^/user/([a-zA-Z0-9_-]+)/?$ { 
        proxy_pass http://user_service/profile/$1; 
    }
    
    # Catch-all for SPA
    location / { 
        try_files $uri $uri/ /index.html; 
    }
}
```

#### **Content Management System**
```nginx
server {
    # Admin area - exact match for security
    location = /admin { return 301 /admin/; }
    
    # Admin routes - prefix with auth
    location /admin/ {
        auth_basic "Admin Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://admin_backend;
    }
    
    # Media uploads - size restrictions
    location /uploads/ {
        client_max_body_size 50M;
        root /var/www/media;
    }
    
    # Plugin assets - regex matching
    location ~* ^/plugins/([^/]+)/assets/ {
        expires 1M;
        root /var/www/plugins;
    }
    
    # Blog posts - date-based URLs
    location ~* ^/blog/([0-9]{4})/([0-9]{2})/ {
        proxy_pass http://blog_backend;
        proxy_set_header X-Year $1;
        proxy_set_header X-Month $2;
    }
}
```

#### **Microservices API Gateway**
```nginx
server {
    # Health checks - exact match
    location = /health { return 200 "OK"; }
    
    # Service-specific routing with rate limiting
    location /api/users/ {
        limit_req zone=users burst=100;
        proxy_pass http://user_service/;
    }
    
    location /api/orders/ {
        limit_req zone=orders burst=50;
        proxy_pass http://order_service/;
    }
    
    location /api/inventory/ {
        limit_req zone=inventory burst=200;
        proxy_pass http://inventory_service/;
    }
    
    # WebSocket connections - specific path
    location /ws/ {
        proxy_pass http://websocket_service;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # File downloads - prefix matching
    location /files/ {
        internal;
        alias /var/secure/files/;
    }
    
    # Versioned API - regex matching
    location ~* ^/api/v([0-9]+)/ {
        proxy_pass http://api_v$1_service;
    }
}
```

 | **Slower** | Regex compilation needed | Complex patterns only |
| `/health` | **Medium** | Longest prefix comparison | General routing |

#### **Common Mistakes:**

```nginx
# WRONG: This is not valid nginx syntax
location ^/health {  # Missing ~ for regex or = for exact
    return 200 "Invalid";
}

# WRONG: Overlapping without consideration
location /health {
    return 200 "This will never execute";
}
location = /health {
    return 200 "This executes first";
}

# CORRECT: Order matters for prefix matches
location /health/detailed {  # More specific first
    return 200 "Detailed health";
}
location /health {           # General match second
    return 200 "General health";
}
```

#### **Interview Question Examples:**

**Q: "What's the difference between `location /health` and `location = /health`?"**

**A:** "`location /health` is a prefix match that matches `/health` and anything starting with `/health` like `/health123` or `/health/status`. `location = /health` is an exact match that only matches `/health` exactly - it's faster and has the highest priority in nginx processing."

**Q: "When would you use `^~ /health` instead of `/health`?"**

**A:** "I'd use `^~ /health` when I want prefix matching but need to skip regex processing for performance. It's useful for high-traffic paths like static assets or API endpoints where I know regex locations aren't needed."

**Q: "How does nginx decide which location block to use?"**

**A:** "Nginx follows a specific priority: 1) Exact matches (`=`) first, 2) Prefix with modifier (`^~`) second, 3) Regex matches (`~` or `~*`) third, and 4) Regular prefix matches last, where the longest match wins."

This comparison shows exactly how different location patterns behave and when to use each one!

---

 ensures we only match URIs that actually END with `.php`. This prevents double extension attacks, path traversal, and accidental serving of backup files."

#### **Q: "How would you secure a file upload directory in nginx?"**

**Expert Answer:**
"I'd use multiple security layers:
```nginx
# 1. Strict regex with anchors
location ~* ^/uploads/[a-zA-Z0-9_-]+\.(jpg|png|gif)$ {
    # 2. No path separators in filename  
    # 3. Must end with allowed extension
    
    # 4. Prevent execution
    location ~* \.php$ { deny all; }
    
    # 5. Security headers
    add_header X-Content-Type-Options nosniff;
    
    root /var/www/uploads;
}
```
This prevents directory traversal, executable uploads, and MIME confusion attacks."

#### **Q: "Explain the security difference between these patterns:"**
```nginx
location ~* /admin/.*\.php      # Pattern A
location ~* ^/admin/.*\.php$    # Pattern B  
location = /admin/index.php     # Pattern C
```

**Expert Answer:**
"Pattern A is dangerous - it matches `/admin/config.php.backup` and allows path traversal like `/malicious/admin/hack.php`. Pattern B is secure with proper anchoring. Pattern C is most secure for specific files - exact match has highest priority and no regex processing. For admin areas, I'd use Pattern C for specific files and Pattern B for dynamic routing."

### **Best Practices Summary for Interviews**

#### **✅ Always Do:**
```nginx
# 1. Use $ anchor for file extensions
location ~* \.(css|js|png|jpg)$ { }

# 2. Use ^ and $ for precise matching  
location ~* ^/api/v[0-9]+/users$ { }

# 3. Validate filename characters
location ~* ^/uploads/[a-zA-Z0-9_-]+\.(jpg|png)$ { }

# 4. Block executables explicitly
location ~* \.(php|py|sh|exe)$ { deny all; }
```

#### **❌ Never Do:**
```nginx
# 1. Missing anchors (security risk)
location ~* \.pdf { }           # WRONG

# 2. Overly broad patterns  
location ~* /admin/ { }         # WRONG - allows /evil/admin/

# 3. No executable blocking
location ~* \.(txt|log) { }     # WRONG - could serve .txt.php
```

### **Production Security Checklist**
```nginx
# Complete secure file serving example
server {
    # 1. Block all executables first
    location ~* \.(php|php5|phtml|py|sh|cgi|exe)$ {
        deny all;
        access_log /var/log/nginx/blocked.log;
    }
    
    # 2. Secure static assets
    location ~* \.(css|js)$ {
        expires 1y;
        add_header X-Content-Type-Options nosniff;
    }
    
    # 3. Secure uploads with strict validation
    location ~* ^/uploads/[a-zA-Z0-9_-]+\.(jpg|png|gif)$ {
        expires 1M;
        add_header X-Content-Type-Options nosniff;
        root /var/www/uploads;
    }
    
    # 4. Admin area with exact matches
    location = /admin { return 301 /admin/; }
    location ^~ /admin/ {
        auth_basic "Admin";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

This security knowledge demonstrates senior-level nginx expertise and is crucial for DevOps roles handling production systems.

```nginx
http {
    # Global settings
    client_max_body_size 10M;
    
    server {
        # Server-specific override
        client_max_body_size 50M;
        
        location /upload/ {
            # Location-specific override
            client_max_body_size 100M;
        }
        
        location /api/ {
            # Inherits server setting (50M)
        }
    }
}
```

### **Inheritance Rules:**
- **Child contexts inherit** from parent contexts
- **Child settings override** parent settings
- **Some directives are additive** (like `add_header`)

---

## 10. Context Inheritance and Overrides

```nginx
http {
    # Global settings
    client_max_body_size 10M;           # Default upload limit for all servers
    
    server {
        # Server-specific override
        client_max_body_size 50M;       # Override: This server allows 50MB uploads
        
        location /upload/ {
            # Location-specific override
            client_max_body_size 100M;  # Override: Upload endpoint allows 100MB
        }
        
        location /api/ {
            # Inherits server setting (50M)
            proxy_pass http://api_backend;
        }
    }
}
```

### **Inheritance Rules:**
- **Child contexts inherit** from parent contexts
- **Child settings override** parent settings  
- **Some directives are additive** (like `add_header`)

---

## 11. Real-World Configuration Scenarios

### **Scenario 1: E-commerce Application**
```nginx
server {
    listen 443 ssl http2;
    server_name shop.example.com;
    
    # Product images - aggressive caching
    location /images/ {
        expires 1y;                       # Cache product images for 1 year
        root /var/www/static;             # Static images directory
    }
    
    # API - rate limited
    location /api/ {
        limit_req zone=api burst=20 nodelay;  # API rate limiting with burst
        proxy_pass http://ecommerce_api;      # Route to e-commerce backend
    }
    
    # Payment processing - strict security
    location /payment/ {
        limit_req zone=payment burst=5;      # Strict rate limiting for payments
        proxy_pass https://secure_payment_backend;  # HTTPS to payment processor
        proxy_ssl_verify on;                 # Verify SSL certificate of backend
    }
    
    # User uploads - size limits
    location /upload/ {
        client_max_body_size 5M;             # Limit upload size to 5MB
        proxy_pass http://upload_service;    # Route to upload service
    }
}
```

### **Scenario 2: SaaS Application with Multi-tenancy**
```nginx
# Different backends for different tenants
upstream tenant_a { server 10.0.1.10:8080; }    # Tenant A backend
upstream tenant_b { server 10.0.1.11:8080; }    # Tenant B backend

server {
    listen 443 ssl http2;
    server_name ~^(?<tenant>\w+)\.myapp\.com$;    # Capture tenant from subdomain
    
    location / {
        # Route to tenant-specific backend using captured variable
        proxy_pass http://$tenant;               # Dynamic backend based on subdomain
        proxy_set_header X-Tenant $tenant;      # Pass tenant info to backend
    }
}
```

### **Scenario 3: Microservices Gateway**
```nginx
# Different rate limits for different services
limit_req_zone $binary_remote_addr zone=user_service:10m rate=50r/s;        # User service zone
limit_req_zone $binary_remote_addr zone=payment_service:10m rate=10r/s;     # Payment service zone  
limit_req_zone $binary_remote_addr zone=notification_service:10m rate=100r/s; # Notification zone

server {
    listen 80;
    server_name api.example.com;
    
    location /users/ {
        limit_req zone=user_service burst=100 nodelay;  # User service rate limiting
        proxy_pass http://user_service_backend;         # Route to user service
    }
    
    location /payments/ {
        limit_req zone=payment_service burst=20;        # Strict payment rate limiting
        proxy_pass http://payment_service_backend;      # Route to payment service
    }
    
    location /notifications/ {
        limit_req zone=notification_service burst=200 nodelay;  # High-volume notifications
        proxy_pass http://notification_service_backend;         # Route to notification service
    }
}
```

## 12. Interview Tips

### **Key Points to Emphasize:**

1. **Block Hierarchy Understanding** - Show you understand how settings inherit and override
2. **Performance Considerations** - Explain why you chose specific settings
3. **Security Implications** - Demonstrate awareness of security best practices
4. **Scalability Planning** - Show how configuration supports growth
5. **Troubleshooting Knowledge** - Explain how to debug issues in each block

### **Common Interview Questions:**

**Q: "Why use upstream blocks instead of direct proxy_pass?"**
**A:** "Upstream blocks provide load balancing, health checks, connection pooling, and failover capabilities. Direct proxy_pass is limited to single backend."

**Q: "When would you use different location matching types?"**
**A:** "Exact match (=) for specific endpoints like /health, regex (~) for file extensions, prefix (/) for general routing. Priority matters for overlapping patterns."

**Q: "How do you handle different rate limits for different user types?"**
**A:** "Use map directive to set different zones based on user characteristics, or use different location blocks with appropriate rate limiting zones."

This deep understanding of nginx blocks and their purposes demonstrates senior-level expertise in reverse proxy configuration!