# Complete Nginx Interview Preparation Guide
## From Basics to Advanced

---

# **LEVEL 1: FUNDAMENTALS** 

## 1. What is Nginx?

### **Basic Definition:**
Nginx (pronounced "engine-x") is a high-performance web server, reverse proxy, load balancer, and HTTP cache.

### **Key Characteristics:**
- **Event-driven architecture** - Handles thousands of concurrent connections efficiently
- **Low memory footprint** - Uses less RAM than Apache
- **High performance** - Can serve static files very fast
- **Modular design** - Functionality through modules

### **Common Use Cases:**
- **Web server** - Serving static content (HTML, CSS, JS, images)
- **Reverse proxy** - Forward requests to backend applications
- **Load balancer** - Distribute traffic across multiple servers
- **SSL termination** - Handle HTTPS certificates
- **API gateway** - Route API requests to microservices

### **Interview Questions:**
**Q: "What is nginx and why use it?"**
**A:** "Nginx is a high-performance web server and reverse proxy. I use it because it can handle thousands of concurrent connections with low memory usage, making it perfect for high-traffic applications and microservices architectures."

**Q: "Nginx vs Apache - when would you choose nginx?"**
**A:** "I choose nginx for high-concurrency scenarios, static file serving, and as a reverse proxy because of its event-driven architecture. Apache is better for dynamic content with modules like mod_php, but nginx excels at handling many simultaneous connections efficiently."

---

## 2. Basic Nginx Architecture

### **Process Model:**
```
Master Process (root)
├── Worker Process 1 (nginx user)
├── Worker Process 2 (nginx user)
├── Worker Process 3 (nginx user)
└── Worker Process N (nginx user)
```

### **How It Works:**
- **Master Process** - Reads configuration, manages worker processes
- **Worker Processes** - Handle actual client requests
- **Event-driven** - Each worker can handle thousands of connections
- **Non-blocking I/O** - Doesn't wait for slow operations

### **Interview Questions:**
**Q: "How does nginx handle multiple requests?"**
**A:** "Nginx uses an event-driven, non-blocking architecture. A master process spawns worker processes that can each handle thousands of concurrent connections using an event loop, without creating threads for each connection like traditional servers."

---

## 3. Basic Configuration Structure

### **Configuration Hierarchy:**
```nginx
# Main context (global settings)
user nginx;
worker_processes auto;

# Events context
events {
    worker_connections 1024;
}

# HTTP context
http {
    # Server context
    server {
        listen 80;
        server_name example.com;
        
        # Location context
        location / {
            # Directives here
        }
    }
}
```

### **Configuration Files:**
- **Main config:** `/etc/nginx/nginx.conf`
- **Site configs:** `/etc/nginx/sites-available/` and `/etc/nginx/sites-enabled/`
- **Include pattern:** `include /etc/nginx/sites-enabled/*;`

### **Basic Commands:**
```bash
# Test configuration
nginx -t

# Reload configuration
nginx -s reload

# Stop nginx
nginx -s stop

# Start nginx
systemctl start nginx

# Check status
systemctl status nginx
```

### **Interview Questions:**
**Q: "How do you test nginx configuration before applying?"**
**A:** "I use `nginx -t` to test the configuration syntax. This validates the config without applying it, so I can catch errors before reloading."

**Q: "How do you apply configuration changes?"**
**A:** "I use `nginx -s reload` which gracefully reloads the configuration without dropping existing connections, or `systemctl reload nginx` for the same effect."

---

# **LEVEL 2: WEB SERVER BASICS**

## 4. Serving Static Content

### **Basic Static File Serving:**
```nginx
server {
    listen 80;
    server_name mysite.com;
    root /var/www/html;
    index index.html index.htm;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    # Static assets with caching
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
```

### **Key Directives:**
- **`root`** - Document root directory
- **`index`** - Default files to serve
- **`try_files`** - File lookup order
- **`expires`** - Cache control headers
- **`access_log off`** - Disable logging for performance

### **Interview Questions:**
**Q: "How do you serve static files efficiently with nginx?"**
**A:** "I set appropriate cache headers using `expires`, disable access logging for static assets, and use `try_files` for efficient file lookups. For performance, I also enable gzip compression for text files."

---

## 5. Basic Reverse Proxy

### **Simple Reverse Proxy:**
```nginx
server {
    listen 80;
    server_name api.example.com;
    
    location / {
        proxy_pass http://backend_server:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### **Essential Proxy Headers:**
- **`Host`** - Original host header
- **`X-Real-IP`** - Client's real IP address
- **`X-Forwarded-For`** - Chain of proxy IPs
- **`X-Forwarded-Proto`** - Original protocol (http/https)

### **Interview Questions:**
**Q: "What is a reverse proxy and why use nginx for it?"**
**A:** "A reverse proxy sits between clients and backend servers, forwarding client requests to backends and returning responses. Nginx is excellent for this because it can handle SSL termination, load balancing, and add security headers while efficiently managing connections."

**Q: "What headers do you set when proxying requests?"**
**A:** "I set `Host` to preserve the original hostname, `X-Real-IP` for the client's actual IP, `X-Forwarded-For` for the proxy chain, and `X-Forwarded-Proto` so backends know if the original request was HTTPS."

---

# **LEVEL 3: INTERMEDIATE CONCEPTS**

## 6. Load Balancing

### **Basic Load Balancing:**
```nginx
# Define upstream servers
upstream backend_pool {
    server backend1:8080;
    server backend2:8080;
    server backend3:8080;
}

server {
    listen 80;
    location / {
        proxy_pass http://backend_pool;
    }
}
```

### **Load Balancing Methods:**
```nginx
upstream backend_pool {
    # Round-robin (default)
    server backend1:8080;
    server backend2:8080;
    
    # Weighted round-robin
    server backend1:8080 weight=3;
    server backend2:8080 weight=1;
    
    # Least connections
    least_conn;
    server backend1:8080;
    server backend2:8080;
    
    # IP Hash (session persistence)
    ip_hash;
    server backend1:8080;
    server backend2:8080;
}
```

### **Health Checks:**
```nginx
upstream backend_pool {
    server backend1:8080 max_fails=3 fail_timeout=30s;
    server backend2:8080 max_fails=3 fail_timeout=30s;
    server backend3:8080 backup;  # Backup server
}
```

### **Interview Questions:**
**Q: "What load balancing algorithms does nginx support?"**
**A:** "Nginx supports round-robin (default), weighted round-robin for different server capacities, least_conn for servers with varying response times, and ip_hash for session persistence."

**Q: "How do you handle server failures in load balancing?"**
**A:** "I configure health checks with `max_fails` and `fail_timeout`. If a server fails 3 times within 30 seconds, nginx temporarily removes it from the pool. I also set backup servers that activate when primary servers are down."

---

## 7. SSL/TLS Configuration

### **Basic HTTPS Setup:**
```nginx
server {
    listen 443 ssl http2;
    server_name secure.example.com;
    
    # SSL Certificate
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # SSL Session
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    location / {
        proxy_pass http://backend;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name secure.example.com;
    return 301 https://$server_name$request_uri;
}
```

### **Security Headers:**
```nginx
# Add security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
```

### **Interview Questions:**
**Q: "How do you configure HTTPS in nginx?"**
**A:** "I configure SSL certificates with `ssl_certificate` and `ssl_certificate_key`, set secure protocols like TLSv1.2 and TLSv1.3, configure strong ciphers, and add security headers. I also set up HTTP to HTTPS redirects and enable session caching for performance."

---

## 8. Basic Security

### **Access Control:**
```nginx
# IP-based access control
location /admin/ {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
}

# Basic authentication
location /secure/ {
    auth_basic "Secure Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}

# Deny hidden files
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}
```

### **Rate Limiting (Basic):**
```nginx
# Define rate limiting zone
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
}

# Apply rate limiting
server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }
}
```

### **Interview Questions:**
**Q: "How do you secure nginx?"**
**A:** "I implement multiple layers: IP-based access control for admin areas, basic authentication where needed, rate limiting to prevent abuse, security headers for XSS protection, and deny access to hidden files and backup files."

---

# **LEVEL 4: ADVANCED CONCEPTS**

## 9. Advanced Rate Limiting

### **Multiple Rate Limiting Zones:**
```nginx
http {
    # Different zones for different purposes
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone $binary_remote_addr zone=general:10m rate=5r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=addr:10m;
}

server {
    # API endpoints
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        limit_conn addr 10;
        proxy_pass http://api_backend;
    }
    
    # Login endpoint - stricter
    location /login {
        limit_req zone=login burst=5;
        proxy_pass http://auth_backend;
    }
}
```

### **Advanced Rate Limiting:**
```nginx
# Geographic rate limiting
geo $limit {
    default 1;
    10.0.0.0/8 0;      # Internal networks
    192.168.0.0/16 0;  # Internal networks
}

map $limit $limit_key {
    0 "";
    1 $binary_remote_addr;
}

limit_req_zone $limit_key zone=geo_limited:10m rate=5r/s;

# User-agent based limiting
map $http_user_agent $bot {
    default 0;
    ~*bot 1;
    ~*crawler 1;
    ~*spider 1;
}

limit_req_zone $bot zone=bot_protection:10m rate=1r/s;
```

### **Interview Questions:**
**Q: "How do you implement different rate limits for different types of users?"**
**A:** "I use multiple rate limiting zones and map directives. For example, I create different zones for API users, regular users, and bots, then apply appropriate limits. I can also use geographic restrictions to treat internal traffic differently."

---

## 10. Caching

### **Proxy Caching:**
```nginx
http {
    # Cache path and settings
    proxy_cache_path /var/cache/nginx/proxy 
                     levels=1:2 
                     keys_zone=my_cache:10m 
                     max_size=1g 
                     inactive=60m;
}

server {
    location / {
        proxy_cache my_cache;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        
        # Cache key
        proxy_cache_key "$scheme$request_method$host$request_uri";
        
        # Headers
        add_header X-Cache-Status $upstream_cache_status;
        
        proxy_pass http://backend;
    }
}
```

### **Cache Control:**
```nginx
# Different cache rules for different content
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Vary Accept-Encoding;
}

location ~* \.(html|htm)$ {
    expires 1h;
    add_header Cache-Control "public, must-revalidate";
}
```

### **Interview Questions:**
**Q: "How do you implement caching in nginx?"**
**A:** "I use proxy_cache for dynamic content caching, setting cache paths, zones, and validity periods. For static content, I use expires directives with appropriate Cache-Control headers. I also implement cache invalidation strategies and use stale cache during backend failures."

---

## 11. Advanced Performance Optimization

### **Connection Optimization:**
```nginx
# Global settings
events {
    use epoll;                    # Linux
    worker_connections 4096;
    multi_accept on;
    accept_mutex off;
}

http {
    # TCP optimization
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    
    # Keep-alive
    keepalive_timeout 65;
    keepalive_requests 100;
    
    # Client settings
    client_max_body_size 50M;
    client_body_buffer_size 1M;
    client_header_buffer_size 4k;
    large_client_header_buffers 4 8k;
}
```

### **Compression:**
```nginx
# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_proxied any;
gzip_comp_level 6;
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/javascript
    application/json
    application/xml+rss
    application/atom+xml
    image/svg+xml;

# Brotli compression (if module available)
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json application/javascript;
```

### **Buffer Optimization:**
```nginx
# Proxy buffering
proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 4k;
proxy_busy_buffers_size 8k;

# Connection pooling to backends
upstream backend {
    server backend1:8080;
    server backend2:8080;
    keepalive 32;
    keepalive_requests 100;
    keepalive_timeout 60s;
}

location / {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}
```

### **Interview Questions:**
**Q: "How do you optimize nginx for high performance?"**
**A:** "I optimize at multiple levels: tune worker processes and connections, enable sendfile and TCP optimizations, implement gzip compression, configure proxy buffering, use connection pooling to backends, and optimize cache settings. I also monitor metrics to identify bottlenecks."

---

## 12. Monitoring and Logging

### **Access Logs:**
```nginx
# Custom log format
log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" '
                '"$http_user_agent" "$http_x_forwarded_for" '
                'rt=$request_time uct="$upstream_connect_time" '
                'uht="$upstream_header_time" urt="$upstream_response_time"';

# Conditional logging
map $status $loggable {
    ~^[23]  0;  # Don't log 2xx and 3xx
    default 1;  # Log everything else
}

server {
    access_log /var/log/nginx/access.log main if=$loggable;
    error_log /var/log/nginx/error.log warn;
}
```

### **Status Monitoring:**
```nginx
# Nginx status module
location /nginx_status {
    stub_status on;
    access_log off;
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;
}

# Custom health check
location /health {
    access_log off;
    return 200 "healthy\n";
    add_header Content-Type text/plain;
}
```

### **Interview Questions:**
**Q: "How do you monitor nginx performance?"**
**A:** "I use multiple approaches: custom log formats to track response times and status codes, nginx status module for real-time metrics, health check endpoints, and integrate with monitoring tools like Prometheus. I also set up alerts for error rates and response time degradation."

---

# **LEVEL 5: EXPERT TOPICS**

## 13. Microservices and API Gateway

### **API Gateway Pattern:**
```nginx
# Service discovery simulation
upstream user_service { server user-api:8080; }
upstream order_service { server order-api:8080; }
upstream payment_service { server payment-api:8080; }

# Rate limiting per service
limit_req_zone $binary_remote_addr zone=users:10m rate=100r/s;
limit_req_zone $binary_remote_addr zone=orders:10m rate=50r/s;
limit_req_zone $binary_remote_addr zone=payments:10m rate=10r/s;

server {
    listen 80;
    server_name api.company.com;
    
    # API versioning
    location ~ ^/api/v1/users/ {
        limit_req zone=users burst=200 nodelay;
        proxy_pass http://user_service;
        proxy_set_header X-API-Version "v1";
    }
    
    location ~ ^/api/v1/orders/ {
        limit_req zone=orders burst=100 nodelay;
        proxy_pass http://order_service;
        proxy_set_header X-API-Version "v1";
    }
    
    location ~ ^/api/v1/payments/ {
        limit_req zone=payments burst=20;
        proxy_pass http://payment_service;
        proxy_set_header X-API-Version "v1";
    }
    
    # CORS handling
    if ($request_method = 'OPTIONS') {
        add_header Access-Control-Allow-Origin '*';
        add_header Access-Control-Allow-Methods 'GET, POST, PUT, DELETE, OPTIONS';
        add_header Access-Control-Allow-Headers 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
        add_header Access-Control-Max-Age 1728000;
        add_header Content-Type 'text/plain; charset=utf-8';
        add_header Content-Length 0;
        return 204;
    }
}
```

### **Circuit Breaker Pattern:**
```nginx
# Simulate circuit breaker with error handling
location /api/external/ {
    proxy_pass http://external_service;
    proxy_next_upstream error timeout http_500 http_502 http_503;
    proxy_next_upstream_tries 3;
    proxy_next_upstream_timeout 10s;
    
    # Fallback to cached response
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
}
```

---

## 14. Advanced Troubleshooting

### **Debug Configuration:**
```nginx
# Enable debug logging
error_log /var/log/nginx/debug.log debug;

# Debug specific modules
location /debug/ {
    # Debug proxy
    proxy_pass http://backend;
    
    # Add debug headers
    add_header X-Debug-Upstream-Addr $upstream_addr;
    add_header X-Debug-Upstream-Status $upstream_status;
    add_header X-Debug-Upstream-Response-Time $upstream_response_time;
}
```

### **Common Issues and Solutions:**

#### **502 Bad Gateway:**
```nginx
# Troubleshooting 502 errors
location /api/ {
    # Increase timeouts
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
    
    # Better error handling
    proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    
    proxy_pass http://backend;
}
```

#### **504 Gateway Timeout:**
```nginx
# Handle slow backends
location /slow-api/ {
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
    
    # Buffer large responses
    proxy_buffering on;
    proxy_buffer_size 8k;
    proxy_buffers 16 8k;
    
    proxy_pass http://slow_backend;
}
```

### **Interview Questions:**
**Q: "How do you troubleshoot 502 errors in nginx?"**
**A:** "I check multiple layers: verify backend services are running and reachable, check nginx error logs, review proxy timeout settings, examine upstream health, and test direct backend connectivity. I also implement proper error handling with proxy_next_upstream."

**Q: "How would you debug performance issues?"**
**A:** "I use nginx status module for real-time metrics, analyze access logs for response time patterns, enable detailed logging with timing information, monitor upstream response times, and check for resource constraints like worker connections or file descriptors."

---

# **PRACTICAL INTERVIEW SCENARIOS**

## 15. Real-World Problem Solving

### **Scenario 1: High Traffic E-commerce Site**
```nginx
# Performance-optimized configuration
worker_processes auto;
events {
    worker_connections 4096;
    use epoll;
}

http {
    # Performance settings
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    
    # Rate limiting for different areas
    limit_req_zone $binary_remote_addr zone=api:10m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=checkout:10m rate=10r/s;
    
    # Caching
    proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=product_cache:10m;
    
    upstream app_servers {
        least_conn;
        server app1:8080 max_fails=3 fail_timeout=30s;
        server app2:8080 max_fails=3 fail_timeout=30s;
        server app3:8080 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }
    
    server {
        listen 443 ssl http2;
        
        # Product images - aggressive caching
        location ~* ^/images/products/ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            root /var/www/static;
        }
        
        # API - rate limited
        location /api/ {
            limit_req zone=api burst=100 nodelay;
            proxy_cache product_cache;
            proxy_cache_valid 200 5m;
            proxy_pass http://app_servers;
        }
        
        # Checkout - strict rate limiting
        location /checkout/ {
            limit_req zone=checkout burst=20;
            proxy_pass http://app_servers;
        }
    }
}
```

### **Interview Discussion Points:**
- **Performance optimization** strategies
- **Security considerations** for payment processing
- **Monitoring and alerting** setup
- **Disaster recovery** planning

---

## 16. Interview Questions by Experience Level

### **Junior Level (1-2 years):**
1. "What is nginx and how is it different from Apache?"
2. "How do you serve static files with nginx?"
3. "What is a reverse proxy?"
4. "How do you reload nginx configuration?"
5. "What are the basic nginx configuration blocks?"

### **Mid Level (2-4 years):**
1. "How do you configure load balancing in nginx?"
2. "Explain nginx location matching priority"
3. "How do you implement SSL/TLS in nginx?"
4. "What is rate limiting and how do you configure it?"
5. "How do you troubleshoot 502 and 504 errors?"

### **Senior Level (4+ years):**
1. "Design an nginx configuration for a microservices architecture"
2. "How do you optimize nginx for high-traffic applications?"
3. "Explain nginx caching strategies and when to use each"
4. "How do you implement advanced security with nginx?"
5. "Describe your approach to nginx monitoring and alerting"

---

## 17. Quick Reference for Interviews

### **Common Commands:**
```bash
# Configuration testing
nginx -t
nginx -T  # Test and dump configuration

# Graceful operations
nginx -s reload
nginx -s quit
nginx -s stop

# Process management
systemctl start nginx
systemctl status nginx
systemctl enable nginx

# Log analysis
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

### **Key Metrics to Monitor:**
- **Requests per second**
- **Response time (avg, 95th percentile)**
- **Error rates (4xx, 5xx)**
- **Active connections**
- **Upstream response time**
- **Cache hit ratio**

### **Performance Tuning Checklist:**
- ✅ Worker processes = CPU cores
- ✅ Worker connections optimized
- ✅ Sendfile enabled
- ✅ Gzip compression configured
- ✅ Keep-alive connections tuned
- ✅ Proxy buffering optimized
- ✅ Cache headers set appropriately
- ✅ Rate limiting implemented

---

## 18. Common Mistakes to Avoid

### **Configuration Mistakes:**
```nginx
# WRONG: Missing semicolon
location / {
    proxy_pass http://backend  # Missing semicolon
}

# WRONG: Incorrect proxy_pass
location /api/ {
    proxy_pass http://backend;  # Missing trailing slash
}

# WRONG: Overlapping locations
location /app/ { ... }
location /app/admin/ { ... }  # Will never match

# CORRECT:
location /app/admin/ { ... }  # More specific first
location /app/ { ... }
```

### **Security Mistakes:**
- Not hiding nginx version: `server_tokens off;`
- Weak SSL configuration
- Missing security headers
- No rate limiting on sensitive endpoints
- Exposing nginx status to public

### **Performance Mistakes:**
- Not enabling gzip compression
- Incorrect worker_processes setting
- Missing connection pooling to backends
- Poor cache configuration
- Not optimizing buffer sizes

This comprehensive guide covers everything from basic concepts to advanced nginx configurations that a DevOps engineer should know for interviews!