# Certificate Renewal Hooks - Part 2: Mail & Database Services

## Table of Contents
1. [Email Server Hooks](#email-server-hooks)
2. [Database Service Hooks](#database-service-hooks)
3. [Cache & Message Queue Hooks](#cache--message-queue-hooks)

---

## Email Server Hooks

### 1. Postfix Hook Concepts

#### Basic Postfix Pattern
```bash
#!/bin/bash
# Basic postfix certificate update

for domain in $RENEWED_DOMAINS; do
    # Update main.cf
    postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$domain/fullchain.pem"
    postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$domain/privkey.pem"
done

# Validate and reload
postfix check && systemctl reload postfix
```

#### Multi-Domain SNI Pattern
```bash
#!/bin/bash
# SNI support for multiple domains

TLS_DIR="/etc/postfix/tls"
mkdir -p "$TLS_DIR"

# Create certificate maps
echo "# Certificate map" > "$TLS_DIR/cert_map"
echo "# Key map" > "$TLS_DIR/key_map"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$TLS_DIR/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$TLS_DIR/$domain.key"
    
    echo "$domain $TLS_DIR/$domain.crt" >> "$TLS_DIR/cert_map"
    echo "$domain $TLS_DIR/$domain.key" >> "$TLS_DIR/key_map"
done

# Update maps and configure SNI
postmap "$TLS_DIR/cert_map"
postmap "$TLS_DIR/key_map"
postconf -e "tls_server_sni_maps = hash:$TLS_DIR/cert_map"

systemctl reload postfix
```

#### SMTP Security Configuration
```bash
#!/bin/bash
# Enhanced security settings

configure_postfix_security() {
    postconf -e "smtpd_tls_security_level = may"
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtpd_tls_ciphers = medium"
    postconf -e "smtpd_tls_exclude_ciphers = MD5, SRP, PSK"
    postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
}

update_certificates
configure_postfix_security
systemctl reload postfix
```

### 2. Dovecot Hook Concepts

#### Basic Dovecot Pattern
```bash
#!/bin/bash
# Dovecot SSL update

SSL_DIR="/etc/dovecot/ssl"
mkdir -p "$SSL_DIR"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$SSL_DIR/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$SSL_DIR/$domain.key"
    chown dovecot:dovecot "$SSL_DIR/$domain".*
    chmod 600 "$SSL_DIR/$domain.key"
done

# Update SSL config
cat > /etc/dovecot/conf.d/10-ssl.conf << EOF
ssl = required
ssl_cert = <$SSL_DIR/\${hostname}.crt
ssl_key = <$SSL_DIR/\${hostname}.key
ssl_protocols = !SSLv3 !TLSv1 !TLSv1.1
EOF

doveconf -n && systemctl reload dovecot
```

#### Service Testing Pattern
```bash
#!/bin/bash
# Test email services after renewal

test_smtp_tls() {
    local domain=$1
    echo "QUIT" | openssl s_client -connect "$domain:587" -starttls smtp >/dev/null 2>&1
}

test_imap_tls() {
    local domain=$1
    echo "a1 logout" | openssl s_client -connect "$domain:993" >/dev/null 2>&1
}

for domain in $RENEWED_DOMAINS; do
    if test_smtp_tls "$domain"; then
        echo "SMTP TLS OK for $domain"
    fi
    
    if test_imap_tls "$domain"; then
        echo "IMAP TLS OK for $domain"
    fi
done
```

---

## Database Service Hooks

### 1. PostgreSQL Hook Concepts

#### Basic PostgreSQL SSL Pattern
```bash
#!/bin/bash
# PostgreSQL SSL configuration

POSTGRES_VERSION="13"
SSL_DIR="/etc/postgresql/$POSTGRES_VERSION/ssl"
mkdir -p "$SSL_DIR"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$SSL_DIR/server.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$SSL_DIR/server.key"
    chown postgres:postgres "$SSL_DIR/server".*
    chmod 600 "$SSL_DIR/server.key"
done

# Update postgresql.conf
echo "ssl = on" >> /etc/postgresql/$POSTGRES_VERSION/main/postgresql.conf
echo "ssl_cert_file = '$SSL_DIR/server.crt'" >> /etc/postgresql/$POSTGRES_VERSION/main/postgresql.conf
echo "ssl_key_file = '$SSL_DIR/server.key'" >> /etc/postgresql/$POSTGRES_VERSION/main/postgresql.conf

# Reload configuration
sudo -u postgres pg_ctl reload -D /var/lib/postgresql/$POSTGRES_VERSION/main
```

#### Connection Testing Pattern
```bash
#!/bin/bash
# Test database SSL connections

test_postgres_ssl() {
    sudo -u postgres psql -h localhost -c "SELECT version();" sslmode=require >/dev/null 2>&1
}

test_mysql_ssl() {
    mysql -e "SHOW STATUS LIKE 'Ssl_cipher';" 2>/dev/null | grep -q "AES"
}

if test_postgres_ssl; then
    echo "PostgreSQL SSL connection successful"
fi
```

### 2. MySQL/MariaDB Hook Concepts

#### Basic MySQL SSL Pattern
```bash
#!/bin/bash
# MySQL SSL configuration

SSL_DIR="/etc/mysql/ssl"
mkdir -p "$SSL_DIR"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$SSL_DIR/server-cert.pem"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$SSL_DIR/server-key.pem"
    chown mysql:mysql "$SSL_DIR/server"*
    chmod 600 "$SSL_DIR/server-key.pem"
done

# Create SSL configuration
cat > /etc/mysql/mysql.conf.d/ssl.cnf << EOF
[mysqld]
ssl-cert=$SSL_DIR/server-cert.pem
ssl-key=$SSL_DIR/server-key.pem
require_secure_transport=ON
EOF

systemctl restart mysql  # MySQL requires restart for SSL changes
```

---

## Cache & Message Queue Hooks

### 1. Redis Hook Concepts

#### Redis TLS Pattern
```bash
#!/bin/bash
# Redis TLS configuration

REDIS_CERT_DIR="/etc/redis/ssl"
mkdir -p "$REDIS_CERT_DIR"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$REDIS_CERT_DIR/redis.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$REDIS_CERT_DIR/redis.key"
    chown redis:redis "$REDIS_CERT_DIR/redis".*
    chmod 600 "$REDIS_CERT_DIR/redis.key"
done

# Update redis.conf
sed -i 's/^# tls-port.*/tls-port 6380/' /etc/redis/redis.conf
sed -i "s|^# tls-cert-file.*|tls-cert-file $REDIS_CERT_DIR/redis.crt|" /etc/redis/redis.conf
sed -i "s|^# tls-key-file.*|tls-key-file $REDIS_CERT_DIR/redis.key|" /etc/redis/redis.conf

systemctl restart redis  # Redis requires restart for TLS changes
```

#### Redis Testing Pattern
```bash
#!/bin/bash
# Test Redis TLS connection

test_redis_tls() {
    redis-cli --tls \
        --cert /etc/redis/ssl/redis.crt \
        --key /etc/redis/ssl/redis.key \
        --cacert /etc/redis/ssl/redis.crt \
        ping >/dev/null 2>&1
}

if test_redis_tls; then
    echo "Redis TLS connection successful"
fi
```

### 2. RabbitMQ Hook Concepts

#### RabbitMQ SSL Pattern
```bash
#!/bin/bash
# RabbitMQ SSL configuration

RABBITMQ_SSL_DIR="/etc/rabbitmq/ssl"
mkdir -p "$RABBITMQ_SSL_DIR"

for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$RABBITMQ_SSL_DIR/cert.pem"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$RABBITMQ_SSL_DIR/key.pem"
    chown rabbitmq:rabbitmq "$RABBITMQ_SSL_DIR"/*
    chmod 600 "$RABBITMQ_SSL_DIR/key.pem"
done

# Update rabbitmq.conf
cat > /etc/rabbitmq/rabbitmq.conf << EOF
listeners.ssl.default = 5671
ssl_options.certfile = $RABBITMQ_SSL_DIR/cert.pem
ssl_options.keyfile = $RABBITMQ_SSL_DIR/key.pem
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = false
EOF

systemctl restart rabbitmq-server
```

## Advanced Database Concepts

### 1. Certificate Validation Pattern
```bash
#!/bin/bash
# Comprehensive certificate validation

validate_cert_for_service() {
    local domain=$1
    local service=$2
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    local key_path="/etc/letsencrypt/live/$domain/privkey.pem"
    
    # Check certificate validity (30 days)
    if ! openssl x509 -in "$cert_path" -noout -checkend 2592000; then
        echo "WARNING: Certificate for $domain expires within 30 days"
        return 1
    fi
    
    # Check certificate and key match
    local cert_mod=$(openssl x509 -noout -modulus -in "$cert_path" | openssl md5)
    local key_mod=$(openssl rsa -noout -modulus -in "$key_path" | openssl md5)
    
    if [ "$cert_mod" != "$key_mod" ]; then
        echo "ERROR: Certificate and key don't match for $domain"
        return 1
    fi
    
    echo "Certificate validation passed for $domain ($service)"
    return 0
}
```

### 2. Service Restart Strategy
```bash
#!/bin/bash
# Smart restart strategy

restart_service_smartly() {
    local service=$1
    
    # Check if service supports reload
    if systemctl show "$service" | grep -q "CanReload=yes"; then
        systemctl reload "$service"
        echo "Reloaded $service"
    else
        systemctl restart "$service"
        echo "Restarted $service"
        
        # Wait for service to stabilize
        sleep 5
        
        if ! systemctl is-active --quiet "$service"; then
            echo "ERROR: $service failed to start"
            return 1
        fi
    fi
}
```

### 3. Backup and Recovery Pattern
```bash
#!/bin/bash
# Backup configuration before changes

backup_config() {
    local config_file=$1
    local backup_dir="/var/backups/cert-renewal"
    
    mkdir -p "$backup_dir"
    cp "$config_file" "$backup_dir/$(basename $config_file).$(date +%Y%m%d-%H%M%S)"
}

restore_config() {
    local config_file=$1
    local backup_dir="/var/backups/cert-renewal"
    
    local latest_backup=$(ls -t "$backup_dir/$(basename $config_file)".* | head -1)
    if [ -f "$latest_backup" ]; then
        cp "$latest_backup" "$config_file"
        echo "Restored configuration from $latest_backup"
    fi
}
```

This covers the essential concepts for email servers, databases, and cache services with focus on practical patterns rather than exhaustive details.