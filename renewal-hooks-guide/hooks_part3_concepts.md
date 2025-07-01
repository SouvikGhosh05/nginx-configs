# Certificate Renewal Hooks - Part 3: Containers & Applications

## Table of Contents
1. [Container Service Hooks](#container-service-hooks)
2. [Application-Specific Hooks](#application-specific-hooks)
3. [Cloud Service Integration](#cloud-service-integration)

---

## Container Service Hooks

### 1. Docker Hook Concepts

#### Basic Docker Container Pattern
```bash
#!/bin/bash
# Update certificates in running containers

CERT_VOLUME_DIR="/opt/docker/certs"

for domain in $RENEWED_DOMAINS; do
    # Copy to shared volume
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$CERT_VOLUME_DIR/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$CERT_VOLUME_DIR/$domain.key"
    chmod 644 "$CERT_VOLUME_DIR/$domain.crt"
    chmod 600 "$CERT_VOLUME_DIR/$domain.key"
done

# Signal containers to reload
docker exec nginx-proxy nginx -s reload
docker exec app-server kill -HUP 1
```

#### Docker Compose Pattern
```bash
#!/bin/bash
# Docker Compose service restart

COMPOSE_DIR="/opt/myapp"
cd "$COMPOSE_DIR"

# Copy certificates to project directory
for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "./certs/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "./certs/$domain.key"
done

# Restart services that use certificates
docker-compose restart nginx
docker-compose restart api-server
```

#### Container Health Check Pattern
```bash
#!/bin/bash
# Verify container health after certificate update

check_container_health() {
    local container=$1
    local health_endpoint=$2
    
    if docker exec "$container" curl -sf "$health_endpoint" >/dev/null 2>&1; then
        echo "$container: healthy"
        return 0
    else
        echo "$container: unhealthy"
        return 1
    fi
}

# Update certificates
update_container_certificates

# Check health
check_container_health "nginx-proxy" "http://localhost/health"
check_container_health "app-server" "http://localhost:8080/health"
```

### 2. Kubernetes Hook Concepts

#### Secret Update Pattern
```bash
#!/bin/bash
# Update Kubernetes TLS secrets

update_k8s_secret() {
    local domain=$1
    local namespace=$2
    local secret_name="${domain//./-}-tls"
    
    kubectl create secret tls "$secret_name" \
        --cert="/etc/letsencrypt/live/$domain/fullchain.pem" \
        --key="/etc/letsencrypt/live/$domain/privkey.pem" \
        --dry-run=client -o yaml | \
    kubectl apply -n "$namespace" -f -
    
    echo "Updated secret $secret_name in namespace $namespace"
}

# Define domain to namespace mappings
declare -A DOMAIN_NAMESPACES=(
    ["api.example.com"]="production"
    ["app.example.com"]="default"
)

for domain in $RENEWED_DOMAINS; do
    namespace="${DOMAIN_NAMESPACES[$domain]:-default}"
    update_k8s_secret "$domain" "$namespace"
done
```

#### Deployment Restart Pattern
```bash
#!/bin/bash
# Restart deployments using updated certificates

restart_deployments() {
    local namespace=$1
    local secret_name=$2
    
    # Find deployments using this secret
    local deployments=$(kubectl get deployments -n "$namespace" -o json | \
        jq -r ".items[] | select(.spec.template.spec.volumes[]?.secret.secretName == \"$secret_name\") | .metadata.name")
    
    for deployment in $deployments; do
        kubectl rollout restart deployment "$deployment" -n "$namespace"
        echo "Restarted deployment $deployment"
    done
}
```

---

## Application-Specific Hooks

### 1. Java Application Concepts

#### Java Keystore Pattern
```bash
#!/bin/bash
# Update Java keystores

KEYSTORE_DIR="/opt/app/keystores"
KEYSTORE_PASSWORD="changeit"

update_java_keystore() {
    local domain=$1
    local keystore_file="$KEYSTORE_DIR/$domain.jks"
    local p12_file="/tmp/$domain.p12"
    
    # Create PKCS12 from PEM
    openssl pkcs12 -export \
        -in "/etc/letsencrypt/live/$domain/fullchain.pem" \
        -inkey "/etc/letsencrypt/live/$domain/privkey.pem" \
        -out "$p12_file" \
        -name "$domain" \
        -passout pass:"$KEYSTORE_PASSWORD"
    
    # Remove existing entry
    keytool -delete -alias "$domain" -keystore "$keystore_file" \
        -storepass "$KEYSTORE_PASSWORD" 2>/dev/null || true
    
    # Import new certificate
    keytool -importkeystore \
        -srckeystore "$p12_file" -srcstoretype PKCS12 \
        -destkeystore "$keystore_file" \
        -srcstorepass "$KEYSTORE_PASSWORD" \
        -deststorepass "$KEYSTORE_PASSWORD"
    
    rm -f "$p12_file"
    chown app:app "$keystore_file"
}

for domain in $RENEWED_DOMAINS; do
    update_java_keystore "$domain"
done

# Restart Java applications
systemctl restart tomcat
systemctl restart spring-boot-app
```

### 2. Node.js Application Concepts

#### PM2 Process Manager Pattern
```bash
#!/bin/bash
# Update Node.js applications managed by PM2

PM2_USER="nodejs"
CERT_DIR="/var/www/certs"

# Copy certificates to application directory
for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$CERT_DIR/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$CERT_DIR/$domain.key"
    chown "$PM2_USER:$PM2_USER" "$CERT_DIR/$domain".*
done

# Reload PM2 applications
sudo -u "$PM2_USER" pm2 reload all

# Check application status
sudo -u "$PM2_USER" pm2 status
```

#### Express.js SSL Context Update
```bash
#!/bin/bash
# Update SSL context for Express.js apps

update_ssl_context() {
    local domain=$1
    local pid_file="/var/run/nodejs-$domain.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        # Send USR1 signal to reload SSL context
        kill -USR1 "$pid" 2>/dev/null
        echo "Sent reload signal to Node.js app for $domain"
    fi
}

for domain in $RENEWED_DOMAINS; do
    update_ssl_context "$domain"
done
```

### 3. .NET Application Concepts

#### .NET Core PFX Pattern
```bash
#!/bin/bash
# Update .NET Core applications

CERT_STORE_DIR="/etc/ssl/dotnet"
APP_DIR="/opt/dotnet-app"

convert_to_pfx() {
    local domain=$1
    local pfx_file="$CERT_STORE_DIR/$domain.pfx"
    
    openssl pkcs12 -export \
        -out "$pfx_file" \
        -inkey "/etc/letsencrypt/live/$domain/privkey.pem" \
        -in "/etc/letsencrypt/live/$domain/fullchain.pem" \
        -passout pass: \
        -name "$domain"
    
    chmod 600 "$pfx_file"
    chown dotnet:dotnet "$pfx_file"
}

update_appsettings() {
    local domain=$1
    local config_file="$APP_DIR/appsettings.json"
    local pfx_path="$CERT_STORE_DIR/$domain.pfx"
    
    # Update certificate path in appsettings.json
    jq ".Kestrel.Certificates.Default.Path = \"$pfx_path\"" "$config_file" > tmp.json
    mv tmp.json "$config_file"
}

for domain in $RENEWED_DOMAINS; do
    convert_to_pfx "$domain"
    update_appsettings "$domain"
done

systemctl restart dotnet-app
```

### 4. Python Application Concepts

#### Django/Flask SSL Context Pattern
```bash
#!/bin/bash
# Update Python web applications

PYTHON_CERT_DIR="/etc/ssl/python-apps"

# Copy certificates for Python applications
for domain in $RENEWED_DOMAINS; do
    cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$PYTHON_CERT_DIR/$domain.crt"
    cp "/etc/letsencrypt/live/$domain/privkey.pem" "$PYTHON_CERT_DIR/$domain.key"
    chown python-app:python-app "$PYTHON_CERT_DIR/$domain".*
done

# Restart Python applications
systemctl restart gunicorn
systemctl restart celery
supervisorctl restart django-app
```

#### WSGI Application Pattern
```bash
#!/bin/bash
# Update WSGI applications (Gunicorn, uWSGI)

reload_wsgi_apps() {
    # Graceful reload for Gunicorn
    if [ -f "/var/run/gunicorn.pid" ]; then
        kill -HUP $(cat /var/run/gunicorn.pid)
        echo "Reloaded Gunicorn"
    fi
    
    # Reload uWSGI
    if command -v uwsgi >/dev/null; then
        uwsgi --reload /var/run/uwsgi.pid
        echo "Reloaded uWSGI"
    fi
}

# Update certificates
copy_certificates_for_python_apps
reload_wsgi_apps
```

---

## Cloud Service Integration

### 1. AWS Integration Concepts

#### S3 Certificate Backup Pattern
```bash
#!/bin/bash
# Backup certificates to AWS S3

S3_BUCKET="company-ssl-certificates"
BACKUP_PREFIX="certificates/$(hostname)"

backup_to_s3() {
    local domain=$1
    local backup_date=$(date +%Y%m%d-%H%M%S)
    
    # Create archive
    tar -czf "/tmp/$domain-$backup_date.tar.gz" -C "/etc/letsencrypt/live" "$domain"
    
    # Upload to S3
    aws s3 cp "/tmp/$domain-$backup_date.tar.gz" \
        "s3://$S3_BUCKET/$BACKUP_PREFIX/$domain/$backup_date.tar.gz"
    
    # Cleanup
    rm -f "/tmp/$domain-$backup_date.tar.gz"
}

for domain in $RENEWED_DOMAINS; do
    backup_to_s3 "$domain"
done
```

#### ELB Certificate Update Pattern
```bash
#!/bin/bash
# Update AWS Application Load Balancer certificates

update_elb_certificate() {
    local domain=$1
    
    # Import certificate to ACM
    local cert_arn=$(aws acm import-certificate \
        --certificate fileb:///etc/letsencrypt/live/$domain/fullchain.pem \
        --private-key fileb:///etc/letsencrypt/live/$domain/privkey.pem \
        --query 'CertificateArn' --output text)
    
    # Update load balancer listener
    aws elbv2 modify-listener \
        --listener-arn "$LISTENER_ARN" \
        --certificates CertificateArn="$cert_arn"
    
    echo "Updated ELB certificate for $domain: $cert_arn"
}
```

### 2. Azure Integration Concepts

#### Key Vault Upload Pattern
```bash
#!/bin/bash
# Upload certificates to Azure Key Vault

KEYVAULT_NAME="company-certificates"

upload_to_keyvault() {
    local domain=$1
    local cert_name="${domain//./-}-certificate"
    local pfx_file="/tmp/$domain.pfx"
    
    # Create PFX for Azure
    openssl pkcs12 -export \
        -out "$pfx_file" \
        -inkey "/etc/letsencrypt/live/$domain/privkey.pem" \
        -in "/etc/letsencrypt/live/$domain/fullchain.pem" \
        -passout pass:
    
    # Upload to Key Vault
    az keyvault certificate import \
        --vault-name "$KEYVAULT_NAME" \
        --name "$cert_name" \
        --file "$pfx_file"
    
    rm -f "$pfx_file"
}

for domain in $RENEWED_DOMAINS; do
    upload_to_keyvault "$domain"
done
```

### 3. Google Cloud Integration Concepts

#### Secret Manager Pattern
```bash
#!/bin/bash
# Upload to Google Cloud Secret Manager

GCP_PROJECT="company-ssl-project"

upload_to_secret_manager() {
    local domain=$1
    local cert_secret="${domain//./-}-certificate"
    local key_secret="${domain//./-}-private-key"
    
    # Upload certificate
    gcloud secrets versions add "$cert_secret" \
        --data-file="/etc/letsencrypt/live/$domain/fullchain.pem" \
        --project="$GCP_PROJECT"
    
    # Upload private key
    gcloud secrets versions add "$key_secret" \
        --data-file="/etc/letsencrypt/live/$domain/privkey.pem" \
        --project="$GCP_PROJECT"
}

for domain in $RENEWED_DOMAINS; do
    upload_to_secret_manager "$domain"
done
```

## Advanced Application Concepts

### 1. Zero-Downtime Deployment Pattern
```bash
#!/bin/bash
# Zero-downtime certificate updates

perform_zero_downtime_update() {
    local service=$1
    
    # Create temporary service with new certificates
    systemctl start "$service-temp"
    sleep 2
    
    # Health check
    if check_service_health "$service-temp"; then
        # Switch traffic
        systemctl stop "$service"
        systemctl stop "$service-temp"
        systemctl start "$service"
        echo "Zero-downtime update completed for $service"
    else
        systemctl stop "$service-temp"
        echo "Update failed, keeping original service"
        return 1
    fi
}
```

### 2. Certificate Validation Framework
```bash
#!/bin/bash
# Comprehensive validation framework

validate_certificate_chain() {
    local domain=$1
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    
    # Basic validation
    openssl x509 -in "$cert_path" -noout -text | grep -q "Signature Algorithm"
    
    # Chain validation
    openssl verify -CAfile "$cert_path" "$cert_path" >/dev/null 2>&1
    
    # Expiry check (30 days)
    openssl x509 -in "$cert_path" -noout -checkend 2592000
    
    echo "Certificate validation passed for $domain"
}

validate_service_integration() {
    local domain=$1
    local service=$2
    
    case "$service" in
        "nginx"|"apache")
            curl -sSf "https://$domain" >/dev/null
            ;;
        "postfix")
            echo "QUIT" | openssl s_client -connect "$domain:587" -starttls smtp >/dev/null 2>&1
            ;;
        "mysql")
            mysql -h "$domain" -e "SELECT 1;" --ssl-mode=REQUIRED >/dev/null 2>&1
            ;;
    esac
}
```

### 3. Rollback Mechanism
```bash
#!/bin/bash
# Automated rollback on failure

BACKUP_DIR="/var/backups/certificates"

create_backup() {
    local timestamp=$(date +%Y%m%d-%H%M%S)
    mkdir -p "$BACKUP_DIR/$timestamp"
    
    for domain in $RENEWED_DOMAINS; do
        cp -r "/etc/letsencrypt/live/$domain" "$BACKUP_DIR/$timestamp/"
    done
    
    echo "$timestamp" > "$BACKUP_DIR/latest"
}

rollback_certificates() {
    local latest_backup=$(cat "$BACKUP_DIR/latest" 2>/dev/null)
    
    if [ -n "$latest_backup" ] && [ -d "$BACKUP_DIR/$latest_backup" ]; then
        cp -r "$BACKUP_DIR/$latest_backup"/* "/etc/letsencrypt/live/"
        echo "Rolled back to backup: $latest_backup"
        return 0
    else
        echo "No backup available for rollback"
        return 1
    fi
}

# Main hook logic with rollback
create_backup

if ! update_all_services; then
    echo "Service update failed, rolling back..."
    rollback_certificates
    restart_all_services
    exit 1
fi
```

### 4. Multi-Environment Management
```bash
#!/bin/bash
# Handle different environments

determine_environment() {
    if [[ $(hostname) == *"prod"* ]]; then
        echo "production"
    elif [[ $(hostname) == *"staging"* ]]; then
        echo "staging"
    else
        echo "development"
    fi
}

get_services_for_environment() {
    local env=$1
    
    case "$env" in
        "production")
            echo "nginx haproxy postfix mysql"
            ;;
        "staging")
            echo "nginx mysql"
            ;;
        "development")
            echo "nginx"
            ;;
    esac
}

# Environment-specific logic
ENVIRONMENT=$(determine_environment)
SERVICES=$(get_services_for_environment "$ENVIRONMENT")

echo "Environment: $ENVIRONMENT"
echo "Services to update: $SERVICES"

for service in $SERVICES; do
    update_service_certificates "$service"
done
```

This concludes Part 3, covering container services, application-specific patterns, and cloud integrations with focus on practical concepts and reusable patterns.