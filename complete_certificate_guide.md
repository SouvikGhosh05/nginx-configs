# Complete Certificate Issuance Methods - Master Guide

## Table of Contents
1. [Overview & Fundamentals](#overview--fundamentals)
2. [Basic Certbot Methods](#basic-certbot-methods)
3. [Server State-Based Approaches](#server-state-based-approaches)
4. [DNS Challenge Methods](#dns-challenge-methods)
5. [Alternative ACME Clients](#alternative-acme-clients)
6. [Automated Server Integration](#automated-server-integration)
7. [IP-to-Domain Services](#ip-to-domain-services)
8. [Container & Docker Methods](#container--docker-methods)
9. [Enterprise & Cloud Solutions](#enterprise--cloud-solutions)
10. [Programming Language Integrations](#programming-language-integrations)
11. [Specialized Use Cases](#specialized-use-cases)
12. [Renewal & Automation](#renewal--automation)
13. [Troubleshooting & Best Practices](#troubleshooting--best-practices)

---

## Overview & Fundamentals

### What is ACME and Let's Encrypt?
- **ACME (Automatic Certificate Management Environment)**: Protocol for automating interactions between certificate authorities and users' servers
- **Let's Encrypt**: Free, automated, and open Certificate Authority using ACME protocol
- **Certificate Lifetime**: 90 days with automatic renewal recommended
- **Challenge Types**: HTTP-01, DNS-01, TLS-ALPN-01
- **Rate Limits**: 5 duplicate certificates per week per domain

### Core Concepts
- **Domain Validation (DV)**: Let's Encrypt only offers DV certificates
- **Certificate Authority (CA)**: Entity that issues digital certificates
- **Certificate Signing Request (CSR)**: Request for a digital certificate
- **Subject Alternative Names (SANs)**: Additional domains in a single certificate

---

## Basic Certbot Methods

### 1. Installation
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install certbot

# CentOS/RHEL
sudo yum install certbot

# Snap (universal)
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot

# With plugins
sudo apt install python3-certbot-nginx python3-certbot-apache
sudo apt install python3-certbot-dns-cloudflare python3-certbot-dns-route53
```

### 2. Basic Certificate Generation
```bash
# Simplest form - certonly
sudo certbot certonly -d example.com

# With email and agreement
sudo certbot certonly -d example.com \
  --agree-tos --email admin@example.com

# Multiple domains
sudo certbot certonly -d example.com -d www.example.com -d api.example.com

# Wildcard certificate (requires DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.example.com" -d example.com
```

---

## Server State-Based Approaches

### 1. Server Running (Zero Downtime Methods)

#### Webroot Method (Recommended for Production)
```bash
# Basic webroot
sudo certbot certonly --webroot -w /var/www/html -d example.com

# Multiple domains with same webroot
sudo certbot certonly --webroot -w /var/www/html \
  -d example.com -d www.example.com -d api.example.com

# Different webroots for different domains
sudo certbot certonly \
  --webroot -w /var/www/main -d example.com \
  --webroot -w /var/www/api -d api.example.com

# Custom webroot location
sudo certbot certonly --webroot -w /opt/webapp/public -d example.com
```

**Nginx Configuration for Webroot:**
```nginx
server {
    listen 80;
    server_name example.com;
    root /var/www/html;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files $uri =404;
    }
}
```

#### Plugin Methods (Automatic Configuration)
```bash
# Nginx plugin - generates cert + configures SSL + redirects
sudo certbot --nginx -d example.com

# Apache plugin - same functionality for Apache
sudo certbot --apache -d example.com

# Multiple domains with plugin
sudo certbot --nginx -d example.com -d www.example.com

# With specific options
sudo certbot --nginx -d example.com \
  --redirect --agree-tos --email admin@example.com
```

### 2. Server Not Running

#### Standalone Method
```bash
# Basic standalone (server must be stopped)
sudo systemctl stop nginx
sudo certbot certonly --standalone -d example.com
sudo systemctl start nginx

# With automatic service management
sudo certbot certonly --standalone -d example.com \
  --pre-hook "systemctl stop nginx" \
  --post-hook "systemctl start nginx"

# Multiple domains standalone
sudo certbot certonly --standalone \
  -d example.com -d www.example.com -d api.example.com
```

### 3. Instant HTTPS Activation

#### One-Command HTTPS Setup
```bash
# Nginx - Complete HTTPS setup in one command
sudo certbot --nginx -d example.com \
  --noninteractive --agree-tos --email admin@example.com --redirect

# Without email (not recommended for production)
sudo certbot --nginx -d example.com \
  --noninteractive --agree-tos --register-unsafely-without-email --redirect

# Apache equivalent
sudo certbot --apache -d example.com \
  --noninteractive --agree-tos --email admin@example.com --redirect

# Multiple domains instant setup
sudo certbot --nginx \
  -d example.com -d www.example.com -d api.example.com \
  --noninteractive --agree-tos --email admin@example.com --redirect
```

---

## DNS Challenge Methods

### 1. Manual DNS Challenge
```bash
# Basic manual DNS challenge
sudo certbot certonly --manual --preferred-challenges dns -d example.com

# Wildcard certificate
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.example.com" -d example.com

# With email and agreement
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.example.com" --agree-tos --email admin@example.com
```

### 2. Automated DNS Plugins

#### Cloudflare DNS Plugin
```bash
# Install plugin
sudo apt install python3-certbot-dns-cloudflare

# Create credentials file
cat > ~/.secrets/cloudflare.ini << EOF
# Cloudflare API token (recommended)
dns_cloudflare_api_token = your_token_here

# Or Global API Key (less secure)
dns_cloudflare_email = your-email@example.com
dns_cloudflare_api_key = your_global_api_key
EOF

chmod 600 ~/.secrets/cloudflare.ini

# Request certificate
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d example.com

# Wildcard certificate
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d "*.example.com" -d example.com

# With propagation delay
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 120 \
  -d example.com
```

#### AWS Route53 DNS Plugin
```bash
# Install plugin
sudo apt install python3-certbot-dns-route53

# Configure AWS credentials
aws configure
# OR set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key

# Request certificate
sudo certbot certonly --dns-route53 -d example.com

# Wildcard certificate
sudo certbot certonly --dns-route53 -d "*.example.com" -d example.com
```

**Required IAM Policy for Route53:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetChange"
      ],
      "Resource": ["*"]
    },
    {
      "Effect": "Allow",
      "Action": ["route53:ChangeResourceRecordSets"],
      "Resource": ["arn:aws:route53:::hostedzone/ZONE_ID"]
    }
  ]
}
```

#### DigitalOcean DNS Plugin
```bash
# Install plugin
sudo apt install python3-certbot-dns-digitalocean

# Create credentials file
echo "dns_digitalocean_token = your_token_here" > ~/.secrets/digitalocean.ini
chmod 600 ~/.secrets/digitalocean.ini

# Request certificate
sudo certbot certonly --dns-digitalocean \
  --dns-digitalocean-credentials ~/.secrets/digitalocean.ini \
  -d example.com
```

#### Other DNS Plugins
Available DNS plugins include:
- `certbot-dns-dnsimple`
- `certbot-dns-dnsmadeeasy`
- `certbot-dns-gehirn`
- `certbot-dns-google`
- `certbot-dns-linode`
- `certbot-dns-luadns`
- `certbot-dns-nsone`
- `certbot-dns-ovh`
- `certbot-dns-rfc2136`

---

## Alternative ACME Clients

### 1. acme.sh (Pure Shell Script)
A pure Unix shell script implementing ACME client protocol.

```bash
# Install acme.sh
curl https://get.acme.sh | sh
source ~/.bashrc

# Basic HTTP challenge
acme.sh --issue -d example.com --webroot /var/www/html

# Standalone mode
acme.sh --issue -d example.com --standalone

# Nginx mode
acme.sh --issue -d example.com --nginx

# Apache mode
acme.sh --issue -d example.com --apache

# DNS challenge with Cloudflare
export CF_Key="your-api-key"
export CF_Email="your-email@example.com"
acme.sh --issue --dns dns_cf -d example.com

# Wildcard certificate
acme.sh --issue --dns dns_cf -d "*.example.com" -d example.com

# Install certificate
acme.sh --install-cert -d example.com \
  --key-file /etc/nginx/ssl/example.com.key \
  --fullchain-file /etc/nginx/ssl/example.com.crt \
  --reloadcmd "systemctl reload nginx"

# Force renewal
acme.sh --renew -d example.com --force

# List certificates
acme.sh --list

# Remove certificate
acme.sh --remove -d example.com
```

### 2. Lego (Go-based Client)
Popular command-line ACME client written in Go.

```bash
# Download and install lego
wget https://github.com/go-acme/lego/releases/download/v4.14.2/lego_v4.14.2_linux_amd64.tar.gz
tar -xzf lego_*.tar.gz
sudo mv lego /usr/local/bin/

# HTTP challenge
lego --email="admin@example.com" -d example.com --http run

# Standalone mode
lego --email="admin@example.com" -d example.com --http --http.port 80 run

# DNS challenge with Cloudflare
export CLOUDFLARE_EMAIL="your-email@example.com"
export CLOUDFLARE_API_KEY="your-api-key"
lego --email="admin@example.com" -d example.com --dns cloudflare run

# Wildcard certificate
lego --email="admin@example.com" -d "*.example.com" --dns cloudflare run

# Custom certificate storage
lego --email="admin@example.com" -d example.com --path /etc/ssl/certs --http run

# Renew certificates
lego --email="admin@example.com" -d example.com --http renew

# Renew if expiring within 30 days
lego --email="admin@example.com" -d example.com --http renew --days 30
```

### 3. Windows ACME Clients

#### win-acme (Command Line)
```powershell
# Simple certificate request
wacs.exe --target manual --host example.com

# Multiple domains
wacs.exe --target manual --host example.com,www.example.com

# Automatic IIS installation
wacs.exe --target iis --siteid 1

# Store certificate in Windows Certificate Store
wacs.exe --target manual --host example.com --store certificatestore

# Custom validation
wacs.exe --target manual --host example.com --validation dns --validationmode manual
```

#### Posh-ACME (PowerShell Module)
```powershell
# Install module
Install-Module -Name Posh-ACME -Force

# Set ACME server
Set-PAServer LE_PROD

# Basic certificate
New-PACertificate -Domain example.com -AcceptTOS -Contact admin@example.com

# Multiple domains
New-PACertificate -Domain example.com,www.example.com -AcceptTOS

# DNS challenge with Cloudflare
$token = Read-Host "Cloudflare API Token" -AsSecureString
New-PACertificate -Domain "*.example.com" -Plugin Cloudflare -PluginArgs @{CFToken=$token}

# List certificates
Get-PACertificate

# Renew certificate
Submit-Renewal example.com
```

#### Certify The Web (GUI Application)
- User-friendly graphical interface for Windows
- IIS integration and automatic installation
- Support for multiple validation methods
- Commercial support and enterprise features
- Dashboard and certificate monitoring

---

## Automated Server Integration

### 1. Traefik Reverse Proxy
Traefik automatically generates and manages certificates using ACME.

#### Basic Traefik Configuration
```yaml
# traefik.yml
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: acme.json
      httpChallenge:
        entryPoint: web
      # Alternative: DNS challenge
      # dnsChallenge:
      #   provider: cloudflare
      #   delayBeforeCheck: 0
```

#### Docker Compose with Traefik
```yaml
version: '3.8'
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.dashboard=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./letsencrypt:/letsencrypt"
    labels:
      - "traefik.enable=true"

  app:
    image: nginx:alpine
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`example.com`)"
      - "traefik.http.routers.app.entrypoints=websecure"
      - "traefik.http.routers.app.tls.certresolver=letsencrypt"
      - "traefik.http.routers.app-insecure.rule=Host(`example.com`)"
      - "traefik.http.routers.app-insecure.entrypoints=web"
      - "traefik.http.routers.app-insecure.middlewares=redirect-to-https"
      - "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
```

#### Traefik with DNS Challenge
```yaml
# docker-compose.yml with DNS challenge
version: '3.8'
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--certificatesresolvers.letsencrypt.acme.dnschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.dnschallenge.provider=cloudflare"
    environment:
      - CF_API_EMAIL=your-email@example.com
      - CF_API_KEY=your-api-key
    # ... rest of configuration
```

### 2. Caddy Web Server
Caddy provides automatic HTTPS with zero configuration.

#### Basic Caddyfile
```caddyfile
# Automatic HTTPS for any domain
example.com {
    root * /var/www/html
    file_server
}

# Multiple sites
example.com {
    root * /var/www/example
    file_server
}

api.example.com {
    reverse_proxy localhost:3000
}

# Custom ACME settings
example.com {
    root * /var/www/html
    file_server
    tls admin@example.com {
        ca https://acme-v02.api.letsencrypt.org/directory
    }
}

# Wildcard with DNS challenge
*.example.com {
    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
    respond "Hello from {host}"
}

# On-demand TLS (advanced)
*.example.com {
    tls {
        on_demand
    }
    respond "On-demand certificate for {host}"
}
```

#### Caddy with Docker
```dockerfile
# Dockerfile
FROM caddy:alpine
COPY Caddyfile /etc/caddy/Caddyfile
COPY www /var/www/html
```

```bash
# Run Caddy with automatic HTTPS
docker run -d -p 80:80 -p 443:443 \
  -v $PWD/Caddyfile:/etc/caddy/Caddyfile \
  -v $PWD/data:/data \
  -v $PWD/config:/config \
  caddy:alpine
```

### 3. Apache mod_md
Apache HTTP Server with automatic certificate management.

```apache
# Apache configuration with mod_md
LoadModule md_module modules/mod_md.so

# Configure domains for automatic certificates
MDomain example.com www.example.com
MDomain api.example.com

# ACME settings
MDCertificateAgreement accepted
MDContactEmail admin@example.com
MDCAChallenges http-01 tls-alpn-01

# Optional: staging for testing
# MDCertificateAuthority https://acme-staging-v02.api.letsencrypt.org/directory

# DNS challenge with external script
# MDChallengeDns01 /path/to/dns-challenge-script.sh

# Virtual host configuration
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/html
    
    SSLEngine on
    # mod_md will handle certificate configuration automatically
</VirtualHost>

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

---

## IP-to-Domain Services

### 1. Service Comparison

| Service | IPv6 Support | Custom Domains | Wildcard Support | Example Format |
|---------|-------------|----------------|------------------|----------------|
| nip.io | No | No | Yes | app.192.168.1.1.nip.io |
| sslip.io | Yes | Yes | Yes | app.192-168-1-1.sslip.io |
| xip.io | No | No | Deprecated | app.192.168.1.1.xip.io |

### 2. nip.io Usage Examples
```bash
# Your original example
sudo certbot --nginx -d st-momentum.35.244.6.123.nip.io \
  --noninteractive --agree-tos --register-unsafely-without-email --redirect

# Development environment
LOCAL_IP=$(hostname -I | awk '{print $1}')
sudo certbot --nginx -d dev.$LOCAL_IP.nip.io \
  --noninteractive --agree-tos --email dev@company.com --redirect

# Multiple services on same IP
sudo certbot --nginx \
  -d api.35.244.6.123.nip.io \
  -d web.35.244.6.123.nip.io \
  -d admin.35.244.6.123.nip.io \
  --noninteractive --agree-tos --email admin@company.com --redirect

# Cloud instance automation
CLOUD_IP=$(curl -s ifconfig.me)
sudo certbot --nginx -d myapp.$CLOUD_IP.nip.io \
  --noninteractive --agree-tos --email ops@company.com --redirect
```

### 3. sslip.io Usage Examples
```bash
# Basic usage (supports IPv6)
sudo certbot --nginx -d app.192.168.1.100.sslip.io \
  --noninteractive --agree-tos --email admin@company.com --redirect

# Dash notation for IPs
sudo certbot --nginx -d app.192-168-1-100.sslip.io \
  --noninteractive --agree-tos --email admin@company.com --redirect

# IPv6 support
sudo certbot --nginx -d app.--1.sslip.io \
  --noninteractive --agree-tos --email admin@company.com --redirect

# Custom domain branding
# Set NS records for subdomain to point to sslip.io nameservers
# Then use: app.xip.yourdomain.com
```

### 4. Wildcard Certificates for IP Services
```bash
# Wildcard for nip.io domain (requires DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.35.244.6.123.nip.io" -d "35.244.6.123.nip.io" \
  --agree-tos --email admin@company.com

# Using acme.sh for wildcard with custom DNS
acme.sh --issue --dns dns_cf \
  -d "*.52-0-56-137.sslip.io" -d "52-0-56-137.sslip.io"

# Manual process for wildcard
# 1. Request certificate with manual DNS
# 2. Add TXT record to DNS
# 3. Complete validation
```

---

## Container & Docker Methods

### 1. Docker Standalone Certbot
```bash
# Standalone mode
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  -p 80:80 \
  certbot/certbot certonly --standalone -d example.com

# Webroot mode
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  -v "/var/www/html:/var/www/html" \
  certbot/certbot certonly --webroot -w /var/www/html -d example.com

# DNS challenge with Cloudflare
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  -v "/path/to/credentials:/credentials" \
  certbot/dns-cloudflare certonly \
  --dns-cloudflare --dns-cloudflare-credentials /credentials/cloudflare.ini \
  -d example.com

# Certificate renewal
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  certbot/certbot renew
```

### 2. Docker Compose with Certbot
```yaml
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./www:/var/www/html
      - certbot-etc:/etc/letsencrypt
      - certbot-var:/var/lib/letsencrypt
    depends_on:
      - certbot

  certbot:
    image: certbot/certbot
    volumes:
      - certbot-etc:/etc/letsencrypt
      - certbot-var:/var/lib/letsencrypt
      - ./www:/var/www/html
    command: certonly --webroot -w /var/www/html -d example.com --agree-tos --email admin@example.com

volumes:
  certbot-etc:
  certbot-var:
```

### 3. Automated Certificate Renewal with Docker
```bash
# Renewal script
#!/bin/bash
# renew-certs.sh
docker run --rm \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  -v "/var/www/html:/var/www/html" \
  certbot/certbot renew --webroot -w /var/www/html

# Reload nginx after renewal
docker exec nginx nginx -s reload

# Add to crontab
echo "0 12 * * * /path/to/renew-certs.sh" | crontab -
```

---

## Enterprise & Cloud Solutions

### 1. DigiCert CertCentral with ACME
```bash
# Using Certbot with DigiCert
certbot certonly \
  --server https://acme.digicert.com/v2/acme/directory \
  --eab-kid your-external-account-binding-key-id \
  --eab-hmac-key your-external-account-binding-hmac-key \
  --email admin@example.com \
  --agree-tos \
  -d example.com

# OV/EV certificates with custom validity
certbot certonly \
  --server https://acme.digicert.com/v2/acme/directory \
  --eab-kid your-key-id \
  --eab-hmac-key your-hmac-key \
  --preferred-challenges http \
  --cert-name example-ov \
  -d example.com
```

### 2. SSL.com ACME Service
```bash
# ECC certificate
certbot certonly \
  --server https://acme.ssl.com/sslcom-dv-ecc \
  --eab-kid your-account-key \
  --eab-hmac-key your-hmac-key \
  --email admin@example.com \
  --agree-tos \
  -d example.com

# RSA certificate
certbot certonly \
  --server https://acme.ssl.com/sslcom-dv-rsa \
  --eab-kid your-account-key \
  --eab-hmac-key your-hmac-key \
  --key-type rsa \
  --email admin@example.com \
  --agree-tos \
  -d example.com
```

### 3. ZeroSSL Integration
```bash
# Using ZeroSSL with certbot
certbot certonly \
  --server https://acme.zerossl.com/v2/DV90 \
  --eab-kid your-key-id \
  --eab-hmac-key your-hmac-key \
  --email admin@example.com \
  --agree-tos \
  -d example.com

# ZeroSSL API integration
curl -X POST https://api.zerossl.com/certificates \
  -H "Authorization: Bearer your-api-key" \
  -d "certificate_domains=example.com" \
  -d "certificate_validity_days=90"
```

### 4. Azure Key Vault Integration
```bash
# Azure CLI certificate management
az keyvault certificate create \
  --vault-name MyVault \
  --name example-com \
  --policy '{
    "issuerParameters": {
      "name": "DigiCert"
    },
    "keyProperties": {
      "keyType": "RSA",
      "keySize": 2048
    },
    "x509CertificateProperties": {
      "subject": "CN=example.com"
    }
  }'

# Using Key Vault Acmebot
# Deploy using ARM template or Terraform
# Automatically manages Let's Encrypt certificates in Key Vault
```

---

## Programming Language Integrations

### 1. Go Integration with CertMagic
```go
package main

import (
    "log"
    "net/http"
    "github.com/caddyserver/certmagic"
)

func main() {
    // Simple automatic HTTPS
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, HTTPS!"))
    })
    
    // One line for automatic HTTPS
    log.Fatal(certmagic.HTTPS([]string{"example.com"}, mux))
}

// Advanced configuration
func advancedExample() {
    // Configure ACME settings
    certmagic.DefaultACME.Agreed = true
    certmagic.DefaultACME.Email = "admin@example.com"
    certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
    
    // Custom storage
    cfg := certmagic.NewDefault()
    cfg.Storage = &certmagic.FileStorage{Path: "/etc/certificates"}
    
    // DNS challenge
    cfg.Issuers = []certmagic.Issuer{
        &certmagic.ACMEIssuer{
            Agreed:  true,
            Email:   "admin@example.com",
            CA:      certmagic.LetsEncryptProductionCA,
            DNS01Solver: &certmagic.DNS01Solver{
                DNSProvider: cloudflareProvider, // implement DNSProvider interface
            },
        },
    }
    
    // Manage certificates
    err := cfg.ManageSync([]string{"example.com"})
    if err != nil {
        log.Fatal(err)
    }
    
    // Start HTTPS server
    srv := &http.Server{
        Addr:    ":443",
        Handler: mux,
        TLSConfig: cfg.TLSConfig(),
    }
    
    log.Fatal(srv.ListenAndServeTLS("", ""))
}

// On-Demand TLS example
func onDemandExample() {
    certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
        DecisionFunc: func(name string) error {
            // Allow certificates for subdomains of example.com
            if strings.HasSuffix(name, ".example.com") {
                return nil
            }
            return fmt.Errorf("domain not allowed: %s", name)
        },
    }
    
    // Server will automatically get certificates for any valid subdomain
    log.Fatal(http.ListenAndServe(":443", certmagic.HTTPSRedirectHandler(mux)))
}
```

### 2. Python Integration
```python
# Using python-acme library
from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
import josepy as jose

class ACMEClient:
    def __init__(self, directory_url, email):
        self.directory_url = directory_url
        self.email = email
        self.account_key = self._generate_account_key()
        self.client = self._create_client()
        
    def _generate_account_key(self):
        """Generate RSA key for ACME account"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return jose.JWKRSA(key=private_key)
    
    def _create_client(self):
        """Create ACME client"""
        directory = messages.Directory.from_json(
            requests.get(self.directory_url).json()
        )
        net = client.ClientNetwork(self.account_key)
        return client.ClientV2(directory, net=net)
    
    def register_account(self):
        """Register new ACME account"""
        regr = messages.NewRegistration.from_data(
            email=self.email,
            terms_of_service_agreed=True
        )
        return self.client.new_account(regr)
    
    def request_certificate(self, domains, challenge_type='http-01'):
        """Request certificate for domains"""
        # Generate private key for certificate
        cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
        )
        
        # Add SANs
        if len(domains) > 1:
            csr = csr.add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain) for domain in domains
                ]),
                critical=False
            )
        
        csr = csr.sign(cert_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # Create order
        order = self.client.new_order(csr_pem)
        
        # Process challenges
        for authz in order.authorizations:
            self._process_challenge(authz, challenge_type)
        
        # Finalize order
        order = self.client.poll_and_finalize(order)
        
        return order.fullchain_pem, cert_key
    
    def _process_challenge(self, authz, challenge_type):
        """Process ACME challenge"""
        domain = authz.body.identifier.value
        
        # Find the appropriate challenge
        challenge = None
        for chall in authz.body.challenges:
            if chall.typ == challenge_type:
                challenge = chall
                break
        
        if not challenge:
            raise ValueError(f"Challenge type {challenge_type} not available")
        
        # Create challenge response
        response, validation = challenge.response_and_validation(self.account_key)
        
        if challenge_type == 'http-01':
            # HTTP challenge - create file
            token = challenge.encode("token")
            self._create_http_challenge_file(token, validation)
        elif challenge_type == 'dns-01':
            # DNS challenge - create TXT record
            self._create_dns_challenge_record(domain, validation)
        
        # Answer challenge
        self.client.answer_challenge(challenge, response)
        
        # Poll for validation
        self.client.poll(authz)

# Usage example
def main():
    # Initialize client
    acme_client = ACMEClient(
        directory_url="https://acme-v02.api.letsencrypt.org/directory",
        email="admin@example.com"
    )
    
    # Register account
    account = acme_client.register_account()
    print(f"Account registered: {account.uri}")
    
    # Request certificate
    domains = ["example.com", "www.example.com"]
    cert_pem, private_key = acme_client.request_certificate(domains)
    
    # Save certificate and key
    with open("/etc/ssl/certs/example.com.crt", "w") as f:
        f.write(cert_pem.decode())
    
    with open("/etc/ssl/private/example.com.key", "w") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode())

if __name__ == "__main__":
    main()
```

### 3. Node.js Integration
```javascript
// Using node-acme-client
const acme = require('acme-client');
const fs = require('fs').promises;
const path = require('path');

class ACMEManager {
    constructor(email, staging = false) {
        this.email = email;
        this.directoryUrl = staging 
            ? acme.directory.letsencrypt.staging 
            : acme.directory.letsencrypt.production;
        this.accountKey = null;
        this.client = null;
    }
    
    async initialize() {
        // Create account key
        this.accountKey = await acme.crypto.createPrivateKey();
        
        // Create ACME client
        this.client = new acme.Client({
            directoryUrl: this.directoryUrl,
            accountKey: this.accountKey
        });
        
        console.log('ACME client initialized');
    }
    
    async requestCertificate(domains, challengeType = 'http-01') {
        if (!this.client) {
            throw new Error('Client not initialized. Call initialize() first.');
        }
        
        // Create private key and CSR
        const [key, csr] = await acme.crypto.createCsr({
            commonName: domains[0],
            altNames: domains.slice(1)
        });
        
        // Request certificate
        const cert = await this.client.auto({
            csr,
            email: this.email,
            termsOfServiceAgreed: true,
            challengeCreateFn: async (authz, challenge, keyAuthorization) => {
                console.log(`Creating challenge for ${authz.identifier.value}`);
                
                if (challenge.type === 'http-01') {
                    await this.createHttpChallenge(challenge.token, keyAuthorization);
                } else if (challenge.type === 'dns-01') {
                    await this.createDnsChallenge(authz.identifier.value, keyAuthorization);
                }
            },
            challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
                console.log(`Removing challenge for ${authz.identifier.value}`);
                
                if (challenge.type === 'http-01') {
                    await this.removeHttpChallenge(challenge.token);
                } else if (challenge.type === 'dns-01') {
                    await this.removeDnsChallenge(authz.identifier.value);
                }
            }
        });
        
        return { certificate: cert, privateKey: key };
    }
    
    async createHttpChallenge(token, keyAuthorization) {
        const challengePath = path.join('/var/www/html/.well-known/acme-challenge', token);
        await fs.mkdir(path.dirname(challengePath), { recursive: true });
        await fs.writeFile(challengePath, keyAuthorization);
        console.log(`HTTP challenge created: ${challengePath}`);
    }
    
    async removeHttpChallenge(token) {
        const challengePath = path.join('/var/www/html/.well-known/acme-challenge', token);
        try {
            await fs.unlink(challengePath);
            console.log(`HTTP challenge removed: ${challengePath}`);
        } catch (err) {
            console.warn(`Failed to remove challenge file: ${err.message}`);
        }
    }
    
    async createDnsChallenge(domain, keyAuthorization) {
        // Implement DNS provider integration
        console.log(`Create DNS TXT record for _acme-challenge.${domain}`);
        console.log(`Value: ${keyAuthorization}`);
        // Example: await dnsProvider.createTxtRecord(`_acme-challenge.${domain}`, keyAuthorization);
    }
    
    async removeDnsChallenge(domain) {
        // Implement DNS provider cleanup
        console.log(`Remove DNS TXT record for _acme-challenge.${domain}`);
        // Example: await dnsProvider.deleteTxtRecord(`_acme-challenge.${domain}`);
    }
    
    async saveCertificate(domains, certificate, privateKey, certDir = '/etc/ssl') {
        const domain = domains[0];
        const certPath = path.join(certDir, 'certs', `${domain}.crt`);
        const keyPath = path.join(certDir, 'private', `${domain}.key`);
        
        // Ensure directories exist
        await fs.mkdir(path.dirname(certPath), { recursive: true });
        await fs.mkdir(path.dirname(keyPath), { recursive: true });
        
        // Save certificate and key
        await fs.writeFile(certPath, certificate);
        await fs.writeFile(keyPath, privateKey);
        
        // Set proper permissions
        await fs.chmod(keyPath, 0o600);
        
        console.log(`Certificate saved: ${certPath}`);
        console.log(`Private key saved: ${keyPath}`);
        
        return { certPath, keyPath };
    }
}

// Express.js middleware for automatic HTTPS
function createHttpsMiddleware(acmeManager) {
    return async (req, res, next) => {
        const hostname = req.get('host');
        
        // Check if certificate exists
        const certExists = await checkCertificateExists(hostname);
        
        if (!certExists) {
            try {
                console.log(`Requesting certificate for ${hostname}`);
                const { certificate, privateKey } = await acmeManager.requestCertificate([hostname]);
                await acmeManager.saveCertificate([hostname], certificate, privateKey);
                
                // Restart HTTPS server with new certificate
                await restartHttpsServer();
            } catch (err) {
                console.error(`Failed to get certificate for ${hostname}:`, err);
                return res.status(500).send('Certificate generation failed');
            }
        }
        
        next();
    };
}

// Usage example
async function main() {
    const acmeManager = new ACMEManager('admin@example.com', false); // production
    await acmeManager.initialize();
    
    try {
        // Request certificate for multiple domains
        const domains = ['example.com', 'www.example.com'];
        const { certificate, privateKey } = await acmeManager.requestCertificate(domains);
        
        // Save certificate
        await acmeManager.saveCertificate(domains, certificate, privateKey);
        
        console.log('Certificate obtained and saved successfully!');
    } catch (err) {
        console.error('Certificate request failed:', err);
    }
}

// Express.js integration example
const express = require('express');
const https = require('https');

async function createServer() {
    const app = express();
    const acmeManager = new ACMEManager('admin@example.com');
    await acmeManager.initialize();
    
    // Add ACME middleware for automatic certificate generation
    app.use(createHttpsMiddleware(acmeManager));
    
    app.get('/', (req, res) => {
        res.send('Hello, HTTPS!');
    });
    
    // HTTP server for ACME challenges
    app.listen(80, () => {
        console.log('HTTP server listening on port 80');
    });
    
    // HTTPS server
    const httpsOptions = {
        // Load certificates dynamically
        SNICallback: async (servername, callback) => {
            try {
                const cert = await loadCertificate(servername);
                callback(null, cert);
            } catch (err) {
                callback(err);
            }
        }
    };
    
    https.createServer(httpsOptions, app).listen(443, () => {
        console.log('HTTPS server listening on port 443');
    });
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = { ACMEManager, createHttpsMiddleware };
```

---

## Specialized Use Cases

### 1. Microcontrollers & IoT Devices
```c
// CycloneACME for embedded systems
#include "acme_client.h"
#include "crypto.h"
#include "net_config.h"

typedef struct {
    char* serverUrl;
    char* email;
    char* accountKey;
    char* deviceId;
} AcmeConfig;

// Initialize ACME client for IoT device
error_t acmeIotInit(AcmeConfig* config) {
    error_t error;
    
    // Initialize crypto module
    error = cryptoInit();
    if (error) return error;
    
    // Generate device-specific account key
    error = generateAccountKey(config->deviceId, &config->accountKey);
    if (error) return error;
    
    // Configure ACME server
    error = acmeSetServer(config->serverUrl);
    if (error) return error;
    
    // Register account
    error = acmeRegisterAccount(config->email, config->accountKey);
    if (error) return error;
    
    return NO_ERROR;
}

// Request certificate for IoT device
error_t requestDeviceCertificate(AcmeConfig* config, const char* hostname) {
    error_t error;
    char* csr;
    char* certificate;
    char* privateKey;
    
    // Generate key pair
    error = generateKeyPair(&privateKey, NULL);
    if (error) return error;
    
    // Create CSR
    error = createCsr(hostname, privateKey, &csr);
    if (error) return error;
    
    // Request certificate using TLS-ALPN-01 challenge
    // (suitable for IoT devices with direct internet access)
    error = acmeRequestCert(csr, CHALLENGE_TLS_ALPN_01, &certificate);
    if (error) return error;
    
    // Store certificate in device flash memory
    error = storeDeviceCertificate(certificate, privateKey);
    if (error) return error;
    
    // Schedule automatic renewal
    error = scheduleRenewal(hostname, 60); // 60 days before expiration
    if (error) return error;
    
    return NO_ERROR;
}

// Main IoT certificate management
int main(void) {
    AcmeConfig config = {
        .serverUrl = "https://acme-v02.api.letsencrypt.org/directory",
        .email = "iot@company.com",
        .deviceId = "device-001",
        .accountKey = NULL
    };
    
    // Initialize network
    if (netInit() != NO_ERROR) {
        return -1;
    }
    
    // Initialize ACME
    if (acmeIotInit(&config) != NO_ERROR) {
        return -1;
    }
    
    // Request certificate for device
    char hostname[64];
    snprintf(hostname, sizeof(hostname), "device-001.iot.company.com");
    
    if (requestDeviceCertificate(&config, hostname) != NO_ERROR) {
        return -1;
    }
    
    // Start secure communication
    startSecureServices();
    
    return 0;
}
```

### 2. Private Networks & Internal CAs
```bash
# Using step-ca for private ACME server
# Install step-ca
wget https://github.com/smallstep/certificates/releases/download/v0.25.0/step-ca_linux_0.25.0_amd64.tar.gz
tar -xzf step-ca_*.tar.gz
sudo mv step-ca_*/bin/step-ca /usr/local/bin/

# Initialize CA
step ca init --name "Internal CA" \
  --dns internal.company.com \
  --address ":443" \
  --provisioner admin@company.com

# Start CA server
step-ca $(step path)/config/ca.json

# Configure clients to use private CA
export STEP_CA_URL=https://internal.company.com
step ca root root_ca.crt
sudo cp root_ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Use certbot with private CA
certbot certonly \
  --server https://internal.company.com/acme/acme/directory \
  --webroot -w /var/www/html \
  -d internal-app.company.com
```

### 3. Multi-Instance Certificate Sharing
```yaml
# Kubernetes certificate sharing with cert-manager
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: shared-wildcard-cert
  namespace: default
spec:
  secretName: wildcard-tls-secret
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - "*.company.com"
  - company.com
---
# Use shared certificate in multiple services
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app1
spec:
  template:
    spec:
      containers:
      - name: app1
        image: nginx
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/ssl/certs
      volumes:
      - name: tls-certs
        secret:
          secretName: wildcard-tls-secret
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app2
spec:
  template:
    spec:
      containers:
      - name: app2
        image: nginx
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/ssl/certs
      volumes:
      - name: tls-certs
        secret:
          secretName: wildcard-tls-secret
```

---

## Renewal & Automation

### 1. Systemd Timer Setup
```bash
# Create service file
sudo tee /etc/systemd/system/certbot-renewal.service << 'EOF'
[Unit]
Description=Certbot Renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
User=root
EOF

# Create timer file
sudo tee /etc/systemd/system/certbot-renewal.timer << 'EOF'
[Unit]
Description=Timer for Certbot Renewal

[Timer]
OnCalendar=0/12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start timer
sudo systemctl daemon-reload
sudo systemctl enable certbot-renewal.timer
sudo systemctl start certbot-renewal.timer

# Check timer status
sudo systemctl list-timers | grep certbot
```

### 2. Cron-Based Renewal
```bash
# Create renewal script
sudo tee /usr/local/bin/certbot-renew.sh << 'EOF'
#!/bin/bash
/usr/bin/certbot renew --quiet
if [ $? -eq 0 ]; then
    systemctl reload nginx
    systemctl reload apache2
    logger "Certbot renewal successful"
else
    logger "Certbot renewal failed"
    # Send notification email
    echo "Certbot renewal failed on $(hostname)" | mail -s "Certificate Renewal Failed" admin@company.com
fi
EOF

chmod +x /usr/local/bin/certbot-renew.sh

# Add to crontab (run twice daily)
echo "43 6,18 * * * /usr/local/bin/certbot-renew.sh" | sudo crontab -

# Alternative: user-specific crontab
crontab -e
# Add: 43 6,18 * * * /usr/local/bin/certbot-renew.sh
```

### 3. Hooks and Post-Processing
```bash
# Create hook directories
sudo mkdir -p /etc/letsencrypt/renewal-hooks/{pre,deploy,post}

# Pre-hook: stop services
sudo tee /etc/letsencrypt/renewal-hooks/pre/01-stop-services.sh << 'EOF'
#!/bin/bash
systemctl stop nginx
systemctl stop apache2
EOF

# Deploy hook: reload services
sudo tee /etc/letsencrypt/renewal-hooks/deploy/01-reload-services.sh << 'EOF'
#!/bin/bash
systemctl reload nginx
systemctl reload apache2
systemctl reload haproxy

# Copy certificates to other locations
cp /etc/letsencrypt/live/example.com/fullchain.pem /etc/ssl/certs/
cp /etc/letsencrypt/live/example.com/privkey.pem /etc/ssl/private/

# Restart services that need full restart
systemctl restart postfix
systemctl restart dovecot

# Send notification
logger "Certificate deployed successfully for $(echo $RENEWED_DOMAINS)"
EOF

# Post-hook: cleanup and notifications
sudo tee /etc/letsencrypt/renewal-hooks/post/01-cleanup.sh << 'EOF'
#!/bin/bash
systemctl start nginx
systemctl start apache2

# Clean up old certificates
find /etc/letsencrypt/archive -name "*.pem" -mtime +180 -delete

# Send success notification
if [ -n "$RENEWED_DOMAINS" ]; then
    echo "Certificates renewed for: $RENEWED_DOMAINS" | \
    mail -s "Certificate Renewal Success" admin@company.com
fi
EOF

# Make hooks executable
sudo chmod +x /etc/letsencrypt/renewal-hooks/*/*.sh
```

### 4. Docker Renewal Automation
```bash
# Docker renewal script
#!/bin/bash
# docker-certbot-renew.sh

# Renew certificates
docker run --rm \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
  -v "/var/www/html:/var/www/html" \
  certbot/certbot renew

# Reload nginx container
docker exec nginx nginx -s reload

# Or restart entire stack
# docker-compose restart nginx

# Add to crontab
echo "0 2,14 * * * /path/to/docker-certbot-renew.sh" | crontab -
```

---

## Troubleshooting & Best Practices

### 1. Common Issues and Solutions

#### Rate Limiting
```bash
# Check rate limits
curl -s "https://crt.sh/?q=example.com&output=json" | jq '. | length'

# Use staging for testing
certbot certonly --staging -d example.com

# Switch to production
certbot certonly -d example.com
```

#### Port 80 Access Issues
```bash
# Check port accessibility
telnet example.com 80
nmap -p 80 example.com

# Alternative: use DNS challenge
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  -d example.com
```

#### DNS Propagation Problems
```bash
# Check DNS propagation
dig +trace example.com
dig @8.8.8.8 _acme-challenge.example.com TXT

# Increase propagation delay
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials ~/.secrets/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 120 \
  -d example.com
```

### 2. Security Best Practices

#### File Permissions
```bash
# Secure certificate files
sudo chmod 644 /etc/letsencrypt/live/*/fullchain.pem
sudo chmod 600 /etc/letsencrypt/live/*/privkey.pem

# Secure credentials
chmod 600 ~/.secrets/*.ini
chown root:root ~/.secrets/*.ini

# Secure renewal hooks
chmod 755 /etc/letsencrypt/renewal-hooks/*/
chmod 644 /etc/letsencrypt/renewal-hooks/*/*.sh
```

#### Network Security
```bash
# Firewall configuration for ACME
ufw allow 80/tcp comment "HTTP for ACME challenge"
ufw allow 443/tcp comment "HTTPS"

# For DNS challenge only
ufw deny 80/tcp
ufw allow 443/tcp
```

### 3. Monitoring and Alerting
```bash
# Certificate expiration check script
#!/bin/bash
# check-cert-expiry.sh

DOMAIN="example.com"
THRESHOLD=30  # days

EXPIRY=$(echo | openssl s_client -servername $DOMAIN -connect $DOMAIN:443 2>/dev/null | \
         openssl x509 -noout -dates | grep notAfter | cut -d= -f2)

EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_UNTIL_EXPIRY=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

if [ $DAYS_UNTIL_EXPIRY -lt $THRESHOLD ]; then
    echo "WARNING: Certificate for $DOMAIN expires in $DAYS_UNTIL_EXPIRY days"
    # Send alert
    echo "Certificate for $DOMAIN expires in $DAYS_UNTIL_EXPIRY days" | \
    mail -s "Certificate Expiry Warning" admin@company.com
fi
```

### 4. Backup and Recovery
```bash
# Backup Let's Encrypt configuration
tar -czf letsencrypt-backup-$(date +%Y%m%d).tar.gz \
  -C /etc letsencrypt \
  -C /var/lib letsencrypt

# Restore from backup
tar -xzf letsencrypt-backup-*.tar.gz -C /

# Export certificates for external use
openssl pkcs12 -export \
  -out certificate.p12 \
  -inkey /etc/letsencrypt/live/example.com/privkey.pem \
  -in /etc/letsencrypt/live/example.com/cert.pem \
  -certfile /etc/letsencrypt/live/example.com/chain.pem
```

---

## Quick Reference Commands

### Essential Commands
```bash
# Generate certificate (webroot)
sudo certbot certonly --webroot -w /var/www/html -d example.com

# Generate with plugin (instant HTTPS)
sudo certbot --nginx -d example.com --agree-tos --email admin@example.com --redirect

# Wildcard certificate
sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cf.ini -d "*.example.com"

# Test renewal
sudo certbot renew --dry-run

# Force renewal
sudo certbot renew --force-renewal

# List certificates
sudo certbot certificates

# Delete certificate
sudo certbot delete --cert-name example.com

# Check logs
sudo tail -f /var/log/letsencrypt/letsencrypt.log
```

### Automation Commands
```bash
# Enable systemd timer
sudo systemctl enable certbot.timer && sudo systemctl start certbot.timer

# Check timer status
systemctl list-timers | grep certbot

# Manual renewal with hooks
sudo certbot renew --deploy-hook "systemctl reload nginx"

# IP-based domain automation
sudo certbot --nginx -d app.$(curl -s ifconfig.me).nip.io --noninteractive --agree-tos --email ops@company.com --redirect
```

This comprehensive guide covers every method of certificate issuance we've discussed, from basic Certbot usage to advanced enterprise integrations, providing a complete reference for any certificate management scenario.