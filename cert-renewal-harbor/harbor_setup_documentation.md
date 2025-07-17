# Harbor Registry Setup Documentation

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
   - [Deployment Method](#deployment-method)
   - [Harbor Services](#harbor-services)
   - [Network Configuration](#network-configuration)
3. [Current System Architecture](#current-system-architecture)
   - [Harbor Deployment Structure](#harbor-deployment-structure)
   - [Key System Components](#key-system-components)
4. [Directory Structure](#directory-structure)
   - [Application Directory](#application-directory)
   - [Data Directory](#data-directory)
5. [SSL Certificate Management](#ssl-certificate-management)
   - [Let's Encrypt Configuration](#lets-encrypt-configuration)
   - [Certificate Renewal Hooks Architecture](#certificate-renewal-hooks-architecture)
   - [Certificate Files](#certificate-files)
6. [Certificate Renewal Process Flow](#certificate-renewal-process-flow)
   - [Pre-Hook Execution](#1-pre-hook-execution-harbor-certbot-pre-hooksh)
   - [Let's Encrypt Certificate Generation](#2-lets-encrypt-certificate-generation)
   - [Post-Hook Execution](#3-post-hook-execution-harbor-certbot-post-hooksh)
   - [Complete Renewal Sequence Summary](#complete-renewal-sequence-summary)
7. [Operational Management](#operational-management)
   - [Service Management Commands](#service-management-commands)
   - [Certificate Management Operations](#certificate-management-operations)
8. [Troubleshooting](#troubleshooting)
   - [Certificate Renewal Status Monitoring](#certificate-renewal-status-monitoring)
   - [Common Operational Scenarios](#common-operational-scenarios)
9. [Data Backup and Recovery](#data-backup-and-recovery)
   - [Harbor Data Backup](#harbor-data-backup)
   - [Database Operations](#database-operations)
   - [Certificate Backup](#certificate-backup)
10. [Knowledge Transfer - Critical Understanding Points](#knowledge-transfer---critical-understanding-points)
    - [System Architecture Understanding](#system-architecture-understanding)
    - [Critical Operational Knowledge](#critical-operational-knowledge)
    - [DevOps Responsibilities](#devops-responsibilities)
    - [Emergency Response Knowledge](#emergency-response-knowledge)
11. [Monitoring and Alerting](#monitoring-and-alerting)
    - [Certificate Renewal Monitoring](#certificate-renewal-monitoring)
    - [Automated Monitoring Script](#automated-monitoring-script)
    - [Health Checks](#health-checks)
    - [Performance Monitoring](#performance-monitoring)
    - [Alerting Setup](#alerting-setup)
    - [Monitoring Dashboard](#monitoring-dashboard)
12. [Security Considerations](#security-considerations)
13. [Support Information](#support-information)

---

## Overview

This document describes the setup and configuration of Harbor container registry running on `registry.codezeros.com`. Harbor is deployed as a Docker Swarm stack with automated SSL certificate management using Let's Encrypt.

## System Architecture

### Deployment Method
- **Platform**: Docker Swarm
- **Stack Name**: `harbor-registry`
- **Domain**: `registry.codezeros.com`
- **SSL**: Let's Encrypt certificates with automatic renewal

### Harbor Services

The Harbor deployment consists of 10 services running as a Docker Swarm stack:

| Service | Image | Purpose |
|---------|-------|---------|
| `harbor-registry_proxy` | `goharbor/nginx-photon:v2.12.2` | SSL termination and reverse proxy |
| `harbor-registry_core` | `goharbor/harbor-core:v2.12.2` | Core Harbor API and web interface |
| `harbor-registry_portal` | `goharbor/harbor-portal:v2.12.2` | Web UI frontend |
| `harbor-registry_jobservice` | `goharbor/harbor-jobservice:v2.12.2` | Background job processing |
| `harbor-registry_registry` | `goharbor/registry-photon:v2.12.2` | Container registry service |
| `harbor-registry_registryctl` | `goharbor/harbor-registryctl:v2.12.2` | Registry controller |
| `harbor-registry_postgresql` | `goharbor/harbor-db:v2.12.2` | Database service |
| `harbor-registry_redis` | `goharbor/redis-photon:v2.12.2` | Cache and session store |
| `harbor-registry_log` | `goharbor/harbor-log:v2.12.2` | Log collector |
| `harbor-registry_trivy-adapter` | `goharbor/trivy-adapter-photon:v2.12.2` | Security scanner |

### Network Configuration

- **HTTP Port**: 80 → 8080 (container)
- **HTTPS Port**: 443 → 8443 (container)
- **Syslog Port**: 1514 → 10514 (container)

## Directory Structure

### Application Directory
```
/home/ubuntu/harbor/
├── LICENSE
├── common/
├── common.sh
├── docker-compose.yml
├── harbor.yml
├── harbor.yml.tmpl
├── install.sh
└── prepare
```

### Data Directory
```
/harbor/
├── ca_download/          # Certificate authority downloads
├── database/             # PostgreSQL data (uid:999, gid:systemd-journal)
├── job_logs/             # Job service logs (uid:10000, gid:10000)
├── redis/                # Redis data (uid:999, gid:systemd-journal)
├── registry/             # Container registry data (uid:10000, gid:10000)
├── secret/               # SSL certificates and secrets
│   └── cert/
│       ├── server.crt    # SSL certificate
│       └── server.key    # SSL private key
└── trivy-adapter/        # Security scanner data
```

## SSL Certificate Management

### Let's Encrypt Configuration

**Certificate Renewal Config**: `/etc/letsencrypt/renewal/registry.codezeros.com.conf`

```ini
# Auto-renewal: 30 days before expiry
version = 2.9.0
archive_dir = /etc/letsencrypt/archive/registry.codezeros.com
cert = /etc/letsencrypt/live/registry.codezeros.com/cert.pem
privkey = /etc/letsencrypt/live/registry.codezeros.com/privkey.pem
chain = /etc/letsencrypt/live/registry.codezeros.com/chain.pem
fullchain = /etc/letsencrypt/live/registry.codezeros.com/fullchain.pem

[renewalparams]
account = 85fe4ad705357824facba4898423d681
authenticator = standalone
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
pre_hook = /usr/local/bin/harbor-certbot-pre-hook.sh
post_hook = /usr/local/bin/harbor-certbot-post-hook.sh
```

### Certificate Renewal Hooks Architecture

The renewal hooks solve the fundamental conflict between Let's Encrypt's standalone authenticator and Harbor's proxy service, which both require exclusive access to ports 80 and 443. The system implements a coordinated shutdown-renew-restore sequence.

#### Hook Integration Points

- **Hook Registration**: Hooks are registered in `/etc/letsencrypt/renewal/registry.codezeros.com.conf`
- **Execution Context**: Hooks run with root privileges during certbot renewal process
- **Execution Timing**: Pre-hook runs before domain validation, post-hook runs after certificate issuance
- **Trigger Conditions**: Hooks execute only during actual renewals, not during dry-run testing

### Certificate Renewal Process Flow

### Certificate Renewal Process Flow

When Let's Encrypt automatic renewal is triggered (typically runs twice daily), the renewal process follows this sequence:

#### 1. Pre-Hook Execution (`harbor-certbot-pre-hook.sh`)
**Purpose**: Prepare the environment for certificate renewal by freeing ports 80/443

```bash
#!/usr/bin/env bash
# /usr/local/bin/harbor-certbot-pre-hook.sh
# Harbor Certificate Pre-Hook
set -euo pipefail

# Configuration variables
DOMAIN="registry.codezeros.com"              # Target domain for certificate renewal
PROXY_SERVICE="harbor-registry_proxy"        # Docker service name for Harbor's reverse proxy
LOG_FILE="/var/log/certbot-harbor.log"      # Centralized log file for renewal activities

# Logging function with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [PRE-HOOK] $1" | tee -a "$LOG_FILE"
}

# Create log file if it doesn't exist
touch "$LOG_FILE"
log "Certificate renewal starting for $DOMAIN - scaling down Harbor proxy service"

# Check current service status - get running replica count
CURRENT_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
log "Current Harbor proxy replicas: $CURRENT_REPLICAS"

# Scale down Harbor proxy service if it's running
if [ "$CURRENT_REPLICAS" != "0" ]; then
    log "Scaling down Harbor proxy service to free ports 80/443"
    docker service scale ${PROXY_SERVICE}=0    # Scale to 0 replicas (temporary shutdown)
    
    log "Waiting for service to scale down..."
    sleep 15                                   # Wait for Docker Swarm to complete shutdown
    
    # Verify service is down and check final replica count
    FINAL_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
    log "Harbor proxy service scaled to: $FINAL_REPLICAS replicas"
    
    # Check if ports 80/443 are actually free for Let's Encrypt
    if ss -tlnp | grep -E ':80 |:443 ' >/dev/null; then
        log "⚠️ Warning: Some processes still binding to ports 80/443"
        # Log which processes are still using the ports
        ss -tlnp | grep -E ':80 |:443 ' | while read line; do
            log "Port usage: $line"
        done
    else
        log "✅ Ports 80/443 are now free"
    fi
    
    log "Ready for certbot standalone authenticator"
else
    log "Harbor proxy service already scaled down"
fi
```

#### 2. Let's Encrypt Certificate Generation
At this point, Let's Encrypt's standalone authenticator:
- Binds to ports 80/443 (now free)
- Performs domain validation
- Generates new certificate files
- Stores certificates in `/etc/letsencrypt/live/registry.codezeros.com/`

#### 3. Post-Hook Execution (`harbor-certbot-post-hook.sh`)
**Purpose**: Deploy new certificates to Harbor and restore service availability

```bash
#!/usr/bin/env bash
# /usr/local/bin/harbor-certbot-post-hook.sh
# Harbor Certificate Post-Hook
set -euo pipefail

# Configuration variables
DOMAIN="registry.codezeros.com"                           # Target domain
LIVE_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"  # Source certificate path
SECRET_DIR="/harbor/secret/cert"                         # Harbor certificate directory
PROXY_SERVICE="harbor-registry_proxy"                    # Docker service name
LOG_FILE="/var/log/certbot-harbor.log"                  # Log file location

# Logging function with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [POST-HOOK] $1" | tee -a "$LOG_FILE"
}

# Function to deploy certificates to Harbor
deploy_certificates() {
    log "Deploying renewed certificates to Harbor"
    if [ -f "$LIVE_CERT" ]; then
        # Copy fullchain certificate to Harbor's expected location
        cp "$LIVE_CERT" "$SECRET_DIR/server.crt"
        # Copy private key to Harbor's expected location  
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SECRET_DIR/server.key"
        # Set secure permissions (owner read/write only)
        chmod 600 "$SECRET_DIR/server.crt" "$SECRET_DIR/server.key"
        log "Certificates deployed successfully"
    else
        log "⚠️ Certificate file not found: $LIVE_CERT"
    fi
}

# Function to verify certificate deployment
verify_certificates() {
    log "Verifying certificate deployment..."
    sleep 10  # Give Harbor time to detect and load new certificates
    
    if [ -f "$LIVE_CERT" ]; then
        # Get expiry date from local certificate file
        HOST_EXP=$(openssl x509 -in "$LIVE_CERT" -noout -enddate | cut -d= -f2)
        
        # Try to get expiry date from certificate served by Harbor (with timeout)
        SERVED_EXP=$(timeout 30 openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null </dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
        
        # Compare local and served certificate expiry dates
        if [ -n "$SERVED_EXP" ] && [ "$HOST_EXP" = "$SERVED_EXP" ]; then
            log "✅ Certificate verification successful - Harbor is serving the new certificate"
            log "Certificate expires: $HOST_EXP"
        else
            log "⚠️ Certificate verification failed or timeout - manual check recommended"
            log "Expected: $HOST_EXP"
            log "Served: ${SERVED_EXP:-'Unable to retrieve'}"
        fi
    else
        log "⚠️ Cannot verify - certificate file not found"
    fi
}

log "Certificate renewal completed for $DOMAIN - restoring Harbor proxy service"

# Deploy certificates (only for actual renewals, not dry-run)
if [ -f "$LIVE_CERT" ]; then
    deploy_certificates
fi

# Scale Harbor service back up (always executed as failsafe)
CURRENT_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
log "Current Harbor proxy replicas: $CURRENT_REPLICAS"

if [ "$CURRENT_REPLICAS" = "0" ]; then
    log "Scaling Harbor proxy service back up"
    docker service scale ${PROXY_SERVICE}=1    # Scale back to 1 replica (restore service)
    
    log "Waiting for service to scale up..."
    sleep 30                                   # Wait for Docker Swarm to start service
    
    # Check final service status
    FINAL_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}")
    log "Final Harbor proxy status: $FINAL_REPLICAS"
    
    # Verify certificates only for actual renewals (not dry-run)
    if [ -f "$LIVE_CERT" ]; then
        verify_certificates
    fi
    
    log "Harbor certificate renewal process completed successfully"
else
    log "Harbor proxy service already running with $CURRENT_REPLICAS replicas"
fi
```

#### Complete Renewal Sequence Summary

1. **Pre-Hook Phase**:
   - Checks Harbor proxy service status
   - Scales proxy service to 0 replicas (temporary shutdown)
   - Waits 15 seconds for complete shutdown
   - Verifies ports 80/443 are free
   - Logs all activities for audit trail

2. **Certificate Generation Phase**:
   - Let's Encrypt standalone authenticator binds to ports 80/443
   - Performs domain validation with registry.codezeros.com
   - Generates new ECDSA certificate
   - Stores certificate files in Let's Encrypt directory

3. **Post-Hook Phase**:
   - Copies new certificates to Harbor directory
   - Sets proper file permissions (600)
   - Scales Harbor proxy service back to 1 replica
   - Waits 30 seconds for service startup
   - Verifies Harbor is serving the new certificate
   - Logs completion status

**Key Timing Elements**:
- 15-second wait after scaling down for complete service shutdown
- 30-second wait after scaling up for complete service startup  
- 10-second delay before certificate verification
- 30-second timeout for SSL verification connection

## Knowledge Transfer - Critical Understanding Points

### System Architecture Understanding

**Port Conflict Resolution**:
- Harbor proxy service normally occupies ports 80/443
- Let's Encrypt standalone authenticator requires exclusive access to these ports
- The hook system orchestrates a temporary handoff of port control
- **Key Point**: Never manually stop Harbor services during renewal - let hooks handle it

**Certificate Lifecycle**:
- Let's Encrypt generates certificates in `/etc/letsencrypt/live/`
- Harbor expects certificates in `/harbor/secret/cert/` with specific names
- Post-hook copies and renames: `fullchain.pem` → `server.crt`, `privkey.pem` → `server.key`
- **Key Point**: Harbor automatically reloads certificates when files change

**Service Scaling Logic**:
- Docker Swarm allows scaling services to 0 replicas (temporary shutdown)
- Scaling back to 1 replica restarts the service with current configuration
- **Key Point**: Service state is preserved during scaling operations

### Critical Operational Knowledge

**Renewal Timing**:
- Certbot timer runs twice daily but only renews certificates within 30 days of expiry
- Hooks only execute during actual renewals, not during dry-run tests
- **Key Point**: Use `--dry-run` for testing without triggering hooks

**Log Interpretation**:
- All hook activities are logged to `/var/log/certbot-harbor.log`
- Each log entry includes timestamp and phase marker (`[PRE-HOOK]` or `[POST-HOOK]`)
- **Key Point**: Check logs immediately after any renewal issues

**Service Recovery**:
- Post-hook always attempts to scale proxy service back up, even if certificate deployment fails
- This ensures Harbor remains accessible even during partial failures
- **Key Point**: System is designed to fail-safe (maintain service availability)

### DevOps Responsibilities

**Regular Monitoring**:
- Check certificate expiry dates (30+ days remaining is healthy)
- Monitor Harbor service replica counts (all should be 1/1)
- Review renewal logs for any warnings or errors
- **Key Point**: Proactive monitoring prevents service interruptions

**Troubleshooting Authority**:
- DevOps can manually scale services if hooks fail
- Manual certificate deployment is possible if automated process fails
- Hook scripts can be executed independently for testing
- **Key Point**: Multiple recovery paths exist for different failure scenarios

**Change Management**:
- Any changes to Harbor configuration may affect certificate deployment
- Domain changes require updating hook scripts and renewal configuration
- **Key Point**: Certificate system is tightly coupled to Harbor service naming

### Emergency Response Knowledge

**Immediate Actions for Certificate Failures**:
1. Check Harbor service status: `sudo docker service ls`
2. Review recent logs: `sudo tail -50 /var/log/certbot-harbor.log`
3. Verify certificate files: `sudo ls -la /harbor/secret/cert/`
4. Test HTTPS connectivity: `curl -I https://registry.codezeros.com`

**Service Recovery Procedures**:
- If Harbor proxy is down: `sudo docker service scale harbor-registry_proxy=1`
- If certificates are missing: Manual deployment from Let's Encrypt directory
- If renewal fails: Manual certificate request with hooks disabled

**Escalation Criteria**:
- Multiple consecutive renewal failures
- Harbor services in failed state
- Certificate expiry within 7 days
- HTTPS connectivity lost

### Certificate Files
- **Source**: `/etc/letsencrypt/live/registry.codezeros.com/`
- **Deployment**: `/harbor/secret/cert/`
- **Permissions**: 600 (owner read/write only)

## Current System Architecture

### Harbor Deployment Structure
Harbor is currently deployed as a Docker Swarm stack named `harbor-registry` with 10 interconnected services. The deployment uses the standard Harbor v2.12.2 installation with custom SSL certificate management.

### Key System Components

#### Core Services
- **Proxy Service**: `harbor-registry_proxy` - handles SSL termination and traffic routing
- **Core Service**: `harbor-registry_core` - main Harbor API and business logic
- **Registry Service**: `harbor-registry_registry` - container image storage and retrieval
- **Database**: `harbor-registry_postgresql` - persistent data storage
- **Cache**: `harbor-registry_redis` - session and cache management

#### Supporting Services
- **Portal**: `harbor-registry_portal` - web interface frontend
- **Job Service**: `harbor-registry_jobservice` - background task processing
- **Registry Controller**: `harbor-registry_registryctl` - registry management
- **Security Scanner**: `harbor-registry_trivy-adapter` - vulnerability scanning
- **Log Collector**: `harbor-registry_log` - centralized logging

## Operational Management

### Service Management Commands

#### Harbor Stack Operations
```bash
# View complete stack status
sudo docker stack ls

# List all Harbor services with replica status
sudo docker service ls

# Check specific service health
sudo docker service ps harbor-registry_proxy

# View service logs
sudo docker service logs harbor-registry_proxy
sudo docker service logs harbor-registry_core

# Manual service scaling (for maintenance)
sudo docker service scale harbor-registry_proxy=0  # Stop proxy
sudo docker service scale harbor-registry_proxy=1  # Start proxy
```

#### Service Health Monitoring
```bash
# Check all service replicas
sudo docker service ls | grep harbor-registry

# View service resource usage
sudo docker stats --no-stream | grep harbor-registry

# Check service update status
sudo docker service ps harbor-registry_proxy --format "table {{.Name}}\t{{.CurrentState}}\t{{.Error}}"
```

### Certificate Management Operations

#### Certificate Status and Renewal
```bash
# Check current certificate status and expiry
sudo certbot certificates

# View specific certificate details
sudo certbot certificates --cert-name registry.codezeros.com

# Test renewal process (dry run - doesn't actually renew)
sudo certbot renew --dry-run

# Force certificate renewal for testing
sudo certbot renew --force-renewal --cert-name registry.codezeros.com

# Check automatic renewal timer status
sudo systemctl status certbot.timer
```

#### Certificate File Verification
```bash
# Check Let's Encrypt certificate files
sudo ls -la /etc/letsencrypt/live/registry.codezeros.com/

# Check deployed Harbor certificates
sudo ls -la /harbor/secret/cert/

# Verify certificate expiry dates
sudo openssl x509 -in /harbor/secret/cert/server.crt -noout -enddate
sudo openssl x509 -in /etc/letsencrypt/live/registry.codezeros.com/fullchain.pem -noout -enddate

# Check certificate served by Harbor
echo | openssl s_client -servername registry.codezeros.com -connect registry.codezeros.com:443 2>/dev/null | openssl x509 -noout -enddate
```

#### Hook Script Monitoring
```bash
# Monitor renewal process in real-time
sudo tail -f /var/log/certbot-harbor.log

# View recent renewal activities
sudo grep "$(date '+%Y-%m-%d')" /var/log/certbot-harbor.log

# Check for renewal errors or warnings
sudo grep -i "error\|fail\|warn" /var/log/certbot-harbor.log

# View last renewal attempt
sudo grep "Certificate renewal" /var/log/certbot-harbor.log | tail -5
```

### Data Backup and Recovery

#### Harbor Data Backup
```bash
# Backup all Harbor data
sudo tar -czf harbor-backup-$(date +%Y%m%d).tar.gz -C /harbor .

# Backup specific components
sudo tar -czf harbor-registry-$(date +%Y%m%d).tar.gz -C /harbor registry/
sudo tar -czf harbor-database-$(date +%Y%m%d).tar.gz -C /harbor database/

# Backup certificates
sudo tar -czf harbor-certs-$(date +%Y%m%d).tar.gz -C /harbor secret/cert/
```

#### Database Operations
```bash
# Access PostgreSQL database
POSTGRES_CONTAINER=$(sudo docker ps --filter "name=harbor-registry_postgresql" --format "{{.Names}}")
sudo docker exec -it $POSTGRES_CONTAINER psql -U postgres registry

# Create database backup
sudo docker exec $POSTGRES_CONTAINER pg_dump -U postgres registry > harbor-db-backup-$(date +%Y%m%d).sql

# View database size and activity
sudo docker exec $POSTGRES_CONTAINER psql -U postgres registry -c "SELECT pg_size_pretty(pg_database_size('registry'));"
```

#### Certificate Backup
```bash
# Backup Let's Encrypt certificates
sudo tar -czf letsencrypt-backup-$(date +%Y%m%d).tar.gz -C /etc/letsencrypt .

# Backup renewal configuration
sudo cp /etc/letsencrypt/renewal/registry.codezeros.com.conf /backup/
```

## Troubleshooting

### Certificate Renewal Status Monitoring

#### Certificate Status Commands
```bash
# Check current certificate status and expiry
sudo certbot certificates

# View specific certificate details
sudo certbot certificates --cert-name registry.codezeros.com

# Check certificate served by Harbor
echo | openssl s_client -servername registry.codezeros.com -connect registry.codezeros.com:443 2>/dev/null | openssl x509 -noout -enddate

# Compare local vs served certificate
sudo openssl x509 -in /harbor/secret/cert/server.crt -noout -enddate
```

#### Service Status Monitoring
```bash
# Check Harbor service status
sudo docker service ls | grep harbor-registry_proxy

# View service health
sudo docker service ps harbor-registry_proxy

# Check port availability
sudo ss -tlnp | grep -E ':80 |:443 '
```

#### Log Analysis
```bash
# Monitor renewal process
sudo tail -f /var/log/certbot-harbor.log

# View recent renewal activities
sudo grep "$(date '+%Y-%m-%d')" /var/log/certbot-harbor.log

# Check renewal success/failure
sudo grep -E "completed successfully|failed|error" /var/log/certbot-harbor.log | tail -5
```

### Common Operational Scenarios

#### Manual Certificate Renewal Testing
```bash
# Test renewal process (dry run)
sudo certbot renew --dry-run

# Force renewal for testing
sudo certbot renew --force-renewal --cert-name registry.codezeros.com
```

#### Service Recovery
```bash
# If Harbor proxy service is down
sudo docker service scale harbor-registry_proxy=1

# Check service logs for issues
sudo docker service logs harbor-registry_proxy

# Verify HTTPS connectivity
curl -I https://registry.codezeros.com
```

#### Certificate File Verification
```bash
# Check certificate file existence
sudo ls -la /harbor/secret/cert/
sudo ls -la /etc/letsencrypt/live/registry.codezeros.com/

# Verify certificate permissions
sudo ls -la /harbor/secret/cert/server.crt
sudo ls -la /harbor/secret/cert/server.key
```

## Security Considerations

1. **Certificate Security**
   - Private keys have 600 permissions
   - ECDSA key type for better performance
   - Automatic 30-day renewal

2. **Network Security**
   - Only necessary ports exposed
   - SSL/TLS termination at proxy layer
   - Internal service communication

3. **Data Security**
   - Proper file ownership and permissions
   - Database isolation
   - Regular backups recommended

## Monitoring

### Health Checks
```bash
# Service health
sudo docker service ls
sudo docker service ps harbor-registry_proxy

# Certificate expiry
sudo certbot certificates

# Disk usage
df -h /harbor

# Service connectivity
curl -I https://registry.codezeros.com
```

### Alerts
- Monitor certificate expiry dates
- Watch service replica counts
- Monitor disk space usage
- Track renewal process logs

## Support Information

- **Harbor Version**: v2.12.2
- **Docker Swarm**: Single node deployment
- **SSL Provider**: Let's Encrypt
- **Domain**: registry.codezeros.com
- **Data Location**: /harbor/
- **Installation Path**: /home/ubuntu/harbor/