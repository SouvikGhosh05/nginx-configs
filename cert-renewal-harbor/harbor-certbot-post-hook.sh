#!/usr/bin/env bash
# /usr/local/bin/harbor-certbot-post-hook.sh
# Harbor Certificate Post-Hook
set -euo pipefail

DOMAIN="registry.codezeros.com"
LIVE_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
SECRET_DIR="/harbor/secret/cert"
PROXY_SERVICE="harbor-registry_proxy"
LOG_FILE="/var/log/certbot-harbor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [POST-HOOK] $1" | tee -a "$LOG_FILE"
}

deploy_certificates() {
    log "Deploying renewed certificates to Harbor"
    if [ -f "$LIVE_CERT" ]; then
        cp "$LIVE_CERT" "$SECRET_DIR/server.crt"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SECRET_DIR/server.key"
        chmod 600 "$SECRET_DIR/server.crt" "$SECRET_DIR/server.key"
        log "Certificates deployed successfully"
    else
        log "⚠️ Certificate file not found: $LIVE_CERT"
    fi
}

verify_certificates() {
    log "Verifying certificate deployment..."
    sleep 10  # Give Harbor time to start
    
    if [ -f "$LIVE_CERT" ]; then
        HOST_EXP=$(openssl x509 -in "$LIVE_CERT" -noout -enddate | cut -d= -f2)
        
        # Try to get served certificate with timeout
        SERVED_EXP=$(timeout 30 openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null </dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")
        
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

# Scale Harbor service back up (always, as failsafe)
CURRENT_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
log "Current Harbor proxy replicas: $CURRENT_REPLICAS"

if [ "$CURRENT_REPLICAS" = "0" ]; then
    log "Scaling Harbor proxy service back up"
    docker service scale ${PROXY_SERVICE}=1
    
    log "Waiting for service to scale up..."
    sleep 30
    
    # Check final status
    FINAL_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}")
    log "Final Harbor proxy status: $FINAL_REPLICAS"
    
    # Verify certificates only for actual renewals
    if [ -f "$LIVE_CERT" ]; then
        verify_certificates
    fi
    
    log "Harbor certificate renewal process completed successfully"
else
    log "Harbor proxy service already running with $CURRENT_REPLICAS replicas"
fi
