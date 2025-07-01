#!/usr/bin/env bash
# /usr/local/bin/harbor-certbot-pre-hook.sh
# Harbor Certificate Pre-Hook
set -euo pipefail

DOMAIN="registry.codezeros.com"
PROXY_SERVICE="harbor-registry_proxy"
LOG_FILE="/var/log/certbot-harbor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [PRE-HOOK] $1" | tee -a "$LOG_FILE"
}

# Create log file if it doesn't exist
touch "$LOG_FILE"

log "Certificate renewal starting for $DOMAIN - scaling down Harbor proxy service"

# Check current service status
CURRENT_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
log "Current Harbor proxy replicas: $CURRENT_REPLICAS"

if [ "$CURRENT_REPLICAS" != "0" ]; then
    log "Scaling down Harbor proxy service to free ports 80/443"
    docker service scale ${PROXY_SERVICE}=0
    
    log "Waiting for service to scale down..."
    sleep 15
    
    # Verify service is down and ports are free
    FINAL_REPLICAS=$(docker service ls --filter "name=$PROXY_SERVICE" --format "{{.Replicas}}" | cut -d'/' -f1)
    log "Harbor proxy service scaled to: $FINAL_REPLICAS replicas"
    
    # Check if ports are free
    if ss -tlnp | grep -E ':80 |:443 ' >/dev/null; then
        log "⚠️ Warning: Some processes still binding to ports 80/443"
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
