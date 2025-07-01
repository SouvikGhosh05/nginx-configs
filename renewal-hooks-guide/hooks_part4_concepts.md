# Certificate Renewal Hooks - Part 4: Monitoring & Advanced Workflows

## Table of Contents
1. [Monitoring & Notification Hooks](#monitoring--notification-hooks)
2. [Error Handling & Recovery](#error-handling--recovery)
3. [Complex Multi-Service Workflows](#complex-multi-service-workflows)
4. [Testing & Validation](#testing--validation)

---

## Monitoring & Notification Hooks

### 1. Notification Concepts

#### Slack Notification Pattern
```bash
#!/bin/bash
# Send Slack notifications

SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

send_slack_notification() {
    local status=$1
    local domains=$2
    local color="good"
    
    [ "$status" != "success" ] && color="danger"
    
    local payload="{
        \"attachments\": [{
            \"color\": \"$color\",
            \"title\": \"Certificate Renewal $status\",
            \"fields\": [
                {\"title\": \"Server\", \"value\": \"$(hostname)\", \"short\": true},
                {\"title\": \"Domains\", \"value\": \"$domains\", \"short\": true},
                {\"title\": \"Time\", \"value\": \"$(date)\", \"short\": false}
            ]
        }]
    }"
    
    curl -X POST -H 'Content-type: application/json' \
        --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1
}

# Usage
if [ -n "$RENEWED_DOMAINS" ]; then
    send_slack_notification "success" "$RENEWED_DOMAINS"
fi
```

#### Email Notification Pattern
```bash
#!/bin/bash
# Email notification with details

send_email_notification() {
    local domains=$1
    local admin_email="admin@example.com"
    
    {
        echo "Subject: Certificate Renewal Success - $(hostname)"
        echo "To: $admin_email"
        echo ""
        echo "Certificate renewal completed successfully:"
        echo ""
        
        for domain in $domains; do
            local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
            local expiry=$(openssl x509 -in "$cert_path" -noout -dates | grep notAfter | cut -d= -f2)
            echo "Domain: $domain"
            echo "Expires: $expiry"
            echo ""
        done
        
        echo "Server: $(hostname)"
        echo "Time: $(date)"
    } | sendmail "$admin_email"
}

if [ -n "$RENEWED_DOMAINS" ]; then
    send_email_notification "$RENEWED_DOMAINS"
fi
```

### 2. Metrics Collection Concepts

#### Prometheus Metrics Pattern
```bash
#!/bin/bash
# Export certificate metrics

METRICS_FILE="/var/lib/prometheus/node-exporter/certbot.prom"

export_certificate_metrics() {
    local domains=$1
    local timestamp=$(date +%s)
    
    cat > "$METRICS_FILE" << EOF
# HELP certbot_renewal_timestamp Last certificate renewal time
# TYPE certbot_renewal_timestamp gauge
# HELP certbot_certificate_expiry Certificate expiration time
# TYPE certbot_certificate_expiry gauge
EOF
    
    for domain in $domains; do
        local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
        local expiry_date=$(openssl x509 -in "$cert_path" -noout -dates | grep notAfter | cut -d= -f2)
        local expiry_timestamp=$(date -d "$expiry_date" +%s)
        
        echo "certbot_renewal_timestamp{domain=\"$domain\"} $timestamp" >> "$METRICS_FILE"
        echo "certbot_certificate_expiry{domain=\"$domain\"} $expiry_timestamp" >> "$METRICS_FILE"
    done
    
    chown prometheus:prometheus "$METRICS_FILE"
}

export_certificate_metrics "$RENEWED_DOMAINS"
```

#### Log Aggregation Pattern
```bash
#!/bin/bash
# Structured logging for aggregation

log_renewal_event() {
    local domain=$1
    local status=$2
    local service=$3
    
    local log_entry="{
        \"timestamp\": \"$(date -Iseconds)\",
        \"event\": \"certificate_renewal\",
        \"domain\": \"$domain\",
        \"status\": \"$status\",
        \"service\": \"$service\",
        \"hostname\": \"$(hostname)\"
    }"
    
    echo "$log_entry" >> /var/log/certificate-events.jsonl
}

# Usage throughout hooks
log_renewal_event "$domain" "success" "nginx"
log_renewal_event "$domain" "failed" "postfix"
```

---

## Error Handling & Recovery

### 1. Error Handling Patterns

#### Graceful Failure Pattern
```bash
#!/bin/bash
# Handle failures gracefully

handle_service_failure() {
    local service=$1
    local exit_on_failure=${2:-false}
    
    if ! systemctl reload "$service"; then
        echo "ERROR: Failed to reload $service"
        
        # Attempt restart
        if systemctl restart "$service"; then
            echo "Successfully restarted $service after reload failure"
        else
            echo "CRITICAL: Failed to restart $service"
            
            if [ "$exit_on_failure" = "true" ]; then
                exit 1
            fi
        fi
    else
        echo "Successfully reloaded $service"
    fi
}

# Critical services fail the hook, non-critical continue
handle_service_failure "nginx" true
handle_service_failure "optional-service" false
```

#### Retry Mechanism Pattern
```bash
#!/bin/bash
# Retry failed operations

retry_operation() {
    local operation=$1
    local max_attempts=${2:-3}
    local delay=${3:-5}
    
    for attempt in $(seq 1 $max_attempts); do
        if eval "$operation"; then
            echo "Operation succeeded on attempt $attempt"
            return 0
        else
            echo "Operation failed (attempt $attempt/$max_attempts)"
            [ $attempt -lt $max_attempts ] && sleep $delay
        fi
    done
    
    echo "Operation failed after $max_attempts attempts"
    return 1
}

# Usage
retry_operation "systemctl reload nginx" 3 5
retry_operation "test_ssl_connection example.com" 2 10
```

### 2. Recovery Mechanisms

#### Configuration Backup Pattern
```bash
#!/bin/bash
# Backup and restore configurations

BACKUP_DIR="/var/backups/cert-renewal"

backup_config() {
    local config_file=$1
    local service_name=$(basename "$config_file")
    local timestamp=$(date +%Y%m%d-%H%M%S)
    
    mkdir -p "$BACKUP_DIR"
    cp "$config_file" "$BACKUP_DIR/${service_name}.${timestamp}"
    echo "$BACKUP_DIR/${service_name}.${timestamp}" > "$BACKUP_DIR/${service_name}.latest"
}

restore_config() {
    local config_file=$1
    local service_name=$(basename "$config_file")
    local backup_file=$(cat "$BACKUP_DIR/${service_name}.latest" 2>/dev/null)
    
    if [ -f "$backup_file" ]; then
        cp "$backup_file" "$config_file"
        echo "Restored $config_file from backup"
        return 0
    else
        echo "No backup found for $config_file"
        return 1
    fi
}
```

#### Service Health Validation
```bash
#!/bin/bash
# Validate service health

validate_service_health() {
    local service=$1
    local health_url=$2
    local timeout=${3:-10}
    
    # Check if service is running
    if ! systemctl is-active --quiet "$service"; then
        echo "$service is not running"
        return 1
    fi
    
    # Check health endpoint if provided
    if [ -n "$health_url" ]; then
        if timeout "$timeout" curl -sf "$health_url" >/dev/null 2>&1; then
            echo "$service health check passed"
            return 0
        else
            echo "$service health check failed"
            return 1
        fi
    fi
    
    echo "$service is running (no health check)"
    return 0
}
```

---

## Complex Multi-Service Workflows

### 1. Orchestrated Updates

#### Dependency-Aware Updates Pattern
```bash
#!/bin/bash
# Update services in dependency order

declare -A SERVICE_DEPENDENCIES=(
    ["database"]=""
    ["cache"]="database"
    ["app-server"]="database cache"
    ["web-server"]="app-server"
    ["load-balancer"]="web-server"
)

get_update_order() {
    # Simple dependency resolution (for complex cases, use proper topological sort)
    echo "database cache app-server web-server load-balancer"
}

update_service_with_dependencies() {
    local service=$1
    local dependencies="${SERVICE_DEPENDENCIES[$service]}"
    
    # Wait for dependencies to be healthy
    for dep in $dependencies; do
        while ! validate_service_health "$dep"; do
            echo "Waiting for dependency: $dep"
            sleep 5
        done
    done
    
    # Update the service
    update_service_certificates "$service"
}

# Execute in dependency order
for service in $(get_update_order); do
    update_service_with_dependencies "$service"
done
```

#### Blue-Green Deployment Pattern
```bash
#!/bin/bash
# Blue-green deployment for certificate updates

perform_blue_green_update() {
    local service=$1
    local blue_service="${service}-blue"
    local green_service="${service}-green"
    local active_service=$(get_active_service "$service")
    
    if [ "$active_service" = "$blue_service" ]; then
        local standby_service="$green_service"
    else
        local standby_service="$blue_service"
    fi
    
    # Update standby environment
    update_service_certificates "$standby_service"
    
    # Health check
    if validate_service_health "$standby_service"; then
        # Switch traffic
        switch_traffic_to "$standby_service"
        sleep 10
        
        # Final health check
        if validate_service_health "$standby_service"; then
            echo "Blue-green update successful"
            systemctl stop "$active_service"
        else
            echo "Health check failed, rolling back"
            switch_traffic_to "$active_service"
            return 1
        fi
    else
        echo "Standby service health check failed"
        return 1
    fi
}
```

### 2. Parallel Processing Patterns

#### Concurrent Service Updates
```bash
#!/bin/bash
# Update multiple services concurrently

update_service_async() {
    local service=$1
    {
        echo "Starting update for $service"
        update_service_certificates "$service"
        echo "Completed update for $service"
    } &
}

wait_for_all_updates() {
    local pids=("$@")
    local failed=0
    
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            ((failed++))
        fi
    done
    
    if [ $failed -gt 0 ]; then
        echo "$failed service updates failed"
        return 1
    else
        echo "All service updates completed successfully"
        return 0
    fi
}

# Start parallel updates
pids=()
for service in nginx postfix mysql redis; do
    update_service_async "$service"
    pids+=($!)
done

# Wait for completion
wait_for_all_updates "${pids[@]}"
```

---

## Testing & Validation

### 1. Certificate Testing Frameworks

#### Comprehensive Certificate Tests
```bash
#!/bin/bash
# Complete certificate validation suite

run_certificate_tests() {
    local domain=$1
    local tests_passed=0
    local tests_total=0
    
    # Test 1: Certificate file exists
    ((tests_total++))
    if [ -f "/etc/letsencrypt/live/$domain/fullchain.pem" ]; then
        ((tests_passed++))
        echo "✓ Certificate file exists for $domain"
    else
        echo "✗ Certificate file missing for $domain"
    fi
    
    # Test 2: Certificate is valid
    ((tests_total++))
    if openssl x509 -in "/etc/letsencrypt/live/$domain/fullchain.pem" -noout -text >/dev/null 2>&1; then
        ((tests_passed++))
        echo "✓ Certificate is valid for $domain"
    else
        echo "✗ Certificate is invalid for $domain"
    fi
    
    # Test 3: Certificate not expiring soon
    ((tests_total++))
    if openssl x509 -in "/etc/letsencrypt/live/$domain/fullchain.pem" -noout -checkend 2592000; then
        ((tests_passed++))
        echo "✓ Certificate not expiring within 30 days for $domain"
    else
        echo "✗ Certificate expiring soon for $domain"
    fi
    
    # Test 4: HTTPS connectivity
    ((tests_total++))
    if curl -sSf --max-time 10 "https://$domain" >/dev/null 2>&1; then
        ((tests_passed++))
        echo "✓ HTTPS connectivity test passed for $domain"
    else
        echo "✗ HTTPS connectivity test failed for $domain"
    fi
    
    echo "Certificate tests for $domain: $tests_passed/$tests_total passed"
    [ $tests_passed -eq $tests_total ]
}
```

#### Service Integration Tests
```bash
#!/bin/bash
# Test service-specific certificate integration

test_service_integration() {
    local domain=$1
    local service=$2
    
    case "$service" in
        "nginx"|"apache")
            test_web_server_ssl "$domain"
            ;;
        "postfix")
            test_smtp_ssl "$domain"
            ;;
        "dovecot")
            test_imap_ssl "$domain"
            ;;
        "mysql")
            test_mysql_ssl "$domain"
            ;;
        "postgresql")
            test_postgres_ssl "$domain"
            ;;
        *)
            echo "No specific test for service: $service"
            return 0
            ;;
    esac
}

test_web_server_ssl() {
    local domain=$1
    local ssl_info=$(echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | \
                     openssl x509 -noout -subject -dates 2>/dev/null)
    
    if [ -n "$ssl_info" ]; then
        echo "✓ Web server SSL test passed for $domain"
        return 0
    else
        echo "✗ Web server SSL test failed for $domain"
        return 1
    fi
}

test_smtp_ssl() {
    local domain=$1
    if echo "QUIT" | openssl s_client -connect "$domain:587" -starttls smtp >/dev/null 2>&1; then
        echo "✓ SMTP SSL test passed for $domain"
        return 0
    else
        echo "✗ SMTP SSL test failed for $domain"
        return 1
    fi
}
```

### 2. Automated Testing Patterns

#### Hook Testing Framework
```bash
#!/bin/bash
# Test renewal hooks in isolation

test_hook_execution() {
    local hook_script=$1
    local test_domains="test1.example.com test2.example.com"
    
    # Set up test environment
    export RENEWED_DOMAINS="$test_domains"
    export RENEWED_LINEAGE="/etc/letsencrypt/live/test1.example.com"
    
    # Execute hook
    if bash "$hook_script"; then
        echo "✓ Hook executed successfully: $hook_script"
        return 0
    else
        echo "✗ Hook execution failed: $hook_script"
        return 1
    fi
}

# Test all deploy hooks
for hook in /etc/letsencrypt/renewal-hooks/deploy/*.sh; do
    test_hook_execution "$hook"
done
```

#### Dry Run Pattern
```bash
#!/bin/bash
# Dry run mode for testing

DRY_RUN=${DRY_RUN:-false}

execute_command() {
    local command=$1
    
    if [ "$DRY_RUN" = "true" ]; then
        echo "[DRY RUN] Would execute: $command"
    else
        eval "$command"
    fi
}

reload_service() {
    local service=$1
    execute_command "systemctl reload $service"
}

# Usage: DRY_RUN=true ./hook-script.sh
reload_service "nginx"
reload_service "postfix"
```

### 3. Monitoring Integration

#### Health Check Integration
```bash
#!/bin/bash
# Integrate with monitoring systems

report_to_monitoring() {
    local metric_name=$1
    local value=$2
    local tags=$3
    
    # Example: InfluxDB
    curl -XPOST 'http://localhost:8086/write?db=monitoring' \
        --data-binary "$metric_name,host=$(hostname),$tags value=$value $(date +%s)000000000"
    
    # Example: Prometheus Pushgateway
    echo "$metric_name $value" | curl --data-binary @- \
        "http://localhost:9091/metrics/job/certbot/instance/$(hostname)"
}

# Report renewal success
report_to_monitoring "certbot_renewal_success" 1 "domains=$RENEWED_DOMAINS"

# Report service reload times
start_time=$(date +%s)
systemctl reload nginx
end_time=$(date +%s)
reload_duration=$((end_time - start_time))
report_to_monitoring "service_reload_duration" "$reload_duration" "service=nginx"
```

This completes the 4-part series covering all essential concepts for certificate renewal hooks, from basic patterns to advanced monitoring and validation frameworks. Each part focuses on practical, reusable concepts rather than exhaustive implementation details.