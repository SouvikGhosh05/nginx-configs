# Standalone mode needs to stop nginx

#!/bin/bash
sudo systemctl stop nginx
sudo certbot certonly --standalone --cert-name authentik.codezeros.com --key-type ecdsa -d authentik.codezeros.com --agree-tos  # for ecdsa key type
sudo systemctl start nginx

# For testing purposes, you can use the following commands to check the certificate
# and restart nginx to apply the new certificate.
# Make sure to replace the domain with your actual domain if needed.
# Note: The `-k` option in curl allows connections to SSL sites without certificates.
sudo systemctl restart nginx
curl -I http://authentik.codezeros.com
curl -I -k https://authentik.codezeros.com
curl -k https://authentik.codezeros.com
curl -I -k https://adminyomaas.webcluesstaging.com

# Let's also check the Nginx configuration with verbose output to see how it's interpreting our configuration
sudo nginx -T | grep -A 20 adminyomaas

# Test with curl using a specific IP and Host header to bypass DNS
curl -I -k https://192.168.97.235 -H "Host: adminyomaas.webcluesstaging.com"

# self-signed certificate
sudo mkdir -p /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx-selfsigned.key -out /etc/nginx/ssl/nginx-selfsigned.crt

# Verify the certificate for the domain
sudo openssl x509 -in /etc/letsencrypt/live/auth.wdcstechnology.com/fullchain.pem -text -noout | grep -E 'Not Before|Not After|Subject:' 

# To see what domains are covered by the certificate
sudo openssl x509 -in /etc/letsencrypt/live/auth.wdcstechnology.com/fullchain.pem -text -noout | grep -A1 "Subject Alternative Name"