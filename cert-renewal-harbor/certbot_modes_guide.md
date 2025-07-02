# Comprehensive Guide: Certbot Modes and Usage Scenarios

## Overview

This guide explains how Certbot, the client for Let's Encrypt, can be used in different modes to obtain and manage SSL certificates. It compares various plugins such as `--webroot`, `--standalone`, and `--nginx`, and provides clarity on when to use them, how they work internally, and how they differ from one another.

---

## 1. Certbot Plugins and Their Working

### A. `--webroot`

- **Usage**:

  ```bash
  sudo certbot certonly --webroot -w /path/to/webroot -d yourdomain.com
  ```

- **How it works**:

  - Certbot writes a temporary challenge file under `.well-known/acme-challenge/` in the specified webroot directory.
  - Let's Encrypt server verifies the file via HTTP.
  - Your web server (e.g., Nginx) must be running and serving this path.

- **When to use**:

  - Web server is already running and serving content.
  - No need or desire to stop the server.
  - You want more control over certificate installation.

- **Pros**:

  - No downtime.
  - Great for automation.

- **Cons**:

  - Must know and correctly configure the webroot path.

### B. `--standalone`

- **Usage**:

  ```bash
  sudo certbot certonly --standalone -d yourdomain.com
  ```

- **How it works**:

  - Certbot runs a temporary web server on port 80 to serve the challenge.
  - Let's Encrypt connects directly to this Certbot server.
  - Existing web server (e.g., Nginx) must be stopped temporarily.

- **When to use**:

  - No existing web server.
  - Lightweight environments or APIs.

- **Pros**:

  - Simple for headless/embedded systems.

- **Cons**:

  - Requires stopping any service on port 80.
  - Downtime during issuance/renewal.

### C. `--nginx`

- **Usage**:

  ```bash
  sudo certbot --nginx -d yourdomain.com
  ```

- **How it works**:

  - Certbot detects the Nginx configuration and injects temporary configuration for HTTP-01 challenge.
  - Automatically sets up HTTPS server block and reloads Nginx.

- **Alternative**:

  ```bash
  sudo certbot certonly --nginx -d yourdomain.com
  ```

  - This will only obtain the cert without editing the Nginx config.

- **When to use**:

  - You want Certbot to automatically configure Nginx for SSL.

- **Pros**:

  - Very convenient for beginners.
  - Automatic HTTPS setup.

- **Cons**:

  - Less control over Nginx configuration.

---

## 2. Difference Between `certbot --nginx` and `certbot certonly --nginx`

| Feature                       | `certbot --nginx` | `certbot certonly --nginx`            |
| ----------------------------- | ----------------- | ------------------------------------- |
| Obtains certificate           | ✅ Yes             | ✅ Yes                                 |
| Installs certificate in Nginx | ✅ Yes             | ❌ No                                  |
| Modifies Nginx config (HTTPS) | ✅ Yes             | ❌ No                                  |
| Reloads Nginx                 | ✅ Yes             | ✅ Only during challenge               |
| Adds HTTP to HTTPS redirect   | ✅ Optional        | ❌ No                                  |
| Best for                      | Full automation   | Manual config with automated issuance |

---

## 3. DNS-01 Challenge (Other Certificate Authorities)

- **Description**: Adds a TXT record to your DNS zone instead of using HTTP.
- **Best for**:
  - Wildcard domains.
  - Closed environments.
  - Avoiding open ports.

### Example with ZeroSSL or DNS Plugin:

```bash
sudo certbot --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/cloudflare.ini -d example.com -d '*.example.com'
```

- **Providers**: ZeroSSL, Buypass, etc.
- **When to use**:
  - Wildcard certificates needed.
  - You're not allowed to open ports 80/443.

---

## 4. Comparison Table

| Feature                      | --webroot | --standalone | --nginx | DNS-01 |
| ---------------------------- | --------- | ------------ | ------- | ------ |
| Needs running web server     | Yes       | No           | Yes     | No     |
| Stops web server required    | No        | Yes          | No      | No     |
| Supports wildcard            | No        | No           | No      | Yes    |
| Installs SSL automatically   | No        | No           | Yes     | No     |
| Ideal for automation         | Yes       | Yes          | Yes     | Yes    |
| Requires DNS provider config | No        | No           | No      | Yes    |

---

## 5. Summary: When to Use What

| Use Case                               | Recommended Mode     |
| -------------------------------------- | -------------------- |
| Running web server, no downtime needed | `--webroot`          |
| No server running, headless server     | `--standalone`       |
| Use nginx and want full automation     | `--nginx`            |
| Need wildcard or internal certs        | `DNS-01` via plugins |

---

## 6. Extra Tips

- Use `--deploy-hook` to reload your server after cert renewal:

  ```bash
  --deploy-hook "systemctl reload nginx"
  ```

- Combine `certonly` with your own config management for better control.

- Use `/var/log/letsencrypt/letsencrypt.log` to debug issues.

- To test renewal without hitting rate limits:

  ```bash
  sudo certbot renew --dry-run
  ```

- To schedule automatic renewals (cron job example):

  ```bash
  0 3 * * * /usr/bin/certbot renew --quiet --deploy-hook "systemctl reload nginx"
  ```

- Certbot certificate files are stored in `/etc/letsencrypt/live/<yourdomain>/`

  - `fullchain.pem`, `privkey.pem`, `cert.pem`, etc.

---

## 7. Certificate Authority Alternatives

| CA            | Type  | Wildcard | ACME Support | Free | Notes                           |
| ------------- | ----- | -------- | ------------ | ---- | ------------------------------- |
| Let's Encrypt | DV    | ✅        | ✅            | ✅    | Most popular open CA            |
| ZeroSSL       | DV    | ✅        | ✅            | ✅    | Offers GUI and ACME API         |
| Buypass       | DV    | ✅        | ✅            | ✅    | Long-lived certs (180 days)     |
| DigiCert      | OV/EV | ✅        | ❌            | ❌    | Paid, high-trust with warranty  |
| Self-Signed   | N/A   | ✅        | ❌            | ✅    | For internal or development use |

---

## Conclusion

Choosing the right Certbot mode depends on your environment, desired automation level, and certificate scope. For most public-facing web apps, Let's Encrypt with `--nginx` or `--webroot` suffices. For wildcard domains, DNS-01 validation with plugins or ZeroSSL is a better choice. Paid CAs are ideal when business validation or warranties are needed.

