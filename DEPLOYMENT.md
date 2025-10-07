# Production Deployment Guide

Deploy Shade on a server with nginx as reverse proxy.

## Architecture

```
Internet → nginx (host) → Shade container (127.0.0.1:8080)
                              ↓
                         PostgreSQL container
                              ↓
                         Redis container
```

## Prerequisites

- Server with nginx installed
- Docker and Docker Compose
- Domain name pointing to your server
- SSL certificate (Let's Encrypt recommended)
- Ports 80 and 443 open

## Step 1: Prepare Your Server

### Install Requirements

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install nginx if not already installed
sudo apt install -y nginx certbot python3-certbot-nginx

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo apt install -y docker-compose-plugin

# Add your user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify installations
nginx -v
docker --version
docker compose version
```

### Configure Firewall

```bash
# Allow SSH, HTTP, HTTPS
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## Step 2: Obtain SSL Certificate

### Option A: Let's Encrypt (Recommended)

```bash
# Get certificate for your domain
sudo certbot --nginx -d auth.yourdomain.com

# Test auto-renewal
sudo certbot renew --dry-run
```

### Option B: Custom Certificate

Place your certificates in:
- `/etc/nginx/ssl/auth.yourdomain.com.crt`
- `/etc/nginx/ssl/auth.yourdomain.com.key`

Update paths in nginx config accordingly.

## Step 3: Clone and Configure Shade

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/yourusername/shade.git
sudo chown -R $USER:$USER shade
cd shade

# Create production environment file
cp .env.production.example .env.production

# Generate secure secrets
echo "Generating secure secrets..."

# Cookie secret (64 bytes)
COOKIE_SECRET=$(openssl rand -base64 64 | tr -d '\n')
echo "SHADE_COOKIE_SECRET=base64:$COOKIE_SECRET"

# Database password
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
echo "POSTGRES_PASSWORD=$DB_PASSWORD"

# Redis password
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
echo "REDIS_PASSWORD=$REDIS_PASSWORD"

# Edit .env.production with these values
nano .env.production
```

### Update .env.production

```bash
# CRITICAL: Update these values in .env.production

# Domain (replace with your actual domain)
SHADE_ISSUER=https://auth.yourdomain.com
SHADE_EXTERNAL_URL=https://auth.yourdomain.com

# Use the generated secrets above
SHADE_COOKIE_SECRET=base64:your_generated_cookie_secret
POSTGRES_PASSWORD=your_generated_db_password
REDIS_PASSWORD=your_generated_redis_password

# Update database URL with password
DATABASE_URL=postgres://shade:your_generated_db_password@db:5432/shade
REDIS_URL=redis://:your_generated_redis_password@redis:6379

# Set admin credentials
SHADE_ADMIN_EMAIL=admin@yourdomain.com
SHADE_ADMIN_PASSWORD=YourStrongPassword123!

# Configure OAuth providers (see OAUTH_SETUP.md)
OIDC_GOOGLE_CLIENT_ID=...
OIDC_GOOGLE_CLIENT_SECRET=...
OIDC_GOOGLE_REDIRECT_URI=https://auth.yourdomain.com/callback/google

OIDC_GITHUB_CLIENT_ID=...
OIDC_GITHUB_CLIENT_SECRET=...
OIDC_GITHUB_REDIRECT_URI=https://auth.yourdomain.com/callback/github

OIDC_ENTRA_TENANT_ID=...
OIDC_ENTRA_CLIENT_ID=...
OIDC_ENTRA_CLIENT_SECRET=...
OIDC_ENTRA_REDIRECT_URI=https://auth.yourdomain.com/callback/entra
```

## Step 4: Configure OAuth Providers

Follow [OAUTH_SETUP.md](OAUTH_SETUP.md) to set up OAuth applications with **production URLs**:

### Google OAuth
- Redirect URI: `https://auth.yourdomain.com/callback/google`
- In Google Cloud Console, add this to authorized redirect URIs

### GitHub OAuth
- Callback URL: `https://auth.yourdomain.com/callback/github`
- In GitHub OAuth app settings, update the callback URL

### Microsoft Entra
- Redirect URI: `https://auth.yourdomain.com/callback/entra`
- In Azure portal, add this to redirect URIs

## Step 5: Configure Nginx

```bash
# Copy nginx config
sudo cp /opt/shade/nginx/shade.conf /etc/nginx/sites-available/shade

# Update domain in config
sudo sed -i 's/auth.yourdomain.com/auth.YOURACTUALDOMAIN.com/g' /etc/nginx/sites-available/shade

# Or edit manually
sudo nano /etc/nginx/sites-available/shade

# Enable site
sudo ln -s /etc/nginx/sites-available/shade /etc/nginx/sites-enabled/

# Test nginx configuration
sudo nginx -t

# If test passes, reload nginx
sudo systemctl reload nginx
```

## Step 6: Start Shade

```bash
cd /opt/shade

# Build and start services
docker compose -f docker-compose.prod.yml up -d --build

# Check logs
docker compose -f docker-compose.prod.yml logs -f shade

# You should see:
# shade | Starting Shade Identity Provider on 0.0.0.0:8080
# shade | OIDC Issuer: https://auth.yourdomain.com
```

## Step 7: Verify Deployment

### Check Services

```bash
# Check all containers are running
docker compose -f docker-compose.prod.yml ps

# Should show:
# shade         Up (healthy)
# shade-db      Up (healthy)
# shade-redis   Up (healthy)

# Test health endpoint
curl http://127.0.0.1:8080/health
# Should return: OK

# Test via nginx (public)
curl https://auth.yourdomain.com/health
# Should return: OK
```

### Test OIDC Discovery

```bash
curl https://auth.yourdomain.com/.well-known/openid-configuration | jq

# Should return JSON with:
# - issuer: "https://auth.yourdomain.com"
# - authorization_endpoint, token_endpoint, etc.
```

### Test OAuth Login

1. Open browser: `https://auth.yourdomain.com/login`
2. Click "Sign in with Google" (or GitHub/Microsoft)
3. Complete OAuth flow
4. Verify redirect back to Shade

### Access Admin Interface

1. Open: `https://auth.yourdomain.com/admin`
2. Login with admin credentials
3. **IMMEDIATELY change the admin password**

## Step 8: Set Up Monitoring

### Enable Prometheus Metrics

```bash
# Metrics available at (localhost only)
curl http://127.0.0.1:8080/metrics

# Or configure nginx to allow from monitoring server
# (see nginx config - /metrics location block)
```

### Set Up Log Rotation

```bash
# Docker handles log rotation (see docker-compose.prod.yml)
# Logs are limited to 10MB x 3 files per container

# View logs
docker compose -f docker-compose.prod.yml logs -f shade
docker compose -f docker-compose.prod.yml logs -f db
docker compose -f docker-compose.prod.yml logs -f redis
```

### Set Up Database Backups

```bash
# Create backup directory
mkdir -p /opt/shade/backups

# Manual backup
docker compose -f docker-compose.prod.yml --profile backup run --rm db-backup

# Automated daily backups with cron
crontab -e

# Add this line (backup at 2 AM daily)
0 2 * * * cd /opt/shade && docker compose -f docker-compose.prod.yml --profile backup run --rm db-backup

# Keep backups for 30 days
0 3 * * * find /opt/shade/backups -name "shade_*.sql" -mtime +30 -delete
```

## Step 9: Security Hardening

### Restrict Database Access

```bash
# Edit docker-compose.prod.yml
# Comment out the db ports section to prevent external access:

# db:
#   ports:
#     - "127.0.0.1:5432:5432"  # Comment this out

# Restart
docker compose -f docker-compose.prod.yml up -d db
```

### Enable Fail2Ban

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create nginx jail
sudo nano /etc/fail2ban/jail.local
```

Add:
```ini
[nginx-shade]
enabled = true
port = http,https
filter = nginx-shade
logpath = /var/log/nginx/shade-error.log
maxretry = 5
bantime = 3600
```

Create filter:
```bash
sudo nano /etc/fail2ban/filter.d/nginx-shade.conf
```

Add:
```ini
[Definition]
failregex = ^<HOST> .* "(GET|POST) .*/login .* 401
ignoreregex =
```

```bash
# Restart fail2ban
sudo systemctl restart fail2ban
```

### Limit Rate at Nginx Level

Add to nginx config:
```nginx
# In http block of /etc/nginx/nginx.conf
limit_req_zone $binary_remote_addr zone=shade_login:10m rate=5r/m;

# In server block
location /login {
    limit_req zone=shade_login burst=2 nodelay;
    proxy_pass http://shade_backend;
    # ... other proxy settings
}
```

## Step 10: Create Systemd Service (Optional)

For auto-start on reboot:

```bash
sudo nano /etc/systemd/system/shade.service
```

Add:
```ini
[Unit]
Description=Shade Identity Provider
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/shade
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable shade
sudo systemctl start shade
```

## Maintenance

### Update Shade

```bash
cd /opt/shade

# Pull latest code
git pull

# Rebuild and restart
docker compose -f docker-compose.prod.yml up -d --build

# Check logs
docker compose -f docker-compose.prod.yml logs -f shade
```

### Restart Services

```bash
# Restart all
docker compose -f docker-compose.prod.yml restart

# Restart only Shade
docker compose -f docker-compose.prod.yml restart shade
```

### View Logs

```bash
# All services
docker compose -f docker-compose.prod.yml logs -f

# Specific service
docker compose -f docker-compose.prod.yml logs -f shade
docker compose -f docker-compose.prod.yml logs -f db
```

### Database Management

```bash
# Connect to database
docker compose -f docker-compose.prod.yml exec db psql -U shade -d shade

# Common queries
shade=# SELECT id, email, is_admin, created_at FROM users;
shade=# SELECT count(*) FROM users;
shade=# SELECT * FROM oauth_clients;
shade=# \dt  -- List tables
shade=# \q   -- Quit
```

### Restore Database Backup

```bash
# Stop shade
docker compose -f docker-compose.prod.yml stop shade

# Restore from backup
docker compose -f docker-compose.prod.yml exec -T db psql -U shade -d shade < backups/shade_20240101_120000.sql

# Restart
docker compose -f docker-compose.prod.yml start shade
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose -f docker-compose.prod.yml logs shade

# Check if port is already in use
sudo netstat -tulpn | grep 8080

# Rebuild from scratch
docker compose -f docker-compose.prod.yml down -v
docker compose -f docker-compose.prod.yml up -d --build
```

### Database Connection Failed

```bash
# Check database is running
docker compose -f docker-compose.prod.yml ps db

# Check database logs
docker compose -f docker-compose.prod.yml logs db

# Verify password in .env.production matches
grep POSTGRES_PASSWORD .env.production
```

### OAuth Redirect Not Working

```bash
# Verify redirect URIs match exactly
# In .env.production:
grep REDIRECT_URI .env.production

# Must match exactly in OAuth provider console
# Common issues:
# - http vs https
# - trailing slash
# - wrong domain
```

### SSL Certificate Issues

```bash
# Test SSL
openssl s_client -connect auth.yourdomain.com:443

# Renew Let's Encrypt
sudo certbot renew

# Check certificate expiry
sudo certbot certificates
```

## Production Checklist

Before going live:

- [ ] Domain DNS pointing to server
- [ ] SSL certificate installed and valid
- [ ] Firewall configured (80, 443, SSH only)
- [ ] All secrets generated and unique
- [ ] OAuth apps configured with production URLs
- [ ] Admin password changed from default
- [ ] Database backups configured
- [ ] Monitoring/alerting set up
- [ ] Log rotation configured
- [ ] Fail2ban or rate limiting enabled
- [ ] All OAuth flows tested
- [ ] Health checks passing
- [ ] OIDC discovery endpoint working
- [ ] Reverse proxy working correctly
- [ ] Database not exposed externally
- [ ] Redis not exposed externally

## Integration with Zeke/Omen

After deployment, update your zeke and omen configurations:

### Zeke Configuration

```json
{
  "auth": {
    "provider": "shade",
    "url": "https://auth.yourdomain.com",
    "client_id": "zeke-cli"
  }
}
```

### Omen Configuration

```toml
[auth]
issuer_url = "https://auth.yourdomain.com"
jwks_url = "https://auth.yourdomain.com/jwks.json"
```

## Support

For issues:
1. Check logs: `docker compose -f docker-compose.prod.yml logs -f`
2. Review this guide
3. Check [OAUTH_SETUP.md](OAUTH_SETUP.md)
4. Open GitHub issue with logs (redact secrets!)
