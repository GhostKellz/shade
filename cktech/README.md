# CKTech.org Deployment

This directory contains the production deployment configuration for Shade on CKTech.org infrastructure.

## Configuration

**Domain:** auth.cktech.org
**Nginx:** Running on host with wildcard cert at `/etc/nginx/certs/cktech.org/`
**Container:** Exposed on `127.0.0.1:8083`
**Deployment Path:** `/opt/shade`

## Files

- `nginx-shade.conf` - Nginx reverse proxy configuration
- `docker-compose.yml` - Docker Compose for CKTech deployment
- `.env.example` - Environment template (copy to `.env`)
- `.env` - Your actual config (not tracked by git)
- `backups/` - Database backups (created automatically)

## Quick Deployment

```bash
# 1. Clone to /opt/shade on your nginx host
cd /opt
sudo git clone <repo> shade
cd shade/cktech

# 2. Create .env from template
cp .env.example .env

# 3. Generate secrets and update .env
openssl rand -base64 64  # Cookie secret
openssl rand -base64 32  # DB password
openssl rand -base64 32  # Redis password
nano .env  # Update with secrets and OAuth credentials

# 4. Deploy with Docker
docker compose up -d --build

# 5. Configure nginx
sudo cp nginx-shade.conf /etc/nginx/conf.d/shade.conf
sudo nginx -t
sudo systemctl reload nginx

# 6. Test
curl http://127.0.0.1:8083/health
curl https://auth.cktech.org/health
```

## OAuth Provider URLs

When setting up OAuth apps, use these redirect URIs:

- **Google:** `https://auth.cktech.org/callback/google`
- **GitHub:** `https://auth.cktech.org/callback/github`
- **Entra:** `https://auth.cktech.org/callback/entra`

## Maintenance

```bash
# View logs
docker compose logs -f

# Restart
docker compose restart shade

# Backup database
docker compose --profile backup run --rm db-backup

# Update
git pull
docker compose up -d --build
```

## SSL Certificate

Using wildcard certificate at:
- Cert: `/etc/nginx/certs/cktech.org/fullchain.pem`
- Key: `/etc/nginx/certs/cktech.org/privkey.pem`

## Security

- Container only exposed to localhost (127.0.0.1:8083)
- Nginx handles SSL termination
- Database and Redis only accessible via Docker network
- All secrets in `.env` (not tracked by git)

## Support

See parent directory documentation:
- `../DEPLOYMENT.md` - Detailed deployment guide
- `../OAUTH_SETUP.md` - OAuth provider setup
- `../README.md` - Main documentation
