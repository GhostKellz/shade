# Shade Quick Start Guide

Get Shade running in 5 minutes for local development and testing.

## Prerequisites

- Docker and Docker Compose
- OpenSSL (for generating secrets)
- A web browser
- OAuth app credentials (Google/GitHub/Entra) - see [OAUTH_SETUP.md](OAUTH_SETUP.md)

## Step 1: Configure OAuth Providers

Before starting Shade, you need to set up OAuth applications. Follow the detailed guide in [OAUTH_SETUP.md](OAUTH_SETUP.md) to:

1. **Google OAuth** (for Claude Max):
   - Create OAuth client at [Google Cloud Console](https://console.cloud.google.com/)
   - Add redirect URI: `http://localhost:8080/callback/google`

2. **GitHub OAuth** (for Copilot Pro):
   - Create OAuth app at [GitHub Developer Settings](https://github.com/settings/developers)
   - Add callback URL: `http://localhost:8080/callback/github`

3. **Microsoft Entra** (for M365 - optional):
   - Register app at [Azure Portal](https://portal.azure.com/)
   - Add redirect URI: `http://localhost:8080/callback/entra`

## Step 2: Update .env File

A `.env` file has been created with a secure cookie secret. Now update it with your OAuth credentials:

```bash
# Edit .env file
nano .env

# Or use your favorite editor
code .env
```

Update these sections with your OAuth app credentials:

```bash
# Google
OIDC_GOOGLE_CLIENT_ID=your_actual_client_id.apps.googleusercontent.com
OIDC_GOOGLE_CLIENT_SECRET=your_actual_client_secret

# GitHub
OIDC_GITHUB_CLIENT_ID=your_actual_client_id
OIDC_GITHUB_CLIENT_SECRET=your_actual_client_secret

# Entra (optional)
OIDC_ENTRA_TENANT_ID=your_actual_tenant_id
OIDC_ENTRA_CLIENT_ID=your_actual_client_id
OIDC_ENTRA_CLIENT_SECRET=your_actual_client_secret
```

## Step 3: Start Shade

```bash
# Build and start all services
docker-compose up -d

# Check logs to ensure everything started correctly
docker-compose logs -f shade
```

You should see output like:
```
shade | Starting Shade Identity Provider on 0.0.0.0:8080
shade | Listening on 0.0.0.0:8080
shade | OIDC Issuer: http://localhost:8080
shade | Admin UI: http://localhost:8080/admin
```

## Step 4: Verify Services

```bash
# Check all services are running
docker-compose ps

# Should show:
# shade         Up      0.0.0.0:8080->8080/tcp
# shade-db      Up      0.0.0.0:5432->5432/tcp
# shade-redis   Up      0.0.0.0:6379->6379/tcp

# Test health endpoint
curl http://localhost:8080/health
# Should return: OK

# Test OIDC discovery
curl http://localhost:8080/.well-known/openid-configuration | jq
```

## Step 5: Test OAuth Login

### Test Google OAuth
```bash
# Open in browser
open http://localhost:8080/login

# Or manually navigate to the Google OAuth URL
curl -v "http://localhost:8080/authorize?client_id=test&response_type=code&scope=openid&redirect_uri=http://localhost:8080/callback&state=test123"
```

The flow:
1. Click "Sign in with Google"
2. Redirected to Google consent screen
3. Approve access
4. Redirected back to Shade
5. Session created

### Test GitHub OAuth
Same process but click "Sign in with GitHub" instead.

## Step 6: Access Admin Interface

```bash
open http://localhost:8080/admin
```

Login with default credentials:
- **Email**: `admin@example.com`
- **Password**: `ChangeMe!Long1`

**⚠️ IMPORTANT**: Change the admin password immediately!

## Step 7: Verify User Creation

```bash
# Connect to database
docker-compose exec db psql -U shade -d shade

# Check users table
shade=# SELECT id, email, email_verified, provider, created_at FROM users;
shade=# \q
```

## Integration with Zeke

Once Shade is running, configure your zeke CLI to use it:

### Option 1: Use Zeke's Config File

Edit `~/.config/zeke/config.json`:

```json
{
  "auth": {
    "type": "oauth",
    "provider_url": "http://localhost:8080",
    "client_id": "zeke-cli"
  },
  "ai": {
    "claude": {
      "enabled": true,
      "use_account_subscription": true
    },
    "copilot": {
      "enabled": true,
      "use_account_subscription": true
    }
  }
}
```

### Option 2: Set Environment Variables

```bash
export ZEKE_AUTH_PROVIDER=http://localhost:8080
export ZEKE_OAUTH_CLIENT_ID=zeke-cli
export ZEKE_USE_CLAUDE_MAX=true
export ZEKE_USE_COPILOT_PRO=true
```

### Option 3: Register Zeke as OAuth Client in Shade

```bash
# Connect to shade database
docker-compose exec db psql -U shade -d shade

# Insert OAuth client for zeke
INSERT INTO oauth_clients (
  client_id,
  client_secret_hash,
  name,
  redirect_uris,
  grant_types,
  scopes,
  is_public,
  require_pkce
) VALUES (
  'zeke-cli',
  '$argon2id$v=19$m=19456,t=2,p=1$...',  -- Hash of your client secret
  'Zeke CLI Tool',
  ARRAY['http://localhost:8181/callback', 'http://127.0.0.1:8181/callback'],
  ARRAY['authorization_code', 'refresh_token'],
  ARRAY['openid', 'email', 'profile'],
  true,
  true
);
```

Then in zeke:
```bash
zeke auth login --provider shade --url http://localhost:8080
```

## Integration with Omen

Configure omen gateway to use Shade for authentication:

Edit `omen.toml`:

```toml
[server]
host = "0.0.0.0"
port = 3000

[auth]
provider = "shade"
issuer_url = "http://localhost:8080"
jwks_url = "http://localhost:8080/jwks.json"
required_scopes = ["openid", "email"]

# Route AI providers through authenticated users
[providers.claude]
enabled = true
use_user_credentials = true
credential_source = "token"  # Extract from Shade JWT

[providers.github_copilot]
enabled = true
use_user_credentials = true
credential_source = "token"

[providers.openai]
enabled = true
api_key_source = "env"  # Fallback to API key
```

Then restart omen:
```bash
docker-compose -f /path/to/omen/docker-compose.yml up -d
```

## Common Commands

```bash
# View logs
docker-compose logs -f shade

# Restart Shade
docker-compose restart shade

# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v

# Rebuild after code changes
docker-compose build shade
docker-compose up -d shade

# Check database migrations
docker-compose exec shade sqlx migrate info --database-url postgres://shade:shadepass@db/shade

# Generate new cookie secret
openssl rand -base64 48

# Test token endpoint
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=...&client_id=...&redirect_uri=..."
```

## Troubleshooting

### Problem: Database connection refused

```bash
# Check if database is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Restart database
docker-compose restart db
```

### Problem: Redis connection failed

```bash
# Check if Redis is running
docker-compose ps redis

# Test Redis connection
docker-compose exec redis redis-cli ping
# Should return: PONG
```

### Problem: OAuth redirect mismatch

Make sure redirect URIs match exactly:
- In `.env`: `http://localhost:8080/callback/google`
- In Google Console: `http://localhost:8080/callback/google`

No trailing slashes, exact match!

### Problem: Invalid client credentials

Double-check your client ID and secret:
```bash
# View current config (secrets will be masked)
docker-compose exec shade env | grep OIDC
```

### Problem: Session not persisting

```bash
# Check Redis is working
docker-compose exec redis redis-cli KEYS '*'

# Should show session keys like: session:abc123...
```

## Next Steps

1. **Secure your deployment**
   - Change admin password
   - Use strong database passwords
   - Enable HTTPS in production

2. **Configure production settings**
   - Update `SHADE_ISSUER` to your domain
   - Update all OAuth redirect URIs
   - Set up reverse proxy (Nginx/Traefik)

3. **Set up monitoring**
   - Configure Prometheus scraping: `http://localhost:8080/metrics`
   - Set up Grafana dashboards
   - Configure audit log collection

4. **Backup your data**
   - Regular PostgreSQL backups
   - Backup JWT signing keys
   - Document disaster recovery procedures

## Production Checklist

Before deploying to production:

- [ ] Change `SHADE_ISSUER` to production domain
- [ ] Update all OAuth redirect URIs to production URLs
- [ ] Generate new, secure `SHADE_COOKIE_SECRET` (64+ bytes)
- [ ] Use strong database passwords
- [ ] Set up HTTPS/TLS with valid certificates
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerting
- [ ] Configure automated backups
- [ ] Test disaster recovery procedures
- [ ] Enable rate limiting
- [ ] Configure log aggregation
- [ ] Set up security scanning
- [ ] Document runbooks

## Resources

- [Full Documentation](DOCS.md)
- [OAuth Setup Guide](OAUTH_SETUP.md)
- [API Reference](README.md#api-endpoints)
- [Security Best Practices](README.md#security)

## Support

For issues or questions:
1. Check the logs: `docker-compose logs -f shade`
2. Review [Troubleshooting](OAUTH_SETUP.md#troubleshooting)
3. Check GitHub issues
4. Open a new issue with logs and config (redact secrets!)
