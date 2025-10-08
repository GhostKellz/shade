# OAuth Provider Setup Guide

This guide walks you through setting up OAuth applications for Google, GitHub, and Microsoft Entra ID (M365) to use with Shade.

## Table of Contents
- [Google OAuth Setup (for Claude Max)](#google-oauth-setup)
- [GitHub OAuth Setup (for Copilot Pro)](#github-oauth-setup)
- [Microsoft Entra ID Setup (for M365)](#microsoft-entra-id-setup)
- [Testing Your Setup](#testing-your-setup)

---

## Google OAuth Setup

**Purpose**: Access Claude Max subscription via Google account

### Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" → "New Project"
3. Name it (e.g., "Shade Identity Provider")
4. Click "Create"

### Step 2: Enable Required APIs

1. In the project, go to **APIs & Services** → **Library**
2. Search for and enable:
   - **Google+ API** (for user profile)
   - **People API** (optional, for extended profile data)

### Step 3: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** (unless you have a Google Workspace)
3. Fill in the required fields:
   - **App name**: Shade Identity Provider
   - **User support email**: Your email
   - **Developer contact email**: Your email
4. Click **Save and Continue**
5. On **Scopes** page, click **Add or Remove Scopes**:
   - Add: `openid`, `email`, `profile`
6. Click **Save and Continue**
7. On **Test users** page (if app is in testing mode):
   - Add your Google email address and any other users who need access
8. Click **Save and Continue**

### Step 4: Create OAuth Client

1. Go to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Select **Web application**
4. Configure:
   - **Name**: Shade OAuth Client
   - **Authorized redirect URIs**:
  - `http://localhost:8083/callback/google` (for local testing)
     - `https://auth.yourdomain.com/callback/google` (for production)
5. Click **Create**
6. **Save the Client ID and Client Secret** - you'll need these for your `.env` file

### Step 5: Update .env File

```bash
OIDC_GOOGLE_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
OIDC_GOOGLE_CLIENT_SECRET=your_client_secret_here
OIDC_GOOGLE_REDIRECT_URI=http://localhost:8083/callback/google
```

---

## GitHub OAuth Setup

**Purpose**: Access GitHub Copilot Pro subscription

### Step 1: Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **OAuth Apps** → **New OAuth App**
3. Fill in the form:
   - **Application name**: Shade Identity Provider
   - **Homepage URL**:
  - `http://localhost:8083` (for local testing)
     - `https://auth.yourdomain.com` (for production)
   - **Authorization callback URL**:
  - `http://localhost:8083/callback/github` (for local testing)
     - `https://auth.yourdomain.com/callback/github` (for production)
4. Click **Register application**

### Step 2: Generate Client Secret

1. On the OAuth App page, click **Generate a new client secret**
2. **Save the Client ID and Client Secret** immediately

### Step 3: Update .env File

```bash
OIDC_GITHUB_CLIENT_ID=Iv1.your_client_id_here
OIDC_GITHUB_CLIENT_SECRET=your_client_secret_here
OIDC_GITHUB_REDIRECT_URI=http://localhost:8083/callback/github
```

---

## Microsoft Entra ID Setup

**Purpose**: M365 SSO integration

### Step 1: Register Application in Azure

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Fill in the form:
   - **Name**: Shade Identity Provider
   - **Supported account types**:
     - "Accounts in this organizational directory only" (single tenant)
     - Or "Accounts in any organizational directory" (multi-tenant)
   - **Redirect URI**:
     - Platform: **Web**
  - URI: `http://localhost:8083/callback/entra` (local)
     - URI: `https://auth.yourdomain.com/callback/entra` (production)
5. Click **Register**

### Step 2: Note Important IDs

1. On the app **Overview** page, copy:
   - **Application (client) ID**
   - **Directory (tenant) ID**

### Step 3: Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add description: "Shade OAuth Secret"
4. Select expiration (recommended: 24 months)
5. Click **Add**
6. **Copy the secret Value immediately** (it won't be shown again)

### Step 4: Configure API Permissions

1. Go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Select **Delegated permissions**
5. Add these permissions:
   - `openid`
   - `profile`
   - `email`
   - `User.Read`
6. Click **Add permissions**
7. Click **Grant admin consent** (if you have admin rights)

### Step 5: Update .env File

```bash
OIDC_ENTRA_TENANT_ID=your_tenant_id_here
OIDC_ENTRA_CLIENT_ID=your_client_id_here
OIDC_ENTRA_CLIENT_SECRET=your_client_secret_here
OIDC_ENTRA_REDIRECT_URI=http://localhost:8083/callback/entra
```

---

## Testing Your Setup

### 1. Start Shade Locally

```bash
# Copy the example env file
cp .env.example .env

# Edit .env with your OAuth credentials
nano .env

# Generate a secure cookie secret
export SHADE_COOKIE_SECRET="base64:$(openssl rand -base64 48)"
echo "SHADE_COOKIE_SECRET=$SHADE_COOKIE_SECRET" >> .env

# Start services with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f shade
```

### 2. Test Each Provider

#### Google OAuth Test
1. Open browser to: `http://localhost:8083/login`
2. Click "Sign in with Google" button
3. Should redirect to Google consent screen
4. After approval, redirects back to Shade

#### GitHub OAuth Test
1. Open browser to: `http://localhost:8083/login`
2. Click "Sign in with GitHub" button
3. Should redirect to GitHub authorization
4. After approval, redirects back to Shade

#### Entra OAuth Test
1. Open browser to: `http://localhost:8083/login`
2. Click "Sign in with Microsoft" button
3. Should redirect to Microsoft login
4. After approval, redirects back to Shade

### 3. Verify Authentication

```bash
# Check if user was created
docker-compose exec db psql -U shade -d shade -c "SELECT id, email, provider FROM users;"
```

### 4. Test OIDC Endpoints

```bash
# Check OIDC discovery
curl http://localhost:8083/.well-known/openid-configuration | jq

# Check JWKS endpoint
curl http://localhost:8083/jwks.json | jq
```

---

## Integration with Zeke

Once Shade is running, configure your zeke tool to use Shade for authentication:

```json
{
  "auth": {
    "provider": "shade",
  "oidc_url": "http://localhost:8083",
    "client_id": "zeke-cli",
    "scopes": ["openid", "email", "profile"]
  },
  "ai": {
    "claude": {
      "use_account_subscription": true,
      "auth_provider": "google"
    }
  }
}
```

## Integration with Omen

Configure omen to use Shade as the authentication layer:

```toml
[auth]
provider = "shade"
oidc_issuer = "http://localhost:8083"
client_id = "omen-gateway"
client_secret = "your_omen_client_secret"

[providers.claude]
use_user_credentials = true
credential_provider = "shade"
```

---

## Troubleshooting

### Common Issues

**1. Redirect URI Mismatch**
- Error: `redirect_uri_mismatch`
- Solution: Ensure the redirect URI in your OAuth app matches exactly with the one in `.env`

**2. Invalid Client**
- Error: `invalid_client`
- Solution: Double-check your Client ID and Client Secret are correct

**3. Scope Not Approved**
- Error: `access_denied` or `insufficient_scope`
- Solution: Make sure you've granted admin consent (Entra) or added test users (Google)

**4. Database Connection Failed**
- Error: `connection refused`
- Solution: Ensure PostgreSQL is running: `docker-compose ps db`

**5. Redis Connection Failed**
- Error: `redis connection error`
- Solution: Ensure Redis is running: `docker-compose ps redis`

### Debug Logging

Enable verbose logging to troubleshoot:

```bash
export RUST_LOG=shade=debug,tower_http=debug
docker-compose up
```

### Check Provider Configuration

```bash
# Verify provider config loaded
docker-compose logs shade | grep -i "provider"
```

---

## Production Deployment

For production deployment:

1. **Use HTTPS**: All redirect URIs must use `https://`
2. **Secure secrets**: Use a secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager)
3. **Update redirect URIs**: Change all OAuth apps to use production domain
4. **Enable MFA**: Configure TOTP for admin accounts
5. **Set up monitoring**: Use `/metrics` endpoint with Prometheus
6. **Configure backup**: Regular PostgreSQL backups
7. **Use strong cookie secret**: Generate with `openssl rand -base64 64`

### Production Environment Variables

```bash
SHADE_ISSUER=https://auth.yourdomain.com
SHADE_EXTERNAL_URL=https://auth.yourdomain.com
SHADE_COOKIE_SECRET=base64:your_very_long_secure_secret
DATABASE_URL=postgres://shade:secure_password@db:5432/shade
REDIS_URL=redis://redis:6379

# Update all redirect URIs to production domain
OIDC_GOOGLE_REDIRECT_URI=https://auth.yourdomain.com/callback/google
OIDC_GITHUB_REDIRECT_URI=https://auth.yourdomain.com/callback/github
OIDC_ENTRA_REDIRECT_URI=https://auth.yourdomain.com/callback/entra
```

---

## Security Best Practices

1. **Never commit `.env` files** to version control
2. **Rotate secrets regularly** (every 90 days recommended)
3. **Use different OAuth apps** for development and production
4. **Enable MFA** for all admin accounts
5. **Monitor audit logs** regularly
6. **Keep Shade updated** with security patches
7. **Use PKCE** (enabled by default in Shade)
8. **Implement rate limiting** (enabled by default in Shade)

---

## Next Steps

1. Set up monitoring with Prometheus/Grafana
2. Configure reverse proxy (Nginx/Traefik) with TLS
3. Implement backup and restore procedures
4. Set up high availability with multiple Shade instances
5. Configure custom branding for login pages

For more information, see the [main README](README.md) and [DOCS.md](DOCS.md).
