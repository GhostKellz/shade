# Shade Identity Provider - Complete Documentation

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [OAuth Provider Setup](#oauth-provider-setup)
- [API Reference](#api-reference)
- [Admin Interface](#admin-interface)
- [Forward Authentication](#forward-authentication)
- [Security](#security)
- [Deployment](#deployment)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Overview

Shade is a lightweight, self-hosted Identity & Access Management (IAM) solution that provides:

- **OIDC/OAuth2 Provider**: Full OpenID Connect and OAuth 2.0 support
- **Social Login**: Integration with Google, GitHub, and Microsoft Entra ID
- **Forward Authentication**: Nginx/Traefik reverse proxy authentication
- **Admin Interface**: Web-based management console
- **Enterprise Ready**: PostgreSQL, Redis, audit logging, metrics

### Key Features

- ✅ OpenID Connect Provider (OIDC)
- ✅ OAuth 2.0 Authorization Server
- ✅ PKCE Support (RFC 7636)
- ✅ Social Login Providers (Google, GitHub, Microsoft)
- ✅ Forward Authentication for Reverse Proxies
- ✅ JWT with RS256/ES256 signing
- ✅ Multi-factor Authentication (TOTP)
- ✅ Session Management with Redis
- ✅ Audit Logging
- ✅ Prometheus Metrics
- ✅ Docker & Kubernetes Ready

## Architecture

### Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│   Reverse Proxy │◄──►│      Shade      │
│                 │    │ (Nginx/Traefik) │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                               ┌────────────────────────┼────────────────────────┐
                               │                        │                        │
                         ┌─────▼─────┐         ┌────────▼────────┐    ┌─────────▼─────────┐
                         │PostgreSQL │         │      Redis      │    │  OAuth Providers  │
                         │           │         │                 │    │ Google│GitHub│MS │
                         └───────────┘         └─────────────────┘    └───────────────────┘
```

### Technology Stack

- **Backend**: Rust with Axum web framework
- **Database**: PostgreSQL for persistent data
- **Cache/Sessions**: Redis for session management
- **Authentication**: Argon2id password hashing, TOTP MFA
- **Tokens**: JWT with RS256/ES256 signing
- **Frontend**: WASM-based admin interface
- **Deployment**: Docker containers with health checks

## Installation

### Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/your-org/shade.git
cd shade
```

2. Copy and configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start services:
```bash
docker-compose up -d
```

4. Access the admin interface at `http://localhost:8083/admin`

### Manual Installation

1. Install dependencies:
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install PostgreSQL and Redis
# On Ubuntu/Debian:
sudo apt install postgresql postgresql-contrib redis-server

# Install SQLx CLI
cargo install sqlx-cli --no-default-features --features postgres
```

2. Setup database:
```bash
# Create database and user
sudo -u postgres psql -c "CREATE DATABASE shade;"
sudo -u postgres psql -c "CREATE USER shade WITH PASSWORD 'shadepass';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE shade TO shade;"
```

3. Configure and run:
```bash
cp .env.example .env
# Edit .env file
make migrate
make dev
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHADE_ISSUER` | Public issuer URL | Required |
| `SHADE_EXTERNAL_URL` | External facing URL | Same as issuer |
| `SHADE_HOST` | Bind host | `0.0.0.0` |
| `SHADE_PORT` | Bind port | `8083` |
| `SHADE_COOKIE_SECRET` | Base64 encoded cookie secret (32+ bytes) | Required |
| `SHADE_JWT_SIGNING_ALG` | JWT signing algorithm | `RS256` |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |
| `SHADE_ADMIN_EMAIL` | Bootstrap admin email | Optional |
| `SHADE_ADMIN_PASSWORD` | Bootstrap admin password | Optional |

### Security Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SHADE_ACCESS_TOKEN_TTL` | Access token lifetime (seconds) | `3600` |
| `SHADE_REFRESH_TOKEN_TTL` | Refresh token lifetime (seconds) | `2592000` |
| `SHADE_REQUIRE_PKCE` | Require PKCE for all clients | `true` |
| `SHADE_REFRESH_TOKEN_ROTATION` | Enable refresh token rotation | `true` |
| `SHADE_MAX_FAILED_ATTEMPTS` | Max failed login attempts | `5` |
| `SHADE_LOCKOUT_DURATION_MINUTES` | Account lockout duration | `15` |

### Generating Secrets

Generate a secure cookie secret:
```bash
openssl rand -base64 48
```

Set in environment:
```bash
SHADE_COOKIE_SECRET=base64:generated_secret_here
```

## OAuth Provider Setup

### Google Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `https://auth.example.com/callback/google`

5. Configure environment:
```bash
OIDC_GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
OIDC_GOOGLE_CLIENT_SECRET=your_client_secret
OIDC_GOOGLE_REDIRECT_URI=https://auth.example.com/callback/google
```

### GitHub Setup

1. Go to [GitHub Settings > Developer settings > OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Configure:
   - Application name: Your app name
   - Homepage URL: `https://auth.example.com`
   - Authorization callback URL: `https://auth.example.com/callback/github`

4. Configure environment:
```bash
OIDC_GITHUB_CLIENT_ID=your_client_id
OIDC_GITHUB_CLIENT_SECRET=your_client_secret
OIDC_GITHUB_REDIRECT_URI=https://auth.example.com/callback/github
```

### Microsoft Entra ID (Azure AD) Setup

1. Go to [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Click "New registration"
4. Configure:
   - Name: Your app name
   - Supported account types: Choose appropriate option
   - Redirect URI: Web - `https://auth.example.com/callback/entra`

5. After creation:
   - Note the Application (client) ID
   - Note the Directory (tenant) ID
   - Go to Certificates & secrets > New client secret

6. Configure environment:
```bash
OIDC_ENTRA_TENANT_ID=your_tenant_id
OIDC_ENTRA_CLIENT_ID=your_client_id
OIDC_ENTRA_CLIENT_SECRET=your_client_secret
OIDC_ENTRA_REDIRECT_URI=https://auth.example.com/callback/entra
```

## API Reference

### Well-Known Endpoints

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OpenID Connect Discovery |
| `/jwks.json` | JSON Web Key Set |

### Authorization Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET | OAuth 2.0 authorization endpoint |
| `/token` | POST | Token exchange endpoint |
| `/userinfo` | GET | OIDC UserInfo endpoint |
| `/introspect` | POST | Token introspection |
| `/revoke` | POST | Token revocation |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET/POST | User login page and handler |
| `/logout` | GET | User logout |
| `/callback/{provider}` | GET | OAuth callback handlers |

### Administrative Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin` | GET | Admin dashboard |
| `/admin/*` | GET | Admin interface routes |
| `/api/admin/*` | GET/POST | Admin API endpoints |

### Utility Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/forward-auth` | GET | Forward authentication |

### Authorization Code Flow

1. **Authorization Request**:
```http
GET /authorize?
  response_type=code&
  client_id=your_client_id&
  redirect_uri=https://yourapp.com/callback&
  scope=openid%20profile%20email&
  state=random_state&
  code_challenge=challenge&
  code_challenge_method=S256
```

2. **Token Exchange**:
```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=auth_code&
redirect_uri=https://yourapp.com/callback&
client_id=your_client_id&
client_secret=your_secret&
code_verifier=verifier
```

3. **Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "random_refresh_token",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "scope": "openid profile email"
}
```

## Admin Interface

### Dashboard

The admin dashboard provides:
- User statistics
- Active sessions
- Recent audit logs
- System health status

### User Management

- View all users
- Create/edit/disable users
- Reset passwords
- Manage user groups
- View user login history

### OAuth Client Management

- Register new OAuth clients
- Configure redirect URIs
- Set allowed scopes
- Enable/disable clients
- View client statistics

### Audit Logs

- View all authentication events
- Filter by user, client, or action
- Export logs for compliance

### Settings

- Global security settings
- OAuth provider configuration
- System maintenance

## Forward Authentication

Shade supports forward authentication for reverse proxies like Nginx and Traefik.

### Nginx Configuration

```nginx
# Forward-auth endpoint
location = /_shade_auth {
  internal;
  proxy_pass              http://shade:8083/forward-auth;
  proxy_set_header        Host $host;
  proxy_set_header        X-Original-URI $request_uri;
  proxy_set_header        X-Real-IP $remote_addr;
  proxy_set_header        X-Forwarded-Proto $scheme;
  proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
}

# Protected application
location /app/ {
  auth_request /_shade_auth;
  error_page 401 = @shade_signin;

  # Forward identity headers
  proxy_set_header X-User  $upstream_http_x_user;
  proxy_set_header X-Email $upstream_http_x_email;
  proxy_set_header X-Groups $upstream_http_x_groups;
  
  proxy_pass http://your-app:8080;
}

# Redirect to login on auth failure
location @shade_signin {
  return 302 https://auth.example.com/login?rd=$scheme://$host$request_uri;
}
```

### Traefik Configuration

```yaml
# Traefik v2 configuration
http:
  middlewares:
    shade-auth:
      forwardAuth:
  address: http://shade:8083/forward-auth
        authResponseHeaders:
          - X-User
          - X-Email  
          - X-Groups

  routers:
    my-app:
      rule: Host(`app.example.com`)
      middlewares:
        - shade-auth
      service: my-app

  services:
    my-app:
      loadBalancer:
        servers:
          - url: http://my-app:8080
```

### Forward Auth Headers

When authentication succeeds, Shade sets these headers:

- `X-User`: User's full name
- `X-Email`: User's email address
- `X-User-Id`: User's UUID
- `X-Groups`: Comma-separated list of user groups
- `X-Authenticated-At`: ISO 8601 timestamp

## Security

### Password Security

- Argon2id password hashing
- Configurable password policies
- Account lockout after failed attempts
- Password reset functionality

### Multi-Factor Authentication

- TOTP (Time-based One-Time Password)
- Backup recovery codes
- QR code generation for easy setup

### Token Security

- JWT tokens signed with RS256/ES256
- Configurable token lifetimes
- Refresh token rotation
- Token introspection endpoint

### Session Security

- Secure, HTTPOnly cookies
- SameSite=Lax cookie attribute
- Configurable session timeouts
- Session invalidation on logout

### PKCE Support

- Proof Key for Code Exchange (RFC 7636)
- Required for public clients
- Optional for confidential clients
- S256 code challenge method

### Audit Logging

All security events are logged:
- User logins/logouts
- Failed authentication attempts
- Admin actions
- Token exchanges
- Configuration changes

## Deployment

### Production Docker Setup

```yaml
version: "3.9"
services:
  shade:
    image: ghcr.io/your-org/shade:latest
    restart: unless-stopped
    environment:
      - RUST_LOG=info
      - SHADE_ISSUER=https://auth.example.com
      - SHADE_COOKIE_SECRET=base64:your_secure_secret
      - DATABASE_URL=postgres://shade:secure_password@db/shade
      - REDIS_URL=redis://redis:6379
    ports:
      - "8083:8083"
    depends_on:
      - db
      - redis
    healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8083/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      - POSTGRES_DB=shade
      - POSTGRES_USER=shade
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - shade-dbdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U shade"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass secure_redis_password
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "secure_redis_password", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  shade-dbdata:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shade
spec:
  replicas: 2
  selector:
    matchLabels:
      app: shade
  template:
    metadata:
      labels:
        app: shade
    spec:
      containers:
      - name: shade
        image: ghcr.io/your-org/shade:latest
        ports:
  - containerPort: 8083
        env:
        - name: SHADE_ISSUER
          value: "https://auth.example.com"
        - name: SHADE_COOKIE_SECRET
          valueFrom:
            secretKeyRef:
              name: shade-secrets
              key: cookie-secret
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: shade-secrets
              key: database-url
        - name: REDIS_URL
          value: "redis://redis:6379"
        livenessProbe:
          httpGet:
            path: /health
            port: 8083
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8083
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: shade
spec:
  selector:
    app: shade
  ports:
  - port: 8083
    targetPort: 8083
```

### Environment Considerations

#### Production Checklist

- [ ] Use HTTPS with valid TLS certificates
- [ ] Set strong, unique `SHADE_COOKIE_SECRET`
- [ ] Use PostgreSQL with connection pooling
- [ ] Configure Redis with authentication
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up automated backups
- [ ] Review and set security policies
- [ ] Configure rate limiting
- [ ] Set up health checks

#### Performance Tuning

- Adjust `DATABASE_MAX_CONNECTIONS` based on load
- Configure Redis memory settings
- Set appropriate token lifetimes
- Use read replicas for high-traffic deployments
- Implement connection pooling

## Development

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/shade.git
cd shade
```

2. Install dependencies:
```bash
make install-deps
```

3. Setup environment:
```bash
make setup
```

4. Start development services:
```bash
docker-compose -f docker-compose.dev.yml up -d db redis
```

5. Run migrations and start development server:
```bash
make dev
```

### Project Structure

```
shade/
├── src/
│   ├── auth/              # Authentication utilities
│   ├── config/            # Configuration management
│   ├── db/                # Database connection and migrations
│   ├── handlers/          # HTTP request handlers
│   │   ├── admin.rs       # Admin interface handlers
│   │   ├── auth.rs        # Authentication handlers
│   │   ├── oidc.rs        # OIDC/OAuth2 handlers
│   │   └── wellknown.rs   # Well-known endpoints
│   ├── middleware/        # Custom middleware
│   ├── models/            # Database models
│   ├── providers/         # OAuth provider implementations
│   ├── services/          # Business logic services
│   │   ├── auth.rs        # Authentication service
│   │   ├── jwt.rs         # JWT handling
│   │   ├── oidc.rs        # OIDC service
│   │   └── session.rs     # Session management
│   ├── utils/             # Utility functions
│   ├── web/               # Web server state
│   └── main.rs            # Application entry point
├── migrations/            # Database migrations
├── Dockerfile             # Production container
├── docker-compose.yml     # Production compose
├── Makefile              # Build automation
└── README.md             # Project overview
```

### Adding New OAuth Providers

1. Create provider implementation in `src/providers/`:
```rust
use super::{OAuthProvider, TokenResponse, UserInfo};

pub struct CustomProvider {
    config: OAuthConfig,
}

impl OAuthProvider for CustomProvider {
    fn get_authorize_url(&self, state: &str, nonce: Option<&str>) -> String {
        // Implementation
    }
    
    async fn exchange_code(&self, code: &str) -> anyhow::Result<TokenResponse> {
        // Implementation  
    }
    
    async fn get_user_info(&self, access_token: &str) -> anyhow::Result<UserInfo> {
        // Implementation
    }
    
    fn get_provider_name(&self) -> &'static str {
        "custom"
    }
}
```

2. Add configuration in `src/config/mod.rs`
3. Add callback handler in `src/handlers/auth.rs`
4. Register provider in `src/providers/mod.rs`

### Testing

Run tests:
```bash
make test
```

Run specific test:
```bash
cargo test test_name
```

Run tests with output:
```bash
cargo test -- --nocapture
```

### Database Migrations

Create new migration:
```bash
sqlx migrate add migration_name
```

Run migrations:
```bash
make migrate
```

Revert last migration:
```bash
make migrate-revert
```

## Troubleshooting

### Common Issues

#### Database Connection Failed
```
Error: connection to server at "localhost" (127.0.0.1), port 5432 failed
```

**Solution**: Verify PostgreSQL is running and accessible:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -U shade -d shade -h localhost
```

#### Redis Connection Failed
```
Error: No connection could be made because the target machine actively refused it
```

**Solution**: Verify Redis is running:
```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli ping
```

#### JWT Signing Key Error
```
Error: Failed to initialize JWT service: Invalid RSA key
```

**Solution**: Ensure proper key generation and format. Shade automatically generates keys on startup.

#### Cookie Secret Not Set
```
Error: SHADE_COOKIE_SECRET environment variable not set
```

**Solution**: Generate and set cookie secret:
```bash
export SHADE_COOKIE_SECRET="base64:$(openssl rand -base64 48)"
```

#### Migration Failed
```
Error: relation "users" does not exist
```

**Solution**: Run database migrations:
```bash
make migrate
```

### Debug Mode

Enable debug logging:
```bash
export RUST_LOG=shade=debug,tower_http=debug
```

### Health Checks

Check application health:
```bash
curl http://localhost:8083/health
```

Check OIDC configuration:
```bash
curl http://localhost:8083/.well-known/openid-configuration | jq
```

### Performance Issues

Monitor metrics:
```bash
curl http://localhost:8083/metrics
```

Check database performance:
```sql
-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check connection count
SELECT count(*) FROM pg_stat_activity;
```

### Security Debugging

Check audit logs:
```sql
SELECT * FROM audit_logs 
WHERE created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;
```

Check failed login attempts:
```sql
SELECT user_id, count(*) as failed_attempts
FROM audit_logs 
WHERE action = 'user.login_failed' 
AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY user_id
ORDER BY failed_attempts DESC;
```

### Getting Help

1. Check the [GitHub Issues](https://github.com/your-org/shade/issues)
2. Review application logs
3. Enable debug logging
4. Check database and Redis connectivity
5. Verify configuration settings

For additional support, please open an issue with:
- Shade version
- Configuration (sensitive data redacted)
- Complete error messages
- Steps to reproduce