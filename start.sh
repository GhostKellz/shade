#!/bin/bash
set -e

echo "🛡️  Shade Identity Provider - Quick Start"
echo "=========================================="
echo

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "   Please create .env file from .env.example and configure OAuth credentials."
    echo "   See OAUTH_SETUP.md for detailed instructions."
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "   Please start Docker and try again."
    exit 1
fi

# Check if required OAuth variables are set
echo "🔍 Checking configuration..."
source .env

MISSING_VARS=()

if [ -z "$SHADE_ISSUER" ]; then
    MISSING_VARS+=("SHADE_ISSUER")
fi

if [ -z "$SHADE_COOKIE_SECRET" ]; then
    MISSING_VARS+=("SHADE_COOKIE_SECRET")
fi

if [ -z "$DATABASE_URL" ]; then
    MISSING_VARS+=("DATABASE_URL")
fi

if [ -z "$REDIS_URL" ]; then
    MISSING_VARS+=("REDIS_URL")
fi

# Check at least one OAuth provider is configured
PROVIDERS_CONFIGURED=false

if [ -n "$OIDC_GOOGLE_CLIENT_ID" ] && [ -n "$OIDC_GOOGLE_CLIENT_SECRET" ]; then
    echo "✅ Google OAuth configured"
    PROVIDERS_CONFIGURED=true
fi

if [ -n "$OIDC_GITHUB_CLIENT_ID" ] && [ -n "$OIDC_GITHUB_CLIENT_SECRET" ]; then
    echo "✅ GitHub OAuth configured"
    PROVIDERS_CONFIGURED=true
fi

if [ -n "$OIDC_ENTRA_CLIENT_ID" ] && [ -n "$OIDC_ENTRA_CLIENT_SECRET" ]; then
    echo "✅ Microsoft Entra OAuth configured"
    PROVIDERS_CONFIGURED=true
fi

if [ ${#MISSING_VARS[@]} -ne 0 ]; then
    echo "❌ Error: Missing required environment variables:"
    for var in "${MISSING_VARS[@]}"; do
        echo "   - $var"
    done
    echo
    echo "Please update your .env file."
    exit 1
fi

if [ "$PROVIDERS_CONFIGURED" = false ]; then
    echo "⚠️  Warning: No OAuth providers configured!"
    echo "   You should configure at least one provider (Google/GitHub/Entra)."
    echo "   See OAUTH_SETUP.md for instructions."
    echo
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo
echo "🚀 Starting Shade services..."
echo

# Build and start services
docker-compose up -d --build

echo
echo "⏳ Waiting for services to be ready..."
sleep 5

# Check service health
echo
echo "🏥 Health check..."

# Check database
if docker-compose exec -T db pg_isready -U shade -d shade > /dev/null 2>&1; then
    echo "✅ PostgreSQL is ready"
else
    echo "⚠️  PostgreSQL is not ready yet"
fi

# Check Redis
if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis is ready"
else
    echo "⚠️  Redis is not ready yet"
fi

# Check Shade
if curl -f http://localhost:8083/health > /dev/null 2>&1; then
    echo "✅ Shade is ready"
else
    echo "⚠️  Shade is not ready yet (this is normal on first start)"
    echo "   Run: docker-compose logs -f shade"
fi

echo
echo "=========================================="
echo "🎉 Shade is starting up!"
echo
echo "📍 Services:"
echo "   - Shade:      http://localhost:8083"
echo "   - Admin UI:   http://localhost:8083/admin"
echo "   - OIDC:       http://localhost:8083/.well-known/openid-configuration"
echo "   - Health:     http://localhost:8083/health"
echo
echo "👤 Default admin credentials:"
echo "   - Email:    ${SHADE_ADMIN_EMAIL:-admin@example.com}"
echo "   - Password: ${SHADE_ADMIN_PASSWORD:-ChangeMe!Long1}"
echo
echo "📚 Documentation:"
echo "   - Quick Start:  QUICKSTART.md"
echo "   - OAuth Setup:  OAUTH_SETUP.md"
echo "   - Full Docs:    DOCS.md"
echo
echo "🔧 Useful commands:"
echo "   - View logs:    docker-compose logs -f shade"
echo "   - Stop:         docker-compose down"
echo "   - Restart:      docker-compose restart shade"
echo
echo "⚠️  IMPORTANT: Change the admin password after first login!"
echo "=========================================="
