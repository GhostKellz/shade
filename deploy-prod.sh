#!/bin/bash
set -e

echo "🚀 Shade Production Deployment Script"
echo "======================================"
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Warning: Running as root. Consider using a non-root user with sudo access."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if .env.production exists
if [ ! -f .env.production ]; then
    echo "❌ Error: .env.production not found!"
    echo "   Please create it from .env.production.example:"
    echo "   cp .env.production.example .env.production"
    echo "   Then edit it with your configuration."
    exit 1
fi

# Function to generate secure secret
generate_secret() {
    openssl rand -base64 "$1" | tr -d '\n'
}

# Check if secrets are still default values
echo "🔍 Checking configuration..."
source .env.production

NEEDS_UPDATE=false

if [[ "$SHADE_COOKIE_SECRET" == *"REPLACE_WITH"* ]]; then
    echo "⚠️  SHADE_COOKIE_SECRET needs to be updated"
    NEEDS_UPDATE=true
fi

if [[ "$POSTGRES_PASSWORD" == *"STRONG"* ]]; then
    echo "⚠️  POSTGRES_PASSWORD needs to be updated"
    NEEDS_UPDATE=true
fi

if [[ "$REDIS_PASSWORD" == *"STRONG"* ]]; then
    echo "⚠️  REDIS_PASSWORD needs to be updated"
    NEEDS_UPDATE=true
fi

if [ "$NEEDS_UPDATE" = true ]; then
    echo
    echo "Would you like me to generate secure secrets? (Recommended)"
    read -p "Generate secrets? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo
        echo "📝 Generated Secrets (save these!):"
        echo "=================================="

        COOKIE_SECRET=$(generate_secret 64)
        echo "SHADE_COOKIE_SECRET=base64:$COOKIE_SECRET"

        DB_PASSWORD=$(generate_secret 32)
        echo "POSTGRES_PASSWORD=$DB_PASSWORD"

        REDIS_PASSWORD=$(generate_secret 32)
        echo "REDIS_PASSWORD=$REDIS_PASSWORD"

        echo
        echo "Please update .env.production with these values and run this script again."
        exit 0
    else
        echo "Please update .env.production manually and run this script again."
        exit 1
    fi
fi

# Check if issuer is still example domain
if [[ "$SHADE_ISSUER" == *"yourdomain.com"* ]]; then
    echo "⚠️  Warning: SHADE_ISSUER still contains 'yourdomain.com'"
    echo "   Please update with your actual domain in .env.production"
    exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed!"
    echo "   Install Docker first: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "❌ Error: Docker Compose is not installed!"
    exit 1
fi

# Check nginx
if ! command -v nginx &> /dev/null; then
    echo "⚠️  Warning: nginx not found on this system"
    echo "   Please install nginx: sudo apt install nginx"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "✅ Configuration looks good"
echo

# Ask for confirmation
echo "This will:"
echo "  - Build Shade Docker image"
echo "  - Start PostgreSQL database"
echo "  - Start Redis cache"
echo "  - Start Shade service"
echo "  - Expose Shade on 127.0.0.1:8288 for nginx proxy"
echo
read -p "Continue with deployment? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

echo
echo "🔨 Building and starting services..."
docker compose -f docker-compose.prod.yml up -d --build

echo
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check service health
echo
echo "🏥 Health checks:"

# Check database
if docker compose -f docker-compose.prod.yml exec -T db pg_isready -U shade -d shade > /dev/null 2>&1; then
    echo "✅ PostgreSQL is healthy"
else
    echo "❌ PostgreSQL is not ready"
    echo "   Check logs: docker compose -f docker-compose.prod.yml logs db"
fi

# Check Redis
if docker compose -f docker-compose.prod.yml exec -T redis redis-cli --raw incr ping > /dev/null 2>&1; then
    echo "✅ Redis is healthy"
else
    echo "❌ Redis is not ready"
    echo "   Check logs: docker compose -f docker-compose.prod.yml logs redis"
fi

# Check Shade
sleep 5
if curl -sf http://127.0.0.1:8288/health > /dev/null 2>&1; then
    echo "✅ Shade is healthy"
else
    echo "⚠️  Shade is not responding yet (this may be normal on first start)"
    echo "   Check logs: docker compose -f docker-compose.prod.yml logs -f shade"
fi

echo
echo "======================================"
echo "🎉 Deployment Started!"
echo

# Get issuer from env
ISSUER=$(grep SHADE_ISSUER .env.production | cut -d= -f2)
ADMIN_EMAIL=$(grep SHADE_ADMIN_EMAIL .env.production | cut -d= -f2)

echo "📍 Service Information:"
echo "   - Internal:  http://127.0.0.1:8288"
echo "   - Public:    $ISSUER"
echo "   - Admin UI:  $ISSUER/admin"
echo "   - OIDC:      $ISSUER/.well-known/openid-configuration"
echo
echo "👤 Admin Credentials:"
echo "   - Email:     $ADMIN_EMAIL"
echo "   - Password:  (check .env.production)"
echo
echo "📋 Next Steps:"
echo "   1. Configure nginx (see nginx/shade.conf)"
echo "   2. Test: curl http://127.0.0.1:8288/health"
echo "   3. Test: curl $ISSUER/health"
echo "   4. Access admin UI and change password"
echo "   5. Test OAuth flows"
echo "   6. Set up monitoring and backups"
echo
echo "📚 Documentation:"
echo "   - Deployment: DEPLOYMENT.md"
echo "   - OAuth Setup: OAUTH_SETUP.md"
echo
echo "🔧 Useful Commands:"
echo "   - Logs:      docker compose -f docker-compose.prod.yml logs -f"
echo "   - Restart:   docker compose -f docker-compose.prod.yml restart"
echo "   - Stop:      docker compose -f docker-compose.prod.yml down"
echo "   - Backup DB: docker compose -f docker-compose.prod.yml --profile backup run --rm db-backup"
echo
echo "⚠️  IMPORTANT:"
echo "   - Change admin password after first login!"
echo "   - Set up SSL certificate with Let's Encrypt"
echo "   - Configure automated backups"
echo "   - Enable monitoring"
echo "======================================"
