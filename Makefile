.PHONY: dev build test clean docker docker-build docker-run migrate

# Development
dev: migrate
	cargo run

dev-watch: migrate
	cargo watch -x run

# Build
build:
	cargo build --release

# Testing
test:
	cargo test

# Clean
clean:
	cargo clean

# Docker
docker-build:
	docker build -t shade:latest .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f shade

# Database
migrate:
	@if command -v sqlx >/dev/null 2>&1; then \
		sqlx migrate run --database-url $${DATABASE_URL:-postgres://shade:shadepass@localhost/shade}; \
	else \
		echo "sqlx-cli not found. Install with: cargo install sqlx-cli"; \
	fi

migrate-revert:
	sqlx migrate revert --database-url $${DATABASE_URL:-postgres://shade:shadepass@localhost/shade}

# Generate cookie secret
cookie-secret:
	@openssl rand -base64 48

# Generate JWT keypair (for manual setup)
jwt-keypair:
	@echo "Generating RSA keypair for JWT signing..."
	@openssl genpkey -algorithm RSA -out private_key.pem -pkcs8 -aes256
	@openssl rsa -in private_key.pem -pubout -out public_key.pem

# Setup development environment
setup: install-deps
	cp .env.example .env
	@echo "Created .env file. Please update with your configuration."
	@echo "Generate cookie secret with: make cookie-secret"

install-deps:
	cargo install sqlx-cli --no-default-features --features postgres