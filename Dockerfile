# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/shade
COPY Cargo.toml ./
COPY src ./src
COPY migrations ./migrations

# Build the application
# Note: SQLx queries will be validated at runtime, not compile-time
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 shade

# Copy the binary and migrations
COPY --from=builder /usr/src/shade/target/release/shade /usr/local/bin/shade
COPY --from=builder /usr/src/shade/migrations /usr/local/share/shade/migrations

# Create directories and set permissions
RUN mkdir -p /var/lib/shade && chown -R shade:shade /var/lib/shade
RUN chown -R shade:shade /usr/local/share/shade

USER shade
WORKDIR /var/lib/shade

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8083/health || exit 1

EXPOSE 8083

# Set default environment variables
ENV RUST_LOG=shade=info,tower_http=info
ENV SHADE_HOST=0.0.0.0
ENV SHADE_PORT=8083

CMD ["shade"]