# Build Stage
FROM rust:slim-bullseye as builder

WORKDIR /usr/src/eidolon

# Install build dependencies (openssl, pkg-config)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY . .

# Build actual application
# Touch main.rs to force rebuild
RUN touch src/main.rs
RUN cargo build --release

# Runtime Stage
FROM debian:bullseye-slim

WORKDIR /app

# Install runtime dependencies
# curl/ca-certificates for HTTPS, libssl for crypto
RUN apt-get update && apt-get install -y ca-certificates libssl1.1 curl && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r eidolon && useradd -r -g eidolon eidolon

# Copy binary from builder
COPY --from=builder /usr/src/eidolon/target/release/eidolon /app/eidolon

# Copy configuration and assets
COPY config.toml /app/config.toml
# Bundle NLP model assets in the image (Self-contained)
COPY assets /app/assets

# Set permissions
RUN chown -R eidolon:eidolon /app

# Switch to non-root user
USER eidolon

# Expose port
EXPOSE 3000

# Set environment defaults
ENV RUN_MODE=production
ENV SERVER__HOST=0.0.0.0

CMD ["./eidolon"]
