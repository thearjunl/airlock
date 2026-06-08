# =============================================================================
# AirLock — Multi-stage Docker build
# Stage 1: Build the Go binary in an Alpine-based Go image
# Stage 2: Copy the binary into a scratch (empty) image for minimal footprint
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM golang:1.21-alpine AS builder

# Install ca-certificates so we can copy them to the scratch image later
RUN apk --no-cache add ca-certificates

WORKDIR /build

# Copy dependency manifests first for better Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source directories
COPY proxy/ proxy/
COPY scanner/ scanner/
COPY sandbox/ sandbox/
COPY alerting/ alerting/
COPY config/ config/
COPY ratelimit/ ratelimit/

# Build a statically-linked binary with stripped debug info
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o airlock \
    ./proxy/

# ---------------------------------------------------------------------------
# Stage 2: Runtime (scratch — zero OS, minimal attack surface)
# ---------------------------------------------------------------------------
FROM scratch

# Import TLS root certificates for HTTPS upstream connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary
COPY --from=builder /build/airlock /airlock

# Expose the proxy port
EXPOSE 8080

# Run the AirLock proxy
ENTRYPOINT ["/airlock"]
