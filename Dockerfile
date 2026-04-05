# ═══════════════════════════════════════════════════════════════
#  EdgeMask Backend — Multi-Stage Dockerfile
#  Produces a minimal, secure production image (~20MB)
# ═══════════════════════════════════════════════════════════════

# ─── Stage 1: Build ──────────────────────────────────────────
FROM golang:1.25-alpine AS builder

# Install git & ca-certificates (needed for go mod download over HTTPS)
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Dependency caching: copy mod files first, download before copying source
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the source code
COPY . .

# Build a fully static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-w -s -extldflags '-static'" \
      -trimpath \
      -o /bin/edgemask \
      cmd/api/main.go

# ─── Stage 2: Production ────────────────────────────────────
FROM alpine:3.20 AS production

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -S appgroup \
    && adduser -S appuser -G appgroup

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/edgemask .

# Copy migration files for runtime init
COPY --from=builder /src/migrations ./migrations

# Ensure binary is executable
RUN chmod +x ./edgemask

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 3000

# Health check: hit /health every 30s
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Run the application
ENTRYPOINT ["./edgemask"]
