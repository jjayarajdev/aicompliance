# AI Gateway PoC - Multi-stage Dockerfile for Go Backend
# Stage 1: Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download
RUN go mod verify

# Copy source code
COPY cmd/ cmd/
COPY internal/ internal/
COPY configs/ configs/

# Build the application
# CGO_ENABLED=0 ensures static binary
# -ldflags reduces binary size by stripping debug info
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o gateway \
    ./cmd/gateway

# Stage 2: Final stage - minimal runtime image
FROM scratch

# Copy timezone data for time operations
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy SSL certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary from builder stage
COPY --from=builder /app/gateway /gateway

# Copy configuration files
COPY --from=builder /app/configs /configs

# Create a non-root user (scratch doesn't have adduser, so we define it)
# Use numeric user ID for better security
USER 65534:65534

# Expose the server port
EXPOSE 8080

# Expose metrics port
EXPOSE 9090

# Health check will be handled externally by orchestration system
# (Kubernetes, Docker Compose, etc.) using HTTP endpoint /api/v1/health

# Set environment variables
ENV GIN_MODE=release
ENV GATEWAY_ENVIRONMENT=production

# Run the binary
ENTRYPOINT ["/gateway"] 