# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies (cached if go.mod/go.sum haven't changed)
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG COMMIT_SHA=unknown
ARG BUILD_TIME
ARG GO_VERSION

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags="-s -w -extldflags '-static' \
              -X main.version=${VERSION} \
              -X main.commit=${COMMIT_SHA} \
              -X main.buildTime=${BUILD_TIME} \
              -X main.goVersion=${GO_VERSION}" \
    -o oauth2-server \
    cmd/server/main.go

# Final stage - use distroless for security
FROM gcr.io/distroless/static:nonroot

# Copy binary from builder stage
COPY --from=builder /app/oauth2-server /app/oauth2-server
COPY --from=builder /app/templates /app/templates

# Copy configuration files
COPY --from=builder /app/config.yaml /app/config.yaml

# Set working directory
WORKDIR /app

# Use non-root user (already set in distroless/static:nonroot)
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["./oauth2-server"]