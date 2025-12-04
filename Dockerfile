# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies including C compiler and SQLite dev libraries
RUN apk add --no-cache git ca-certificates gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies (cached if go.mod/go.sum haven't changed)
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_TIME

# Build the application with CGO enabled for SQLite support
RUN VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)} && \
    GIT_COMMIT_FULL=${GIT_COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)} && \
    GIT_COMMIT_SHORT=$(echo $GIT_COMMIT_FULL | cut -c1-8) && \
    BUILD_TIME_RAW=${BUILD_TIME:-$(date +%s)} && \
    BUILD_TIME_FORMATTED=$(date -u -d "@$BUILD_TIME_RAW" +"%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S UTC") && \
    CGO_ENABLED=1 GOOS=linux go build \
        -ldflags="-s -w \
                  -X 'main.Version=${VERSION}' \
                  -X 'main.GitCommit=${GIT_COMMIT_SHORT}' \
                  -X 'main.BuildTime=${BUILD_TIME_FORMATTED}'" \
        -o oauth2-server \
        cmd/server/main.go

# Final stage - use alpine for healthcheck capabilities
FROM alpine:3.20

# Install ca-certificates for HTTPS calls and SQLite runtime libraries
RUN apk add --no-cache ca-certificates curl sqlite-libs

# Copy binary from builder stage
COPY --from=builder /app/oauth2-server /app/oauth2-server

# Copy configuration files
COPY --from=builder /app/config.yaml /app/config.yaml
COPY --from=builder /app/templates /app/templates

# Set working directory
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Change ownership of app directory
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["./oauth2-server"]