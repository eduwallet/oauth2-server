# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies including C compiler and SQLite dev libraries
RUN apk add --no-cache git ca-certificates tzdata gcc musl-dev sqlite-dev

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
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application with CGO enabled for SQLite support
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w \
              -X main.Version=${VERSION} \
              -X main.GitCommit=${GIT_COMMIT} \
              -X main.BuildTime=${BUILD_TIME}" \
    -o oauth2-server \
    cmd/server/main.go

# Final stage - use alpine for healthcheck capabilities
FROM alpine:latest

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