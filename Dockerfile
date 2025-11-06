# Build stage
FROM golang:1.25-alpine AS builder

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
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags="-s -w -extldflags '-static' \
              -X main.Version=${VERSION} \
              -X main.GitCommit=${GIT_COMMIT} \
              -X main.BuildTime=${BUILD_TIME}" \
    -o oauth2-server \
    cmd/server/main.go

# Final stage - use distroless for security
FROM gcr.io/distroless/static:nonroot

# Copy binary from builder stage
COPY --from=builder /app/oauth2-server /app/oauth2-server

# Copy configuration files
COPY --from=builder /app/config.yaml /app/config.yaml
COPY --from=builder /app/templates /app/templates

# Set working directory
WORKDIR /app

# Use non-root user (already set in distroless/static:nonroot)
USER nonroot:nonroot

# Expose port
EXPOSE 8080

# Run the application
ENTRYPOINT ["./oauth2-server"]