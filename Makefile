# OAuth2 Demo Server Makefile
# ==============================

.PHONY: help clean build run test fmt vet lint staticcheck test-coverage test-discovery check-discovery test-dynamic-registration check-dynamic-registration test-redirect-uri-logic test-backend-client deps tidy docker-build docker-run docker-clean install-tools dev watch all

# Variables
APP_NAME := oauth2-server
MODULE := oauth2-demo
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# Docker variables
DOCKER_IMAGE := $(APP_NAME)
DOCKER_TAG := $(VERSION)
DOCKER_REGISTRY ?= localhost

# Directories
BUILD_DIR := ./build
DIST_DIR := ./dist
CMD_DIR := ./cmd/server
INTERNAL_DIR := ./internal
TESTS_DIR := ./tests
CGO_ENABLED ?= 1

# Go build flags
GO_BUILD_FLAGS := -trimpath -mod=readonly

# Conditional race flag based on CGO availability
ifeq ($(CGO_ENABLED),0)
	GO_TEST_FLAGS := -coverprofile=coverage.out
	RACE_FLAG := 
	RACE_NOTE := (race detection disabled - CGO_ENABLED=0)
else
	GO_TEST_FLAGS := -race -coverprofile=coverage.out
	RACE_FLAG := -race
	RACE_NOTE := (with race detection)
endif

# Default target
all: clean fmt vet lint test build

# Help target
help: ## Show this help message
	@echo "OAuth2 Demo Server - Available Make Targets:"
	@echo "=============================================="
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development
dev: ## Start development server with hot reload (requires air)
	@echo "🔄 Starting development server with hot reload..."
	@if command -v air > /dev/null; then \
		air -c .air.toml; \
	else \
		echo "❌ Air not found. Install with: go install github.com/cosmtrek/air@latest"; \
		echo "💡 Falling back to regular build and run..."; \
		$(MAKE) build && ./$(APP_NAME); \
	fi

watch: ## Watch for file changes and rebuild (basic version)
	@echo "👁️  Watching for changes... (Press Ctrl+C to stop)"
	@while true; do \
		inotifywait -q -r -e modify,create,delete --include='\.go$$|\.yaml$$|\.html$$' . 2>/dev/null || \
		(echo "⚠️  inotifywait not available, using sleep-based watching"; sleep 2); \
		echo "🔄 Changes detected, rebuilding..."; \
		$(MAKE) build && echo "✅ Build complete"; \
	done

run: build ## Build and run the server
	@echo "🚀 Running $(APP_NAME)..."
	./$(APP_NAME)

##@ Build
build: ## Build the application
	@echo "🔨 Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(APP_NAME) $(CMD_DIR)/main.go
	@echo "✅ Build complete: $(APP_NAME)"

build-all: ## Build for multiple platforms
	@echo "🔨 Building for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ]; then ext=".exe"; else ext=""; fi; \
			echo "Building $$os/$$arch..."; \
			GOOS=$$os GOARCH=$$arch go build $(GO_BUILD_FLAGS) $(LDFLAGS) \
				-o $(DIST_DIR)/$(APP_NAME)-$$os-$$arch$$ext $(CMD_DIR)/main.go; \
		done; \
	done
	@echo "✅ Multi-platform build complete in $(DIST_DIR)/"

install: ## Install the binary to $GOPATH/bin
	@echo "📦 Installing $(APP_NAME)..."
	go install $(LDFLAGS) $(CMD_DIR)/main.go

##@ Code Quality
fmt: ## Format Go code
	@echo "🎨 Formatting Go code..."
	go fmt ./...
	@echo "✅ Code formatted"

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	go vet ./...
	@echo "✅ go vet passed"

lint: install-golangci-lint ## Run golangci-lint
	@echo "🔍 Running golangci-lint..."
	golangci-lint run ./...
	@echo "✅ Linting passed"

staticcheck: install-staticcheck ## Run staticcheck
	@echo "🔍 Running staticcheck..."
	staticcheck ./...
	@echo "✅ Static analysis passed"

##@ Testing
test: ## Run tests
	@echo "🧪 Running tests $(RACE_NOTE)..."
	go test $(GO_TEST_FLAGS) ./...
	@echo "✅ Tests passed"

test-verbose: ## Run tests with verbose output
	@echo "🧪 Running tests (verbose) $(RACE_NOTE)..."
	go test -v $(GO_TEST_FLAGS) ./...

test-coverage: ## Run tests with coverage report
	@echo "🧪 Running tests with coverage $(RACE_NOTE)..."
	go test $(GO_TEST_FLAGS) ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report generated: coverage.html"

test-race: ## Run tests with race detection (forces CGO_ENABLED=1)
	@echo "🧪 Running tests with race detection..."
	CGO_ENABLED=1 go test -race -coverprofile=coverage.out ./...
	@echo "✅ Tests with race detection passed"

test-no-race: ## Run tests without race detection
	@echo "🧪 Running tests without race detection..."
	go test -coverprofile=coverage.out ./...
	@echo "✅ Tests passed"

benchmark: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	go test -bench=. -benchmem $(RACE_FLAG) ./...

test-discovery: build ## Test OAuth2 discovery endpoints
	@echo "🧪 Testing OAuth2 discovery endpoints..."
	@./$(APP_NAME) & SERVER_PID=$$!; \
	sleep 2; \
	echo ""; \
	echo "📋 Testing discovery endpoints:"; \
	echo ""; \
	echo "1️⃣  OAuth2 Authorization Server Discovery:"; \
	curl -s http://localhost:8080/.well-known/oauth-authorization-server -w "\n" || echo "❌ Failed"; \
	echo ""; \
	echo "2️⃣  OpenID Connect Discovery:"; \
	curl -s http://localhost:8080/.well-known/openid-configuration -w "\n" || echo "❌ Failed"; \
	echo ""; \
	echo "3️⃣  JSON Web Key Set:"; \
	curl -s http://localhost:8080/.well-known/jwks.json -w "\n" || echo "❌ Failed"; \
	echo ""; \
	kill $$SERVER_PID 2>/dev/null || true; \
	echo "✅ Discovery endpoints test complete!"

check-discovery: ## Check if discovery endpoints are accessible (requires running server)
	@echo "🔍 Checking discovery endpoints..."
	@echo "OAuth2 Discovery:" && curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq -r '.issuer // "Not available"' 2>/dev/null || echo "❌ Not accessible"
	@echo "OpenID Discovery:" && curl -s http://localhost:8080/.well-known/openid-configuration | jq -r '.issuer // "Not available"' 2>/dev/null || echo "❌ Not accessible"  
	@echo "JWKS:" && curl -s http://localhost:8080/.well-known/jwks.json | jq -r '.keys | length // "Not available"' 2>/dev/null || echo "❌ Not accessible"

test-dynamic-registration: build ## Test dynamic client registration
	@echo "🔄 Testing dynamic client registration..."
	@if [ ! -f $(TESTS_DIR)/test-dynamic-registration.sh ]; then \
		echo "❌ Test script not found: $(TESTS_DIR)/test-dynamic-registration.sh"; \
		exit 1; \
	fi
	@chmod +x $(TESTS_DIR)/test-dynamic-registration.sh
	@./$(APP_NAME) & SERVER_PID=$$!; \
	sleep 2; \
	$(TESTS_DIR)/test-dynamic-registration.sh; \
	kill $$SERVER_PID 2>/dev/null || true

check-dynamic-registration: ## Check dynamic registration endpoint (requires running server)
	@echo "🔍 Checking dynamic registration..."
	@echo "Registration endpoint available:" && curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq -r '.registration_endpoint // "Not available"' 2>/dev/null || echo "❌ Not accessible"

test-redirect-uri-logic: build ## Test intelligent redirect URI validation logic
	@echo "🧪 Testing redirect URI validation logic..."
	@if [ ! -f $(TESTS_DIR)/test-redirect-uri-logic.sh ]; then \
		echo "❌ Test script not found: $(TESTS_DIR)/test-redirect-uri-logic.sh"; \
		exit 1; \
	fi
	@chmod +x $(TESTS_DIR)/test-redirect-uri-logic.sh
	@./$(APP_NAME) & SERVER_PID=$$!; \
	sleep 2; \
	$(TESTS_DIR)/test-redirect-uri-logic.sh; \
	kill $$SERVER_PID 2>/dev/null || true

test-backend-client: build ## Test backend service client registration (no redirect URIs)
	@echo "🧪 Testing backend service client registration..."
	@if [ ! -f $(TESTS_DIR)/test-backend-client.sh ]; then \
		echo "❌ Test script not found: $(TESTS_DIR)/test-backend-client.sh"; \
		exit 1; \
	fi
	@chmod +x $(TESTS_DIR)/test-backend-client.sh
	@./$(APP_NAME) & SERVER_PID=$$!; \
	sleep 2; \
	$(TESTS_DIR)/test-backend-client.sh; \
	kill $$SERVER_PID 2>/dev/null || true

test-all-scripts: build ## Run all test scripts in the tests directory
	@echo "🧪 Running all test scripts..."
	@if [ ! -d $(TESTS_DIR) ]; then \
		echo "❌ Tests directory not found: $(TESTS_DIR)"; \
		exit 1; \
	fi
	@chmod +x $(TESTS_DIR)/*.sh 2>/dev/null || true
	@./$(APP_NAME) & SERVER_PID=$$!; \
	sleep 2; \
	for script in $(TESTS_DIR)/*.sh; do \
		if [ -f "$$script" ]; then \
			echo "🧪 Running $$script..."; \
			$$script || echo "❌ $$script failed"; \
			echo ""; \
		fi; \
	done; \
	kill $$SERVER_PID 2>/dev/null || true; \
	echo "✅ All test scripts completed!"

##@ Dependencies
deps: ## Download dependencies
	@echo "📦 Downloading dependencies..."
	go mod download
	@echo "✅ Dependencies downloaded"

tidy: ## Tidy up go.mod
	@echo "🧹 Tidying go.mod..."
	go mod tidy
	@echo "✅ go.mod tidied"

update: ## Update dependencies
	@echo "⬆️  Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "✅ Dependencies updated"

vendor: ## Create vendor directory
	@echo "📦 Creating vendor directory..."
	go mod vendor
	@echo "✅ Vendor directory created"

##@ Docker
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	@echo "✅ Docker image built: $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)"

docker-run: ## Run Docker container
	@echo "🐳 Running Docker container..."
	docker run --rm -p 8080:8080 \
		--name $(APP_NAME)-container \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run-detached: ## Run Docker container in background
	@echo "🐳 Running Docker container in background..."
	docker run -d -p 8080:8080 \
		--name $(APP_NAME)-container \
		$(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ Container started. Use 'docker logs $(APP_NAME)-container' to view logs"

docker-stop: ## Stop Docker container
	@echo "🛑 Stopping Docker container..."
	docker stop $(APP_NAME)-container || true

docker-logs: ## Show Docker container logs
	@echo "📋 Docker container logs:"
	docker logs -f $(APP_NAME)-container

docker-shell: ## Get shell access to running container
	@echo "🐚 Accessing container shell..."
	docker exec -it $(APP_NAME)-container /bin/sh

docker-clean: ## Clean up Docker images and containers
	@echo "🧹 Cleaning up Docker..."
	docker stop $(APP_NAME)-container 2>/dev/null || true
	docker rm $(APP_NAME)-container 2>/dev/null || true
	docker rmi $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	docker rmi $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest 2>/dev/null || true
	@echo "✅ Docker cleanup complete"

docker-compose-up: ## Start services with docker-compose
	@echo "🐳 Starting services with docker-compose..."
	docker-compose up -d
	@echo "✅ Services started. Access at http://localhost:8080"

docker-compose-down: ## Stop services with docker-compose
	@echo "🛑 Stopping docker-compose services..."
	docker-compose down

docker-compose-logs: ## Show docker-compose logs
	@echo "📋 Docker-compose logs:"
	docker-compose logs -f

docker-compose-build: ## Build and start with docker-compose
	@echo "🔨 Building and starting with docker-compose..."
	docker-compose up --build -d

##@ Utilities
clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f $(APP_NAME)
	rm -f coverage.out coverage.html
	go clean -cache -testcache -modcache
	@echo "✅ Cleanup complete"

clean-all: clean docker-clean ## Clean everything including Docker

config-validate: ## Validate configuration file
	@echo "✅ Validating config.yaml..."
	@if [ -f config.yaml ]; then \
		go run $(CMD_DIR)/main.go -validate-config || echo "❌ Config validation failed"; \
	else \
		echo "❌ config.yaml not found"; \
	fi

endpoints: ## Test OAuth2 endpoints
	@echo "🔗 Testing OAuth2 endpoints..."
	@if [ -f $(TESTS_DIR)/test-endpoints.sh ]; then \
		chmod +x $(TESTS_DIR)/test-endpoints.sh && $(TESTS_DIR)/test-endpoints.sh; \
	else \
		echo "❌ $(TESTS_DIR)/test-endpoints.sh not found"; \
	fi

serve: build ## Serve the application (alias for run)
	@$(MAKE) run

##@ Security
security-scan: install-gosec ## Run security scan
	@echo "🔒 Running security scan..."
	gosec ./...
	@echo "✅ Security scan complete"

vuln-check: install-govulncheck ## Check for vulnerabilities
	@echo "🛡️  Checking for vulnerabilities..."
	govulncheck ./...
	@echo "✅ Vulnerability check complete"

##@ Installation of Tools
install-tools: install-golangci-lint install-staticcheck install-gosec install-govulncheck install-air ## Install development tools

install-golangci-lint:
	@if ! command -v golangci-lint > /dev/null; then \
		echo "📦 Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	fi

install-staticcheck:
	@if ! command -v staticcheck > /dev/null; then \
		echo "📦 Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi

install-gosec:
	@if ! command -v gosec > /dev/null; then \
		echo "📦 Installing gosec..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	fi

install-govulncheck:
	@if ! command -v govulncheck > /dev/null; then \
		echo "📦 Installing govulncheck..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi

install-air:
	@if ! command -v air > /dev/null; then \
		echo "📦 Installing air (hot reload)..."; \
		go install github.com/cosmtrek/air@latest; \
	fi

##@ Information
version: ## Show version information
	@echo "📋 Version Information:"
	@echo "  App Name:	$(APP_NAME)"
	@echo "  Module:	  $(MODULE)"
	@echo "  Version:	 $(VERSION)"
	@echo "  Git Commit:  $(GIT_COMMIT)"
	@echo "  Build Time:  $(BUILD_TIME)"
	@echo "  Go Version:  $$(go version)"

status: ## Show project status
	@echo "📊 Project Status:"
	@echo "  Module:	  $(MODULE)"
	@echo "  Go Version:  $$(go version | cut -d' ' -f3)"
	@echo "  Files:	   $$(find . -name '*.go' | wc -l) Go files"
	@echo "  Tests:	   $$(find . -name '*_test.go' | wc -l) test files"
	@echo "  Test Scripts: $$(find $(TESTS_DIR) -name '*.sh' 2>/dev/null | wc -l) shell scripts"
	@echo "  Docker:	  $$(if command -v docker > /dev/null; then echo "available"; else echo "not available"; fi)"
	@echo "  Git Branch:  $$(git branch --show-current 2>/dev/null || echo "not in git repo")"
	@echo "  Git Status:  $$(git status --porcelain 2>/dev/null | wc -l) changed files"

##@ Documentation
docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@if command -v godoc > /dev/null; then \
		echo "Starting godoc server at http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "❌ godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

##@ Maintenance
check: fmt vet lint staticcheck test ## Run all quality checks

ci: deps check build ## Run CI pipeline

release: clean check build-all ## Prepare release artifacts

quick: ## Quick build and test
	@$(MAKE) fmt vet test build

# Special targets for different environments
.PHONY: dev-setup prod-build

dev-setup: install-tools deps ## Setup development environment
	@echo "🎯 Setting up development environment..."
	@$(MAKE) tidy
	@echo "✅ Development environment ready!"

prod-build: ## Production build with optimizations
	@echo "🏭 Building for production..."
	CGO_ENABLED=0 GOOS=linux go build \
		-a -installsuffix cgo \
		-ldflags "-s -w $(LDFLAGS)" \
		-o $(APP_NAME) $(CMD_DIR)/main.go
	@echo "✅ Production build complete"