.PHONY: build test clean run dev

# Configuration variables
OAUTH2_SERVER_URL ?= http://localhost:8080
TEST_DATABASE_TYPE ?= memory
TEST_USERNAME ?= john.doe
TEST_PASSWORD ?= password123
TEST_SCOPE ?= openid profile email offline_access
API_KEY ?= super-secure-random-api-key-change-in-production-32-chars-minimum
LOG_LEVEL ?= info
LOG_FORMAT ?= text


# Check if port 8080 is available and offer to kill occupying process
check-port:
	@echo "🔍 Checking if port 8080 is available..."
	@if lsof -i :8080 >/dev/null 2>&1; then \
		echo "⚠️  Port 8080 is already in use by:"; \
		lsof -i :8080 -t | xargs ps -p 2>/dev/null || echo "   Unable to identify process"; \
		lsof -i :8080; \
		echo ""; \
		echo "💡 Options:"; \
		echo "   1. Kill the process and continue"; \
		echo "   2. Exit and handle manually"; \
		echo ""; \
		read -p "Choose option (1/2) [2]: " choice; \
		case $$choice in \
			1) \
				echo "🔪 Killing process(es) using port 8080..."; \
				lsof -ti :8080 | xargs kill -9 2>/dev/null || true; \
				sleep 2; \
				if lsof -i :8080 >/dev/null 2>&1; then \
					echo "❌ Failed to free port 8080. Please check manually."; \
					exit 1; \
				else \
					echo "✅ Port 8080 is now free."; \
				fi; \
				;; \
			*) \
				echo "👋 Exiting. Please free port 8080 manually."; \
				exit 1; \
				;; \
		esac; \
	else \
		echo "✅ Port 8080 is available."; \
	fi

# Build the application
build:
	@echo "🔨 Building OAuth2 server..."
	@mkdir -p bin
	go build -ldflags "-s -w" -o bin/oauth2-server cmd/server/main.go
	@echo "✅ Build completed: bin/oauth2-server"

# Check for compilation errors without building
check:
	@echo "🔍 Checking for compilation errors..."
	go build -o /dev/null cmd/server/main.go
	@echo "✅ No compilation errors found"

# Run the application
run:
	@echo "🚀 Starting OAuth2 server..."
	go run cmd/server/main.go

# Run with live reload (requires air: go install github.com/cosmtrek/air@latest)
dev:
	@echo "🔄 Starting development server with live reload..."
	air

# Tidy dependencies
tidy:
	@echo "🧹 Tidying dependencies..."
	go mod tidy
	go mod download

# Clean build artifacts
clean:
	@echo "🗑️ Cleaning build artifacts..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Code quality targets
fmt:
	@echo "🎨 Formatting Go code..."
	gofmt -s -w .
	@echo "✅ Code formatted successfully"

vet:
	@echo "🔍 Running go vet..."
	go vet ./...
	@echo "✅ go vet completed"

staticcheck:
	@echo "🔍 Running staticcheck..."
	@if ! command -v staticcheck >/dev/null 2>&1; then \
		echo "Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	fi
	@echo "Running staticcheck with full Go bin path..."
	$(shell go env GOPATH)/bin/staticcheck ./...
	@echo "✅ staticcheck completed"

# Alternative staticcheck target that uses go run instead
staticcheck-alt:
	@echo "🔍 Running staticcheck (alternative method)..."
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	@echo "✅ staticcheck completed"

check-deadcode:
	@echo "🔍 Checking for dead code..."
	@if ! command -v deadcode >/dev/null 2>&1; then \
		echo "Installing deadcode..."; \
		go install golang.org/x/tools/cmd/deadcode@latest; \
	fi
	@echo "Running deadcode with full Go bin path..."
	$(shell go env GOPATH)/bin/deadcode ./...
	@echo "✅ deadcode check completed"

# Enhanced lint target with better error handling
lint: fmt vet
	@echo "🔍 Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	elif [ -f "$(shell go env GOPATH)/bin/staticcheck" ]; then \
		$(shell go env GOPATH)/bin/staticcheck ./...; \
	else \
		echo "Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
		$(shell go env GOPATH)/bin/staticcheck ./...; \
	fi
	@echo "✅ All linting completed"

# Install all development tools with proper PATH setup
install-deps:
	@echo "📦 Installing development dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install github.com/cosmtrek/air@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	@echo "📍 Tools installed in: $(shell go env GOPATH)/bin"
	@echo "💡 Make sure $(shell go env GOPATH)/bin is in your PATH"
	@echo "   Add this to your shell profile:"
	@echo "   export PATH=\"$(shell go env GOPATH)/bin:\$$PATH\""

# Check if tools are properly installed
check-tools:
	@echo "🔧 Checking development tools..."
	@echo "Go version: $(shell go version)"
	@echo "GOPATH: $(shell go env GOPATH)"
	@echo "GOBIN: $(shell go env GOBIN)"
	@echo ""
	@echo "Checking tool availability:"
	@if command -v staticcheck >/dev/null 2>&1; then \
		echo "✅ staticcheck: $(shell which staticcheck)"; \
	#elif [ -f "$(shell go env GOPATH)/bin/staticcheck" ]; then \
	#	echo "⚠️  staticcheck: $(shell go env GOPATH)/bin/staticcheck (not in PATH)"; \
	#else \
	#	echo "❌ staticcheck: not installed"; \
	#fi
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "✅ golangci-lint: $(shell which golangci-lint)"; \
	#elif [ -f "$(shell go env GOPATH)/bin/golangci-lint" ]; then \
	#	echo "⚠️  golangci-lint: $(shell go env GOPATH)/bin/golangci-lint (not in PATH)"; \
	#else \
	#	echo "❌ golangci-lint: not installed"; \
	#fi
	@if command -v gosec >/dev/null 2>&1; then \
		echo "✅ gosec: $(shell which gosec)"; \
	#elif [ -f "$(shell go env GOPATH)/bin/gosec" ]; then \
	#	echo "⚠️  gosec: $(shell go env GOPATH)/bin/gosec (not in PATH)"; \
	#else \
	#	echo "❌ gosec: not installed"; \
	#fi

# Enhanced security check with proper path handling
security:
	@echo "🔒 Checking for security vulnerabilities..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	#elif [ -f "$(shell go env GOPATH)/bin/gosec" ]; then \
	#	$(shell go env GOPATH)/bin/gosec ./...; \
	#else \
	#	echo "Installing gosec..."; \
	#	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	#	$(shell go env GOPATH)/bin/gosec ./...; \
	#fi

# Enhanced golangci-lint target
golangci-lint:
	@echo "🔍 Running golangci-lint..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	#elif [ -f "$(shell go env GOPATH)/bin/golangci-lint" ]; then \
	#	$(shell go env GOPATH)/bin/golangci-lint run; \
	#else \
	#	echo "Installing golangci-lint..."; \
	#	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	#	$(shell go env GOPATH)/bin/golangci-lint run; \
	#fi
	@echo "✅ golangci-lint completed"

# Comprehensive lint target using golangci-lint (includes staticcheck)
lint-comprehensive: fmt vet golangci-lint
	@echo "✅ Comprehensive linting completed"

# Fix PATH issues by setting up proper Go environment
setup-env:
	@echo "🔧 Setting up Go development environment..."
	@echo "Current GOPATH: $(shell go env GOPATH)"
	@echo "Current PATH: $$PATH"
	@echo ""
	@echo "To fix PATH issues, add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
	@echo "export PATH=\"$(shell go env GOPATH)/bin:\$$PATH\""
	@echo ""
	@echo "Or run this command to add it temporarily:"
	@echo "export PATH=\"$(shell go env GOPATH)/bin:\$$PATH\""

# Test target - runs all test scripts with server lifecycle management and isolation
test: build
	@echo "🧪 Starting automated test suite with test isolation..."
	@echo "📦 Building server..."
	@$(MAKE) build
	@echo "✅ Test setup complete, running test scripts with server isolation..."
	@passed=0; failed=0; \
	for script in tests/test_*.sh; do \
		if [ -f "$$script" ]; then \
			echo "🧪 Running $$script with fresh server instance..."; \
			$(MAKE) test-script SCRIPT=$$(basename $$script) && { \
				echo "✅ $$script passed"; \
				passed=$$((passed + 1)); \
			} || { \
				echo "❌ $$script failed"; \
				failed=$$((failed + 1)); \
			}; \
			echo ""; \
		fi; \
	done; \
	echo "📊 Test Results: $$passed passed, $$failed failed"; \
	if [ $$failed -gt 0 ]; then \
		echo "❌ Some tests failed"; \
		exit 1; \
	else \
		echo "✅ All tests passed!"; \
	fi

# Test with verbose output and isolation
test-verbose: build
	@echo "🧪 Starting automated test suite (verbose mode with isolation)..."
	@echo "📦 Building server..."
	@$(MAKE) build
	@echo "✅ Test setup complete, running test scripts with server isolation..."
	@passed=0; failed=0; \
	for script in tests/test_*.sh; do \
		if [ -f "$$script" ]; then \
			echo "🧪 Running $$script with fresh server instance (verbose)..."; \
			$(MAKE) test-script-verbose SCRIPT=$$(basename $$script) && { \
				echo "✅ $$script passed"; \
				passed=$$((passed + 1)); \
			} || { \
				echo "❌ $$script failed"; \
				failed=$$((failed + 1)); \
			}; \
			echo ""; \
		fi; \
	done; \
	echo "📊 Test Results: $$passed passed, $$failed failed"; \
	if [ $$failed -gt 0 ]; then \
		echo "❌ Some tests failed"; \
		exit 1; \
	else \
	@echo "✅ All tests passed!"; \
	fi

# Test specific script
test-script: build
	@if [ -z "$(SCRIPT)" ]; then \
		echo "❌ Please specify a script: make test-script SCRIPT=test_device_native.sh"; \
		exit 1; \
	fi
	@if [ ! -f "tests/$(SCRIPT)" ]; then \
		echo "❌ Script tests/$(SCRIPT) not found"; \
		exit 1; \
	fi
	@echo "🧪 Testing single script: $(SCRIPT)"
	@if [ ! -f "bin/oauth2-server" ]; then \
		echo "📦 Building server..."; \
		$(MAKE) build; \
	fi
	@$(MAKE) check-port
	@echo "🚀 Starting OAuth2 server in background..."
	@DATABASE_TYPE=$(TEST_DATABASE_TYPE) UPSTREAM_PROVIDER_URL="" ENABLE_TRUST_ANCHOR_API=true API_KEY="$(API_KEY)" ./bin/oauth2-server > server-test.log 2>&1 & echo $$! > server.pid
	@echo "⏳ Waiting for server to start..."
	@sleep 5
	@echo "🔍 Testing server health..."
	@for i in 1 2 3 4 5; do \
		if curl -f -s --max-time 5 $(OAUTH2_SERVER_URL)/health > /dev/null 2>&1; then \
			echo "✅ Server is healthy"; \
			break; \
		else \
			echo "⏳ Waiting for server to respond (attempt $$i/5)..."; \
			sleep 2; \
			if [ $$i -eq 5 ]; then \
				echo "❌ Server failed to start after 5 attempts"; \
				cat server-test.log; \
				if [ -f server.pid ]; then kill $$(cat server.pid) 2>/dev/null || true; rm -f server.pid; fi; \
				exit 1; \
			fi; \
		fi; \
	done
	@echo "🔧 Setting up test certificates..."
	@if [ -f "init-certs.sh" ]; then \
		API_KEY="$(API_KEY)" OAUTH_URL="$(OAUTH2_SERVER_URL)" bash init-certs.sh; \
	else \
		echo "⚠️  init-certs.sh not found, skipping certificate setup"; \
	fi
	@echo "✅ Server is healthy, running $(SCRIPT)..."
	@if TEST_USERNAME=$(TEST_USERNAME) TEST_PASSWORD=$(TEST_PASSWORD) TEST_SCOPE="$(TEST_SCOPE)" bash tests/$(SCRIPT); then \
		echo "✅ $(SCRIPT) passed"; \
		result=0; \
	else \
		echo "❌ $(SCRIPT) failed"; \
		result=1; \
	fi; \
	if [ -f server.pid ]; then \
		echo "🛑 Stopping server..."; \
		kill $$(cat server.pid) 2>/dev/null || true; \
		rm -f server.pid; \
	fi; \
	echo "Server logs:"; \
	cat server-test.log; \
	rm -f server-test.log; \
	exit $$result

# Test specific script with verbose output
test-script-verbose:
	@if [ -z "$(SCRIPT)" ]; then \
		echo "❌ Please specify a script: make test-script-verbose SCRIPT=test_device_native.sh"; \
		exit 1; \
	fi
	@if [ ! -f "tests/$(SCRIPT)" ]; then \
		echo "❌ Script tests/$(SCRIPT) not found"; \
		exit 1; \
	fi
	@echo "🧪 Testing single script (verbose): $(SCRIPT)"
	@if [ ! -f "bin/oauth2-server" ]; then \
		echo "📦 Building server..."; \
		$(MAKE) build; \
	fi
	@$(MAKE) check-port
	@echo "🚀 Starting OAuth2 server in background..."
	@DATABASE_TYPE=$(TEST_DATABASE_TYPE) UPSTREAM_PROVIDER_URL="" ENABLE_TRUST_ANCHOR_API=true API_KEY="$(API_KEY)" ./bin/oauth2-server > server-test.log 2>&1 & echo $$! > server.pid
	@echo "⏳ Waiting for server to start..."
	@sleep 5
	@echo "🔍 Testing server health..."
	@for i in 1 2 3 4 5; do \
		if curl -f -s --max-time 5 $(OAUTH2_SERVER_URL)/health > /dev/null 2>&1; then \
			echo "✅ Server is healthy"; \
			break; \
		else \
			echo "⏳ Waiting for server to respond (attempt $$i/5)..."; \
			sleep 2; \
			if [ $$i -eq 5 ]; then \
				echo "❌ Server failed to start after 5 attempts"; \
				cat server-test.log; \
				if [ -f server.pid ]; then kill $$(cat server.pid) 2>/dev/null || true; rm -f server.pid; fi; \
				exit 1; \
			fi; \
		fi; \
	done
	@echo "🔧 Setting up test certificates..."
	@if [ -f "init-certs.sh" ]; then \
		API_KEY="$(API_KEY)" OAUTH_URL="$(OAUTH2_SERVER_URL)" bash init-certs.sh ; \
	else \
		echo "⚠️  init-certs.sh not found, skipping certificate setup"; \
	fi
	@echo "✅ Server is healthy, running $(SCRIPT) (verbose)..."
	@if TEST_USERNAME=$(TEST_USERNAME) TEST_PASSWORD=$(TEST_PASSWORD) TEST_SCOPE="$(TEST_SCOPE)" bash -x tests/$(SCRIPT); then \
		echo "✅ $(SCRIPT) passed"; \
		result=0; \
	else \
		echo "❌ $(SCRIPT) failed"; \
		result=1; \
	fi; \
	if [ -f server.pid ]; then \
		echo "🛑 Stopping server..."; \
		kill $$(cat server.pid) 2>/dev/null || true; \
		rm -f server.pid; \
	fi; \
	echo "Server logs:"; \
	cat server-test.log; \
	rm -f server-test.log; \
	exit $$result

# Test with memory database
test-memory:
	@$(MAKE) test TEST_DATABASE_TYPE=memory

test-sqlite:
	@$(MAKE) test TEST_DATABASE_TYPE=sqlite

# Help target
help:
	@echo "Available targets:"
	@echo "  build              - Build the OAuth2 server binary"
	@echo "  build-version      - Build with embedded version information"
	@echo "  run                - Build and run the server"
	@echo "  dev                - Run in development mode with auto-reload"
	@echo "  clean              - Remove build artifacts"
	@echo "  tidy               - Tidy and vendor Go modules"
	@echo ""
	@echo "Version Management:"
	@echo "  tag                - Create and push a new version tag"
	@echo "  version            - Show version information"
	@echo "  release            - Trigger GitHub release workflow"
	@echo ""
	@echo "Testing:"
	@echo "  test               - Run all test scripts with server lifecycle (includes port check)"
	@echo "  test-verbose       - Run tests with verbose output and logs (includes port check)"
	@echo "  test-script        - Run specific test script (SCRIPT=filename, includes port check)"
	@echo "  test-script-verbose- Run specific test script with verbose output (includes port check)"
	@echo "  check-port         - Check if port 8080 is available and offer to kill occupying process"
	@echo "  test-coverage      - Run tests and generate coverage report"
	@echo "  test-memory        - Run tests with memory database (TEST_DATABASE_TYPE=memory)"
	@echo ""
	@echo "Test Configuration Variables:"
	@echo "  TEST_DATABASE_TYPE - Database type for tests (default: sqlite)"
	@echo "  TEST_USERNAME      - Username for test authentication (default: john.doe)"
	@echo "  TEST_PASSWORD      - Password for test authentication (default: password123)"
	@echo "  TEST_SCOPE         - OAuth scopes for tests (default: 'openid profile email')"
	@echo "  Examples:"
	@echo "    make test TEST_DATABASE_TYPE=memory"
	@echo "    make test TEST_USERNAME=testuser TEST_PASSWORD=testpass"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt                - Format Go code"
	@echo "  vet                - Run go vet"
	@echo "  staticcheck        - Run staticcheck linter"
	@echo "  lint               - Run golangci-lint"
	@echo "  lint-comprehensive - Run comprehensive linting"
	@echo "  security           - Run security checks with gosec"
	@echo "  check-deadcode     - Check for unused (dead) code"
	@echo "  pre-commit         - Run pre-commit checks (fmt, vet, staticcheck, test)"
	@echo "  full-check         - Run all checks and tests"
	@echo ""
	@echo "Development Tools:"
	@echo "  install-deps       - Install all development dependencies"
	@echo "  check-tools        - Check if required tools are installed"
	@echo "  setup-env          - Show environment setup instructions"
	@echo ""
	@echo "Build Variants:"
	@echo "  build-all          - Build for multiple platforms"
	@echo ""
	@echo "Examples:"
	@echo "  make tag                               - Create a new version tag"
	@echo "  make test                              - Run all tests"
	@echo "  make test-script SCRIPT=test_complete_flow.sh  - Run specific test"
	@echo "  make test-verbose                      - Run tests with detailed output"
	@echo "  make check-deadcode                    - Check for unused code"

# Update .PHONY to include new targets
.PHONY: fmt vet staticcheck staticcheck-alt lint golangci-lint lint-comprehensive fix-imports pre-commit install-deps check-tools security setup-env test test-verbose test-script test-script-verbose check-port help tag version release

# Version management targets
tag:
	@echo "🏷️  Creating a new version tag..."
	@./scripts/tag-version.sh

version:
	@echo "📋 Version information:"
	@if [ -f "bin/oauth2-server" ]; then \
		./bin/oauth2-server -version; \
	else \
		echo "⚠️  Binary not found. Run 'make build' first."; \
	fi

# Build with version information
build-version:
	@echo "🔨 Building OAuth2 server with version info..."
	@mkdir -p bin
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "dev"); \
	GIT_COMMIT=$$(git rev-parse --short HEAD); \
	BUILD_TIME=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
	go build -ldflags "-s -w -X main.Version=$$VERSION -X main.GitCommit=$$GIT_COMMIT -X main.BuildTime=$$BUILD_TIME" \
		-o bin/oauth2-server cmd/server/main.go
	@echo "✅ Build completed: bin/oauth2-server"

# Manual release (for testing)
release:
	@echo "🚀 Triggering release workflow..."
	@if ! command -v gh >/dev/null 2>&1; then \
		echo "❌ GitHub CLI (gh) is required for releases"; \
		echo "Install with: brew install gh"; \
		exit 1; \
	fi
	@read -p "Enter version (e.g., v1.2.3): " VERSION; \
	gh workflow run release.yml -f version=$$VERSION
	@echo "✅ Release workflow triggered. Check GitHub Actions for progress."

# Update existing targets to use the new patterns
# Pre-commit checks with better tool handling
pre-commit: fmt vet
	@echo "🔍 Running pre-commit checks..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	fi
	@$(MAKE) test
	@echo "✅ Pre-commit checks completed"

# Full check with comprehensive linting
full-check: fmt tidy lint-comprehensive test security
	@echo "✅ Full check completed"

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o bin/oauth2-server-linux-amd64 ./cmd/server
	GOOS=windows GOARCH=amd64 go build -o bin/oauth2-server-windows-amd64.exe ./cmd/server
	GOOS=darwin GOARCH=amd64 go build -o bin/oauth2-server-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build -o bin/oauth2-server-darwin-arm64 ./cmd/server

# Create bin directory
bin:
	mkdir -p bin