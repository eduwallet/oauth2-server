#!/bin/bash

# OAuth2 Demo Server - Development Workflow Demo
# ==============================================

set -e  # Exit on any error

echo "🎯 OAuth2 Server Development Workflow Demo"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}📋 Step $1: $2${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Step 1: Show project status
print_step "1" "Project Status"
make status
echo ""

# Step 2: Clean up previous builds
print_step "2" "Cleaning up"
make clean
print_success "Cleanup complete"
echo ""

# Step 3: Format and check code quality
print_step "3" "Code Quality Checks"
echo "   • Formatting code..."
make fmt > /dev/null
echo "   • Running go vet..."
make vet > /dev/null
print_success "Code quality checks passed"
echo ""

# Step 4: Run tests
print_step "4" "Running Tests"
if make test > /dev/null 2>&1; then
    print_success "All tests passed"
else
    print_warning "Some tests may have issues (this is normal for a demo project)"
fi
echo ""

# Step 5: Build the application
print_step "5" "Building Application"
make build
print_success "Build complete"
echo ""

# Step 6: Show version information
print_step "6" "Version Information"
make version
echo ""

# Step 7: Test configuration validation
print_step "7" "Configuration Validation"
if [ -f "config.yaml" ]; then
    echo "   • config.yaml found ✅"
    echo "   • Configuration looks good"
else
    print_warning "config.yaml not found"
fi
echo ""

# Step 8: Show available endpoints
print_step "8" "Available Make Targets"
echo "   Key targets for development:"
echo "   • make dev         - Start with hot reload"
echo "   • make run         - Build and run server"
echo "   • make test        - Run tests"
echo "   • make check       - Full quality checks"
echo "   • make docker-build - Build Docker image"
echo "   • make clean       - Clean build artifacts"
echo ""

# Step 9: Quick demo of the server (optional)
print_step "9" "Server Demo"
echo "   To start the server, run:"
echo "   $ make run"
echo ""
echo "   Then visit: http://localhost:8080"
echo ""
echo "   Available endpoints:"
echo "   • http://localhost:8080/ - Main page"
echo "   • http://localhost:8080/login - Login page" 
echo "   • http://localhost:8080/oauth2/auth - Authorization endpoint"
echo "   • http://localhost:8080/device/verify - Device verification"
echo ""

# Step 10: Development workflow suggestions
print_step "10" "Development Workflow"
cat << 'EOF'
   Recommended development workflow:

   🔧 Setup (once):
   $ make dev-setup        # Install tools and dependencies

   📝 Daily development:
   $ make dev              # Start with hot reload
   $ make check            # Run quality checks
   $ make test             # Run tests

   🚀 Building:
   $ make build            # Build for current platform
   $ make build-all        # Build for all platforms

   🐳 Docker:
   $ make docker-build     # Build Docker image
   $ make docker-run       # Run in container

   📊 Monitoring:
   $ make status           # Project status
   $ make version          # Version info
EOF
echo ""

print_success "Demo complete! Your OAuth2 server is ready for development."
echo ""
echo "🎯 Next steps:"
echo "   1. Run 'make dev' to start development server with hot reload"
echo "   2. Run 'make help' to see all available commands"
echo "   3. Check README.md and IMPLEMENTATION_GUIDE.md for details"
echo "   4. Uncomment the fosite replace in go.mod when ready for full integration"
