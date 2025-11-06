#!/bin/bash

# Test script for CI/CD version tagging
# This script helps validate the version tagging system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
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

print_info "Testing CI/CD Version Tagging System"
echo "========================================"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "This is not a git repository"
    exit 1
fi

# Check GitHub CLI
if ! command -v gh >/dev/null 2>&1; then
    print_warning "GitHub CLI (gh) not found. Install with: brew install gh"
    print_info "Some tests will be skipped"
    HAS_GH=false
else
    HAS_GH=true
    print_success "GitHub CLI found"
fi

# Check current repository
REPO=$(git config --get remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/' || echo "unknown")
print_info "Repository: $REPO"

# Check current branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
print_info "Current branch: $BRANCH"

# Check if we have any tags
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "none")
print_info "Latest tag: $LATEST_TAG"

# Check working directory status
if [ -n "$(git status --porcelain)" ]; then
    print_warning "Working directory has uncommitted changes"
    git status --short
else
    print_success "Working directory is clean"
fi

# Test version building
print_info "Testing version build..."
if make build-version >/dev/null 2>&1; then
    print_success "Build with version succeeded"
    
    # Test version output
    if [ -f "bin/oauth2-server" ]; then
        VERSION_OUTPUT=$(./bin/oauth2-server -version 2>&1 || echo "failed")
        if [[ "$VERSION_OUTPUT" == *"OAuth2 Server"* ]]; then
            print_success "Version command works"
            echo "  $VERSION_OUTPUT" | head -1
        else
            print_error "Version command failed: $VERSION_OUTPUT"
        fi
    else
        print_error "Binary not found after build"
    fi
else
    print_error "Build with version failed"
fi

# Test GitHub workflows
print_info "Checking GitHub Actions workflows..."

if [ -f ".github/workflows/ci.yml" ]; then
    print_success "CI workflow found"
    
    # Check for required permissions
    if grep -q "permissions:" .github/workflows/ci.yml; then
        print_success "CI workflow has permissions configured"
    else
        print_warning "CI workflow missing permissions"
    fi
    
    # Check for release step
    if grep -q "softprops/action-gh-release" .github/workflows/ci.yml; then
        print_success "Release action found in CI"
    else
        print_warning "Release action not found in CI"
    fi
else
    print_error "CI workflow not found"
fi

if [ -f ".github/workflows/release.yml" ]; then
    print_success "Release workflow found"
else
    print_warning "Dedicated release workflow not found"
fi

# Test tagging script
if [ -f "scripts/tag-version.sh" ]; then
    print_success "Version tagging script found"
    if [ -x "scripts/tag-version.sh" ]; then
        print_success "Tagging script is executable"
    else
        print_warning "Tagging script not executable"
    fi
else
    print_error "Version tagging script not found"
fi

# Check Makefile targets
print_info "Checking Makefile targets..."
if grep -q "^tag:" Makefile 2>/dev/null; then
    print_success "Makefile has 'tag' target"
else
    print_warning "Makefile missing 'tag' target"
fi

if grep -q "^version:" Makefile 2>/dev/null; then
    print_success "Makefile has 'version' target"
else
    print_warning "Makefile missing 'version' target"
fi

if grep -q "^build-version:" Makefile 2>/dev/null; then
    print_success "Makefile has 'build-version' target"
else
    print_warning "Makefile missing 'build-version' target"
fi

# Test Docker setup
print_info "Checking Docker configuration..."
if [ -f "Dockerfile" ]; then
    print_success "Dockerfile found"
    
    if grep -q "ARG VERSION" Dockerfile; then
        print_success "Dockerfile has version build args"
    else
        print_warning "Dockerfile missing version build args"
    fi
else
    print_error "Dockerfile not found"
fi

# GitHub repository checks
if [ "$HAS_GH" = true ]; then
    print_info "Checking GitHub repository settings..."
    
    # Check if logged in
    if gh auth status >/dev/null 2>&1; then
        print_success "GitHub CLI authenticated"
        
        # Check repository permissions
        REPO_INFO=$(gh repo view --json name,owner,permissions 2>/dev/null || echo "failed")
        if [[ "$REPO_INFO" != "failed" ]]; then
            print_success "Repository accessible"
        else
            print_warning "Repository not accessible or not found"
        fi
        
        # Check for existing releases
        RELEASES=$(gh release list --limit 1 2>/dev/null || echo "none")
        if [[ "$RELEASES" != "none" ]] && [[ "$RELEASES" != "" ]]; then
            print_success "Repository has releases"
        else
            print_info "No releases found (this is expected for new repos)"
        fi
        
        # Check workflows
        WORKFLOWS=$(gh workflow list 2>/dev/null || echo "failed")
        if [[ "$WORKFLOWS" != "failed" ]]; then
            print_success "GitHub Actions workflows accessible"
        else
            print_warning "Cannot access GitHub Actions workflows"
        fi
    else
        print_warning "GitHub CLI not authenticated. Run: gh auth login"
    fi
fi

# Summary
echo
print_info "Test Summary"
echo "============"

if [ -f "bin/oauth2-server" ] && [ -f ".github/workflows/ci.yml" ] && [ -f "scripts/tag-version.sh" ]; then
    print_success "Core version tagging system is ready!"
    echo
    print_info "Next steps:"
    echo "  1. Commit and push any changes"
    echo "  2. Create your first release: make tag"
    echo "  3. Check GitHub Actions for build status"
    echo "  4. Verify Docker images are published"
else
    print_error "Version tagging system has missing components"
    exit 1
fi

# Suggest next version
if [[ "$LATEST_TAG" != "none" ]]; then
    print_info "Suggested next version based on $LATEST_TAG:"
    
    if [[ $LATEST_TAG =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        MAJOR=${BASH_REMATCH[1]}
        MINOR=${BASH_REMATCH[2]}
        PATCH=${BASH_REMATCH[3]}
        
        echo "  • v$MAJOR.$MINOR.$((PATCH + 1)) (patch release)"
        echo "  • v$MAJOR.$((MINOR + 1)).0 (minor release)"
        echo "  • v$((MAJOR + 1)).0.0 (major release)"
    fi
else
    print_info "Suggested first version: v1.0.0"
fi