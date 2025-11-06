#!/bin/bash

# Version tagging script for OAuth2 Server
# Usage: ./scripts/tag-version.sh [version]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "This is not a git repository"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    print_error "Working directory is not clean. Please commit or stash your changes."
    git status --short
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
print_info "Current branch: $CURRENT_BRANCH"

# Check if we're on main/master branch
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    print_warning "You're not on the main/master branch. Current branch: $CURRENT_BRANCH"
    read -p "Do you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted"
        exit 1
    fi
fi

# Get the latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
print_info "Latest tag: $LATEST_TAG"

# If version is provided as argument, use it
if [ -n "$1" ]; then
    NEW_VERSION="$1"
else
    # Generate next version suggestions
    if [[ $LATEST_TAG =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        MAJOR=${BASH_REMATCH[1]}
        MINOR=${BASH_REMATCH[2]}
        PATCH=${BASH_REMATCH[3]}
        
        NEXT_PATCH="v$MAJOR.$MINOR.$((PATCH + 1))"
        NEXT_MINOR="v$MAJOR.$((MINOR + 1)).0"
        NEXT_MAJOR="v$((MAJOR + 1)).0.0"
        
        echo
        print_info "Suggested versions:"
        echo "  1) $NEXT_PATCH (patch)"
        echo "  2) $NEXT_MINOR (minor)" 
        echo "  3) $NEXT_MAJOR (major)"
        echo "  4) Custom version"
        echo
        
        read -p "Select version (1-4): " -n 1 -r
        echo
        
        case $REPLY in
            1)
                NEW_VERSION=$NEXT_PATCH
                ;;
            2)
                NEW_VERSION=$NEXT_MINOR
                ;;
            3)
                NEW_VERSION=$NEXT_MAJOR
                ;;
            4)
                read -p "Enter custom version (e.g., v1.2.3): " NEW_VERSION
                ;;
            *)
                print_error "Invalid selection"
                exit 1
                ;;
        esac
    else
        read -p "Enter version (e.g., v1.0.0): " NEW_VERSION
    fi
fi

# Validate version format
if [[ ! $NEW_VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
    print_error "Invalid version format. Use semantic versioning: v1.2.3"
    exit 1
fi

# Check if tag already exists
if git rev-parse "$NEW_VERSION" >/dev/null 2>&1; then
    print_error "Tag $NEW_VERSION already exists"
    exit 1
fi

# Show what will be included in this release
echo
print_info "Changes since $LATEST_TAG:"
git log --oneline $LATEST_TAG..HEAD

echo
print_info "Ready to create tag: $NEW_VERSION"
read -p "Continue? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Aborted"
    exit 1
fi

# Create and push the tag
print_info "Creating tag $NEW_VERSION..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

print_info "Pushing tag to origin..."
git push origin "$NEW_VERSION"

print_success "Tag $NEW_VERSION created and pushed successfully!"
print_info "GitHub Actions will now build and publish the release."
print_info "Check the progress at: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/actions"

echo
print_info "You can also manually trigger a release with:"
print_info "gh workflow run release.yml -f version=$NEW_VERSION"