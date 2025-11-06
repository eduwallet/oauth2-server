# Version Management and Tagging Guide

This document explains how to create, manage, and deploy versioned releases of the OAuth2 Server.

## Overview

The project uses semantic versioning (`v1.2.3`) with automated CI/CD pipelines for building, testing, and releasing Docker images with proper version tags.

## Version Information

### Build-time Version Embedding

Version information is embedded into the binary at build time using Go's `-ldflags`:

```bash
-ldflags "-X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}"
```

### Checking Version

```bash
# Check version of compiled binary
./bin/oauth2-server -version

# Check version via API
curl http://localhost:8080/version

# Using make target
make version
```

## Creating New Versions

### Method 1: Interactive Script (Recommended)

```bash
# Run the interactive tagging script
make tag
# OR
./scripts/tag-version.sh

# Script will:
# 1. Check for clean working directory
# 2. Show current latest tag
# 3. Suggest next versions (patch/minor/major)
# 4. Show changes since last release
# 5. Create and push the tag
```

### Method 2: Direct Git Tagging

```bash
# Create and push a tag manually
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

### Method 3: GitHub Workflow Dispatch

```bash
# Trigger release workflow manually
gh workflow run release.yml -f version=v1.2.3
```

## Version Formats

We follow [Semantic Versioning](https://semver.org/):

- `v1.0.0` - Major release
- `v1.1.0` - Minor release (new features, backward compatible)
- `v1.1.1` - Patch release (bug fixes)
- `v1.0.0-beta.1` - Pre-release
- `v1.0.0-rc.1` - Release candidate

## CI/CD Workflows

### Main CI Workflow (`.github/workflows/ci.yml`)

Triggers on:
- Push to any branch
- Pull requests
- Push of version tags (`v*`)

**Docker Tags Generated:**
- `latest` (for main branch)
- `main` (for main branch)
- `v1.2.3`, `v1.2`, `v1` (for version tags)
- `branch-name` (for feature branches)
- `pr-123` (for pull requests)

### Release Workflow (`.github/workflows/release.yml`)

Triggers on:
- Push of version tags (`v*`)
- Manual workflow dispatch

**Actions:**
1. Run tests
2. Generate changelog
3. Build multi-platform Docker images
4. Create GitHub release
5. Upload binary artifacts

## Docker Image Tags

### Tagging Strategy

```yaml
tags: |
  # Semantic versioning tags
  type=semver,pattern={{version}}          # v1.2.3
  type=semver,pattern={{major}}.{{minor}}  # v1.2
  type=semver,pattern={{major}}            # v1 (only for v1.0.0+)
  # Latest tag for main branch
  type=raw,value=latest,enable={{is_default_branch}}
  # Branch-based tags
  type=ref,event=branch                    # main, develop
  # Git commit tags
  type=sha,prefix={{branch}}-              # main-abc1234
```

### Using Tagged Images

```bash
# Pull specific version
docker pull ghcr.io/username/oauth2-server:v1.2.3

# Pull latest
docker pull ghcr.io/username/oauth2-server:latest

# Pull major version
docker pull ghcr.io/username/oauth2-server:v1
```

## Build Targets

### Local Development

```bash
# Build with current git info
make build-version

# Check version
make version
```

### Release Builds

```bash
# Build for multiple platforms
make build-all

# Build with specific version
VERSION=v1.2.3 make build-version
```

## GitHub Releases

### Automatic Releases

When you push a version tag, GitHub Actions will:

1. **Test** - Run the full test suite
2. **Build** - Create multi-platform Docker images
3. **Release** - Create GitHub release with:
   - Changelog since last release
   - Binary artifacts for multiple platforms
   - Docker image references

### Manual Releases

```bash
# Using GitHub CLI
gh release create v1.2.3 \
  --title "Release v1.2.3" \
  --notes "Bug fixes and improvements" \
  --latest

# Using Make target
make release
```

## Version Endpoints

### API Endpoints

- **`/version`** - JSON version information
- **`/health`** - Includes version in health check
- **`/status`** - Web UI with version display

### Response Format

```json
{
  "version": "v1.2.3",
  "git_commit": "abc1234",
  "build_time": "2024-01-15T10:30:00Z",
  "server": "OAuth2 Authorization Server"
}
```

## Best Practices

### 1. Version Naming

- Use semantic versioning
- Always prefix with `v` (e.g., `v1.2.3`)
- Use pre-release tags for testing (`v1.2.3-beta.1`)

### 2. Release Process

1. **Prepare** - Ensure all changes are committed
2. **Test** - Run `make test` locally
3. **Tag** - Use `make tag` for interactive tagging
4. **Verify** - Check GitHub Actions for successful build
5. **Deploy** - Update deployment configurations

### 3. Changelog Generation

Changelogs are auto-generated from git commits:

```bash
# Good commit messages
feat: add attestation support for JWT clients
fix: resolve token expiration edge case
docs: update API documentation

# Will generate readable changelog entries
```

### 4. Docker Deployment

```yaml
# docker-compose.yml - Use specific versions in production
services:
  oauth2-server:
    image: ghcr.io/username/oauth2-server:v1.2.3  # Pin to specific version
    # OR for latest stable
    image: ghcr.io/username/oauth2-server:v1      # Major version
```

## Troubleshooting

### Common Issues

**1. Tag already exists**
```bash
# Delete local tag
git tag -d v1.2.3
# Delete remote tag
git push origin :refs/tags/v1.2.3
```

**2. Build fails on tag push**
```bash
# Check GitHub Actions logs
gh run list --workflow=ci.yml
gh run view [run-id]
```

**3. Version not embedded**
```bash
# Ensure build uses ldflags
make build-version
# Check if version is set
./bin/oauth2-server -version
```

**4. Docker image not found**
```bash
# Check if image was pushed
gh run view --log | grep "docker push"
# Verify registry
docker pull ghcr.io/username/oauth2-server:v1.2.3
```

## Scripts and Tools

- **`scripts/tag-version.sh`** - Interactive version tagging
- **`make tag`** - Create new version tags
- **`make version`** - Show version information
- **`make release`** - Trigger release workflow
- **`make build-version`** - Build with version info

## Integration Examples

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-server
spec:
  template:
    spec:
      containers:
      - name: oauth2-server
        image: ghcr.io/username/oauth2-server:v1.2.3
        command: ["./oauth2-server", "-version"]  # Check version on startup
```

### Health Monitoring

```bash
# Monitor version in health checks
curl -s http://oauth2-server:8080/version | jq '.version'

# Include in monitoring dashboards
curl -s http://oauth2-server:8080/health | jq '.version'
```