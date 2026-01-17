#!/bin/bash

# test-storage-consistency.sh
# Comprehensive storage consistency testing script for CI/CD
# Ensures all storage implementations (SQLite, PostgreSQL, Memory) behave identically

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_PACKAGE="./internal/store/storages"
TIMEOUT_DURATION="300s"  # 5 minutes timeout

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run test with timeout
run_test_with_timeout() {
    local test_name="$1"
    local timeout="$2"

    log_info "Running $test_name with ${timeout}s timeout..."

    if timeout "$timeout" go test "$TEST_PACKAGE" -run "$test_name" -v; then
        log_success "$test_name passed"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_error "$test_name timed out after ${timeout}s"
        else
            log_error "$test_name failed with exit code $exit_code"
        fi
        return $exit_code
    fi
}

# Main testing function
main() {
    log_info "Starting comprehensive storage consistency tests..."
    log_info "Project root: $PROJECT_ROOT"
    log_info "Test package: $TEST_PACKAGE"

    cd "$PROJECT_ROOT"

    # Ensure we're in a Go module
    if [ ! -f "go.mod" ]; then
        log_error "Not in a Go module directory"
        exit 1
    fi

    # Run go mod tidy to ensure dependencies are correct
    log_info "Running go mod tidy..."
    go mod tidy

    local failed_tests=0
    local total_tests=0

    # Test 1: Storage Interface Compliance
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestStorageInterfaceCompliance" "$TIMEOUT_DURATION"; then
        log_success "Interface compliance test passed"
    else
        log_error "Interface compliance test failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Test 2: All Storage Implementations
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestAllStorageImplementations" "$TIMEOUT_DURATION"; then
        log_success "All storage implementations test passed"
    else
        log_error "All storage implementations test failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Test 3: Property-based Tests
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestAllPropertyTests" "$TIMEOUT_DURATION"; then
        log_success "Property-based tests passed"
    else
        log_error "Property-based tests failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Test 4: Schema Compatibility
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestSchemaCompatibility" "$TIMEOUT_DURATION"; then
        log_success "Schema compatibility test passed"
    else
        log_error "Schema compatibility test failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Test 5: Data Migration Compatibility
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestDataMigrationCompatibility" "$TIMEOUT_DURATION"; then
        log_success "Data migration compatibility test passed"
    else
        log_error "Data migration compatibility test failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Test 6: Golden File Compatibility
    total_tests=$((total_tests + 1))
    if run_test_with_timeout "TestGoldenFileCompatibility" "$TIMEOUT_DURATION"; then
        log_success "Golden file compatibility test passed"
    else
        log_error "Golden file compatibility test failed"
        failed_tests=$((failed_tests + 1))
    fi

    # Summary
    echo
    log_info "Test Summary:"
    echo "Total tests: $total_tests"
    echo "Passed: $((total_tests - failed_tests))"
    echo "Failed: $failed_tests"

    if [ $failed_tests -eq 0 ]; then
        log_success "All storage consistency tests passed! 🎉"
        log_success "Storage implementations are rock solid and behave identically."
        exit 0
    else
        log_error "Some storage consistency tests failed. Please review the output above."
        exit 1
    fi
}

# Run main function
main "$@"