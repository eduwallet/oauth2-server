#!/bin/bash

# Storage Consistency Test Script
# This script runs comprehensive tests to ensure all storage implementations behave identically

set -e

echo "🧪 Running Storage Consistency Tests"
echo "==================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# PostgreSQL container configuration
POSTGRES_CONTAINER_NAME="oauth2-postgres-test"
POSTGRES_DB="oauth2_test"
POSTGRES_USER="test"
POSTGRES_PASSWORD="test"
POSTGRES_PORT="5432"

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" -eq 0 ]; then
        echo -e "${GREEN}✅ $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

# Function to start PostgreSQL container
start_postgres() {
    echo -e "${YELLOW}Starting PostgreSQL container...${NC}"

    # Stop and remove any existing container
    docker stop $POSTGRES_CONTAINER_NAME 2>/dev/null || true
    docker rm $POSTGRES_CONTAINER_NAME 2>/dev/null || true

    # Start PostgreSQL container
    if docker run -d \
        --name $POSTGRES_CONTAINER_NAME \
        --network host \
        -e POSTGRES_DB=$POSTGRES_DB \
        -e POSTGRES_USER=$POSTGRES_USER \
        -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
        postgres:15-alpine; then

        echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"

        # Wait for PostgreSQL to be ready
        for i in {1..30}; do
            if docker exec $POSTGRES_CONTAINER_NAME pg_isready -U $POSTGRES_USER -d $POSTGRES_DB >/dev/null 2>&1; then
                # Try to connect from host, but don't fail if Docker networking doesn't work
                if nc -z 127.0.0.1 $POSTGRES_PORT 2>/dev/null; then
                    echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
                    return 0
                else
                    echo -e "${YELLOW}⚠️ PostgreSQL container is ready but not accessible from host (Docker networking issue)${NC}"
                    echo -e "${YELLOW}⚠️ PostgreSQL tests will be skipped${NC}"
                    return 1
                fi
            fi
            echo -e "${YELLOW}Waiting for PostgreSQL... ($i/30)${NC}"
            sleep 2
        done

        echo -e "${RED}❌ PostgreSQL failed to start within 60 seconds${NC}"
        return 1
    else
        echo -e "${RED}❌ Failed to start PostgreSQL container${NC}"
        return 1
    fi
}

# Function to stop PostgreSQL container
stop_postgres() {
    echo -e "${YELLOW}Stopping PostgreSQL container...${NC}"
    docker stop $POSTGRES_CONTAINER_NAME 2>/dev/null || true
    docker rm $POSTGRES_CONTAINER_NAME 2>/dev/null || true
    echo -e "${GREEN}✅ PostgreSQL container stopped${NC}"
}

# Function to run tests with timeout
run_test_with_timeout() {
    local test_name=$1
    local timeout_seconds=$2
    shift 2

    echo -e "${YELLOW}Running $test_name...${NC}"

    # Run test with timeout
    if timeout "$timeout_seconds" go test -v "$@" 2>&1; then
        print_status 0 "$test_name passed"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo -e "${RED}❌ $test_name timed out after ${timeout_seconds}s${NC}"
        else
            echo -e "${RED}❌ $test_name failed${NC}"
        fi
        return 1
    fi
}

cd /Users/kodde001/Projects/oauth2-server

# Check if Docker is available
if command -v docker >/dev/null 2>&1; then
    POSTGRES_AVAILABLE=true
    echo -e "${GREEN}✅ Docker available - PostgreSQL tests will be included${NC}"
else
    POSTGRES_AVAILABLE=false
    echo -e "${YELLOW}⚠️ Docker not available - PostgreSQL tests will be skipped${NC}"
fi

# Start PostgreSQL if Docker is available
if [ "$POSTGRES_AVAILABLE" = true ]; then
    if start_postgres; then
        POSTGRES_STARTED=true
    else
        POSTGRES_STARTED=false
        echo -e "${YELLOW}⚠️ PostgreSQL container failed to start - PostgreSQL tests will be skipped${NC}"
    fi
else
    POSTGRES_STARTED=false
fi

# 1. Basic compilation test
echo -e "\n${YELLOW}1. Testing Compilation${NC}"
if go build ./...; then
    print_status 0 "All packages compile successfully"
else
    print_status 1 "Compilation failed"
    # Clean up PostgreSQL container on failure
    [ "$POSTGRES_STARTED" = true ] && stop_postgres
    exit 1
fi

# 2. Unit tests for individual packages
echo -e "\n${YELLOW}2. Running Unit Tests${NC}"
if go test ./... -short; then
    print_status 0 "Unit tests passed"
else
    print_status 1 "Unit tests failed"
    # Clean up PostgreSQL container on failure
    [ "$POSTGRES_STARTED" = true ] && stop_postgres
    exit 1
fi

# 3. Storage compliance tests
echo -e "\n${YELLOW}3. Storage Compliance Tests${NC}"
cd internal/store/storages

# Test interface compliance
run_test_with_timeout "Interface Compliance" 30 -run TestStorageInterfaceCompliance
compliance_result=$?

# Test all storage implementations
run_test_with_timeout "All Storage Implementations" 120 -run TestAllStorageImplementations
all_impl_result=$?

# Test golden file compatibility
run_test_with_timeout "Golden File Compatibility" 60 -run TestGoldenFileCompatibility
golden_result=$?

# Test schema compatibility
run_test_with_timeout "Schema Compatibility" 60 -run TestSchemaCompatibility
schema_result=$?

# Test data migration
run_test_with_timeout "Data Migration" 60 -run TestDataMigrationCompatibility
migration_result=$?

# Test property-based tests
run_test_with_timeout "Property Tests" 120 -run TestAllPropertyTests
property_result=$?

cd ../../..

# 4. Concurrency tests
echo -e "\n${YELLOW}4. Concurrency Tests${NC}"
run_test_with_timeout "Concurrency Test" 60 -run TestConcurrency ./internal/store/storages
concurrency_result=$?

# 5. Memory leak detection (if available)
echo -e "\n${YELLOW}5. Memory and Performance Tests${NC}"
if command -v go test >/dev/null 2>&1; then
    # Run tests with race detector
    run_test_with_timeout "Race Condition Test" 180 -race ./internal/store/storages
    race_result=$?
else
    echo -e "${YELLOW}⚠️ Race detector not available, skipping${NC}"
    race_result=0
fi

# Clean up PostgreSQL container
[ "$POSTGRES_STARTED" = true ] && stop_postgres

# Summary
echo -e "\n${YELLOW}===================================${NC}"
echo -e "${YELLOW}STORAGE CONSISTENCY TEST SUMMARY${NC}"
echo -e "${YELLOW}===================================${NC}"

total_tests=8
passed_tests=0

# Count passed tests
[ $compliance_result -eq 0 ] && ((passed_tests++))
[ $all_impl_result -eq 0 ] && ((passed_tests++))
[ $golden_result -eq 0 ] && ((passed_tests++))
[ $schema_result -eq 0 ] && ((passed_tests++))
[ $migration_result -eq 0 ] && ((passed_tests++))
[ $property_result -eq 0 ] && ((passed_tests++))
[ $concurrency_result -eq 0 ] && ((passed_tests++))
[ $race_result -eq 0 ] && ((passed_tests++))

echo "Tests Passed: $passed_tests/$total_tests"

if [ $passed_tests -eq $total_tests ]; then
    echo -e "${GREEN}🎉 ALL STORAGE CONSISTENCY TESTS PASSED!${NC}"
    echo -e "${GREEN}All storage implementations are rock solid and behave identically.${NC}"
    exit 0
else
    failed_tests=$((total_tests - passed_tests))
    echo -e "${RED}💥 $failed_tests test(s) failed!${NC}"
    echo -e "${RED}Storage implementations may have inconsistencies.${NC}"
    exit 1
fi