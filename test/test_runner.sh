#!/usr/bin/env bash
#
# Lightweight bash test runner - zero external dependencies
#
# Usage: ./test/test_runner.sh [test_file.sh]
#        ./test/test_runner.sh              # runs all tests
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Test state
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
CURRENT_TEST=""
declare -a FAILED_TESTS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Test Framework Functions
# =============================================================================

test_start() {
    CURRENT_TEST="$1"
    ((TESTS_RUN++)) || true
    printf "  %-60s " "$CURRENT_TEST"
}

test_pass() {
    ((TESTS_PASSED++)) || true
    echo -e "${GREEN}PASS${NC}"
}

test_fail() {
    local msg="${1:-}"
    ((TESTS_FAILED++)) || true
    echo -e "${RED}FAIL${NC}"
    [[ -n "$msg" ]] && echo -e "    ${RED}→ $msg${NC}"
    FAILED_TESTS+=("$CURRENT_TEST")
}

test_skip() {
    local reason="${1:-}"
    echo -e "${YELLOW}SKIP${NC} ${reason}"
}

# Assertions - return 0 on success, 1 on failure with message to stdout
assert_equals() {
    local expected="$1"
    local actual="$2"
    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        echo "Expected '$expected' but got '$actual'"
        return 1
    fi
}

assert_not_empty() {
    local value="$1"
    if [[ -n "$value" ]]; then
        return 0
    else
        echo "Value should not be empty"
        return 1
    fi
}

assert_empty() {
    local value="$1"
    if [[ -z "$value" ]]; then
        return 0
    else
        echo "Value should be empty but was '$value'"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        echo "String should contain '$needle'"
        return 1
    fi
}

assert_matches() {
    local value="$1"
    local pattern="$2"
    if [[ "$value" =~ $pattern ]]; then
        return 0
    else
        echo "'$value' should match pattern '$pattern'"
        return 1
    fi
}

assert_exit_code() {
    local expected="$1"
    local actual="$2"
    if [[ "$expected" -eq "$actual" ]]; then
        return 0
    else
        echo "Expected exit code $expected but got $actual"
        return 1
    fi
}

assert_file_exists() {
    local file="$1"
    if [[ -f "$file" ]]; then
        return 0
    else
        echo "File '$file' should exist"
        return 1
    fi
}

# Run a test function with error handling
run_test() {
    local test_func="$1"
    local test_name="${2:-$test_func}"
    
    test_start "$test_name"
    
    # Capture output and exit code
    local output exit_code
    set +e
    output=$("$test_func" 2>&1)
    exit_code=$?
    set -e
    
    if [[ $exit_code -eq 0 ]]; then
        test_pass
    else
        test_fail "$output"
    fi
}

# Print test suite header
suite_header() {
    local name="$1"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  $name${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Print final summary
print_summary() {
    echo ""
    echo "============================================================================"
    echo "TEST SUMMARY"
    echo "============================================================================"
    echo -e "  Total:  $TESTS_RUN"
    echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
    
    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        echo ""
        echo -e "${RED}Failed tests:${NC}"
        for t in "${FAILED_TESTS[@]}"; do
            echo -e "  ${RED}✗${NC} $t"
        done
    fi
    
    echo ""
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        return 1
    fi
}

# =============================================================================
# Main Runner
# =============================================================================

run_all_tests() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║  ZIG Checker Test Suite                                                    ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    
    # Find and run all test files
    local test_files=()
    while IFS= read -r -d '' file; do
        test_files+=("$file")
    done < <(find "$SCRIPT_DIR" -name "test_*.sh" -type f ! -name "test_runner.sh" -print0 | sort -z)
    
    if [[ ${#test_files[@]} -eq 0 ]]; then
        echo ""
        echo -e "${YELLOW}No test files found in $SCRIPT_DIR${NC}"
        echo "Create test files named test_*.sh"
        exit 0
    fi
    
    for test_file in "${test_files[@]}"; do
        # shellcheck source=/dev/null
        source "$test_file"
    done
    
    print_summary
}

run_single_test() {
    local test_file="$1"
    
    if [[ ! -f "$test_file" ]]; then
        echo -e "${RED}Test file not found: $test_file${NC}"
        exit 1
    fi
    
    echo ""
    echo "Running: $test_file"
    # shellcheck source=/dev/null
    source "$test_file"
    
    print_summary
}

# Main
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -gt 0 ]]; then
        run_single_test "$1"
    else
        run_all_tests
    fi
fi
