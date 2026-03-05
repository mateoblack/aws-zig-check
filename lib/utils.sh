#!/usr/bin/env bash
# Utility functions for ZIG checker

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_finding() {
    local severity="$1"
    local activity="$2"
    local message="$3"
    local remediation="${4:-}"
    
    case $severity in
        BLOCKER) echo -e "${RED}[BLOCKER]${NC} [$activity] $message" ;;
        HIGH)    echo -e "${RED}[HIGH]${NC} [$activity] $message" ;;
        MEDIUM)  echo -e "${YELLOW}[MEDIUM]${NC} [$activity] $message" ;;
        LOW)     echo -e "${CYAN}[LOW]${NC} [$activity] $message" ;;
    esac
    
    FINDINGS+=("{\"severity\":\"$severity\",\"activity\":\"$activity\",\"message\":\"$message\",\"remediation\":\"$remediation\"}")
}

# AWS CLI wrapper with rate limiting and error handling
aws_cmd() {
    sleep "$RATE_LIMIT_DELAY"
    
    local timeout_cmd="timeout"
    command -v gtimeout &>/dev/null && timeout_cmd="gtimeout"
    
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${CYAN}[DEBUG] Running: aws $*${NC}" >&2
        local result exit_code
        result=$($timeout_cmd "$TIMEOUT_SECONDS" aws "$@" 2>&1) && exit_code=$? || exit_code=$?
        if [[ $exit_code -ne 0 ]]; then
            echo -e "${RED}[DEBUG] Command failed (exit $exit_code): $result${NC}" >&2
            echo ""
        else
            echo -e "${GREEN}[DEBUG] Command succeeded${NC}" >&2
            echo "$result"
        fi
    else
        $timeout_cmd "$TIMEOUT_SECONDS" aws "$@" 2>/dev/null || echo ""
    fi
}

# Check if a command exists
check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: Required dependency '$1' not found."
        exit 1
    fi
}

# Print pillar header
pillar_header() {
    local number="$1"
    local name="$2"
    echo ""
    echo "============================================================================"
    echo "PILLAR $number: $name"
    echo "============================================================================"
}

# Print pillar score
pillar_score() {
    local name="$1"
    local passed="$2"
    local total="$3"
    echo ""
    log_info "$name Pillar Score: $passed/$total checks passed"
    PILLAR_SCORES["$name"]="$passed/$total"
}

# Check if running in GovCloud
is_govcloud() {
    [[ "$AWS_REGION" == us-gov-* ]]
}
