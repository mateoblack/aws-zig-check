#!/usr/bin/env bash
# Configuration and constants for ZIG checker

SCRIPT_VERSION="0.1.0"
TIMEOUT_SECONDS=300
RATE_LIMIT_DELAY=0.2

# Defaults
DEFAULT_REGION="us-gov-west-1"
DEFAULT_PROFILE="default"
OUTPUT_FORMAT="text"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global state
declare -a FINDINGS=()
declare -A PILLAR_SCORES=()
DEBUG="${DEBUG:-false}"
