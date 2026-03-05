#!/usr/bin/env bash
#
# NSA Zero Trust Implementation Guideline (ZIG) Phase One - AWS Compliance Checker
#
# Usage: ./zig-checker.sh [--profile <aws-profile>] [--region <region>] [--output <json|text>] [--pillar <name>]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load config and utilities
source "$SCRIPT_DIR/lib/config.sh"
source "$SCRIPT_DIR/lib/utils.sh"

# Load pillar checks
source "$SCRIPT_DIR/lib/pillars/1_user.sh"
source "$SCRIPT_DIR/lib/pillars/2_device.sh"
source "$SCRIPT_DIR/lib/pillars/3_application.sh"
source "$SCRIPT_DIR/lib/pillars/4_data.sh"
source "$SCRIPT_DIR/lib/pillars/5_network.sh"
source "$SCRIPT_DIR/lib/pillars/6_automation.sh"
source "$SCRIPT_DIR/lib/pillars/7_visibility.sh"

# Parse arguments
AWS_PROFILE="$DEFAULT_PROFILE"
AWS_REGION="$DEFAULT_REGION"
SELECTED_PILLAR=""
REPORT_FILE="zig-report-$(date +%Y%m%d-%H%M%S).json"

while [[ $# -gt 0 ]]; do
    case $1 in
        --profile) AWS_PROFILE="$2"; shift 2 ;;
        --region)  AWS_REGION="$2"; shift 2 ;;
        --output)  OUTPUT_FORMAT="$2"; shift 2 ;;
        --pillar)  SELECTED_PILLAR="$2"; shift 2 ;;
        --debug)   DEBUG="true"; shift ;;
        --help|-h)
            echo "Usage: $0 [--profile <profile>] [--region <region>] [--output <json|text>] [--pillar <name>] [--debug]"
            echo ""
            echo "Options:"
            echo "  --profile    AWS CLI profile (default: default)"
            echo "  --region     AWS region (default: us-gov-west-1)"
            echo "  --output     Output format: json or text (default: text)"
            echo "  --pillar     Run specific pillar: user, device, application, data, network, automation, visibility"
            echo "  --debug      Enable debug mode"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

export AWS_PROFILE AWS_REGION

# Pre-flight checks
preflight_checks() {
    log_info "Running pre-flight checks..."
    check_dependency "aws"
    check_dependency "jq"
    
    if ! aws sts get-caller-identity &>/dev/null; then
        echo "ERROR: AWS credentials not configured or invalid"
        exit 1
    fi
    
    ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
    log_info "Account: $ACCOUNT_ID | Region: $AWS_REGION | Profile: $AWS_PROFILE"
    echo ""
}

# Generate summary report
generate_report() {
    echo ""
    echo "============================================================================"
    echo "NSA ZIG PHASE ONE COMPLIANCE SUMMARY"
    echo "============================================================================"
    echo ""
    
    echo "PILLAR SCORES:"
    for pillar in User Device Application Data Network Automation Visibility; do
        printf "  %-20s %s\n" "$pillar:" "${PILLAR_SCORES[$pillar]:-N/A}"
    done
    echo ""
    
    # Count findings by severity
    local blockers=0 highs=0 mediums=0 lows=0
    for finding in "${FINDINGS[@]}"; do
        case $(echo "$finding" | jq -r '.severity') in
            BLOCKER) ((blockers++)) || true ;;
            HIGH)    ((highs++)) || true ;;
            MEDIUM)  ((mediums++)) || true ;;
            LOW)     ((lows++)) || true ;;
        esac
    done
    
    echo "FINDINGS SUMMARY:"
    echo -e "  ${RED}BLOCKER:${NC}  $blockers"
    echo -e "  ${RED}HIGH:${NC}     $highs"
    echo -e "  ${YELLOW}MEDIUM:${NC}   $mediums"
    echo -e "  ${CYAN}LOW:${NC}      $lows"
    echo ""
    
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        log_info "Generating JSON report: $REPORT_FILE"
        cat > "$REPORT_FILE" << EOF
{
  "report_date": "$(date -Iseconds)",
  "aws_account": "$ACCOUNT_ID",
  "aws_region": "$AWS_REGION",
  "pillar_scores": {
    "user": "${PILLAR_SCORES[User]:-N/A}",
    "device": "${PILLAR_SCORES[Device]:-N/A}",
    "application": "${PILLAR_SCORES[Application]:-N/A}",
    "data": "${PILLAR_SCORES[Data]:-N/A}",
    "network": "${PILLAR_SCORES[Network]:-N/A}",
    "automation": "${PILLAR_SCORES[Automation]:-N/A}",
    "visibility": "${PILLAR_SCORES[Visibility]:-N/A}"
  },
  "findings_summary": {
    "blocker": $blockers,
    "high": $highs,
    "medium": $mediums,
    "low": $lows
  },
  "findings": [$(IFS=,; echo "${FINDINGS[*]}")]
}
EOF
        log_info "Report saved to: $REPORT_FILE"
    fi
}

# Main
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║  NSA Zero Trust Implementation Guideline (ZIG) Phase One                   ║"
    echo "║  AWS Compliance Checker v$SCRIPT_VERSION                                            ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    preflight_checks
    
    if [[ -n "$SELECTED_PILLAR" ]]; then
        case "$SELECTED_PILLAR" in
            user)        check_pillar_1_user ;;
            device)      check_pillar_2_device ;;
            application) check_pillar_3_application ;;
            data)        check_pillar_4_data ;;
            network)     check_pillar_5_network ;;
            automation)  check_pillar_6_automation ;;
            visibility)  check_pillar_7_visibility ;;
            *) echo "Unknown pillar: $SELECTED_PILLAR"; exit 1 ;;
        esac
    else
        check_pillar_1_user
        check_pillar_2_device
        check_pillar_3_application
        check_pillar_4_data
        check_pillar_5_network
        check_pillar_6_automation
        check_pillar_7_visibility
    fi
    
    generate_report
}

main "$@"
