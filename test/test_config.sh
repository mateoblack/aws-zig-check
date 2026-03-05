#!/usr/bin/env bash
#
# Tests for lib/config.sh
#

# Load the module under test
source "$PROJECT_ROOT/lib/config.sh"

suite_header "lib/config.sh"

# =============================================================================
# Default values tests
# =============================================================================

test_default_region_is_govcloud() {
    assert_equals "us-gov-west-1" "$DEFAULT_REGION"
}

test_default_profile_is_default() {
    assert_equals "default" "$DEFAULT_PROFILE"
}

test_output_format_default_is_text() {
    assert_equals "text" "$OUTPUT_FORMAT"
}

test_script_version_is_set() {
    assert_not_empty "$SCRIPT_VERSION"
}

test_timeout_is_reasonable() {
    # Should be at least 60 seconds
    [[ "$TIMEOUT_SECONDS" -ge 60 ]] || return 1
}

run_test test_default_region_is_govcloud "DEFAULT_REGION is us-gov-west-1"
run_test test_default_profile_is_default "DEFAULT_PROFILE is 'default'"
run_test test_output_format_default_is_text "OUTPUT_FORMAT defaults to 'text'"
run_test test_script_version_is_set "SCRIPT_VERSION is set"
run_test test_timeout_is_reasonable "TIMEOUT_SECONDS is reasonable (>=60)"

# =============================================================================
# Color codes tests
# =============================================================================

test_colors_are_defined() {
    assert_not_empty "$RED" "RED should be defined"
    assert_not_empty "$GREEN" "GREEN should be defined"
    assert_not_empty "$YELLOW" "YELLOW should be defined"
    assert_not_empty "$NC" "NC (no color) should be defined"
}

run_test test_colors_are_defined "Color codes are defined"

# =============================================================================
# Global state initialization
# =============================================================================

test_findings_array_initialized() {
    # FINDINGS should be declared as an array
    declare -p FINDINGS &>/dev/null
    assert_exit_code 0 $?
}

test_pillar_scores_initialized() {
    # PILLAR_SCORES should be declared as an associative array
    declare -p PILLAR_SCORES &>/dev/null
    assert_exit_code 0 $?
}

run_test test_findings_array_initialized "FINDINGS array is initialized"
run_test test_pillar_scores_initialized "PILLAR_SCORES associative array is initialized"
