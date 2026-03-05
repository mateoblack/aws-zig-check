#!/usr/bin/env bash
#
# Tests for lib/utils.sh
#

# Load the module under test
source "$PROJECT_ROOT/lib/config.sh"
source "$PROJECT_ROOT/lib/utils.sh"

suite_header "lib/utils.sh"

# =============================================================================
# log_info tests
# =============================================================================

test_log_info_outputs_message() {
    local output
    output=$(log_info "test message")
    assert_contains "$output" "test message"
}

test_log_info_has_info_prefix() {
    local output
    output=$(log_info "test")
    assert_contains "$output" "[INFO]"
}

run_test test_log_info_outputs_message "log_info outputs message"
run_test test_log_info_has_info_prefix "log_info has [INFO] prefix"

# =============================================================================
# log_pass tests
# =============================================================================

test_log_pass_outputs_message() {
    local output
    output=$(log_pass "check passed")
    assert_contains "$output" "check passed"
}

test_log_pass_has_pass_prefix() {
    local output
    output=$(log_pass "test")
    assert_contains "$output" "[PASS]"
}

run_test test_log_pass_outputs_message "log_pass outputs message"
run_test test_log_pass_has_pass_prefix "log_pass has [PASS] prefix"

# =============================================================================
# log_finding tests
# =============================================================================

test_log_finding_blocker_severity() {
    local output
    output=$(log_finding "BLOCKER" "1.1.1" "test finding" "fix it")
    assert_contains "$output" "[BLOCKER]"
}

test_log_finding_high_severity() {
    local output
    output=$(log_finding "HIGH" "1.1.1" "test finding" "fix it")
    assert_contains "$output" "[HIGH]"
}

test_log_finding_includes_activity() {
    local output
    output=$(log_finding "MEDIUM" "1.3.1-A" "test finding" "fix it")
    assert_contains "$output" "[1.3.1-A]"
}

test_log_finding_adds_to_findings_array() {
    FINDINGS=()
    log_finding "LOW" "1.1.1" "test" "remediation" >/dev/null
    assert_equals "1" "${#FINDINGS[@]}" "Should have 1 finding"
}

run_test test_log_finding_blocker_severity "log_finding BLOCKER severity"
run_test test_log_finding_high_severity "log_finding HIGH severity"
run_test test_log_finding_includes_activity "log_finding includes activity ID"
run_test test_log_finding_adds_to_findings_array "log_finding adds to FINDINGS array"

# =============================================================================
# check_dependency tests
# =============================================================================

test_check_dependency_existing_command() {
    # bash always exists
    check_dependency "bash"
    assert_exit_code 0 $?
}

test_check_dependency_missing_command() {
    local output exit_code
    output=$(check_dependency "nonexistent_command_xyz" 2>&1) && exit_code=$? || exit_code=$?
    assert_exit_code 1 $exit_code
}

run_test test_check_dependency_existing_command "check_dependency finds existing command"
run_test test_check_dependency_missing_command "check_dependency fails on missing command"

# =============================================================================
# pillar_header tests
# =============================================================================

test_pillar_header_includes_number() {
    local output
    output=$(pillar_header 1 "USER")
    assert_contains "$output" "PILLAR 1"
}

test_pillar_header_includes_name() {
    local output
    output=$(pillar_header 1 "USER")
    assert_contains "$output" "USER"
}

run_test test_pillar_header_includes_number "pillar_header includes pillar number"
run_test test_pillar_header_includes_name "pillar_header includes pillar name"

# =============================================================================
# pillar_score tests
# =============================================================================

test_pillar_score_stores_in_array() {
    PILLAR_SCORES=()
    pillar_score "User" 5 7 >/dev/null
    assert_equals "5/7" "${PILLAR_SCORES[User]}"
}

run_test test_pillar_score_stores_in_array "pillar_score stores score in PILLAR_SCORES"

# =============================================================================
# is_govcloud tests
# =============================================================================

test_is_govcloud_true_for_gov_region() {
    AWS_REGION="us-gov-west-1"
    is_govcloud
    assert_exit_code 0 $?
}

test_is_govcloud_false_for_commercial() {
    AWS_REGION="us-east-1"
    is_govcloud
    local exit_code=$?
    assert_exit_code 1 $exit_code
}

run_test test_is_govcloud_true_for_gov_region "is_govcloud returns true for us-gov-west-1"
run_test test_is_govcloud_false_for_commercial "is_govcloud returns false for us-east-1"
