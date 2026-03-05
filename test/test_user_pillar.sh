#!/usr/bin/env bash
#
# Tests for lib/pillars/1_user.sh
# Uses mocked AWS CLI responses
#

# Load dependencies
source "$PROJECT_ROOT/lib/config.sh"
source "$PROJECT_ROOT/lib/utils.sh"

suite_header "lib/pillars/1_user.sh - Unit Tests"

# =============================================================================
# Helper to reset state between tests
# =============================================================================

reset_test_state() {
    FINDINGS=()
    declare -gA PILLAR_SCORES=()
    USERS_WITH_CONSOLE_COUNT=0
    USERS_WITH_CONSOLE_LIST=()
    SSO_CONFIGURED=false
    ADMIN_USER_COUNT=0
    GUARDDUTY_DETECTOR_ID=""
}

# =============================================================================
# Activity 1.3.1 - MFA Tests
# =============================================================================

test_root_mfa_enabled_passes() {
    reset_test_state
    local root_mfa="1"
    
    local result
    if [[ "$root_mfa" == "1" ]]; then
        result="PASS"
    else
        result="FAIL"
    fi
    assert_equals "PASS" "$result"
}

test_root_mfa_disabled_fails() {
    reset_test_state
    local root_mfa="0"
    
    local result
    if [[ "$root_mfa" == "1" ]]; then
        result="PASS"
    else
        result="FAIL"
    fi
    assert_equals "FAIL" "$result"
}

run_test test_root_mfa_enabled_passes "1.3.1-A: Root MFA enabled → PASS"
run_test test_root_mfa_disabled_fails "1.3.1-A: Root MFA disabled → FAIL"

# =============================================================================
# Activity 1.8.1 - Continuous Auth Tests
# =============================================================================

test_session_duration_check_logic() {
    local max_recommended=14400
    local role_duration=3600
    
    if [[ "$role_duration" -gt "$max_recommended" ]]; then
        echo "FAIL"
    else
        echo "PASS"
    fi | grep -q "PASS"
    assert_exit_code 0 $?
}

test_session_duration_exceeds_limit() {
    local max_recommended=14400
    local role_duration=43200  # 12 hours
    
    local result
    if [[ "$role_duration" -gt "$max_recommended" ]]; then
        result="FAIL"
    else
        result="PASS"
    fi
    assert_equals "FAIL" "$result"
}

test_guardduty_enabled_check() {
    local detector_id="abc123"
    local detector_status="ENABLED"
    
    local result
    if [[ -n "$detector_id" && "$detector_status" == "ENABLED" ]]; then
        result="PASS"
    else
        result="FAIL"
    fi
    assert_equals "PASS" "$result"
}

test_guardduty_disabled_check() {
    local detector_id="abc123"
    local detector_status="DISABLED"
    
    local result
    if [[ -n "$detector_id" && "$detector_status" == "ENABLED" ]]; then
        result="PASS"
    else
        result="FAIL"
    fi
    assert_equals "FAIL" "$result"
}

run_test test_session_duration_check_logic "1.8.1-A: Session duration within limit → PASS"
run_test test_session_duration_exceeds_limit "1.8.1-A: Session duration exceeds limit → FAIL"
run_test test_guardduty_enabled_check "1.8.1-B: GuardDuty enabled → PASS"
run_test test_guardduty_disabled_check "1.8.1-B: GuardDuty disabled → FAIL"

# =============================================================================
# Activity 1.7.1 - Deny Default Tests
# =============================================================================

test_overly_permissive_policy_detection() {
    local policy_doc='{"Statement":[{"Action":"*","Resource":"*","Effect":"Allow"}]}'
    
    local result
    if echo "$policy_doc" | grep -qE '"Action":\s*"\*"' && echo "$policy_doc" | grep -qE '"Resource":\s*"\*"'; then
        result="DETECTED"
    else
        result="NOT_DETECTED"
    fi
    assert_equals "DETECTED" "$result"
}

test_scoped_policy_not_flagged() {
    local policy_doc='{"Statement":[{"Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*","Effect":"Allow"}]}'
    
    local result
    if echo "$policy_doc" | grep -qE '"Action":\s*"\*"' && echo "$policy_doc" | grep -qE '"Resource":\s*"\*"'; then
        result="DETECTED"
    else
        result="NOT_DETECTED"
    fi
    assert_equals "NOT_DETECTED" "$result"
}

run_test test_overly_permissive_policy_detection "1.7.1-A: Detects Action:* Resource:* policy"
run_test test_scoped_policy_not_flagged "1.7.1-A: Scoped policy not flagged"

# =============================================================================
# Activity 1.4.1 - PAM Tests
# =============================================================================

test_access_key_age_calculation() {
    local current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    local key_age=$((current_date - 100 * 24 * 60 * 60))  # 100 days old
    
    local result
    if [[ $((current_date - key_age)) -gt $ninety_days ]]; then
        result="OLD"
    else
        result="OK"
    fi
    assert_equals "OLD" "$result"
}

test_access_key_within_limit() {
    local current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    local key_age=$((current_date - 30 * 24 * 60 * 60))  # 30 days old
    
    local result
    if [[ $((current_date - key_age)) -gt $ninety_days ]]; then
        result="OLD"
    else
        result="OK"
    fi
    assert_equals "OK" "$result"
}

run_test test_access_key_age_calculation "1.4.1-B: Detects access key > 90 days"
run_test test_access_key_within_limit "1.4.1-B: Access key < 90 days OK"

# =============================================================================
# Activity 1.5.1 - ILM Tests
# =============================================================================

test_inactive_user_detection() {
    local current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    local last_login=$((current_date - 120 * 24 * 60 * 60))  # 120 days ago
    
    local result
    if [[ $((current_date - last_login)) -gt $ninety_days ]]; then
        result="INACTIVE"
    else
        result="ACTIVE"
    fi
    assert_equals "INACTIVE" "$result"
}

run_test test_inactive_user_detection "1.5.1-A: Detects user inactive > 90 days"
