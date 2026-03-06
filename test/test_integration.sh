#!/usr/bin/env bash
#
# Integration tests - validates script structure and syntax
#

suite_header "Integration Tests"

# =============================================================================
# Script syntax validation
# =============================================================================

test_main_script_syntax() {
    bash -n "$PROJECT_ROOT/zig-checker.sh"
    assert_exit_code 0 $?
}

test_config_syntax() {
    bash -n "$PROJECT_ROOT/lib/config.sh"
    assert_exit_code 0 $?
}

test_utils_syntax() {
    bash -n "$PROJECT_ROOT/lib/utils.sh"
    assert_exit_code 0 $?
}

test_user_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/1_user.sh"
    assert_exit_code 0 $?
}

test_device_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/2_device.sh"
    assert_exit_code 0 $?
}

test_application_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/3_application.sh"
    assert_exit_code 0 $?
}

test_data_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/4_data.sh"
    assert_exit_code 0 $?
}

test_network_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/5_network.sh"
    assert_exit_code 0 $?
}

test_automation_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/6_automation.sh"
    assert_exit_code 0 $?
}

test_visibility_pillar_syntax() {
    bash -n "$PROJECT_ROOT/lib/pillars/7_visibility.sh"
    assert_exit_code 0 $?
}

run_test test_main_script_syntax "zig-checker.sh has valid syntax"
run_test test_config_syntax "lib/config.sh has valid syntax"
run_test test_utils_syntax "lib/utils.sh has valid syntax"
run_test test_user_pillar_syntax "lib/pillars/1_user.sh has valid syntax"
run_test test_device_pillar_syntax "lib/pillars/2_device.sh has valid syntax"
run_test test_application_pillar_syntax "lib/pillars/3_application.sh has valid syntax"
run_test test_data_pillar_syntax "lib/pillars/4_data.sh has valid syntax"
run_test test_network_pillar_syntax "lib/pillars/5_network.sh has valid syntax"
run_test test_automation_pillar_syntax "lib/pillars/6_automation.sh has valid syntax"
run_test test_visibility_pillar_syntax "lib/pillars/7_visibility.sh has valid syntax"

# =============================================================================
# File structure validation
# =============================================================================

test_main_script_exists() {
    assert_file_exists "$PROJECT_ROOT/zig-checker.sh"
}

test_config_exists() {
    assert_file_exists "$PROJECT_ROOT/lib/config.sh"
}

test_utils_exists() {
    assert_file_exists "$PROJECT_ROOT/lib/utils.sh"
}

test_all_pillars_exist() {
    for i in {1..7}; do
        assert_file_exists "$PROJECT_ROOT/lib/pillars/${i}_*.sh" 2>/dev/null || {
            local files
            files=$(ls "$PROJECT_ROOT/lib/pillars/${i}_"*.sh 2>/dev/null | head -1)
            assert_file_exists "$files"
        }
    done
}

run_test test_main_script_exists "zig-checker.sh exists"
run_test test_config_exists "lib/config.sh exists"
run_test test_utils_exists "lib/utils.sh exists"

# =============================================================================
# Documentation validation
# =============================================================================

test_readme_exists() {
    assert_file_exists "$PROJECT_ROOT/README.md"
}

test_check_docs_exist() {
    local doc_count
    doc_count=$(ls "$PROJECT_ROOT/docs/checks/"*.md 2>/dev/null | wc -l)
    [[ "$doc_count" -ge 1 ]] || return 1
}

test_1_8_1_doc_exists() {
    assert_file_exists "$PROJECT_ROOT/docs/checks/1.8.1-single-auth.md"
}

test_1_8_continuous_auth_doc_exists() {
    assert_file_exists "$PROJECT_ROOT/docs/checks/1.8-continuous-auth.md"
}

run_test test_readme_exists "README.md exists"
run_test test_check_docs_exist "Check documentation files exist"
run_test test_1_8_1_doc_exists "1.8.1 single auth documentation exists"
run_test test_1_8_continuous_auth_doc_exists "1.8 continuous auth documentation exists"

# =============================================================================
# Main script help validation
# =============================================================================

test_help_flag_works() {
    local output
    output=$("$PROJECT_ROOT/zig-checker.sh" --help 2>&1)
    assert_contains "$output" "Usage"
}

test_help_shows_pillar_option() {
    local output
    output=$("$PROJECT_ROOT/zig-checker.sh" --help 2>&1)
    assert_contains "$output" "--pillar"
}

test_help_shows_profile_option() {
    local output
    output=$("$PROJECT_ROOT/zig-checker.sh" --help 2>&1)
    assert_contains "$output" "--profile"
}

run_test test_help_flag_works "zig-checker.sh --help works"
run_test test_help_shows_pillar_option "--help shows --pillar option"
run_test test_help_shows_profile_option "--help shows --profile option"

# =============================================================================
# Function existence validation
# =============================================================================

test_check_functions_defined() {
    source "$PROJECT_ROOT/lib/config.sh"
    source "$PROJECT_ROOT/lib/utils.sh"
    source "$PROJECT_ROOT/lib/pillars/1_user.sh"
    
    # Check that key functions are defined
    declare -f check_pillar_1_user >/dev/null
    assert_exit_code 0 $?
}

test_1_8_1_function_defined() {
    source "$PROJECT_ROOT/lib/config.sh"
    source "$PROJECT_ROOT/lib/utils.sh"
    source "$PROJECT_ROOT/lib/pillars/1_user.sh"
    
    declare -f check_1_8_1_single_auth >/dev/null
    assert_exit_code 0 $?
}

test_1_8_continuous_auth_function_defined() {
    source "$PROJECT_ROOT/lib/config.sh"
    source "$PROJECT_ROOT/lib/utils.sh"
    source "$PROJECT_ROOT/lib/pillars/1_user.sh"
    
    declare -f check_1_8_continuous_auth >/dev/null
    assert_exit_code 0 $?
}

test_device_pillar_functions_defined() {
    source "$PROJECT_ROOT/lib/config.sh"
    source "$PROJECT_ROOT/lib/utils.sh"
    source "$PROJECT_ROOT/lib/pillars/2_device.sh"
    
    # Check that all device pillar functions are defined
    declare -f check_pillar_2_device >/dev/null && \
    declare -f check_2_1_2_device_inventory >/dev/null && \
    declare -f check_2_4_1_deny_device_default >/dev/null && \
    declare -f check_2_5_1_vulnerability_patch >/dev/null && \
    declare -f check_2_6_endpoint_management >/dev/null && \
    declare -f check_2_7_1_edr_integration >/dev/null
    assert_exit_code 0 $?
}

test_device_pillar_docs_exist() {
    assert_file_exists "$PROJECT_ROOT/docs/checks/2.1.2-device-inventory.md" && \
    assert_file_exists "$PROJECT_ROOT/docs/checks/2.4.1-deny-device-default.md" && \
    assert_file_exists "$PROJECT_ROOT/docs/checks/2.5.1-vulnerability-patch.md" && \
    assert_file_exists "$PROJECT_ROOT/docs/checks/2.6-endpoint-management.md" && \
    assert_file_exists "$PROJECT_ROOT/docs/checks/2.7.1-edr-integration.md"
}

run_test test_check_functions_defined "Pillar check functions are defined"
run_test test_1_8_1_function_defined "check_1_8_1_single_auth function is defined"
run_test test_1_8_continuous_auth_function_defined "check_1_8_continuous_auth function is defined"
run_test test_device_pillar_functions_defined "Device pillar check functions are defined"
run_test test_device_pillar_docs_exist "Device pillar documentation exists"
