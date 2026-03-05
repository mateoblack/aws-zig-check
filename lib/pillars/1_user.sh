#!/usr/bin/env bash
# Pillar 1: User
# Activities: 1.3.1, 1.4.1, 1.5.1, 1.7.1

# Global vars for cross-check data sharing
USERS_WITH_CONSOLE_COUNT=0
USERS_WITH_CONSOLE_LIST=()
SSO_CONFIGURED=false
ADMIN_USER_COUNT=0

check_pillar_1_user() {
    pillar_header 1 "USER"
    
    local pass_count=0
    local total_checks=0
    
    check_1_3_1_mfa_idp
    check_1_4_1_pam
    check_1_5_1_ilm
    check_1_7_1_deny_default
    
    pillar_score "User" "$pass_count" "$total_checks"
}

# =============================================================================
# Activity 1.3.1 - MFA and IdP
# See docs/checks/1.3.1-mfa-idp.md for detailed documentation
# =============================================================================

check_1_3_1_mfa_idp() {
    log_info "Checking Activity 1.3.1 - MFA and IdP..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 1.3.1-A: Root Account MFA
    ((activity_total++))
    local root_mfa
    root_mfa=$(aws_cmd iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)
    
    if [[ "$root_mfa" == "1" ]]; then
        log_pass "1.3.1-A: Root account has MFA enabled"
        ((activity_pass++))
    else
        log_finding "BLOCKER" "1.3.1-A" \
            "Root account does NOT have MFA enabled" \
            "Enable MFA on root account via AWS Console"
    fi
    
    # Check 1.3.1-B: IAM Users Console Access Without MFA
    ((activity_total++))
    aws_cmd iam generate-credential-report >/dev/null 2>&1
    sleep 3
    
    local cred_report
    cred_report=$(aws_cmd iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [[ -n "$cred_report" ]]; then
        local users_without_mfa=()
        local users_with_console=()
        
        while IFS=, read -r user arn creation_date password_enabled password_last_used password_last_changed password_next_rotation mfa_active rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            if [[ "$password_enabled" == "true" ]]; then
                users_with_console+=("$user")
                if [[ "$mfa_active" == "false" ]]; then
                    users_without_mfa+=("$user")
                fi
            fi
        done <<< "$cred_report"
        
        if [[ ${#users_without_mfa[@]} -gt 0 ]]; then
            log_finding "HIGH" "1.3.1-B" \
                "IAM users with console access but NO MFA: ${users_without_mfa[*]}" \
                "Enable MFA for these users or enforce via IAM policy/SCP"
        else
            if [[ ${#users_with_console[@]} -gt 0 ]]; then
                log_pass "1.3.1-B: All ${#users_with_console[@]} IAM users with console access have MFA"
            else
                log_pass "1.3.1-B: No IAM users with console access found"
            fi
            ((activity_pass++))
        fi
        
        USERS_WITH_CONSOLE_COUNT=${#users_with_console[@]}
        USERS_WITH_CONSOLE_LIST=("${users_with_console[@]}")
    else
        log_finding "MEDIUM" "1.3.1-B" \
            "Could not generate credential report to check MFA status" \
            "Ensure IAM permissions include iam:GenerateCredentialReport"
        USERS_WITH_CONSOLE_COUNT=0
        USERS_WITH_CONSOLE_LIST=()
    fi
    
    # Check 1.3.1-C: IAM Identity Center (SSO) Configured
    ((activity_total++))
    local sso_instance_arn
    sso_instance_arn=$(aws_cmd sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$sso_instance_arn" && "$sso_instance_arn" != "None" && "$sso_instance_arn" != "null" ]]; then
        log_pass "1.3.1-C: IAM Identity Center (SSO) is configured"
        ((activity_pass++))
        SSO_CONFIGURED=true
        local identity_store_id
        identity_store_id=$(aws_cmd sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text 2>/dev/null || echo "")
        log_info "  Identity Store ID: $identity_store_id"
    else
        log_finding "MEDIUM" "1.3.1-C" \
            "IAM Identity Center (SSO) is not configured" \
            "Enable IAM Identity Center for centralized identity management"
        SSO_CONFIGURED=false
    fi
    
    # Check 1.3.1-D: Local IAM Users When SSO Exists
    ((activity_total++))
    if [[ "$SSO_CONFIGURED" == "true" ]]; then
        if [[ "$USERS_WITH_CONSOLE_COUNT" -gt 0 ]]; then
            log_finding "MEDIUM" "1.3.1-D" \
                "SSO configured but $USERS_WITH_CONSOLE_COUNT local IAM users exist: ${USERS_WITH_CONSOLE_LIST[*]}" \
                "Per ZIG 1.3, retire local accounts. If break-glass, document exception."
        else
            log_pass "1.3.1-D: SSO configured and no local IAM users with console access"
            ((activity_pass++))
        fi
    else
        log_info "1.3.1-D: SSO not configured - local IAM user retirement check N/A"
        ((activity_pass++))
    fi
    
    # Check 1.3.1-E: MFA Enforcement SCP
    ((activity_total++))
    local org_id
    org_id=$(aws_cmd organizations describe-organization --query 'Organization.Id' --output text 2>/dev/null || echo "")
    
    if [[ -n "$org_id" && "$org_id" != "None" && "$org_id" != "null" ]]; then
        local master_account_id current_account_id
        master_account_id=$(aws_cmd organizations describe-organization --query 'Organization.MasterAccountId' --output text 2>/dev/null || echo "")
        current_account_id=$(aws_cmd sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "")
        
        if [[ "$master_account_id" == "$current_account_id" ]]; then
            local mfa_scp_found=false
            local scp_list
            scp_list=$(aws_cmd organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text 2>/dev/null || echo "")
            
            for policy_id in $scp_list; do
                local policy_content
                policy_content=$(aws_cmd organizations describe-policy --policy-id "$policy_id" --query 'Policy.Content' --output text 2>/dev/null || echo "")
                if echo "$policy_content" | grep -qE 'aws:MultiFactorAuthPresent|aws:MultiFactorAuthAge'; then
                    mfa_scp_found=true
                    local policy_name
                    policy_name=$(aws_cmd organizations describe-policy --policy-id "$policy_id" --query 'Policy.PolicySummary.Name' --output text 2>/dev/null || echo "$policy_id")
                    log_info "  Found MFA condition in SCP: $policy_name"
                    break
                fi
            done
            
            if [[ "$mfa_scp_found" == "true" ]]; then
                log_pass "1.3.1-E: MFA enforcement SCP exists at organization level"
                ((activity_pass++))
            else
                log_finding "MEDIUM" "1.3.1-E" \
                    "No SCP with MFA enforcement found" \
                    "Create SCP with aws:MultiFactorAuthPresent condition"
            fi
        else
            log_info "1.3.1-E: Member account - cannot inspect SCPs (requires management account)"
            ((activity_pass++))
        fi
    else
        log_finding "LOW" "1.3.1-E" \
            "AWS Organizations not enabled - cannot enforce org-level MFA SCP" \
            "Consider enabling AWS Organizations for centralized policy control"
    fi
    
    # Check 1.3.1-F: External IdP Federation (for CAC/PIV/Enterprise PKI)
    ((activity_total++))
    local external_idp_found=false
    
    if [[ "$SSO_CONFIGURED" == "true" ]]; then
        # Check IAM Identity Center for external identity source
        local identity_source
        identity_source=$(aws_cmd sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text 2>/dev/null || echo "")
        
        # Check for SAML providers in IAM (legacy federation)
        local saml_providers
        saml_providers=$(aws_cmd iam list-saml-providers --query 'SAMLProviderList[].Arn' --output text 2>/dev/null || echo "")
        
        # Check for OIDC providers in IAM
        local oidc_providers
        oidc_providers=$(aws_cmd iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text 2>/dev/null || echo "")
        
        if [[ -n "$saml_providers" && "$saml_providers" != "None" ]]; then
            external_idp_found=true
            local saml_count
            saml_count=$(echo "$saml_providers" | wc -w | tr -d ' ')
            log_info "  Found $saml_count SAML provider(s) configured"
        fi
        
        if [[ -n "$oidc_providers" && "$oidc_providers" != "None" ]]; then
            external_idp_found=true
            local oidc_count
            oidc_count=$(echo "$oidc_providers" | wc -w | tr -d ' ')
            log_info "  Found $oidc_count OIDC provider(s) configured"
        fi
        
        if [[ "$external_idp_found" == "true" ]]; then
            log_pass "1.3.1-F: External IdP federation configured (SAML/OIDC)"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "1.3.1-F" \
                "No external IdP federation (SAML/OIDC) detected" \
                "For CAC/PIV/Enterprise PKI auth, configure external IdP federation"
        fi
    else
        # No SSO - check for standalone SAML/OIDC providers
        local saml_providers
        saml_providers=$(aws_cmd iam list-saml-providers --query 'SAMLProviderList[].Arn' --output text 2>/dev/null || echo "")
        local oidc_providers
        oidc_providers=$(aws_cmd iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text 2>/dev/null || echo "")
        
        if [[ -n "$saml_providers" && "$saml_providers" != "None" ]] || [[ -n "$oidc_providers" && "$oidc_providers" != "None" ]]; then
            external_idp_found=true
            log_pass "1.3.1-F: External IdP federation configured (SAML/OIDC)"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "1.3.1-F" \
                "No external IdP federation (SAML/OIDC) detected" \
                "For CAC/PIV/Enterprise PKI auth, configure external IdP with IAM Identity Center"
        fi
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 1.3.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 1.4.1 - Privileged Access Management (PAM)
# See docs/checks/1.4.1-pam.md for detailed documentation
# NOTE: Full PAM requires external tooling. These checks verify AWS config
#       aligns with PAM principles.
# =============================================================================

check_1_4_1_pam() {
    log_info "Checking Activity 1.4.1 - Privileged Access Management..."
    log_info "  Note: Full PAM requires external tooling. Checking AWS PAM alignment."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 1.4.1-A: IAM Users with Permanent Admin Access
    ((activity_total++))
    local admin_users=()
    local iam_users
    iam_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text 2>/dev/null || echo "")
    
    for user in $iam_users; do
        local has_admin=false
        
        # Check directly attached policies
        local attached_policies
        attached_policies=$(aws_cmd iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
        if echo "$attached_policies" | grep -qE 'arn:aws(-us-gov)?:iam::aws:policy/AdministratorAccess'; then
            has_admin=true
        fi
        
        # Check inline policies for admin-like permissions
        if [[ "$has_admin" == "false" ]]; then
            local inline_policies
            inline_policies=$(aws_cmd iam list-user-policies --user-name "$user" --query 'PolicyNames' --output text 2>/dev/null || echo "")
            for policy_name in $inline_policies; do
                local policy_doc
                policy_doc=$(aws_cmd iam get-user-policy --user-name "$user" --policy-name "$policy_name" --query 'PolicyDocument' --output json 2>/dev/null || echo "")
                if echo "$policy_doc" | grep -qE '"Action":\s*"\*".*"Resource":\s*"\*"'; then
                    has_admin=true
                    break
                fi
            done
        fi
        
        # Check group memberships for admin
        if [[ "$has_admin" == "false" ]]; then
            local groups
            groups=$(aws_cmd iam list-groups-for-user --user-name "$user" --query 'Groups[].GroupName' --output text 2>/dev/null || echo "")
            for group in $groups; do
                local group_policies
                group_policies=$(aws_cmd iam list-attached-group-policies --group-name "$group" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
                if echo "$group_policies" | grep -qE 'arn:aws(-us-gov)?:iam::aws:policy/AdministratorAccess'; then
                    has_admin=true
                    break
                fi
            done
        fi
        
        if [[ "$has_admin" == "true" ]]; then
            admin_users+=("$user")
        fi
    done
    
    if [[ ${#admin_users[@]} -gt 0 ]]; then
        log_finding "HIGH" "1.4.1-A" \
            "IAM users with permanent admin access: ${admin_users[*]}" \
            "Remove permanent admin. Use IAM roles for JIT admin access."
    else
        log_pass "1.4.1-A: No IAM users with permanent admin access"
        ((activity_pass++))
    fi
    
    # Store admin user count for check D
    ADMIN_USER_COUNT=${#admin_users[@]}
    
    # Check 1.4.1-B: Access Keys Older Than 90 Days
    ((activity_total++))
    local old_keys=()
    local current_date
    current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    
    # Use credential report if available, otherwise check each user
    local cred_report
    cred_report=$(aws_cmd iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date pw_enabled pw_last_used pw_last_changed pw_next_rotation mfa_active ak1_active ak1_last_rotated ak1_last_used ak2_active ak2_last_rotated rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            
            # Check access key 1
            if [[ "$ak1_active" == "true" && -n "$ak1_last_rotated" && "$ak1_last_rotated" != "N/A" ]]; then
                local key_date
                key_date=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak1_last_rotated" +%s 2>/dev/null || date -d "$ak1_last_rotated" +%s 2>/dev/null || echo "0")
                if [[ "$key_date" -gt 0 && $((current_date - key_date)) -gt $ninety_days ]]; then
                    old_keys+=("$user:key1")
                fi
            fi
            
            # Check access key 2
            if [[ "$ak2_active" == "true" && -n "$ak2_last_rotated" && "$ak2_last_rotated" != "N/A" ]]; then
                local key_date
                key_date=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak2_last_rotated" +%s 2>/dev/null || date -d "$ak2_last_rotated" +%s 2>/dev/null || echo "0")
                if [[ "$key_date" -gt 0 && $((current_date - key_date)) -gt $ninety_days ]]; then
                    old_keys+=("$user:key2")
                fi
            fi
        done <<< "$cred_report"
    fi
    
    if [[ ${#old_keys[@]} -gt 0 ]]; then
        log_finding "HIGH" "1.4.1-B" \
            "Access keys older than 90 days: ${old_keys[*]}" \
            "Rotate or delete old access keys"
    else
        log_pass "1.4.1-B: No access keys older than 90 days"
        ((activity_pass++))
    fi
    
    # Check 1.4.1-C: Secrets Manager in Use
    ((activity_total++))
    local secrets_count
    secrets_count=$(aws_cmd secretsmanager list-secrets --query 'SecretList | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$secrets_count" -gt 0 ]]; then
        log_pass "1.4.1-C: Secrets Manager in use ($secrets_count secrets)"
        ((activity_pass++))
    else
        log_finding "LOW" "1.4.1-C" \
            "No secrets in Secrets Manager" \
            "Consider using Secrets Manager for credential management (or document external vault)"
    fi
    
    # Check 1.4.1-D: Admin Roles vs Admin Users Ratio
    ((activity_total++))
    local admin_roles=()
    local iam_roles
    iam_roles=$(aws_cmd iam list-roles --query 'Roles[?starts_with(RoleName, `AWS`) == `false`].RoleName' --output text 2>/dev/null || echo "")
    
    for role in $iam_roles; do
        local role_policies
        role_policies=$(aws_cmd iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
        if echo "$role_policies" | grep -qE 'arn:aws(-us-gov)?:iam::aws:policy/AdministratorAccess'; then
            admin_roles+=("$role")
        fi
    done
    
    local admin_role_count=${#admin_roles[@]}
    
    if [[ "$ADMIN_USER_COUNT" -eq 0 ]]; then
        log_pass "1.4.1-D: No admin users (roles preferred for JIT access)"
        ((activity_pass++))
    elif [[ "$admin_role_count" -gt "$ADMIN_USER_COUNT" ]]; then
        log_pass "1.4.1-D: More admin roles ($admin_role_count) than admin users ($ADMIN_USER_COUNT)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "1.4.1-D" \
            "Admin users ($ADMIN_USER_COUNT) >= admin roles ($admin_role_count)" \
            "Prefer IAM roles over users for admin access (supports JIT)"
    fi
    
    # Info 1.4.1-E: Programmatic-Only IAM Users (potential service accounts)
    # This is informational only - helps identify accounts that may need PAM migration
    local programmatic_users=()
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date pw_enabled pw_last_used rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            # Has access keys but no console password = programmatic only
            if [[ "$pw_enabled" == "false" ]]; then
                # Check if user has any active access keys
                local has_keys
                has_keys=$(aws_cmd iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[?Status==`Active`] | length(@)' --output text 2>/dev/null || echo "0")
                if [[ "$has_keys" -gt 0 ]]; then
                    programmatic_users+=("$user")
                fi
            fi
        done <<< "$cred_report"
    fi
    
    if [[ ${#programmatic_users[@]} -gt 0 ]]; then
        log_info "1.4.1-E: [INFO] Programmatic-only IAM users (review for PAM/role migration):"
        log_info "  ${programmatic_users[*]}"
        log_info "  These may be service accounts, CI/CD users, or CLI-only users."
        log_info "  Consider migrating to IAM roles where possible."
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 1.4.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 1.5.1 - Identity Lifecycle Management (ILM)
# See docs/checks/1.5.1-ilm.md for detailed documentation
# =============================================================================

check_1_5_1_ilm() {
    log_info "Checking Activity 1.5.1 - Identity Lifecycle Management..."
    
    local activity_pass=0
    local activity_total=0
    local current_date
    current_date=$(date +%s)
    local ninety_days=$((90 * 24 * 60 * 60))
    local seven_days=$((7 * 24 * 60 * 60))
    
    # Get credential report (may already be cached from earlier checks)
    local cred_report
    cred_report=$(aws_cmd iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [[ -z "$cred_report" ]]; then
        aws_cmd iam generate-credential-report >/dev/null 2>&1
        sleep 3
        cred_report=$(aws_cmd iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    fi
    
    # Check 1.5.1-A: Inactive IAM Users (No Console Login in 90+ Days)
    ((activity_total++))
    local inactive_console_users=()
    
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date pw_enabled pw_last_used rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            
            if [[ "$pw_enabled" == "true" && -n "$pw_last_used" && "$pw_last_used" != "N/A" && "$pw_last_used" != "no_information" ]]; then
                local last_used_date
                last_used_date=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$pw_last_used" +%s 2>/dev/null || date -d "$pw_last_used" +%s 2>/dev/null || echo "0")
                if [[ "$last_used_date" -gt 0 && $((current_date - last_used_date)) -gt $ninety_days ]]; then
                    inactive_console_users+=("$user")
                fi
            fi
        done <<< "$cred_report"
        
        if [[ ${#inactive_console_users[@]} -gt 0 ]]; then
            log_finding "MEDIUM" "1.5.1-A" \
                "IAM users with no console login in 90+ days: ${inactive_console_users[*]}" \
                "Review and disable/delete inactive accounts per ILM policy"
        else
            log_pass "1.5.1-A: No IAM users with stale console access (90+ days inactive)"
            ((activity_pass++))
        fi
    else
        log_finding "MEDIUM" "1.5.1-A" \
            "Could not generate credential report" \
            "Ensure IAM permissions include iam:GenerateCredentialReport"
    fi
    
    # Check 1.5.1-B: Inactive Access Keys (No Use in 90+ Days)
    ((activity_total++))
    local inactive_keys=()
    
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date pw_enabled pw_last_used pw_last_changed pw_next_rotation mfa_active ak1_active ak1_last_rotated ak1_last_used ak1_region ak2_active ak2_last_rotated ak2_last_used rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            
            # Check access key 1
            if [[ "$ak1_active" == "true" && -n "$ak1_last_used" && "$ak1_last_used" != "N/A" ]]; then
                local last_used_date
                last_used_date=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak1_last_used" +%s 2>/dev/null || date -d "$ak1_last_used" +%s 2>/dev/null || echo "0")
                if [[ "$last_used_date" -gt 0 && $((current_date - last_used_date)) -gt $ninety_days ]]; then
                    inactive_keys+=("$user:key1")
                fi
            fi
            
            # Check access key 2
            if [[ "$ak2_active" == "true" && -n "$ak2_last_used" && "$ak2_last_used" != "N/A" ]]; then
                local last_used_date
                last_used_date=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak2_last_used" +%s 2>/dev/null || date -d "$ak2_last_used" +%s 2>/dev/null || echo "0")
                if [[ "$last_used_date" -gt 0 && $((current_date - last_used_date)) -gt $ninety_days ]]; then
                    inactive_keys+=("$user:key2")
                fi
            fi
        done <<< "$cred_report"
        
        if [[ ${#inactive_keys[@]} -gt 0 ]]; then
            log_finding "MEDIUM" "1.5.1-B" \
                "Access keys not used in 90+ days: ${inactive_keys[*]}" \
                "Deactivate or delete unused access keys"
        else
            log_pass "1.5.1-B: No access keys inactive for 90+ days"
            ((activity_pass++))
        fi
    fi
    
    # Check 1.5.1-C: Access Keys Never Used
    ((activity_total++))
    local never_used_keys=()
    
    if [[ -n "$cred_report" ]]; then
        while IFS=, read -r user arn creation_date pw_enabled pw_last_used pw_last_changed pw_next_rotation mfa_active ak1_active ak1_last_rotated ak1_last_used ak1_region ak2_active ak2_last_rotated ak2_last_used rest; do
            [[ "$user" == "user" || "$user" == "<root_account>" ]] && continue
            
            # Check access key 1 - active but never used
            if [[ "$ak1_active" == "true" && ("$ak1_last_used" == "N/A" || -z "$ak1_last_used") ]]; then
                # Exclude keys created in last 7 days
                if [[ -n "$ak1_last_rotated" && "$ak1_last_rotated" != "N/A" ]]; then
                    local key_created
                    key_created=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak1_last_rotated" +%s 2>/dev/null || date -d "$ak1_last_rotated" +%s 2>/dev/null || echo "0")
                    if [[ "$key_created" -gt 0 && $((current_date - key_created)) -gt $seven_days ]]; then
                        never_used_keys+=("$user:key1")
                    fi
                fi
            fi
            
            # Check access key 2 - active but never used
            if [[ "$ak2_active" == "true" && ("$ak2_last_used" == "N/A" || -z "$ak2_last_used") ]]; then
                if [[ -n "$ak2_last_rotated" && "$ak2_last_rotated" != "N/A" ]]; then
                    local key_created
                    key_created=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "$ak2_last_rotated" +%s 2>/dev/null || date -d "$ak2_last_rotated" +%s 2>/dev/null || echo "0")
                    if [[ "$key_created" -gt 0 && $((current_date - key_created)) -gt $seven_days ]]; then
                        never_used_keys+=("$user:key2")
                    fi
                fi
            fi
        done <<< "$cred_report"
        
        if [[ ${#never_used_keys[@]} -gt 0 ]]; then
            log_finding "LOW" "1.5.1-C" \
                "Access keys created but never used: ${never_used_keys[*]}" \
                "Delete unused keys - they may be orphaned or forgotten"
        else
            log_pass "1.5.1-C: No orphaned access keys (created but never used)"
            ((activity_pass++))
        fi
    fi
    
    # Check 1.5.1-D: IAM Users Without Group Membership
    ((activity_total++))
    local users_without_groups=()
    local iam_users
    iam_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text 2>/dev/null || echo "")
    
    for user in $iam_users; do
        local group_count
        group_count=$(aws_cmd iam list-groups-for-user --user-name "$user" --query 'Groups | length(@)' --output text 2>/dev/null || echo "0")
        if [[ "$group_count" -eq 0 ]]; then
            users_without_groups+=("$user")
        fi
    done
    
    if [[ ${#users_without_groups[@]} -gt 0 ]]; then
        log_finding "LOW" "1.5.1-D" \
            "IAM users not in any group: ${users_without_groups[*]}" \
            "Use groups for permission management (easier ILM)"
    else
        if [[ -n "$iam_users" ]]; then
            log_pass "1.5.1-D: All IAM users belong to at least one group"
        else
            log_pass "1.5.1-D: No IAM users to check"
        fi
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 1.5.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 1.7.1 - Deny User by Default Policy
# See docs/checks/1.7.1-deny-default.md for detailed documentation
# =============================================================================

check_1_7_1_deny_default() {
    log_info "Checking Activity 1.7.1 - Deny by Default Policy..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 1.7.1-A: Overly Permissive IAM Policies (Action:* Resource:*)
    ((activity_total++))
    local overly_permissive_policies=()
    local customer_policies
    customer_policies=$(aws_cmd iam list-policies --scope Local --query 'Policies[].Arn' --output text 2>/dev/null || echo "")
    
    for policy_arn in $customer_policies; do
        local version_id
        version_id=$(aws_cmd iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
        if [[ -n "$version_id" ]]; then
            local policy_doc
            policy_doc=$(aws_cmd iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output json 2>/dev/null || echo "")
            
            # Check for Action:* with Resource:*
            if echo "$policy_doc" | grep -qE '"Action":\s*"\*"' && echo "$policy_doc" | grep -qE '"Resource":\s*"\*"'; then
                local policy_name
                policy_name=$(basename "$policy_arn")
                overly_permissive_policies+=("$policy_name")
            fi
        fi
    done
    
    if [[ ${#overly_permissive_policies[@]} -gt 0 ]]; then
        log_finding "HIGH" "1.7.1-A" \
            "Policies with Action:* Resource:* (full admin): ${overly_permissive_policies[*]}" \
            "Scope policies to specific actions and resources (least privilege)"
    else
        log_pass "1.7.1-A: No customer policies with unrestricted Action:* Resource:*"
        ((activity_pass++))
    fi
    
    # Check 1.7.1-B: IAM Policies with Service Wildcards on All Resources
    ((activity_total++))
    local service_wildcard_policies=()
    
    for policy_arn in $customer_policies; do
        local version_id
        version_id=$(aws_cmd iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
        if [[ -n "$version_id" ]]; then
            local policy_doc
            policy_doc=$(aws_cmd iam get-policy-version --policy-arn "$policy_arn" --version-id "$version_id" --query 'PolicyVersion.Document' --output json 2>/dev/null || echo "")
            
            # Check for service:* with Resource:* (but not Action:* which is caught above)
            if echo "$policy_doc" | grep -qE '"Action":\s*"[a-z0-9-]+:\*"' && echo "$policy_doc" | grep -qE '"Resource":\s*"\*"'; then
                # Skip if already caught by check A
                if ! echo "$policy_doc" | grep -qE '"Action":\s*"\*"'; then
                    local policy_name
                    policy_name=$(basename "$policy_arn")
                    service_wildcard_policies+=("$policy_name")
                fi
            fi
        fi
    done
    
    if [[ ${#service_wildcard_policies[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "1.7.1-B" \
            "Policies with service:* on Resource:*: ${service_wildcard_policies[*]}" \
            "Scope to specific actions within service (e.g., s3:GetObject not s3:*)"
    else
        log_pass "1.7.1-B: No policies with service-wide wildcards on all resources"
        ((activity_pass++))
    fi
    
    # Check 1.7.1-C: IAM Access Analyzer Enabled
    ((activity_total++))
    local analyzer_arn=""
    local analyzers
    analyzers=$(aws_cmd accessanalyzer list-analyzers --query 'analyzers[?status==`ACTIVE`]' --output json 2>/dev/null || echo "[]")
    local analyzer_count
    analyzer_count=$(echo "$analyzers" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ "$analyzer_count" -gt 0 ]]; then
        analyzer_arn=$(echo "$analyzers" | jq -r '.[0].arn' 2>/dev/null || echo "")
        local analyzer_type
        analyzer_type=$(echo "$analyzers" | jq -r '.[0].type' 2>/dev/null || echo "")
        log_pass "1.7.1-C: IAM Access Analyzer enabled ($analyzer_type)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "1.7.1-C" \
            "IAM Access Analyzer is not enabled" \
            "Enable Access Analyzer for automated permission auditing"
    fi
    
    # Check 1.7.1-D: Users with Direct Policy Attachments
    ((activity_total++))
    local users_with_direct_policies=()
    local iam_users
    iam_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text 2>/dev/null || echo "")
    
    for user in $iam_users; do
        local attached_count
        attached_count=$(aws_cmd iam list-attached-user-policies --user-name "$user" --query 'AttachedPolicies | length(@)' --output text 2>/dev/null || echo "0")
        local inline_count
        inline_count=$(aws_cmd iam list-user-policies --user-name "$user" --query 'PolicyNames | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$attached_count" -gt 0 || "$inline_count" -gt 0 ]]; then
            users_with_direct_policies+=("$user")
        fi
    done
    
    if [[ ${#users_with_direct_policies[@]} -gt 0 ]]; then
        log_finding "LOW" "1.7.1-D" \
            "Users with direct policy attachments: ${users_with_direct_policies[*]}" \
            "Use groups for RBAC - attach policies to groups, not users"
    else
        if [[ -n "$iam_users" ]]; then
            log_pass "1.7.1-D: No users with direct policy attachments (good RBAC)"
        else
            log_pass "1.7.1-D: No IAM users to check"
        fi
        ((activity_pass++))
    fi
    
    # Check 1.7.1-E: S3 Account-Level Block Public Access
    ((activity_total++))
    local account_id
    account_id=$(aws_cmd sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "")
    local public_access_block
    public_access_block=$(aws_cmd s3control get-public-access-block --account-id "$account_id" --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
    
    local all_blocked=true
    for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
        local value
        value=$(echo "$public_access_block" | jq -r ".$setting" 2>/dev/null || echo "false")
        if [[ "$value" != "true" ]]; then
            all_blocked=false
            break
        fi
    done
    
    if [[ "$all_blocked" == "true" ]]; then
        log_pass "1.7.1-E: S3 Block Public Access fully enabled at account level"
        ((activity_pass++))
    else
        log_finding "HIGH" "1.7.1-E" \
            "S3 Block Public Access not fully enabled at account level" \
            "Enable all four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets"
    fi
    
    # Check 1.7.1-F: Access Analyzer Findings (External Access)
    ((activity_total++))
    if [[ -n "$analyzer_arn" ]]; then
        local active_findings
        active_findings=$(aws_cmd accessanalyzer list-findings --analyzer-arn "$analyzer_arn" \
            --filter '{"status": {"eq": ["ACTIVE"]}}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$active_findings" -gt 0 ]]; then
            log_finding "MEDIUM" "1.7.1-F" \
                "$active_findings active Access Analyzer findings (external access detected)" \
                "Review findings: aws accessanalyzer list-findings --analyzer-arn $analyzer_arn"
        else
            log_pass "1.7.1-F: No active Access Analyzer findings"
            ((activity_pass++))
        fi
    else
        log_info "1.7.1-F: Access Analyzer not enabled - cannot check for findings"
        ((activity_pass++))  # Don't double-penalize
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 1.7.1 Score: $activity_pass/$activity_total"
}
