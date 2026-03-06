#!/usr/bin/env bash
# Pillar 6: Automation and Orchestration
# Activities: 6.1.2, 6.5.2, 6.6.2, 6.7.1

check_pillar_6_automation() {
    pillar_header 6 "AUTOMATION AND ORCHESTRATION"
    
    local pass_count=0
    local total_checks=0
    
    check_6_1_2_access_profiles
    check_6_5_2_soar_tools
    check_6_6_2_api_standardization
    check_6_7_1_workflow_enrichment
    
    pillar_score "Automation" "$pass_count" "$total_checks"
}

# =============================================================================
# Activity 6.1.2 - Organization Access Profile
# See docs/checks/6.1.2-access-profiles.md for detailed documentation
# =============================================================================

check_6_1_2_access_profiles() {
    log_info "Checking Activity 6.1.2 - Organization Access Profiles..."
    log_info "  ZIG: Develop access profile rules using User, Data, Network, Device pillars"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 6.1-A: IAM Access Analyzer Enabled
    ((activity_total++))
    local analyzers
    analyzers=$(aws_cmd accessanalyzer list-analyzers \
        --query 'analyzers[?status==`ACTIVE`] | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$analyzers" -gt 0 ]]; then
        log_pass "6.1-A: IAM Access Analyzer enabled ($analyzers active analyzer(s))"
        ((activity_pass++))
        
        # Check for findings
        local findings
        findings=$(aws_cmd accessanalyzer list-findings \
            --analyzer-arn "$(aws_cmd accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text 2>/dev/null)" \
            --query 'findings[?status==`ACTIVE`] | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$findings" -gt 0 ]]; then
            log_info "  $findings active finding(s) - review for external access"
        fi
    else
        log_finding "HIGH" "6.1-A" \
            "IAM Access Analyzer not enabled" \
            "Enable Access Analyzer to identify resources shared externally"
    fi
    
    # Check 6.1-B: AWS Organizations SCPs (if in org)
    ((activity_total++))
    local org_id
    org_id=$(aws_cmd organizations describe-organization \
        --query 'Organization.Id' --output text 2>/dev/null || echo "")
    
    if [[ -n "$org_id" && "$org_id" != "None" ]]; then
        local scp_count
        scp_count=$(aws_cmd organizations list-policies --filter SERVICE_CONTROL_POLICY \
            --query 'Policies | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$scp_count" -gt 1 ]]; then
            log_pass "6.1-B: Service Control Policies configured ($scp_count policies)"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "6.1-B" \
                "Only default SCP in place" \
                "Implement SCPs for organization-wide access controls"
        fi
    else
        log_info "6.1-B: Not part of AWS Organizations (SCPs not applicable)"
        ((activity_pass++))
    fi
    
    # Check 6.1-C: Permission Boundaries in Use
    ((activity_total++))
    local users_with_boundaries
    users_with_boundaries=$(aws_cmd iam list-users \
        --query 'Users[?PermissionsBoundary].UserName | length(@)' --output text 2>/dev/null || echo "0")
    
    local roles_with_boundaries
    roles_with_boundaries=$(aws_cmd iam list-roles \
        --query 'Roles[?PermissionsBoundary].RoleName | length(@)' --output text 2>/dev/null || echo "0")
    
    local total_boundaries=$((users_with_boundaries + roles_with_boundaries))
    
    if [[ "$total_boundaries" -gt 0 ]]; then
        log_pass "6.1-C: Permission boundaries in use ($users_with_boundaries users, $roles_with_boundaries roles)"
        ((activity_pass++))
    else
        log_info "6.1-C: No permission boundaries configured (optional but recommended)"
        ((activity_pass++))
    fi
    
    # Check 6.1-D: IAM Policy Simulator / Policy Validation
    # Check for overly permissive policies (Action:* Resource:*)
    ((activity_total++))
    local overly_permissive=()
    local policies
    policies=$(aws_cmd iam list-policies --scope Local \
        --query 'Policies[].Arn' --output text 2>/dev/null || echo "")
    
    local checked=0
    for policy_arn in $policies; do
        [[ -z "$policy_arn" ]] && continue
        ((checked++)) || true
        [[ "$checked" -gt 20 ]] && break  # Limit API calls
        
        local version
        version=$(aws_cmd iam get-policy --policy-arn "$policy_arn" \
            --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
        
        [[ -z "$version" ]] && continue
        
        local policy_doc
        policy_doc=$(aws_cmd iam get-policy-version --policy-arn "$policy_arn" \
            --version-id "$version" --query 'PolicyVersion.Document' --output json 2>/dev/null || echo "{}")
        
        # Check for Action:* with Resource:*
        if echo "$policy_doc" | jq -e '.Statement[]? | select(.Effect=="Allow" and .Action=="*" and .Resource=="*")' >/dev/null 2>&1; then
            local policy_name
            policy_name=$(echo "$policy_arn" | awk -F'/' '{print $NF}')
            overly_permissive+=("$policy_name")
        fi
    done
    
    if [[ ${#overly_permissive[@]} -gt 0 ]]; then
        log_finding "HIGH" "6.1-D" \
            "Overly permissive policies (Action:* Resource:*): ${overly_permissive[*]}" \
            "Apply least privilege - scope actions and resources"
    else
        log_pass "6.1-D: No overly permissive customer policies found (checked $checked)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 6.1.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 6.5.2 - Implement SOAR Tools
# See docs/checks/6.5.2-soar-tools.md for detailed documentation
# =============================================================================

check_6_5_2_soar_tools() {
    log_info "Checking Activity 6.5.2 - Security Orchestration, Automation, and Response..."
    log_info "  ZIG: Implement SOAR tools for automated IR and policy enforcement"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 6.5-A: Security Hub Enabled
    ((activity_total++))
    local securityhub_status
    securityhub_status=$(aws_cmd securityhub describe-hub \
        --query 'HubArn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$securityhub_status" && "$securityhub_status" != "None" ]]; then
        log_pass "6.5-A: Security Hub enabled"
        ((activity_pass++))
    else
        log_finding "HIGH" "6.5-A" \
            "Security Hub not enabled" \
            "Enable Security Hub for centralized security findings and SOAR integration"
    fi
    
    # Check 6.5-B: Security Hub Standards Enabled
    ((activity_total++))
    local enabled_standards
    enabled_standards=$(aws_cmd securityhub get-enabled-standards \
        --query 'StandardsSubscriptions | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$enabled_standards" -gt 0 ]]; then
        log_pass "6.5-B: Security Hub standards enabled ($enabled_standards)"
        ((activity_pass++))
        
        # List which standards
        local standard_names
        standard_names=$(aws_cmd securityhub get-enabled-standards \
            --query 'StandardsSubscriptions[].StandardsArn' --output text 2>/dev/null || echo "")
        
        for std in $standard_names; do
            local std_short
            std_short=$(echo "$std" | awk -F'/' '{print $(NF-1)"/"$NF}')
            log_info "  Standard: $std_short"
        done
    else
        if [[ -n "$securityhub_status" && "$securityhub_status" != "None" ]]; then
            log_finding "MEDIUM" "6.5-B" \
                "No Security Hub standards enabled" \
                "Enable AWS Foundational Security Best Practices or CIS standards"
        else
            log_info "6.5-B: Security Hub not enabled (standards check skipped)"
            ((activity_pass++))
        fi
    fi
    
    # Check 6.5-C: Security Hub Automations (Custom Actions or Automation Rules)
    ((activity_total++))
    local automation_rules
    automation_rules=$(aws_cmd securityhub list-automation-rules \
        --query 'AutomationRulesMetadata | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$automation_rules" -gt 0 ]]; then
        log_pass "6.5-C: Security Hub automation rules configured ($automation_rules)"
        ((activity_pass++))
    else
        log_info "6.5-C: No Security Hub automation rules (consider for automated response)"
        ((activity_pass++))
    fi
    
    # Check 6.5-D: EventBridge Rules for Security Events
    ((activity_total++))
    local security_rules
    security_rules=$(aws_cmd events list-rules \
        --query "Rules[?contains(Name, 'security') || contains(Name, 'Security') || contains(Name, 'guardduty') || contains(Name, 'securityhub')] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    # Also check for rules with Security Hub as source
    local securityhub_rules
    securityhub_rules=$(aws_cmd events list-rules \
        --query 'Rules | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$security_rules" -gt 0 ]]; then
        log_pass "6.5-D: EventBridge rules for security events ($security_rules)"
        ((activity_pass++))
    else
        log_info "6.5-D: No security-specific EventBridge rules detected"
        log_info "  Consider EventBridge rules for automated security response"
        ((activity_pass++))
    fi
    
    # Check 6.5-E: Step Functions for Orchestration (optional)
    ((activity_total++))
    local state_machines
    state_machines=$(aws_cmd stepfunctions list-state-machines \
        --query 'stateMachines | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$state_machines" -gt 0 ]]; then
        log_pass "6.5-E: Step Functions available for orchestration ($state_machines state machines)"
        ((activity_pass++))
    else
        log_info "6.5-E: No Step Functions state machines (optional for complex workflows)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 6.5.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 6.6.2 - Standardized API Calls and Schemas
# See docs/checks/6.6.2-api-standardization.md for detailed documentation
# =============================================================================

check_6_6_2_api_standardization() {
    log_info "Checking Activity 6.6.2 - API Standardization..."
    log_info "  ZIG: Establish API standards with approved patterns and protocols"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 6.6-A: API Gateway REST APIs
    ((activity_total++))
    local rest_apis
    rest_apis=$(aws_cmd apigateway get-rest-apis \
        --query 'items | length(@)' --output text 2>/dev/null || echo "0")
    
    local http_apis
    http_apis=$(aws_cmd apigatewayv2 get-apis \
        --query 'Items | length(@)' --output text 2>/dev/null || echo "0")
    
    local total_apis=$((rest_apis + http_apis))
    
    if [[ "$total_apis" -gt 0 ]]; then
        log_pass "6.6-A: API Gateway configured ($rest_apis REST, $http_apis HTTP APIs)"
        ((activity_pass++))
    else
        log_info "6.6-A: No API Gateway APIs found (may use other API patterns)"
        ((activity_pass++))
    fi
    
    # Check 6.6-B: API Gateway Authorization
    ((activity_total++))
    if [[ "$rest_apis" -gt 0 ]]; then
        local apis_without_auth=()
        local api_ids
        api_ids=$(aws_cmd apigateway get-rest-apis \
            --query 'items[].id' --output text 2>/dev/null || echo "")
        
        local checked=0
        for api_id in $api_ids; do
            [[ -z "$api_id" ]] && continue
            ((checked++)) || true
            [[ "$checked" -gt 10 ]] && break  # Limit API calls
            
            local api_name
            api_name=$(aws_cmd apigateway get-rest-api --rest-api-id "$api_id" \
                --query 'name' --output text 2>/dev/null || echo "$api_id")
            
            # Check if any methods have authorization
            local resources
            resources=$(aws_cmd apigateway get-resources --rest-api-id "$api_id" \
                --query 'items[].id' --output text 2>/dev/null || echo "")
            
            local has_auth=false
            for resource_id in $resources; do
                [[ -z "$resource_id" ]] && continue
                
                local methods
                methods=$(aws_cmd apigateway get-resource --rest-api-id "$api_id" \
                    --resource-id "$resource_id" \
                    --query 'resourceMethods | keys(@)' --output text 2>/dev/null || echo "")
                
                for method in $methods; do
                    [[ -z "$method" || "$method" == "OPTIONS" ]] && continue
                    
                    local auth_type
                    auth_type=$(aws_cmd apigateway get-method --rest-api-id "$api_id" \
                        --resource-id "$resource_id" --http-method "$method" \
                        --query 'authorizationType' --output text 2>/dev/null || echo "NONE")
                    
                    if [[ "$auth_type" != "NONE" ]]; then
                        has_auth=true
                        break 2
                    fi
                done
            done
            
            if [[ "$has_auth" == "false" ]]; then
                apis_without_auth+=("$api_name")
            fi
        done
        
        if [[ ${#apis_without_auth[@]} -gt 0 ]]; then
            log_finding "HIGH" "6.6-B" \
                "APIs without authorization: ${apis_without_auth[*]}" \
                "Configure IAM, Cognito, or Lambda authorizers"
        else
            log_pass "6.6-B: All checked APIs have authorization configured"
            ((activity_pass++))
        fi
    else
        log_info "6.6-B: No REST APIs to check for authorization"
        ((activity_pass++))
    fi
    
    # Check 6.6-C: API Gateway Logging
    ((activity_total++))
    if [[ "$rest_apis" -gt 0 ]]; then
        local apis_without_logging=()
        local api_ids
        api_ids=$(aws_cmd apigateway get-rest-apis \
            --query 'items[].id' --output text 2>/dev/null || echo "")
        
        local checked=0
        for api_id in $api_ids; do
            [[ -z "$api_id" ]] && continue
            ((checked++)) || true
            [[ "$checked" -gt 10 ]] && break
            
            local api_name
            api_name=$(aws_cmd apigateway get-rest-api --rest-api-id "$api_id" \
                --query 'name' --output text 2>/dev/null || echo "$api_id")
            
            # Check stages for logging
            local stages
            stages=$(aws_cmd apigateway get-stages --rest-api-id "$api_id" \
                --query 'item[].stageName' --output text 2>/dev/null || echo "")
            
            local has_logging=false
            for stage in $stages; do
                [[ -z "$stage" ]] && continue
                
                local logging_level
                logging_level=$(aws_cmd apigateway get-stage --rest-api-id "$api_id" \
                    --stage-name "$stage" \
                    --query 'methodSettings."*/*".loggingLevel' --output text 2>/dev/null || echo "OFF")
                
                if [[ "$logging_level" != "OFF" && "$logging_level" != "None" && -n "$logging_level" ]]; then
                    has_logging=true
                    break
                fi
            done
            
            if [[ "$has_logging" == "false" && -n "$stages" ]]; then
                apis_without_logging+=("$api_name")
            fi
        done
        
        if [[ ${#apis_without_logging[@]} -gt 0 ]]; then
            log_finding "MEDIUM" "6.6-C" \
                "APIs without logging: ${apis_without_logging[*]}" \
                "Enable CloudWatch logging for API Gateway stages"
        else
            log_pass "6.6-C: API Gateway logging configured"
            ((activity_pass++))
        fi
    else
        log_info "6.6-C: No REST APIs to check for logging"
        ((activity_pass++))
    fi
    
    # Check 6.6-D: API Gateway WAF Integration
    ((activity_total++))
    if [[ "$rest_apis" -gt 0 ]]; then
        local api_ids
        api_ids=$(aws_cmd apigateway get-rest-apis \
            --query 'items[].id' --output text 2>/dev/null || echo "")
        
        local apis_with_waf=0
        local checked=0
        for api_id in $api_ids; do
            [[ -z "$api_id" ]] && continue
            ((checked++)) || true
            [[ "$checked" -gt 10 ]] && break
            
            local stages
            stages=$(aws_cmd apigateway get-stages --rest-api-id "$api_id" \
                --query 'item[].stageName' --output text 2>/dev/null || echo "")
            
            for stage in $stages; do
                [[ -z "$stage" ]] && continue
                
                local stage_arn="arn:aws:apigateway:${AWS_REGION:-us-east-1}::/restapis/$api_id/stages/$stage"
                local waf_acl
                waf_acl=$(aws_cmd wafv2 get-web-acl-for-resource \
                    --resource-arn "$stage_arn" \
                    --query 'WebACL.Name' --output text 2>/dev/null || echo "")
                
                if [[ -n "$waf_acl" && "$waf_acl" != "None" ]]; then
                    ((apis_with_waf++)) || true
                    break
                fi
            done
        done
        
        if [[ "$apis_with_waf" -gt 0 ]]; then
            log_pass "6.6-D: WAF integrated with $apis_with_waf API(s)"
            ((activity_pass++))
        else
            log_info "6.6-D: No API Gateway WAF integration (recommended for public APIs)"
            ((activity_pass++))
        fi
    else
        log_info "6.6-D: No REST APIs to check for WAF"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 6.6.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 6.7.1 - Workflow Enrichment Part 1
# See docs/checks/6.7.1-workflow-enrichment.md for detailed documentation
# =============================================================================

check_6_7_1_workflow_enrichment() {
    log_info "Checking Activity 6.7.1 - Workflow Enrichment..."
    log_info "  ZIG: Establish IR guidance with CTI enrichment and automated workflows"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 6.7-A: GuardDuty Enabled (Threat Intelligence)
    ((activity_total++))
    local guardduty_detectors
    guardduty_detectors=$(aws_cmd guardduty list-detectors \
        --query 'DetectorIds | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$guardduty_detectors" -gt 0 ]]; then
        local detector_id
        detector_id=$(aws_cmd guardduty list-detectors \
            --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")
        
        local detector_status
        detector_status=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Status' --output text 2>/dev/null || echo "")
        
        if [[ "$detector_status" == "ENABLED" ]]; then
            log_pass "6.7-A: GuardDuty enabled for threat intelligence"
            ((activity_pass++))
            
            # Check for findings
            local finding_count
            finding_count=$(aws_cmd guardduty list-findings --detector-id "$detector_id" \
                --query 'FindingIds | length(@)' --output text 2>/dev/null || echo "0")
            
            if [[ "$finding_count" -gt 0 ]]; then
                log_info "  $finding_count finding(s) - review for threat events"
            fi
        else
            log_finding "HIGH" "6.7-A" \
                "GuardDuty detector exists but not enabled" \
                "Enable GuardDuty for continuous threat detection"
        fi
    else
        log_finding "HIGH" "6.7-A" \
            "GuardDuty not enabled" \
            "Enable GuardDuty for threat intelligence and CTI enrichment"
    fi
    
    # Check 6.7-B: Security Hub Findings Aggregation
    ((activity_total++))
    local securityhub_enabled
    securityhub_enabled=$(aws_cmd securityhub describe-hub \
        --query 'HubArn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$securityhub_enabled" && "$securityhub_enabled" != "None" ]]; then
        # Check for integrations
        local integrations
        integrations=$(aws_cmd securityhub list-enabled-products-for-import \
            --query 'ProductSubscriptions | length(@)' --output text 2>/dev/null || echo "0")
        
        log_pass "6.7-B: Security Hub aggregating findings ($integrations product integrations)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "6.7-B" \
            "Security Hub not enabled for findings aggregation" \
            "Enable Security Hub to centralize security findings"
    fi
    
    # Check 6.7-C: CloudWatch Alarms for Security Events
    ((activity_total++))
    local security_alarms
    security_alarms=$(aws_cmd cloudwatch describe-alarms \
        --query "MetricAlarms[?contains(AlarmName, 'security') || contains(AlarmName, 'Security') || contains(AlarmName, 'unauthorized') || contains(AlarmName, 'root')] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    # Also check for alarms on CloudTrail metrics
    local cloudtrail_alarms
    cloudtrail_alarms=$(aws_cmd cloudwatch describe-alarms \
        --query "MetricAlarms[?Namespace=='CloudTrailMetrics'] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    local total_security_alarms=$((security_alarms + cloudtrail_alarms))
    
    if [[ "$total_security_alarms" -gt 0 ]]; then
        log_pass "6.7-C: Security-related CloudWatch alarms configured ($total_security_alarms)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "6.7-C" \
            "No security-related CloudWatch alarms detected" \
            "Configure alarms for unauthorized API calls, root login, etc."
    fi
    
    # Check 6.7-D: SNS Topics for Security Notifications
    ((activity_total++))
    local security_topics
    security_topics=$(aws_cmd sns list-topics \
        --query "Topics[?contains(TopicArn, 'security') || contains(TopicArn, 'Security') || contains(TopicArn, 'alert') || contains(TopicArn, 'incident')] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    if [[ "$security_topics" -gt 0 ]]; then
        log_pass "6.7-D: Security notification topics configured ($security_topics)"
        ((activity_pass++))
    else
        log_info "6.7-D: No security-specific SNS topics detected"
        log_info "  Consider SNS topics for security alerting workflows"
        ((activity_pass++))
    fi
    
    # Check 6.7-E: Lambda Functions for Automated Response
    ((activity_total++))
    local security_lambdas
    security_lambdas=$(aws_cmd lambda list-functions \
        --query "Functions[?contains(FunctionName, 'security') || contains(FunctionName, 'Security') || contains(FunctionName, 'remediat') || contains(FunctionName, 'response')] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    if [[ "$security_lambdas" -gt 0 ]]; then
        log_pass "6.7-E: Security automation Lambda functions ($security_lambdas)"
        ((activity_pass++))
    else
        log_info "6.7-E: No security-specific Lambda functions detected"
        log_info "  Consider Lambda for automated incident response"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 6.7.1 Score: $activity_pass/$activity_total"
}
