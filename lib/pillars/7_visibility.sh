#!/usr/bin/env bash
# Pillar 7: Visibility and Analytics
# Activities: 7.1.2, 7.2.1, 7.2.4, 7.3.1, 7.5.1

check_pillar_7_visibility() {
    pillar_header 7 "VISIBILITY AND ANALYTICS"
    
    local pass_count=0
    local total_checks=0
    
    check_7_1_2_log_parsing
    check_7_2_1_threat_alerting
    check_7_2_4_asset_correlation
    check_7_3_1_analytics_tools
    check_7_5_1_cti_program
    
    pillar_score "Visibility" "$pass_count" "$total_checks"
}

# =============================================================================
# Activity 7.1.2 - Log Parsing
# See docs/checks/7.1.2-log-parsing.md for detailed documentation
# =============================================================================

check_7_1_2_log_parsing() {
    log_info "Checking Activity 7.1.2 - Log Parsing..."
    log_info "  ZIG: Standardize log formats, prioritize sources, forward to SIEM"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 7.1-A: CloudTrail Multi-Region Trail
    ((activity_total++))
    local trails
    trails=$(aws_cmd cloudtrail describe-trails \
        --query 'trailList[].[Name,IsMultiRegionTrail,IsOrganizationTrail]' \
        --output json 2>/dev/null || echo "[]")
    
    local multi_region_trails=0
    local org_trails=0
    local single_region_trails=()
    
    while read -r trail_info; do
        [[ -z "$trail_info" ]] && continue
        local trail_name is_multi is_org
        trail_name=$(echo "$trail_info" | jq -r '.[0]')
        is_multi=$(echo "$trail_info" | jq -r '.[1]')
        is_org=$(echo "$trail_info" | jq -r '.[2]')
        
        if [[ "$is_org" == "true" ]]; then
            ((org_trails++)) || true
        elif [[ "$is_multi" == "true" ]]; then
            ((multi_region_trails++)) || true
        else
            single_region_trails+=("$trail_name")
        fi
    done < <(echo "$trails" | jq -c '.[]' 2>/dev/null)
    
    if [[ "$org_trails" -gt 0 ]]; then
        log_pass "7.1-A: Organization trail enabled (covers all accounts/regions)"
        ((activity_pass++))
    elif [[ "$multi_region_trails" -gt 0 ]]; then
        log_pass "7.1-A: Multi-region CloudTrail enabled ($multi_region_trails trail(s))"
        ((activity_pass++))
        if [[ ${#single_region_trails[@]} -gt 0 ]]; then
            log_info "  Also found ${#single_region_trails[@]} single-region trail(s)"
        fi
    elif [[ ${#single_region_trails[@]} -gt 0 ]]; then
        log_finding "HIGH" "7.1-A" \
            "Only single-region CloudTrail: ${single_region_trails[*]}" \
            "Enable multi-region trail to capture events from ALL regions"
    else
        log_finding "BLOCKER" "7.1-A" \
            "No CloudTrail trails configured" \
            "Enable CloudTrail with multi-region trail immediately"
    fi
    
    # Check 7.1-B: CloudTrail Log File Validation
    ((activity_total++))
    local trails_without_validation=()
    
    while read -r trail_info; do
        [[ -z "$trail_info" ]] && continue
        local trail_name
        trail_name=$(echo "$trail_info" | jq -r '.[0]')
        
        local validation
        validation=$(aws_cmd cloudtrail describe-trails \
            --trail-name-list "$trail_name" \
            --query 'trailList[0].LogFileValidationEnabled' --output text 2>/dev/null || echo "false")
        
        if [[ "$validation" != "true" ]]; then
            trails_without_validation+=("$trail_name")
        fi
    done < <(echo "$trails" | jq -c '.[]' 2>/dev/null)
    
    local trail_count
    trail_count=$(echo "$trails" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ ${#trails_without_validation[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "7.1-B" \
            "CloudTrail without log validation: ${trails_without_validation[*]}" \
            "Enable log file validation to detect tampering"
    elif [[ "$trail_count" -gt 0 ]]; then
        log_pass "7.1-B: CloudTrail log file validation enabled"
        ((activity_pass++))
    else
        log_info "7.1-B: No CloudTrail trails to check"
        ((activity_pass++))
    fi
    
    # Check 7.1-C: CloudTrail S3 Data Events (for critical buckets)
    ((activity_total++))
    local trails_with_data_events=0
    
    while read -r trail_info; do
        [[ -z "$trail_info" ]] && continue
        local trail_name
        trail_name=$(echo "$trail_info" | jq -r '.[0]')
        
        local data_events
        data_events=$(aws_cmd cloudtrail get-event-selectors \
            --trail-name "$trail_name" \
            --query 'EventSelectors[?DataResources] | length(@)' --output text 2>/dev/null || echo "0")
        
        local advanced_selectors
        advanced_selectors=$(aws_cmd cloudtrail get-event-selectors \
            --trail-name "$trail_name" \
            --query 'AdvancedEventSelectors | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$data_events" -gt 0 || "$advanced_selectors" -gt 0 ]]; then
            ((trails_with_data_events++)) || true
        fi
    done < <(echo "$trails" | jq -c '.[]' 2>/dev/null)
    
    if [[ "$trails_with_data_events" -gt 0 ]]; then
        log_pass "7.1-C: CloudTrail data events configured ($trails_with_data_events trail(s))"
        ((activity_pass++))
    else
        log_info "7.1-C: No CloudTrail data events (S3/Lambda) configured"
        log_info "  Consider enabling for critical data access logging"
        ((activity_pass++))
    fi
    
    # Check 7.1-D: CloudWatch Log Groups Exist
    ((activity_total++))
    local log_group_count
    log_group_count=$(aws_cmd logs describe-log-groups \
        --query 'logGroups | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$log_group_count" -gt 0 ]]; then
        log_pass "7.1-D: CloudWatch Log Groups configured ($log_group_count)"
        ((activity_pass++))
        
        # Check for CloudTrail log group
        local cloudtrail_log_groups
        cloudtrail_log_groups=$(aws_cmd logs describe-log-groups \
            --query "logGroups[?contains(logGroupName, 'cloudtrail') || contains(logGroupName, 'CloudTrail')] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$cloudtrail_log_groups" -gt 0 ]]; then
            log_info "  CloudTrail logs sent to CloudWatch ($cloudtrail_log_groups group(s))"
        fi
    else
        log_finding "MEDIUM" "7.1-D" \
            "No CloudWatch Log Groups found" \
            "Configure CloudWatch Logs for centralized logging"
    fi
    
    # Check 7.1-E: Log Retention Policies
    ((activity_total++))
    local groups_without_retention
    groups_without_retention=$(aws_cmd logs describe-log-groups \
        --query 'logGroups[?!retentionInDays] | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$groups_without_retention" -gt 0 && "$log_group_count" -gt 0 ]]; then
        local pct_without=$((groups_without_retention * 100 / log_group_count))
        if [[ "$pct_without" -gt 50 ]]; then
            log_finding "LOW" "7.1-E" \
                "$groups_without_retention of $log_group_count log groups have no retention policy" \
                "Set retention policies to manage storage costs"
        else
            log_pass "7.1-E: Most log groups have retention policies"
            ((activity_pass++))
        fi
    else
        log_pass "7.1-E: Log retention policies configured"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 7.1.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 7.2.1 - Threat Alerting Part 1
# See docs/checks/7.2.1-threat-alerting.md for detailed documentation
# Note: GuardDuty/Security Hub checks are in Pillar 6, focus on SIEM-specific here
# =============================================================================

check_7_2_1_threat_alerting() {
    log_info "Checking Activity 7.2.1 - Threat Alerting..."
    log_info "  ZIG: Develop SIEM rules/alerts for common threat events"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 7.2-A: CloudTrail Insights Enabled
    ((activity_total++))
    local trails_with_insights=0
    local trails
    trails=$(aws_cmd cloudtrail describe-trails \
        --query 'trailList[].Name' --output text 2>/dev/null || echo "")
    
    for trail_name in $trails; do
        [[ -z "$trail_name" ]] && continue
        
        local insights
        insights=$(aws_cmd cloudtrail get-insight-selectors \
            --trail-name "$trail_name" \
            --query 'InsightSelectors | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$insights" -gt 0 ]]; then
            ((trails_with_insights++)) || true
        fi
    done
    
    if [[ "$trails_with_insights" -gt 0 ]]; then
        log_pass "7.2-A: CloudTrail Insights enabled ($trails_with_insights trail(s))"
        ((activity_pass++))
        log_info "  Anomalous API activity detection active"
    else
        log_info "7.2-A: CloudTrail Insights not enabled (optional anomaly detection)"
        ((activity_pass++))
    fi
    
    # Check 7.2-B: CloudWatch Metric Filters for Security Events
    ((activity_total++))
    local metric_filters
    metric_filters=$(aws_cmd logs describe-metric-filters \
        --query 'metricFilters | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$metric_filters" -gt 0 ]]; then
        log_pass "7.2-B: CloudWatch metric filters configured ($metric_filters)"
        ((activity_pass++))
        
        # Check for security-related filters
        local security_filters
        security_filters=$(aws_cmd logs describe-metric-filters \
            --query "metricFilters[?contains(filterName, 'security') || contains(filterName, 'Security') || contains(filterName, 'unauthorized') || contains(filterName, 'root')] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$security_filters" -gt 0 ]]; then
            log_info "  $security_filters security-related metric filter(s)"
        fi
    else
        log_finding "MEDIUM" "7.2-B" \
            "No CloudWatch metric filters configured" \
            "Create metric filters for security events (root login, unauthorized calls)"
    fi
    
    # Check 7.2-C: SNS Topics for Alerting
    ((activity_total++))
    local sns_topics
    sns_topics=$(aws_cmd sns list-topics \
        --query 'Topics | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$sns_topics" -gt 0 ]]; then
        log_pass "7.2-C: SNS topics available for alerting ($sns_topics)"
        ((activity_pass++))
    else
        log_info "7.2-C: No SNS topics configured"
        ((activity_pass++))
    fi
    
    # Check 7.2-D: CloudWatch Alarms Exist
    ((activity_total++))
    local alarm_count
    alarm_count=$(aws_cmd cloudwatch describe-alarms \
        --query 'MetricAlarms | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$alarm_count" -gt 0 ]]; then
        log_pass "7.2-D: CloudWatch alarms configured ($alarm_count)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "7.2-D" \
            "No CloudWatch alarms configured" \
            "Create alarms for security metrics and thresholds"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 7.2.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 7.2.4 - Asset ID and Alert Correlation
# See docs/checks/7.2.4-asset-correlation.md for detailed documentation
# =============================================================================

check_7_2_4_asset_correlation() {
    log_info "Checking Activity 7.2.4 - Asset ID and Alert Correlation..."
    log_info "  ZIG: Identify all assets in SIEM, correlate to alerts"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 7.2.4-A: AWS Config Enabled
    ((activity_total++))
    local config_recorders
    config_recorders=$(aws_cmd configservice describe-configuration-recorders \
        --query 'ConfigurationRecorders | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$config_recorders" -gt 0 ]]; then
        # Check if recording
        local recording_status
        recording_status=$(aws_cmd configservice describe-configuration-recorder-status \
            --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null || echo "false")
        
        if [[ "$recording_status" == "true" ]]; then
            log_pass "7.2.4-A: AWS Config enabled and recording"
            ((activity_pass++))
        else
            log_finding "HIGH" "7.2.4-A" \
                "AWS Config recorder exists but not recording" \
                "Start the Config recorder for asset inventory"
        fi
    else
        log_finding "HIGH" "7.2.4-A" \
            "AWS Config not enabled" \
            "Enable AWS Config for comprehensive asset inventory"
    fi
    
    # Check 7.2.4-B: AWS Config Rules Active
    ((activity_total++))
    local config_rules
    config_rules=$(aws_cmd configservice describe-config-rules \
        --query 'ConfigRules | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$config_rules" -gt 0 ]]; then
        log_pass "7.2.4-B: AWS Config rules active ($config_rules rules)"
        ((activity_pass++))
        
        # Check compliance
        local non_compliant
        non_compliant=$(aws_cmd configservice describe-compliance-by-config-rule \
            --query "ComplianceByConfigRules[?Compliance.ComplianceType=='NON_COMPLIANT'] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$non_compliant" -gt 0 ]]; then
            log_info "  $non_compliant rule(s) have non-compliant resources"
        fi
    else
        log_info "7.2.4-B: No AWS Config rules configured"
        log_info "  Consider enabling managed rules for compliance monitoring"
        ((activity_pass++))
    fi
    
    # Check 7.2.4-C: Systems Manager Inventory
    ((activity_total++))
    local ssm_instances
    ssm_instances=$(aws_cmd ssm describe-instance-information \
        --query 'InstanceInformationList | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$ssm_instances" -gt 0 ]]; then
        log_pass "7.2.4-C: Systems Manager managing $ssm_instances instance(s)"
        ((activity_pass++))
        
        # Check for inventory
        local inventory_count
        inventory_count=$(aws_cmd ssm list-resource-data-sync \
            --query 'ResourceDataSyncItems | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$inventory_count" -gt 0 ]]; then
            log_info "  Inventory data sync configured ($inventory_count)"
        fi
    else
        log_info "7.2.4-C: No instances managed by Systems Manager"
        ((activity_pass++))
    fi
    
    # Check 7.2.4-D: Resource Tagging Coverage
    ((activity_total++))
    # Sample check: EC2 instances with Name tag
    local ec2_count
    ec2_count=$(aws_cmd ec2 describe-instances \
        --query 'Reservations[].Instances[] | length(@)' --output text 2>/dev/null || echo "0")
    
    local ec2_with_name
    ec2_with_name=$(aws_cmd ec2 describe-instances \
        --query "Reservations[].Instances[?Tags[?Key=='Name']] | length(@)" --output text 2>/dev/null || echo "0")
    
    if [[ "$ec2_count" -gt 0 ]]; then
        local tag_pct=$((ec2_with_name * 100 / ec2_count))
        if [[ "$tag_pct" -ge 80 ]]; then
            log_pass "7.2.4-D: Good EC2 tagging coverage ($tag_pct% have Name tag)"
            ((activity_pass++))
        else
            log_finding "LOW" "7.2.4-D" \
                "Low EC2 tagging coverage ($tag_pct% have Name tag)" \
                "Tag resources for better asset identification"
        fi
    else
        log_info "7.2.4-D: No EC2 instances to check tagging"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 7.2.4 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 7.3.1 - Implement Analytics Tools
# See docs/checks/7.3.1-analytics-tools.md for detailed documentation
# =============================================================================

check_7_3_1_analytics_tools() {
    log_info "Checking Activity 7.3.1 - Analytics Tools..."
    log_info "  ZIG: Procure and implement analytics tools for threat detection"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 7.3-A: Amazon Detective Enabled
    ((activity_total++))
    local detective_graphs
    detective_graphs=$(aws_cmd detective list-graphs \
        --query 'GraphList | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$detective_graphs" -gt 0 ]]; then
        log_pass "7.3-A: Amazon Detective enabled ($detective_graphs behavior graph(s))"
        ((activity_pass++))
    else
        log_info "7.3-A: Amazon Detective not enabled (optional advanced analytics)"
        ((activity_pass++))
    fi
    
    # Check 7.3-B: CloudWatch Anomaly Detection
    ((activity_total++))
    local anomaly_detectors
    anomaly_detectors=$(aws_cmd cloudwatch describe-anomaly-detectors \
        --query 'AnomalyDetectors | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$anomaly_detectors" -gt 0 ]]; then
        log_pass "7.3-B: CloudWatch anomaly detection configured ($anomaly_detectors)"
        ((activity_pass++))
    else
        log_info "7.3-B: No CloudWatch anomaly detectors (optional ML-based detection)"
        ((activity_pass++))
    fi
    
    # Check 7.3-C: CloudWatch Logs Insights Queries
    ((activity_total++))
    local saved_queries
    saved_queries=$(aws_cmd logs describe-query-definitions \
        --query 'queryDefinitions | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$saved_queries" -gt 0 ]]; then
        log_pass "7.3-C: CloudWatch Logs Insights queries saved ($saved_queries)"
        ((activity_pass++))
    else
        log_info "7.3-C: No saved Logs Insights queries"
        log_info "  Consider saving common security analysis queries"
        ((activity_pass++))
    fi
    
    # Check 7.3-D: Athena for Log Analysis (check for CloudTrail table)
    ((activity_total++))
    local athena_workgroups
    athena_workgroups=$(aws_cmd athena list-work-groups \
        --query 'WorkGroups | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$athena_workgroups" -gt 1 ]]; then
        log_pass "7.3-D: Athena workgroups configured ($athena_workgroups)"
        ((activity_pass++))
        log_info "  Can be used for CloudTrail/VPC Flow Log analysis"
    else
        log_info "7.3-D: Only default Athena workgroup (optional for log analysis)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 7.3.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 7.5.1 - Cyber Threat Intelligence (CTI) Program Part 1
# See docs/checks/7.5.1-cti-program.md for detailed documentation
# =============================================================================

check_7_5_1_cti_program() {
    log_info "Checking Activity 7.5.1 - Cyber Threat Intelligence Program..."
    log_info "  ZIG: Establish CTI program, integrate threat feeds into SIEM"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 7.5-A: GuardDuty Threat Lists
    ((activity_total++))
    local detector_id
    detector_id=$(aws_cmd guardduty list-detectors \
        --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
        local threat_intel_sets
        threat_intel_sets=$(aws_cmd guardduty list-threat-intel-sets \
            --detector-id "$detector_id" \
            --query 'ThreatIntelSetIds | length(@)' --output text 2>/dev/null || echo "0")
        
        local ip_sets
        ip_sets=$(aws_cmd guardduty list-ip-sets \
            --detector-id "$detector_id" \
            --query 'IpSetIds | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$threat_intel_sets" -gt 0 || "$ip_sets" -gt 0 ]]; then
            log_pass "7.5-A: GuardDuty custom threat intel configured ($threat_intel_sets threat lists, $ip_sets IP sets)"
            ((activity_pass++))
        else
            log_info "7.5-A: GuardDuty using default threat intel only"
            log_info "  Consider adding custom threat lists for your environment"
            ((activity_pass++))
        fi
    else
        log_finding "HIGH" "7.5-A" \
            "GuardDuty not enabled for threat intelligence" \
            "Enable GuardDuty for built-in CTI integration"
    fi
    
    # Check 7.5-B: Security Hub Third-Party Integrations
    ((activity_total++))
    local securityhub_enabled
    securityhub_enabled=$(aws_cmd securityhub describe-hub \
        --query 'HubArn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$securityhub_enabled" && "$securityhub_enabled" != "None" ]]; then
        local integrations
        integrations=$(aws_cmd securityhub list-enabled-products-for-import \
            --query 'ProductSubscriptions | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$integrations" -gt 0 ]]; then
            log_pass "7.5-B: Security Hub integrations enabled ($integrations products)"
            ((activity_pass++))
        else
            log_info "7.5-B: No third-party Security Hub integrations"
            ((activity_pass++))
        fi
    else
        log_info "7.5-B: Security Hub not enabled (checked in Pillar 6)"
        ((activity_pass++))
    fi
    
    # Check 7.5-C: GuardDuty Malware Protection
    ((activity_total++))
    if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
        local malware_scan
        malware_scan=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Features[?Name==`EBS_MALWARE_PROTECTION`].Status' --output text 2>/dev/null || echo "")
        
        if [[ "$malware_scan" == "ENABLED" ]]; then
            log_pass "7.5-C: GuardDuty Malware Protection enabled"
            ((activity_pass++))
        else
            log_info "7.5-C: GuardDuty Malware Protection not enabled (optional)"
            ((activity_pass++))
        fi
    else
        log_info "7.5-C: GuardDuty not enabled (malware protection check skipped)"
        ((activity_pass++))
    fi
    
    # Check 7.5-D: GuardDuty S3 Protection
    ((activity_total++))
    if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
        local s3_protection
        s3_protection=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Features[?Name==`S3_DATA_EVENTS`].Status' --output text 2>/dev/null || echo "")
        
        if [[ "$s3_protection" == "ENABLED" ]]; then
            log_pass "7.5-D: GuardDuty S3 Protection enabled"
            ((activity_pass++))
        else
            log_info "7.5-D: GuardDuty S3 Protection not enabled"
            log_info "  Consider enabling for S3 threat detection"
            ((activity_pass++))
        fi
    else
        log_info "7.5-D: GuardDuty not enabled (S3 protection check skipped)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 7.5.1 Score: $activity_pass/$activity_total"
}
