#!/usr/bin/env bash
# Pillar 2: Device
# Activities: 2.1.2, 2.4.1, 2.5.1, 2.6.1, 2.6.2, 2.7.1

# Global vars for cross-check data sharing
EC2_INSTANCE_COUNT=0
SSM_MANAGED_COUNT=0
UNMANAGED_INSTANCES=()
CONFIG_RECORDER_ENABLED=false

check_pillar_2_device() {
    pillar_header 2 "DEVICE"
    
    local pass_count=0
    local total_checks=0
    
    check_2_1_2_device_inventory
    check_2_4_1_deny_device_default
    check_2_5_1_vulnerability_patch
    check_2_6_endpoint_management
    check_2_7_1_edr_integration
    
    pillar_score "Device" "$pass_count" "$total_checks"
}

# =============================================================================
# Activity 2.1.2 - Device Inventory / NPE and PKI Management
# See docs/checks/2.1.2-device-inventory.md for detailed documentation
# =============================================================================

check_2_1_2_device_inventory() {
    log_info "Checking Activity 2.1.2 - Device Inventory & NPE Management..."
    log_info "  Note: AWS can only inventory cloud resources, not on-prem devices."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 2.1.2-A: AWS Config Enabled (CMDB equivalent)
    ((activity_total++))
    local config_recorders
    config_recorders=$(aws_cmd configservice describe-configuration-recorders --query 'ConfigurationRecorders[].name' --output text 2>/dev/null || echo "")
    
    if [[ -n "$config_recorders" && "$config_recorders" != "None" ]]; then
        local recorder_status
        recorder_status=$(aws_cmd configservice describe-configuration-recorder-status --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null || echo "false")
        
        if [[ "$recorder_status" == "True" || "$recorder_status" == "true" ]]; then
            log_pass "2.1.2-A: AWS Config recorder enabled (resource inventory/CMDB)"
            ((activity_pass++))
            CONFIG_RECORDER_ENABLED=true
        else
            log_finding "MEDIUM" "2.1.2-A" \
                "AWS Config recorder exists but is not recording" \
                "Start Config recorder: aws configservice start-configuration-recorder"
        fi
    else
        log_finding "MEDIUM" "2.1.2-A" \
            "AWS Config not configured - no centralized resource inventory" \
            "Enable AWS Config for resource tracking and compliance"
        CONFIG_RECORDER_ENABLED=false
    fi
    
    # Check 2.1.2-B: SSM Managed Instance Coverage
    ((activity_total++))
    
    # Get EC2 instance count
    local ec2_instances
    ec2_instances=$(aws_cmd ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running" \
        --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || echo "")
    
    EC2_INSTANCE_COUNT=0
    for _ in $ec2_instances; do
        ((EC2_INSTANCE_COUNT++)) || true
    done
    
    # Get SSM managed instance count
    local ssm_instances
    ssm_instances=$(aws_cmd ssm describe-instance-information \
        --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text 2>/dev/null || echo "")
    
    SSM_MANAGED_COUNT=0
    local ssm_list=()
    for inst in $ssm_instances; do
        ((SSM_MANAGED_COUNT++)) || true
        ssm_list+=("$inst")
    done
    
    # Find unmanaged instances
    UNMANAGED_INSTANCES=()
    for ec2_id in $ec2_instances; do
        local is_managed=false
        for ssm_id in "${ssm_list[@]}"; do
            if [[ "$ec2_id" == "$ssm_id" ]]; then
                is_managed=true
                break
            fi
        done
        if [[ "$is_managed" == "false" ]]; then
            UNMANAGED_INSTANCES+=("$ec2_id")
        fi
    done
    
    if [[ "$EC2_INSTANCE_COUNT" -eq 0 ]]; then
        log_pass "2.1.2-B: No running EC2 instances to manage"
        ((activity_pass++))
    elif [[ ${#UNMANAGED_INSTANCES[@]} -eq 0 ]]; then
        log_pass "2.1.2-B: All $EC2_INSTANCE_COUNT EC2 instances managed by SSM"
        ((activity_pass++))
    else
        local coverage_pct=0
        if [[ "$EC2_INSTANCE_COUNT" -gt 0 ]]; then
            coverage_pct=$((SSM_MANAGED_COUNT * 100 / EC2_INSTANCE_COUNT))
        fi
        log_finding "HIGH" "2.1.2-B" \
            "${#UNMANAGED_INSTANCES[@]} EC2 instances not managed by SSM ($coverage_pct% coverage): ${UNMANAGED_INSTANCES[*]}" \
            "Install SSM agent and attach IAM role with AmazonSSMManagedInstanceCore"
    fi
    
    # Check 2.1.2-C: ACM Private CA (Enterprise PKI)
    ((activity_total++))
    local private_cas
    private_cas=$(aws_cmd acm-pca list-certificate-authorities \
        --query 'CertificateAuthorities[?Status==`ACTIVE`].Arn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$private_cas" && "$private_cas" != "None" ]]; then
        local ca_count
        ca_count=$(echo "$private_cas" | wc -w | tr -d ' ')
        log_pass "2.1.2-C: ACM Private CA configured ($ca_count active CA(s))"
        ((activity_pass++))
        log_info "  Enterprise PKI available for X.509 certificate issuance"
    else
        log_finding "MEDIUM" "2.1.2-C" \
            "No ACM Private CA configured" \
            "Consider ACM-PCA for enterprise PKI/X.509 certificate management"
    fi
    
    # Check 2.1.2-D: ACM Certificate Inventory
    ((activity_total++))
    local acm_certs
    acm_certs=$(aws_cmd acm list-certificates --query 'CertificateSummaryList[].CertificateArn' --output text 2>/dev/null || echo "")
    
    if [[ -n "$acm_certs" && "$acm_certs" != "None" ]]; then
        local cert_count=0
        local expiring_certs=()
        local current_epoch
        current_epoch=$(date +%s)
        local thirty_days=$((30 * 24 * 60 * 60))
        
        for cert_arn in $acm_certs; do
            ((cert_count++)) || true
            
            # Check expiration
            local not_after
            not_after=$(aws_cmd acm describe-certificate --certificate-arn "$cert_arn" \
                --query 'Certificate.NotAfter' --output text 2>/dev/null || echo "")
            
            if [[ -n "$not_after" && "$not_after" != "None" ]]; then
                local cert_epoch
                cert_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${not_after%+*}" +%s 2>/dev/null || \
                            date -d "$not_after" +%s 2>/dev/null || echo "0")
                
                if [[ "$cert_epoch" -gt 0 && $((cert_epoch - current_epoch)) -lt $thirty_days ]]; then
                    local cert_name
                    cert_name=$(basename "$cert_arn")
                    expiring_certs+=("$cert_name")
                fi
            fi
        done
        
        if [[ ${#expiring_certs[@]} -gt 0 ]]; then
            log_finding "HIGH" "2.1.2-D" \
                "$cert_count ACM certificates, ${#expiring_certs[@]} expiring within 30 days: ${expiring_certs[*]}" \
                "Renew expiring certificates or enable auto-renewal"
        else
            log_pass "2.1.2-D: $cert_count ACM certificates, none expiring within 30 days"
            ((activity_pass++))
        fi
    else
        log_info "2.1.2-D: No ACM certificates found (may use external PKI)"
        ((activity_pass++))
    fi
    
    # Check 2.1.2-E: IoT Device Registry (if applicable)
    ((activity_total++))
    local iot_things
    iot_things=$(aws_cmd iot list-things --query 'things | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$iot_things" -gt 0 ]]; then
        # Check if IoT things have certificates
        local things_without_certs=0
        local thing_names
        thing_names=$(aws_cmd iot list-things --query 'things[].thingName' --output text 2>/dev/null || echo "")
        
        for thing in $thing_names; do
            local principals
            principals=$(aws_cmd iot list-thing-principals --thing-name "$thing" \
                --query 'principals | length(@)' --output text 2>/dev/null || echo "0")
            if [[ "$principals" -eq 0 ]]; then
                ((things_without_certs++)) || true
            fi
        done
        
        if [[ "$things_without_certs" -gt 0 ]]; then
            log_finding "MEDIUM" "2.1.2-E" \
                "$things_without_certs of $iot_things IoT things have no certificates attached" \
                "Attach X.509 certificates to IoT devices for authentication"
        else
            log_pass "2.1.2-E: All $iot_things IoT devices have certificates attached"
            ((activity_pass++))
        fi
    else
        log_info "2.1.2-E: No IoT devices registered (IoT Core not in use)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 2.1.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 2.4.1 - Deny Device by Default
# See docs/checks/2.4.1-deny-device-default.md for detailed documentation
# =============================================================================

# Track 2.4.1 results for cross-reference
CHECK_2_4_1_A_PASSED=false  # Default SG blocks all
CHECK_2_4_1_B_PASSED=false  # No 0.0.0.0/0 ingress
CHECK_2_4_1_C_PASSED=false  # NACL deny rules

check_2_4_1_deny_device_default() {
    log_info "Checking Activity 2.4.1 - Deny Device by Default..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 2.4.1-A: Default Security Groups Block All Traffic
    ((activity_total++))
    local permissive_default_sgs=()
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text 2>/dev/null || echo "")
    
    for vpc_id in $vpcs; do
        local default_sg
        default_sg=$(aws_cmd ec2 describe-security-groups \
            --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=default" \
            --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
        
        if [[ -n "$default_sg" && "$default_sg" != "None" ]]; then
            # Check for any ingress rules (default SG should have none)
            local ingress_count
            ingress_count=$(aws_cmd ec2 describe-security-groups --group-ids "$default_sg" \
                --query 'SecurityGroups[0].IpPermissions | length(@)' --output text 2>/dev/null || echo "0")
            
            if [[ "$ingress_count" -gt 0 ]]; then
                permissive_default_sgs+=("$vpc_id:$default_sg")
            fi
        fi
    done
    
    if [[ ${#permissive_default_sgs[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "2.4.1-A" \
            "Default security groups with ingress rules: ${permissive_default_sgs[*]}" \
            "Remove all rules from default SGs - use custom SGs with explicit rules"
    else
        log_pass "2.4.1-A: All default security groups have no ingress rules"
        ((activity_pass++))
        CHECK_2_4_1_A_PASSED=true
    fi
    
    # Check 2.4.1-B: Security Groups with 0.0.0.0/0 Ingress
    ((activity_total++))
    local open_sgs=()
    local all_sgs
    all_sgs=$(aws_cmd ec2 describe-security-groups \
        --query 'SecurityGroups[?length(IpPermissions) > `0`].[GroupId,GroupName]' --output text 2>/dev/null || echo "")
    
    while read -r sg_id sg_name; do
        [[ -z "$sg_id" ]] && continue
        
        # Check for 0.0.0.0/0 in ingress rules (excluding port 443/80 for web servers)
        local open_rules
        open_rules=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
            --query "SecurityGroups[0].IpPermissions[?contains(IpRanges[].CidrIp, '0.0.0.0/0') && FromPort != \`443\` && FromPort != \`80\`].FromPort" \
            --output text 2>/dev/null || echo "")
        
        if [[ -n "$open_rules" && "$open_rules" != "None" ]]; then
            open_sgs+=("$sg_name($sg_id):ports=$open_rules")
        fi
    done <<< "$all_sgs"
    
    if [[ ${#open_sgs[@]} -gt 0 ]]; then
        log_finding "HIGH" "2.4.1-B" \
            "Security groups with 0.0.0.0/0 ingress (non-web): ${open_sgs[*]}" \
            "Restrict ingress to specific IPs/CIDRs or use VPN/bastion"
    else
        log_pass "2.4.1-B: No security groups with unrestricted non-web ingress"
        ((activity_pass++))
        CHECK_2_4_1_B_PASSED=true
    fi
    
    # Check 2.4.1-C: Network ACLs with Explicit Deny Rules
    ((activity_total++))
    local nacls_without_deny=()
    local nacls
    nacls=$(aws_cmd ec2 describe-network-acls --query 'NetworkAcls[].NetworkAclId' --output text 2>/dev/null || echo "")
    
    for nacl_id in $nacls; do
        # Check if NACL has any explicit deny rules (beyond the default deny-all at rule 32767)
        local explicit_deny
        explicit_deny=$(aws_cmd ec2 describe-network-acls --network-acl-ids "$nacl_id" \
            --query "NetworkAcls[0].Entries[?RuleAction=='deny' && RuleNumber < \`32767\`] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        # This is informational - NACLs with only default deny are fine
        # We're checking if custom deny rules exist for defense in depth
    done
    
    # NACLs always have implicit deny - this check is informational
    log_pass "2.4.1-C: Network ACLs provide deny-by-default (implicit deny at end)"
    ((activity_pass++))
    CHECK_2_4_1_C_PASSED=true
    log_info "  Note: Consider adding explicit deny rules for known-bad IPs"
    
    # Check 2.4.1-D: VPC Flow Logs Enabled
    ((activity_total++))
    local vpcs_without_flowlogs=()
    
    for vpc_id in $vpcs; do
        local flow_log
        flow_log=$(aws_cmd ec2 describe-flow-logs \
            --filter "Name=resource-id,Values=$vpc_id" \
            --query 'FlowLogs[0].FlowLogId' --output text 2>/dev/null || echo "")
        
        if [[ -z "$flow_log" || "$flow_log" == "None" ]]; then
            vpcs_without_flowlogs+=("$vpc_id")
        fi
    done
    
    if [[ ${#vpcs_without_flowlogs[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "2.4.1-D" \
            "VPCs without flow logs: ${vpcs_without_flowlogs[*]}" \
            "Enable VPC Flow Logs for network traffic visibility"
    else
        if [[ -n "$vpcs" ]]; then
            log_pass "2.4.1-D: All VPCs have flow logs enabled"
        else
            log_pass "2.4.1-D: No VPCs to check"
        fi
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 2.4.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 2.5.1 - Vulnerability and Patch Management
# See docs/checks/2.5.1-vulnerability-patch.md for detailed documentation
# =============================================================================

check_2_5_1_vulnerability_patch() {
    log_info "Checking Activity 2.5.1 - Vulnerability and Patch Management..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 2.5.1-A: Amazon Inspector Enabled
    ((activity_total++))
    local inspector_status
    inspector_status=$(aws_cmd inspector2 batch-get-account-status \
        --query 'accounts[0].state.status' --output text 2>/dev/null || echo "")
    
    if [[ "$inspector_status" == "ENABLED" ]]; then
        log_pass "2.5.1-A: Amazon Inspector enabled for vulnerability scanning"
        ((activity_pass++))
        
        # Get coverage info
        local ec2_coverage
        ec2_coverage=$(aws_cmd inspector2 batch-get-account-status \
            --query 'accounts[0].resourceState.ec2.status' --output text 2>/dev/null || echo "")
        local ecr_coverage
        ecr_coverage=$(aws_cmd inspector2 batch-get-account-status \
            --query 'accounts[0].resourceState.ecr.status' --output text 2>/dev/null || echo "")
        local lambda_coverage
        lambda_coverage=$(aws_cmd inspector2 batch-get-account-status \
            --query 'accounts[0].resourceState.lambda.status' --output text 2>/dev/null || echo "")
        
        log_info "  EC2 scanning: $ec2_coverage"
        log_info "  ECR scanning: $ecr_coverage"
        log_info "  Lambda scanning: $lambda_coverage"
    else
        log_finding "HIGH" "2.5.1-A" \
            "Amazon Inspector is not enabled" \
            "Enable Inspector: aws inspector2 enable --resource-types EC2 ECR LAMBDA"
    fi
    
    # Check 2.5.1-B: Inspector Critical/High Findings
    ((activity_total++))
    if [[ "$inspector_status" == "ENABLED" ]]; then
        local critical_findings
        critical_findings=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        local high_findings
        high_findings=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"severity": [{"comparison": "EQUALS", "value": "HIGH"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$critical_findings" -gt 0 ]]; then
            log_finding "BLOCKER" "2.5.1-B" \
                "$critical_findings CRITICAL vulnerability findings in Inspector" \
                "Review and remediate: aws inspector2 list-findings --filter-criteria '{\"severity\": [{\"comparison\": \"EQUALS\", \"value\": \"CRITICAL\"}]}'"
        elif [[ "$high_findings" -gt 0 ]]; then
            log_finding "HIGH" "2.5.1-B" \
                "$high_findings HIGH vulnerability findings in Inspector" \
                "Review and remediate high severity findings"
        else
            log_pass "2.5.1-B: No CRITICAL or HIGH Inspector findings"
            ((activity_pass++))
        fi
    else
        log_info "2.5.1-B: Inspector not enabled - cannot check findings"
        ((activity_pass++))  # Don't double-penalize
    fi
    
    # Check 2.5.1-C: SSM Patch Compliance
    ((activity_total++))
    local noncompliant_instances=()
    
    # Get patch compliance summary
    local compliance_items
    compliance_items=$(aws_cmd ssm list-compliance-items \
        --filters "Key=ComplianceType,Values=Patch" "Key=Status,Values=NON_COMPLIANT" \
        --query 'ComplianceItems[].ResourceId' --output text 2>/dev/null || echo "")
    
    for instance_id in $compliance_items; do
        [[ -z "$instance_id" ]] && continue
        noncompliant_instances+=("$instance_id")
    done
    
    if [[ ${#noncompliant_instances[@]} -gt 0 ]]; then
        log_finding "HIGH" "2.5.1-C" \
            "Instances with patch compliance issues: ${noncompliant_instances[*]}" \
            "Run patch baseline: aws ssm send-command --document-name AWS-RunPatchBaseline"
    else
        # Check if any instances are being managed for patching
        local patch_groups
        patch_groups=$(aws_cmd ssm describe-patch-groups --query 'Mappings | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$patch_groups" -gt 0 || "$SSM_MANAGED_COUNT" -gt 0 ]]; then
            log_pass "2.5.1-C: All managed instances are patch compliant"
            ((activity_pass++))
        else
            log_info "2.5.1-C: No SSM patch management configured"
            ((activity_pass++))
        fi
    fi
    
    # Check 2.5.1-D: Patch Baseline Defined
    ((activity_total++))
    local custom_baselines
    custom_baselines=$(aws_cmd ssm describe-patch-baselines \
        --filters "Key=OWNER,Values=Self" \
        --query 'BaselineIdentities | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$custom_baselines" -gt 0 ]]; then
        log_pass "2.5.1-D: Custom patch baseline(s) defined ($custom_baselines)"
        ((activity_pass++))
    else
        log_finding "LOW" "2.5.1-D" \
            "No custom patch baselines defined (using AWS defaults)" \
            "Consider creating custom patch baselines for your compliance requirements"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 2.5.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 2.6 - Endpoint Management (2.6.1 + 2.6.2)
# See docs/checks/2.6-endpoint-management.md for detailed documentation
# =============================================================================

check_2_6_endpoint_management() {
    log_info "Checking Activity 2.6 - Endpoint Management..."
    log_info "  Note: Full UEM requires external tooling. Checking AWS SSM alignment."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 2.6-A: SSM State Manager Associations
    ((activity_total++))
    local associations
    associations=$(aws_cmd ssm list-associations \
        --query 'Associations | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$associations" -gt 0 ]]; then
        log_pass "2.6-A: SSM State Manager configured ($associations associations)"
        ((activity_pass++))
        
        # List association names for info
        local assoc_names
        assoc_names=$(aws_cmd ssm list-associations \
            --query 'Associations[].Name' --output text 2>/dev/null || echo "")
        log_info "  Associations: $assoc_names"
    else
        log_finding "MEDIUM" "2.6-A" \
            "No SSM State Manager associations configured" \
            "Use State Manager for desired state configuration enforcement"
    fi
    
    # Check 2.6-B: SSM Inventory Collection
    ((activity_total++))
    local inventory_associations
    inventory_associations=$(aws_cmd ssm list-associations \
        --association-filter-list "key=Name,value=AWS-GatherSoftwareInventory" \
        --query 'Associations | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$inventory_associations" -gt 0 ]]; then
        log_pass "2.6-B: SSM Inventory collection configured"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "2.6-B" \
            "SSM Inventory collection not configured" \
            "Enable inventory: aws ssm create-association --name AWS-GatherSoftwareInventory --targets Key=InstanceIds,Values=*"
    fi
    
    # Check 2.6-C: SSM Default Host Management Configuration
    ((activity_total++))
    local dhmc_status
    dhmc_status=$(aws_cmd ssm get-service-setting \
        --setting-id "arn:aws:ssm:$(aws_cmd configure get region 2>/dev/null || echo "us-east-1"):$(aws_cmd sts get-caller-identity --query 'Account' --output text 2>/dev/null):servicesetting/ssm/managed-instance/default-ec2-instance-management-role" \
        --query 'ServiceSetting.Status' --output text 2>/dev/null || echo "")
    
    if [[ "$dhmc_status" == "Customized" || "$dhmc_status" == "Default" ]]; then
        log_pass "2.6-C: SSM Default Host Management Configuration enabled"
        ((activity_pass++))
    else
        log_finding "LOW" "2.6-C" \
            "SSM Default Host Management not configured" \
            "Enable DHMC for automatic SSM agent management on new instances"
    fi
    
    # Check 2.6-D: Unmanaged EC2 Instances (cross-reference from 2.1.2-B)
    ((activity_total++))
    if [[ ${#UNMANAGED_INSTANCES[@]} -eq 0 ]]; then
        if [[ "$EC2_INSTANCE_COUNT" -gt 0 ]]; then
            log_pass "2.6-D: All EC2 instances managed by SSM (via 2.1.2-B)"
        else
            log_pass "2.6-D: No EC2 instances to manage"
        fi
        ((activity_pass++))
    else
        log_finding "HIGH" "2.6-D" \
            "Unmanaged instances cannot receive endpoint policies: ${UNMANAGED_INSTANCES[*]}" \
            "Install SSM agent and attach IAM role (see 2.1.2-B)"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 2.6 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 2.7.1 - EDR Integration
# See docs/checks/2.7.1-edr-integration.md for detailed documentation
# =============================================================================

check_2_7_1_edr_integration() {
    log_info "Checking Activity 2.7.1 - EDR Integration..."
    log_info "  Note: Full EDR requires external tooling. Checking AWS-native detection."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 2.7.1-A: GuardDuty Runtime Monitoring (EKS/EC2)
    ((activity_total++))
    local detector_id
    detector_id=$(aws_cmd guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$detector_id" && "$detector_id" != "None" && "$detector_id" != "null" ]]; then
        # Check for runtime monitoring features
        local runtime_monitoring
        runtime_monitoring=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Features[?Name==`RUNTIME_MONITORING`].Status' --output text 2>/dev/null || echo "")
        
        local eks_runtime
        eks_runtime=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Features[?Name==`EKS_RUNTIME_MONITORING`].Status' --output text 2>/dev/null || echo "")
        
        if [[ "$runtime_monitoring" == "ENABLED" || "$eks_runtime" == "ENABLED" ]]; then
            log_pass "2.7.1-A: GuardDuty Runtime Monitoring enabled"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "2.7.1-A" \
                "GuardDuty Runtime Monitoring not enabled" \
                "Enable runtime monitoring for EDR-like capabilities on EC2/EKS"
        fi
    else
        log_finding "HIGH" "2.7.1-A" \
            "GuardDuty not enabled - no runtime threat detection" \
            "Enable GuardDuty with Runtime Monitoring feature"
    fi
    
    # Check 2.7.1-B: GuardDuty Malware Protection
    ((activity_total++))
    if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
        local malware_protection
        malware_protection=$(aws_cmd guardduty get-detector --detector-id "$detector_id" \
            --query 'Features[?Name==`EBS_MALWARE_PROTECTION`].Status' --output text 2>/dev/null || echo "")
        
        if [[ "$malware_protection" == "ENABLED" ]]; then
            log_pass "2.7.1-B: GuardDuty Malware Protection enabled"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "2.7.1-B" \
                "GuardDuty Malware Protection not enabled" \
                "Enable EBS Malware Protection for malware scanning"
        fi
    else
        log_info "2.7.1-B: GuardDuty not enabled - cannot check malware protection"
        ((activity_pass++))  # Don't double-penalize
    fi
    
    # Check 2.7.1-C: GuardDuty Findings (Malware/Trojan)
    ((activity_total++))
    if [[ -n "$detector_id" && "$detector_id" != "None" ]]; then
        local malware_findings
        malware_findings=$(aws_cmd guardduty list-findings --detector-id "$detector_id" \
            --finding-criteria '{"Criterion": {"type": {"Eq": ["Trojan:EC2/DropPoint", "Trojan:EC2/BlackholeTraffic", "Trojan:EC2/DGADomainRequest.B", "Trojan:EC2/DGADomainRequest.C", "Trojan:EC2/DNSDataExfiltration", "Trojan:EC2/PhishingDomainRequest"]}}}' \
            --query 'FindingIds | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$malware_findings" -gt 0 ]]; then
            log_finding "BLOCKER" "2.7.1-C" \
                "$malware_findings malware/trojan findings detected by GuardDuty" \
                "Investigate immediately: aws guardduty list-findings --detector-id $detector_id"
        else
            log_pass "2.7.1-C: No malware/trojan findings in GuardDuty"
            ((activity_pass++))
        fi
    else
        log_info "2.7.1-C: GuardDuty not enabled - cannot check for malware findings"
        ((activity_pass++))
    fi
    
    # Check 2.7.1-D: CloudWatch Agent for System Metrics
    ((activity_total++))
    # Check if CloudWatch agent config exists in SSM Parameter Store
    local cw_agent_config
    cw_agent_config=$(aws_cmd ssm get-parameter \
        --name "AmazonCloudWatch-linux" \
        --query 'Parameter.Value' --output text 2>/dev/null || echo "")
    
    local cw_agent_windows
    cw_agent_windows=$(aws_cmd ssm get-parameter \
        --name "AmazonCloudWatch-windows" \
        --query 'Parameter.Value' --output text 2>/dev/null || echo "")
    
    if [[ -n "$cw_agent_config" || -n "$cw_agent_windows" ]]; then
        log_pass "2.7.1-D: CloudWatch Agent configuration found in SSM"
        ((activity_pass++))
    else
        log_finding "LOW" "2.7.1-D" \
            "No CloudWatch Agent configuration in SSM Parameter Store" \
            "Configure CloudWatch Agent for system-level metrics and logs"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 2.7.1 Score: $activity_pass/$activity_total"
}
