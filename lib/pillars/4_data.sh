#!/usr/bin/env bash
# Pillar 4: Data
# Activities: 4.2.1, 4.2.2, 4.3.1, 4.4.3, 4.5.1, 4.6.1

# Compliance tag detection
# Buckets/resources with these tags are held to stricter standards
COMPLIANCE_TAG_KEYS=("DataClassification" "Compliance" "SecurityLevel")
COMPLIANCE_TAG_VALUES=("critical" "required" "high" "sensitive" "pii" "phi" "pci")

# Global tracking
S3_BUCKETS_TOTAL=0
S3_BUCKETS_COMPLIANT_TAGGED=0
MACIE_ENABLED=false

check_pillar_4_data() {
    pillar_header 4 "DATA"
    
    local pass_count=0
    local total_checks=0
    
    check_4_2_data_tagging
    check_4_4_file_monitoring
    check_4_5_data_protection
    check_4_6_dlp_enforcement
    
    pillar_score "Data" "$pass_count" "$total_checks"
}

# Helper: Check if bucket has compliance tags
bucket_has_compliance_tag() {
    local bucket="$1"
    local tags
    tags=$(aws_cmd s3api get-bucket-tagging --bucket "$bucket" --query 'TagSet' --output json 2>/dev/null || echo "[]")
    
    if [[ "$tags" == "[]" || -z "$tags" ]]; then
        return 1  # No tags
    fi
    
    # Check for compliance tag keys and values
    for key in "${COMPLIANCE_TAG_KEYS[@]}"; do
        local value
        value=$(echo "$tags" | jq -r ".[] | select(.Key==\"$key\") | .Value" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        
        if [[ -n "$value" ]]; then
            for comp_val in "${COMPLIANCE_TAG_VALUES[@]}"; do
                if [[ "$value" == *"$comp_val"* ]]; then
                    return 0  # Has compliance tag
                fi
            done
        fi
    done
    
    return 1  # No compliance tags found
}

# =============================================================================
# Activity 4.2.1/4.3.1 - Data Tagging and Classification
# See docs/checks/4.2-data-tagging.md for detailed documentation
# =============================================================================

check_4_2_data_tagging() {
    log_info "Checking Activity 4.2.1/4.3.1 - Data Tagging & Classification..."
    log_info "  Compliance tags: DataClassification, Compliance, SecurityLevel"
    
    local activity_pass=0
    local activity_total=0
    
    # Check 4.2-A: Macie Enabled (Automated Data Discovery)
    ((activity_total++))
    local macie_status
    macie_status=$(aws_cmd macie2 get-macie-session --query 'status' --output text 2>/dev/null || echo "")
    
    if [[ "$macie_status" == "ENABLED" ]]; then
        log_pass "4.2-A: Amazon Macie enabled for data discovery/classification"
        ((activity_pass++))
        MACIE_ENABLED=true
    else
        log_finding "MEDIUM" "4.2-A" \
            "Amazon Macie not enabled" \
            "Enable Macie for automated sensitive data discovery: aws macie2 enable-macie"
        MACIE_ENABLED=false
    fi
    
    # Check 4.2-B: Macie Sensitive Data Findings
    ((activity_total++))
    if [[ "$MACIE_ENABLED" == "true" ]]; then
        local sensitive_findings
        sensitive_findings=$(aws_cmd macie2 list-findings \
            --finding-criteria '{"criterion": {"category": {"eq": ["CLASSIFICATION"]}}}' \
            --query 'findingIds | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$sensitive_findings" -gt 0 ]]; then
            log_finding "HIGH" "4.2-B" \
                "$sensitive_findings Macie sensitive data findings (PII/credentials detected)" \
                "Review findings: aws macie2 get-findings --finding-ids <id>"
        else
            log_pass "4.2-B: No Macie sensitive data findings"
            ((activity_pass++))
        fi
    else
        log_info "4.2-B: Macie not enabled - cannot check for sensitive data findings"
        ((activity_pass++))
    fi
    
    # Check 4.2-C: Glue Data Catalog (Data Inventory)
    ((activity_total++))
    local glue_databases
    glue_databases=$(aws_cmd glue get-databases --query 'DatabaseList | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$glue_databases" -gt 0 ]]; then
        local glue_tables
        glue_tables=$(aws_cmd glue search-tables --query 'TableList | length(@)' --output text 2>/dev/null || echo "0")
        log_pass "4.2-C: Glue Data Catalog configured ($glue_databases databases, $glue_tables tables)"
        ((activity_pass++))
        log_info "  Data catalog available for tagging/classification metadata"
    else
        log_finding "LOW" "4.2-C" \
            "No Glue Data Catalog databases found" \
            "Consider Glue Data Catalog for centralized data inventory"
    fi
    
    # Check 4.2-D: S3 Bucket Tagging Coverage
    ((activity_total++))
    local buckets
    buckets=$(aws_cmd s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")
    
    S3_BUCKETS_TOTAL=0
    S3_BUCKETS_COMPLIANT_TAGGED=0
    local untagged_buckets=()
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        ((S3_BUCKETS_TOTAL++)) || true
        
        if bucket_has_compliance_tag "$bucket"; then
            ((S3_BUCKETS_COMPLIANT_TAGGED++)) || true
        else
            # Check if bucket has ANY tags
            local has_tags
            has_tags=$(aws_cmd s3api get-bucket-tagging --bucket "$bucket" --query 'TagSet | length(@)' --output text 2>/dev/null || echo "0")
            if [[ "$has_tags" -eq 0 ]]; then
                untagged_buckets+=("$bucket")
            fi
        fi
    done
    
    if [[ "$S3_BUCKETS_TOTAL" -eq 0 ]]; then
        log_info "4.2-D: No S3 buckets found"
        ((activity_pass++))
    elif [[ ${#untagged_buckets[@]} -eq 0 ]]; then
        log_pass "4.2-D: All $S3_BUCKETS_TOTAL S3 buckets have tags"
        ((activity_pass++))
        log_info "  $S3_BUCKETS_COMPLIANT_TAGGED bucket(s) with compliance tags"
    else
        log_finding "LOW" "4.2-D" \
            "${#untagged_buckets[@]} S3 buckets have no tags: ${untagged_buckets[*]:0:5}..." \
            "Tag buckets with DataClassification or Compliance tags for ZIG compliance"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 4.2/4.3 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 4.4.3 - File Activity Monitoring
# See docs/checks/4.4-file-monitoring.md for detailed documentation
# =============================================================================

check_4_4_file_monitoring() {
    log_info "Checking Activity 4.4.3 - File Activity Monitoring..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 4.4-A: CloudTrail S3 Data Events
    ((activity_total++))
    local trails_with_s3_events=0
    local trails
    trails=$(aws_cmd cloudtrail list-trails --query 'Trails[].TrailARN' --output text 2>/dev/null || echo "")
    
    for trail_arn in $trails; do
        [[ -z "$trail_arn" ]] && continue
        
        local s3_events
        s3_events=$(aws_cmd cloudtrail get-event-selectors --trail-name "$trail_arn" \
            --query "EventSelectors[?DataResources[?Type=='AWS::S3::Object']] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        # Also check advanced event selectors
        local advanced_s3
        advanced_s3=$(aws_cmd cloudtrail get-event-selectors --trail-name "$trail_arn" \
            --query "AdvancedEventSelectors[?FieldSelectors[?Field=='resources.type' && contains(Equals, 'AWS::S3::Object')]] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$s3_events" -gt 0 || "$advanced_s3" -gt 0 ]]; then
            ((trails_with_s3_events++)) || true
        fi
    done
    
    if [[ "$trails_with_s3_events" -gt 0 ]]; then
        log_pass "4.4-A: CloudTrail S3 data events enabled ($trails_with_s3_events trail(s))"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "4.4-A" \
            "No CloudTrail trails logging S3 data events" \
            "Enable S3 data events for file activity monitoring"
    fi
    
    # Check 4.4-B: S3 Server Access Logging (Compliance-tagged buckets)
    ((activity_total++))
    local buckets
    buckets=$(aws_cmd s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")
    
    local compliance_buckets_without_logging=()
    local total_compliance_buckets=0
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        
        if bucket_has_compliance_tag "$bucket"; then
            ((total_compliance_buckets++)) || true
            
            local logging
            logging=$(aws_cmd s3api get-bucket-logging --bucket "$bucket" \
                --query 'LoggingEnabled.TargetBucket' --output text 2>/dev/null || echo "")
            
            if [[ -z "$logging" || "$logging" == "None" ]]; then
                compliance_buckets_without_logging+=("$bucket")
            fi
        fi
    done
    
    if [[ "$total_compliance_buckets" -eq 0 ]]; then
        log_info "4.4-B: No compliance-tagged S3 buckets to check for access logging"
        ((activity_pass++))
    elif [[ ${#compliance_buckets_without_logging[@]} -eq 0 ]]; then
        log_pass "4.4-B: All $total_compliance_buckets compliance-tagged buckets have access logging"
        ((activity_pass++))
    else
        log_finding "HIGH" "4.4-B" \
            "Compliance buckets without access logging: ${compliance_buckets_without_logging[*]}" \
            "Enable server access logging for compliance-tagged buckets"
    fi
    
    # Check 4.4-C: CloudWatch Log Groups for Data Access
    ((activity_total++))
    local data_log_groups
    data_log_groups=$(aws_cmd logs describe-log-groups \
        --query "logGroups[?contains(logGroupName, 'data') || contains(logGroupName, 's3') || contains(logGroupName, 'rds')] | length(@)" \
        --output text 2>/dev/null || echo "0")
    
    if [[ "$data_log_groups" -gt 0 ]]; then
        log_pass "4.4-C: CloudWatch log groups for data monitoring exist ($data_log_groups)"
        ((activity_pass++))
    else
        log_finding "LOW" "4.4-C" \
            "No CloudWatch log groups for data access monitoring found" \
            "Consider CloudWatch Logs for centralized data access monitoring"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 4.4 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 4.5.1 - Data Rights Management / Encryption
# See docs/checks/4.5-data-protection.md for detailed documentation
# =============================================================================

check_4_5_data_protection() {
    log_info "Checking Activity 4.5.1 - Data Protection & Encryption..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 4.5-A: S3 Default Encryption (Compliance-tagged buckets)
    ((activity_total++))
    local buckets
    buckets=$(aws_cmd s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")
    
    local compliance_buckets_no_encryption=()
    local all_buckets_no_encryption=()
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        
        local encryption
        encryption=$(aws_cmd s3api get-bucket-encryption --bucket "$bucket" \
            --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
            --output text 2>/dev/null || echo "")
        
        if [[ -z "$encryption" || "$encryption" == "None" ]]; then
            if bucket_has_compliance_tag "$bucket"; then
                compliance_buckets_no_encryption+=("$bucket")
            else
                all_buckets_no_encryption+=("$bucket")
            fi
        fi
    done
    
    if [[ ${#compliance_buckets_no_encryption[@]} -gt 0 ]]; then
        log_finding "HIGH" "4.5-A" \
            "Compliance buckets without encryption: ${compliance_buckets_no_encryption[*]}" \
            "Enable default encryption: aws s3api put-bucket-encryption"
    elif [[ ${#all_buckets_no_encryption[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "4.5-A" \
            "${#all_buckets_no_encryption[@]} buckets without default encryption (non-compliance tagged)" \
            "Consider enabling default encryption on all buckets"
    else
        log_pass "4.5-A: All S3 buckets have default encryption enabled"
        ((activity_pass++))
    fi
    
    # Check 4.5-B: S3 Bucket Key (KMS cost optimization)
    ((activity_total++))
    local kms_buckets_without_bucket_key=()
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        
        local sse_algo
        sse_algo=$(aws_cmd s3api get-bucket-encryption --bucket "$bucket" \
            --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
            --output text 2>/dev/null || echo "")
        
        if [[ "$sse_algo" == "aws:kms" ]]; then
            local bucket_key
            bucket_key=$(aws_cmd s3api get-bucket-encryption --bucket "$bucket" \
                --query 'ServerSideEncryptionConfiguration.Rules[0].BucketKeyEnabled' \
                --output text 2>/dev/null || echo "false")
            
            if [[ "$bucket_key" != "True" && "$bucket_key" != "true" ]]; then
                kms_buckets_without_bucket_key+=("$bucket")
            fi
        fi
    done
    
    if [[ ${#kms_buckets_without_bucket_key[@]} -gt 0 ]]; then
        log_finding "LOW" "4.5-B" \
            "KMS-encrypted buckets without Bucket Key: ${kms_buckets_without_bucket_key[*]:0:3}..." \
            "Enable S3 Bucket Key to reduce KMS costs"
    else
        log_pass "4.5-B: All KMS-encrypted buckets have Bucket Key enabled (or use SSE-S3)"
        ((activity_pass++))
    fi
    
    # Check 4.5-C: EBS Default Encryption
    ((activity_total++))
    local ebs_default_encryption
    ebs_default_encryption=$(aws_cmd ec2 get-ebs-encryption-by-default \
        --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "false")
    
    if [[ "$ebs_default_encryption" == "True" || "$ebs_default_encryption" == "true" ]]; then
        log_pass "4.5-C: EBS default encryption enabled"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "4.5-C" \
            "EBS default encryption not enabled" \
            "Enable: aws ec2 enable-ebs-encryption-by-default"
    fi
    
    # Check 4.5-D: RDS Encryption
    ((activity_total++))
    local rds_instances
    rds_instances=$(aws_cmd rds describe-db-instances \
        --query 'DBInstances[].{id:DBInstanceIdentifier,encrypted:StorageEncrypted}' \
        --output json 2>/dev/null || echo "[]")
    
    local unencrypted_rds=()
    while read -r instance; do
        [[ -z "$instance" ]] && continue
        local db_id encrypted
        db_id=$(echo "$instance" | jq -r '.id')
        encrypted=$(echo "$instance" | jq -r '.encrypted')
        
        if [[ "$encrypted" == "false" ]]; then
            unencrypted_rds+=("$db_id")
        fi
    done < <(echo "$rds_instances" | jq -c '.[]' 2>/dev/null)
    
    if [[ ${#unencrypted_rds[@]} -gt 0 ]]; then
        log_finding "HIGH" "4.5-D" \
            "Unencrypted RDS instances: ${unencrypted_rds[*]}" \
            "Enable encryption (requires snapshot restore for existing instances)"
    else
        local rds_count
        rds_count=$(echo "$rds_instances" | jq 'length' 2>/dev/null || echo "0")
        if [[ "$rds_count" -gt 0 ]]; then
            log_pass "4.5-D: All $rds_count RDS instances are encrypted"
        else
            log_info "4.5-D: No RDS instances found"
        fi
        ((activity_pass++))
    fi
    
    # Check 4.5-E: KMS Key Rotation
    ((activity_total++))
    local kms_keys
    kms_keys=$(aws_cmd kms list-keys --query 'Keys[].KeyId' --output text 2>/dev/null || echo "")
    
    local keys_without_rotation=()
    local customer_keys=0
    
    for key_id in $kms_keys; do
        [[ -z "$key_id" ]] && continue
        
        # Check if customer-managed (not AWS managed)
        local key_manager
        key_manager=$(aws_cmd kms describe-key --key-id "$key_id" \
            --query 'KeyMetadata.KeyManager' --output text 2>/dev/null || echo "")
        
        if [[ "$key_manager" == "CUSTOMER" ]]; then
            ((customer_keys++)) || true
            
            local rotation
            rotation=$(aws_cmd kms get-key-rotation-status --key-id "$key_id" \
                --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "false")
            
            if [[ "$rotation" != "True" && "$rotation" != "true" ]]; then
                keys_without_rotation+=("$key_id")
            fi
        fi
    done
    
    if [[ ${#keys_without_rotation[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "4.5-E" \
            "${#keys_without_rotation[@]} KMS keys without automatic rotation" \
            "Enable rotation: aws kms enable-key-rotation --key-id KEY_ID"
    else
        if [[ "$customer_keys" -gt 0 ]]; then
            log_pass "4.5-E: All $customer_keys customer-managed KMS keys have rotation enabled"
        else
            log_info "4.5-E: No customer-managed KMS keys found"
        fi
        ((activity_pass++))
    fi
    
    # Check 4.5-F: Secrets Manager Rotation
    ((activity_total++))
    local secrets
    secrets=$(aws_cmd secretsmanager list-secrets \
        --query 'SecretList[].{name:Name,rotation:RotationEnabled}' \
        --output json 2>/dev/null || echo "[]")
    
    local secrets_without_rotation=()
    while read -r secret; do
        [[ -z "$secret" ]] && continue
        local name rotation
        name=$(echo "$secret" | jq -r '.name')
        rotation=$(echo "$secret" | jq -r '.rotation')
        
        if [[ "$rotation" == "false" || "$rotation" == "null" ]]; then
            secrets_without_rotation+=("$name")
        fi
    done < <(echo "$secrets" | jq -c '.[]' 2>/dev/null)
    
    local secrets_count
    secrets_count=$(echo "$secrets" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ "$secrets_count" -eq 0 ]]; then
        log_info "4.5-F: No Secrets Manager secrets found"
        ((activity_pass++))
    elif [[ ${#secrets_without_rotation[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "4.5-F" \
            "${#secrets_without_rotation[@]} secrets without rotation: ${secrets_without_rotation[*]:0:3}..." \
            "Configure automatic rotation for secrets"
    else
        log_pass "4.5-F: All $secrets_count secrets have rotation enabled"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 4.5 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 4.6.1 - DLP Enforcement Points
# See docs/checks/4.6-dlp-enforcement.md for detailed documentation
# =============================================================================

check_4_6_dlp_enforcement() {
    log_info "Checking Activity 4.6.1 - DLP Enforcement Points..."
    log_info "  Note: Full DLP requires external tooling. Checking AWS-native controls."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 4.6-A: S3 Account-Level Public Access Block
    ((activity_total++))
    local account_block
    account_block=$(aws_cmd s3control get-public-access-block \
        --account-id "$(aws_cmd sts get-caller-identity --query 'Account' --output text 2>/dev/null)" \
        --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
    
    local block_all=true
    for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
        local value
        value=$(echo "$account_block" | jq -r ".$setting" 2>/dev/null || echo "false")
        if [[ "$value" != "true" ]]; then
            block_all=false
            break
        fi
    done
    
    if [[ "$block_all" == "true" ]]; then
        log_pass "4.6-A: S3 account-level public access block enabled (all settings)"
        ((activity_pass++))
    else
        log_finding "HIGH" "4.6-A" \
            "S3 account-level public access block not fully enabled" \
            "Enable all settings: aws s3control put-public-access-block --account-id ACCOUNT"
    fi
    
    # Check 4.6-B: S3 Bucket-Level Public Access (Compliance buckets)
    ((activity_total++))
    local buckets
    buckets=$(aws_cmd s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")
    
    local public_compliance_buckets=()
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        
        if bucket_has_compliance_tag "$bucket"; then
            local bucket_block
            bucket_block=$(aws_cmd s3api get-public-access-block --bucket "$bucket" \
                --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null || echo "{}")
            
            local is_blocked=true
            for setting in BlockPublicAcls IgnorePublicAcls BlockPublicPolicy RestrictPublicBuckets; do
                local value
                value=$(echo "$bucket_block" | jq -r ".$setting" 2>/dev/null || echo "false")
                if [[ "$value" != "true" ]]; then
                    is_blocked=false
                    break
                fi
            done
            
            if [[ "$is_blocked" == "false" ]]; then
                public_compliance_buckets+=("$bucket")
            fi
        fi
    done
    
    if [[ ${#public_compliance_buckets[@]} -gt 0 ]]; then
        log_finding "BLOCKER" "4.6-B" \
            "Compliance buckets without full public access block: ${public_compliance_buckets[*]}" \
            "Enable public access block on compliance-tagged buckets immediately"
    else
        if [[ "$S3_BUCKETS_COMPLIANT_TAGGED" -gt 0 ]]; then
            log_pass "4.6-B: All $S3_BUCKETS_COMPLIANT_TAGGED compliance-tagged buckets block public access"
        else
            log_info "4.6-B: No compliance-tagged buckets to check"
        fi
        ((activity_pass++))
    fi
    
    # Check 4.6-C: S3 Object Lock (Compliance buckets)
    ((activity_total++))
    local compliance_buckets_without_lock=()
    
    for bucket in $buckets; do
        [[ -z "$bucket" ]] && continue
        
        if bucket_has_compliance_tag "$bucket"; then
            local object_lock
            object_lock=$(aws_cmd s3api get-object-lock-configuration --bucket "$bucket" \
                --query 'ObjectLockConfiguration.ObjectLockEnabled' --output text 2>/dev/null || echo "")
            
            if [[ "$object_lock" != "Enabled" ]]; then
                compliance_buckets_without_lock+=("$bucket")
            fi
        fi
    done
    
    if [[ ${#compliance_buckets_without_lock[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "4.6-C" \
            "Compliance buckets without Object Lock: ${compliance_buckets_without_lock[*]}" \
            "Consider Object Lock for immutable compliance data (requires new bucket)"
    else
        if [[ "$S3_BUCKETS_COMPLIANT_TAGGED" -gt 0 ]]; then
            log_pass "4.6-C: All compliance-tagged buckets have Object Lock enabled"
        else
            log_info "4.6-C: No compliance-tagged buckets to check for Object Lock"
        fi
        ((activity_pass++))
    fi
    
    # Check 4.6-D: VPC Endpoints for S3 (Prevent Internet Egress)
    ((activity_total++))
    local s3_endpoints
    s3_endpoints=$(aws_cmd ec2 describe-vpc-endpoints \
        --filters "Name=service-name,Values=*s3*" "Name=vpc-endpoint-type,Values=Gateway" \
        --query 'VpcEndpoints | length(@)' --output text 2>/dev/null || echo "0")
    
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs --query 'Vpcs | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$vpcs" -eq 0 ]]; then
        log_info "4.6-D: No VPCs found"
        ((activity_pass++))
    elif [[ "$s3_endpoints" -gt 0 ]]; then
        log_pass "4.6-D: S3 VPC Gateway Endpoints configured ($s3_endpoints)"
        ((activity_pass++))
        log_info "  S3 traffic can stay within AWS network"
    else
        log_finding "MEDIUM" "4.6-D" \
            "No S3 VPC Gateway Endpoints configured" \
            "Create S3 Gateway Endpoint to keep S3 traffic off public internet"
    fi
    
    # Check 4.6-E: Macie Automated Discovery (DLP-like)
    ((activity_total++))
    if [[ "$MACIE_ENABLED" == "true" ]]; then
        local auto_discovery
        auto_discovery=$(aws_cmd macie2 get-automated-discovery-configuration \
            --query 'status' --output text 2>/dev/null || echo "")
        
        if [[ "$auto_discovery" == "ENABLED" ]]; then
            log_pass "4.6-E: Macie automated sensitive data discovery enabled"
            ((activity_pass++))
        else
            log_finding "MEDIUM" "4.6-E" \
                "Macie automated discovery not enabled" \
                "Enable for continuous DLP-like monitoring: aws macie2 update-automated-discovery-configuration"
        fi
    else
        log_info "4.6-E: Macie not enabled - automated discovery unavailable"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 4.6 Score: $activity_pass/$activity_total"
}
