#!/usr/bin/env bash
# Pillar 5: Network and Environment
# Activities: 5.1.2, 5.2.2, 5.3.1, 5.4.1

# Global tracking
CURRENT_ACCOUNT_ID=""
VPC_COUNT=0
VPCS_WITH_FLOW_LOGS=0

check_pillar_5_network() {
    pillar_header 5 "NETWORK AND ENVIRONMENT"
    
    # Get current account for RAM-shared resource detection
    CURRENT_ACCOUNT_ID=$(aws_cmd sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "")
    
    local pass_count=0
    local total_checks=0
    
    check_5_1_granular_access
    check_5_2_sdn_infrastructure
    check_5_3_macro_segmentation
    check_5_4_micro_segmentation
    
    pillar_score "Network" "$pass_count" "$total_checks"
}

# Helper: Check if resource is RAM-shared (owned by different account)
get_resource_owner_note() {
    local owner_id="$1"
    if [[ -n "$owner_id" && "$owner_id" != "$CURRENT_ACCOUNT_ID" && "$owner_id" != "None" ]]; then
        echo " (RAM-shared from $owner_id)"
    else
        echo ""
    fi
}

# =============================================================================
# Activity 5.1.2 - Granular Control Access Rules
# See docs/checks/5.1-granular-access.md for detailed documentation
# =============================================================================

check_5_1_granular_access() {
    log_info "Checking Activity 5.1.2 - Granular Control Access Rules..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 5.1-A: WAF WebACLs Configured
    ((activity_total++))
    local waf_acls
    waf_acls=$(aws_cmd wafv2 list-web-acls --scope REGIONAL \
        --query 'WebACLs | length(@)' --output text 2>/dev/null || echo "0")
    
    local waf_cloudfront
    waf_cloudfront=$(aws_cmd wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 \
        --query 'WebACLs | length(@)' --output text 2>/dev/null || echo "0")
    
    local total_waf=$((waf_acls + waf_cloudfront))
    
    if [[ "$total_waf" -gt 0 ]]; then
        log_pass "5.1-A: WAF WebACLs configured ($waf_acls regional, $waf_cloudfront CloudFront)"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "5.1-A" \
            "No WAF WebACLs configured" \
            "Consider WAF for API/web application protection"
    fi
    
    # Check 5.1-B: Route 53 Resolver DNS Firewall
    ((activity_total++))
    local dns_firewall_groups
    dns_firewall_groups=$(aws_cmd route53resolver list-firewall-rule-groups \
        --query 'FirewallRuleGroups | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$dns_firewall_groups" -gt 0 ]]; then
        log_pass "5.1-B: Route 53 DNS Firewall configured ($dns_firewall_groups rule groups)"
        ((activity_pass++))
    else
        log_info "5.1-B: No Route 53 DNS Firewall rule groups (optional)"
        ((activity_pass++))
    fi
    
    # Check 5.1-C: VPC Endpoints (PrivateLink) for AWS Services
    ((activity_total++))
    local vpc_endpoints
    vpc_endpoints=$(aws_cmd ec2 describe-vpc-endpoints \
        --query 'VpcEndpoints | length(@)' --output text 2>/dev/null || echo "0")
    
    local interface_endpoints
    interface_endpoints=$(aws_cmd ec2 describe-vpc-endpoints \
        --filters "Name=vpc-endpoint-type,Values=Interface" \
        --query 'VpcEndpoints | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$vpc_endpoints" -gt 0 ]]; then
        log_pass "5.1-C: VPC Endpoints configured ($vpc_endpoints total, $interface_endpoints PrivateLink)"
        ((activity_pass++))
        log_info "  AWS service traffic can stay off public internet"
    else
        log_finding "LOW" "5.1-C" \
            "No VPC Endpoints configured" \
            "Consider VPC Endpoints for AWS service access without internet"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 5.1 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 5.2.2 - SDN Programmable Infrastructure
# See docs/checks/5.2-sdn-infrastructure.md for detailed documentation
# =============================================================================

check_5_2_sdn_infrastructure() {
    log_info "Checking Activity 5.2.2 - SDN Infrastructure..."
    log_info "  Note: AWS provides SDN abstractions. Checking network architecture."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 5.2-A: Multiple VPCs (Network Segmentation)
    ((activity_total++))
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs --query 'Vpcs[].[VpcId,OwnerId]' --output json 2>/dev/null || echo "[]")
    
    VPC_COUNT=$(echo "$vpcs" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ "$VPC_COUNT" -gt 1 ]]; then
        log_pass "5.2-A: Multiple VPCs configured ($VPC_COUNT) - network segmentation in place"
        ((activity_pass++))
        
        # Note any shared VPCs
        local shared_count=0
        while read -r vpc_info; do
            local owner
            owner=$(echo "$vpc_info" | jq -r '.[1]' 2>/dev/null)
            if [[ "$owner" != "$CURRENT_ACCOUNT_ID" && -n "$owner" ]]; then
                ((shared_count++)) || true
            fi
        done < <(echo "$vpcs" | jq -c '.[]' 2>/dev/null)
        
        if [[ "$shared_count" -gt 0 ]]; then
            log_info "  $shared_count VPC(s) are RAM-shared from other accounts"
        fi
    elif [[ "$VPC_COUNT" -eq 1 ]]; then
        log_info "5.2-A: Single VPC architecture (segmentation via subnets/SGs)"
        ((activity_pass++))
    else
        log_info "5.2-A: No VPCs found"
        ((activity_pass++))
    fi
    
    # Check 5.2-B: Transit Gateway (Centralized Routing)
    ((activity_total++))
    local tgws
    tgws=$(aws_cmd ec2 describe-transit-gateways \
        --query 'TransitGateways[?State==`available`].[TransitGatewayId,OwnerId]' \
        --output json 2>/dev/null || echo "[]")
    
    local tgw_count
    tgw_count=$(echo "$tgws" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ "$tgw_count" -gt 0 ]]; then
        local owned_tgw=0
        local shared_tgw=0
        
        while read -r tgw_info; do
            local owner
            owner=$(echo "$tgw_info" | jq -r '.[1]' 2>/dev/null)
            if [[ "$owner" == "$CURRENT_ACCOUNT_ID" ]]; then
                ((owned_tgw++)) || true
            else
                ((shared_tgw++)) || true
            fi
        done < <(echo "$tgws" | jq -c '.[]' 2>/dev/null)
        
        log_pass "5.2-B: Transit Gateway available ($owned_tgw owned, $shared_tgw shared)"
        ((activity_pass++))
        log_info "  Centralized network routing in place"
    else
        log_info "5.2-B: No Transit Gateway (using VPC peering or single-VPC)"
        ((activity_pass++))
    fi
    
    # Check 5.2-C: VPC Peering Connections
    ((activity_total++))
    local peering
    peering=$(aws_cmd ec2 describe-vpc-peering-connections \
        --filters "Name=status-code,Values=active" \
        --query 'VpcPeeringConnections | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$peering" -gt 0 ]]; then
        log_pass "5.2-C: VPC Peering configured ($peering active connections)"
        ((activity_pass++))
    else
        if [[ "$VPC_COUNT" -gt 1 ]]; then
            log_info "5.2-C: No VPC peering (may use Transit Gateway or isolated VPCs)"
        else
            log_info "5.2-C: No VPC peering (single-VPC architecture)"
        fi
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 5.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 5.3.1 - Datacenter Macro-Segmentation
# See docs/checks/5.3-macro-segmentation.md for detailed documentation
# =============================================================================

check_5_3_macro_segmentation() {
    log_info "Checking Activity 5.3.1 - Datacenter Macro-Segmentation..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 5.3-A: Public/Private Subnet Separation
    ((activity_total++))
    local vpcs
    vpcs=$(aws_cmd ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text 2>/dev/null || echo "")
    
    local vpcs_with_separation=0
    local vpcs_without_separation=()
    
    for vpc_id in $vpcs; do
        [[ -z "$vpc_id" ]] && continue
        
        # Check for subnets with and without public IP auto-assign (proxy for public/private)
        local public_subnets
        public_subnets=$(aws_cmd ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query 'Subnets[?MapPublicIpOnLaunch==`true`] | length(@)' --output text 2>/dev/null || echo "0")
        
        local private_subnets
        private_subnets=$(aws_cmd ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
            --query 'Subnets[?MapPublicIpOnLaunch==`false`] | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$public_subnets" -gt 0 && "$private_subnets" -gt 0 ]]; then
            ((vpcs_with_separation++)) || true
        elif [[ "$public_subnets" -gt 0 || "$private_subnets" -gt 0 ]]; then
            # Has subnets but no separation
            vpcs_without_separation+=("$vpc_id")
        fi
    done
    
    if [[ "$vpcs_with_separation" -gt 0 ]]; then
        log_pass "5.3-A: $vpcs_with_separation VPC(s) have public/private subnet separation"
        ((activity_pass++))
    elif [[ ${#vpcs_without_separation[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "5.3-A" \
            "VPCs without public/private separation: ${vpcs_without_separation[*]}" \
            "Implement public/private subnet tiers for macro-segmentation"
    else
        log_info "5.3-A: No VPCs with subnets to check"
        ((activity_pass++))
    fi
    
    # Check 5.3-B: NAT Gateway for Private Subnet Egress
    ((activity_total++))
    local nat_gateways
    nat_gateways=$(aws_cmd ec2 describe-nat-gateways \
        --filter "Name=state,Values=available" \
        --query 'NatGateways | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$nat_gateways" -gt 0 ]]; then
        log_pass "5.3-B: NAT Gateway(s) configured ($nat_gateways) for private subnet egress"
        ((activity_pass++))
    else
        # Check if there are private subnets that might need NAT
        local total_private
        total_private=$(aws_cmd ec2 describe-subnets \
            --query 'Subnets[?MapPublicIpOnLaunch==`false`] | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$total_private" -gt 0 ]]; then
            log_finding "LOW" "5.3-B" \
                "No NAT Gateway but $total_private private subnets exist" \
                "Consider NAT Gateway for controlled egress from private subnets"
        else
            log_info "5.3-B: No NAT Gateway (no private subnets or air-gapped)"
            ((activity_pass++))
        fi
    fi
    
    # Check 5.3-C: VPC Flow Logs Enabled
    ((activity_total++))
    local vpcs_without_flowlogs=()
    VPCS_WITH_FLOW_LOGS=0
    
    for vpc_id in $vpcs; do
        [[ -z "$vpc_id" ]] && continue
        
        local vpc_owner
        vpc_owner=$(aws_cmd ec2 describe-vpcs --vpc-ids "$vpc_id" \
            --query 'Vpcs[0].OwnerId' --output text 2>/dev/null || echo "")
        
        local owner_note
        owner_note=$(get_resource_owner_note "$vpc_owner")
        
        local flow_log
        flow_log=$(aws_cmd ec2 describe-flow-logs \
            --filter "Name=resource-id,Values=$vpc_id" \
            --query 'FlowLogs[0].FlowLogId' --output text 2>/dev/null || echo "")
        
        if [[ -n "$flow_log" && "$flow_log" != "None" ]]; then
            ((VPCS_WITH_FLOW_LOGS++)) || true
        else
            vpcs_without_flowlogs+=("${vpc_id}${owner_note}")
        fi
    done
    
    if [[ ${#vpcs_without_flowlogs[@]} -gt 0 ]]; then
        log_finding "HIGH" "5.3-C" \
            "VPCs without flow logs: ${vpcs_without_flowlogs[*]}" \
            "Enable VPC Flow Logs for network traffic visibility"
    else
        if [[ "$VPC_COUNT" -gt 0 ]]; then
            log_pass "5.3-C: All $VPC_COUNT VPCs have flow logs enabled"
        else
            log_info "5.3-C: No VPCs to check"
        fi
        ((activity_pass++))
    fi
    
    # Check 5.3-D: AWS Network Firewall
    ((activity_total++))
    local network_firewalls
    network_firewalls=$(aws_cmd network-firewall list-firewalls \
        --query 'Firewalls | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$network_firewalls" -gt 0 ]]; then
        log_pass "5.3-D: AWS Network Firewall deployed ($network_firewalls)"
        ((activity_pass++))
        
        # Check for stateful rules
        local firewall_policies
        firewall_policies=$(aws_cmd network-firewall list-firewall-policies \
            --query 'FirewallPolicies | length(@)' --output text 2>/dev/null || echo "0")
        log_info "  $firewall_policies firewall policies configured"
    else
        log_info "5.3-D: No AWS Network Firewall (may use security groups/NACLs only)"
        ((activity_pass++))
    fi
    
    # Check 5.3-E: Internet Gateway Placement
    ((activity_total++))
    local igws
    igws=$(aws_cmd ec2 describe-internet-gateways \
        --query 'InternetGateways[].[InternetGatewayId,Attachments[0].VpcId]' \
        --output json 2>/dev/null || echo "[]")
    
    local igw_count
    igw_count=$(echo "$igws" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ "$igw_count" -gt 0 ]]; then
        log_pass "5.3-E: $igw_count Internet Gateway(s) attached to VPCs"
        ((activity_pass++))
        log_info "  Ensure IGW routes only in public subnets"
    else
        log_info "5.3-E: No Internet Gateways (private-only or air-gapped network)"
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 5.3 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 5.4.1 - Micro-Segmentation
# See docs/checks/5.4-micro-segmentation.md for detailed documentation
# =============================================================================

check_5_4_micro_segmentation() {
    log_info "Checking Activity 5.4.1 - Micro-Segmentation..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 5.4-A: Security Groups - Unrestricted SSH/RDP
    ((activity_total++))
    local risky_sgs=()
    local all_sgs
    all_sgs=$(aws_cmd ec2 describe-security-groups \
        --query 'SecurityGroups[].[GroupId,GroupName,OwnerId]' --output json 2>/dev/null || echo "[]")
    
    while read -r sg_info; do
        [[ -z "$sg_info" ]] && continue
        local sg_id sg_name owner_id
        sg_id=$(echo "$sg_info" | jq -r '.[0]')
        sg_name=$(echo "$sg_info" | jq -r '.[1]')
        owner_id=$(echo "$sg_info" | jq -r '.[2]')
        
        local owner_note
        owner_note=$(get_resource_owner_note "$owner_id")
        
        # Check for 0.0.0.0/0 on SSH (22) or RDP (3389)
        local open_ssh
        open_ssh=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
            --query "SecurityGroups[0].IpPermissions[?FromPort==\`22\` && contains(IpRanges[].CidrIp, '0.0.0.0/0')] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        local open_rdp
        open_rdp=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
            --query "SecurityGroups[0].IpPermissions[?FromPort==\`3389\` && contains(IpRanges[].CidrIp, '0.0.0.0/0')] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$open_ssh" -gt 0 || "$open_rdp" -gt 0 ]]; then
            risky_sgs+=("${sg_name}(${sg_id})${owner_note}")
        fi
    done < <(echo "$all_sgs" | jq -c '.[]' 2>/dev/null)
    
    if [[ ${#risky_sgs[@]} -gt 0 ]]; then
        log_finding "HIGH" "5.4-A" \
            "Security groups with 0.0.0.0/0 SSH/RDP: ${risky_sgs[*]}" \
            "Restrict SSH/RDP to specific IPs or use SSM Session Manager"
    else
        log_pass "5.4-A: No security groups with unrestricted SSH/RDP"
        ((activity_pass++))
    fi
    
    # Check 5.4-B: Security Groups - Unrestricted Egress
    ((activity_total++))
    local unrestricted_egress=()
    
    while read -r sg_info; do
        [[ -z "$sg_info" ]] && continue
        local sg_id sg_name owner_id
        sg_id=$(echo "$sg_info" | jq -r '.[0]')
        sg_name=$(echo "$sg_info" | jq -r '.[1]')
        owner_id=$(echo "$sg_info" | jq -r '.[2]')
        
        # Skip default SGs (they have default egress)
        [[ "$sg_name" == "default" ]] && continue
        
        local owner_note
        owner_note=$(get_resource_owner_note "$owner_id")
        
        # Check for 0.0.0.0/0 egress on all ports
        local open_egress
        open_egress=$(aws_cmd ec2 describe-security-groups --group-ids "$sg_id" \
            --query "SecurityGroups[0].IpPermissionsEgress[?IpProtocol=='-1' && contains(IpRanges[].CidrIp, '0.0.0.0/0')] | length(@)" \
            --output text 2>/dev/null || echo "0")
        
        if [[ "$open_egress" -gt 0 ]]; then
            unrestricted_egress+=("${sg_name}${owner_note}")
        fi
    done < <(echo "$all_sgs" | jq -c '.[]' 2>/dev/null)
    
    local sg_count
    sg_count=$(echo "$all_sgs" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ ${#unrestricted_egress[@]} -gt 0 ]]; then
        # This is common, so LOW severity
        log_finding "LOW" "5.4-B" \
            "${#unrestricted_egress[@]} of $sg_count security groups have unrestricted egress" \
            "Consider restricting egress to required destinations only"
    else
        log_pass "5.4-B: All security groups have restricted egress"
        ((activity_pass++))
    fi
    
    # Check 5.4-C: RDS in Private Subnets
    ((activity_total++))
    local public_rds=()
    local rds_instances
    rds_instances=$(aws_cmd rds describe-db-instances \
        --query 'DBInstances[].[DBInstanceIdentifier,PubliclyAccessible]' \
        --output json 2>/dev/null || echo "[]")
    
    while read -r rds_info; do
        [[ -z "$rds_info" ]] && continue
        local db_id publicly_accessible
        db_id=$(echo "$rds_info" | jq -r '.[0]')
        publicly_accessible=$(echo "$rds_info" | jq -r '.[1]')
        
        if [[ "$publicly_accessible" == "true" ]]; then
            public_rds+=("$db_id")
        fi
    done < <(echo "$rds_instances" | jq -c '.[]' 2>/dev/null)
    
    local rds_count
    rds_count=$(echo "$rds_instances" | jq 'length' 2>/dev/null || echo "0")
    
    if [[ ${#public_rds[@]} -gt 0 ]]; then
        log_finding "HIGH" "5.4-C" \
            "Publicly accessible RDS instances: ${public_rds[*]}" \
            "Move RDS to private subnets and disable public accessibility"
    else
        if [[ "$rds_count" -gt 0 ]]; then
            log_pass "5.4-C: All $rds_count RDS instances are in private subnets"
        else
            log_info "5.4-C: No RDS instances found"
        fi
        ((activity_pass++))
    fi
    
    # Check 5.4-D: EKS Cluster Endpoint Access
    ((activity_total++))
    local public_eks=()
    local eks_clusters
    eks_clusters=$(aws_cmd eks list-clusters --query 'clusters' --output text 2>/dev/null || echo "")
    
    local eks_count=0
    for cluster in $eks_clusters; do
        [[ -z "$cluster" ]] && continue
        ((eks_count++)) || true
        
        local public_access
        public_access=$(aws_cmd eks describe-cluster --name "$cluster" \
            --query 'cluster.resourcesVpcConfig.endpointPublicAccess' --output text 2>/dev/null || echo "")
        
        local private_access
        private_access=$(aws_cmd eks describe-cluster --name "$cluster" \
            --query 'cluster.resourcesVpcConfig.endpointPrivateAccess' --output text 2>/dev/null || echo "")
        
        # Flag if public-only (no private access)
        if [[ "$public_access" == "True" && "$private_access" != "True" ]]; then
            public_eks+=("$cluster")
        fi
    done
    
    if [[ ${#public_eks[@]} -gt 0 ]]; then
        log_finding "MEDIUM" "5.4-D" \
            "EKS clusters with public-only endpoint: ${public_eks[*]}" \
            "Enable private endpoint access for EKS clusters"
    else
        if [[ "$eks_count" -gt 0 ]]; then
            log_pass "5.4-D: All $eks_count EKS clusters have private endpoint access"
        else
            log_info "5.4-D: No EKS clusters found"
        fi
        ((activity_pass++))
    fi
    
    # Check 5.4-E: Elasticsearch/OpenSearch in VPC
    ((activity_total++))
    local public_es=()
    local es_domains
    es_domains=$(aws_cmd opensearch list-domain-names \
        --query 'DomainNames[].DomainName' --output text 2>/dev/null || echo "")
    
    local es_count=0
    for domain in $es_domains; do
        [[ -z "$domain" ]] && continue
        ((es_count++)) || true
        
        local vpc_options
        vpc_options=$(aws_cmd opensearch describe-domain --domain-name "$domain" \
            --query 'DomainStatus.VPCOptions.VPCId' --output text 2>/dev/null || echo "")
        
        if [[ -z "$vpc_options" || "$vpc_options" == "None" ]]; then
            public_es+=("$domain")
        fi
    done
    
    if [[ ${#public_es[@]} -gt 0 ]]; then
        log_finding "HIGH" "5.4-E" \
            "OpenSearch domains not in VPC: ${public_es[*]}" \
            "Deploy OpenSearch in VPC for network isolation"
    else
        if [[ "$es_count" -gt 0 ]]; then
            log_pass "5.4-E: All $es_count OpenSearch domains are in VPC"
        else
            log_info "5.4-E: No OpenSearch domains found"
        fi
        ((activity_pass++))
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 5.4 Score: $activity_pass/$activity_total"
}
