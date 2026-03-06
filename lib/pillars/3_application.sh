#!/usr/bin/env bash
# Pillar 3: Application and Workload
# Activities: 3.2.1, 3.2.2, 3.3.1, 3.3.2, 3.4.1, 3.4.3

# Global vars for cross-check data sharing
CODEPIPELINE_COUNT=0
CODEBUILD_PROJECTS=()
ECR_REPOS_WITH_SCANNING=0
ECR_REPOS_TOTAL=0
INSPECTOR_ENABLED=false

check_pillar_3_application() {
    pillar_header 3 "APPLICATION AND WORKLOAD"
    
    local pass_count=0
    local total_checks=0
    
    check_3_2_devsecops
    check_3_3_software_risk
    check_3_4_resource_authorization
    
    pillar_score "Application" "$pass_count" "$total_checks"
}

# =============================================================================
# Activity 3.2.1/3.2.2 - DevSecOps Software Factory
# See docs/checks/3.2-devsecops.md for detailed documentation
# =============================================================================

check_3_2_devsecops() {
    log_info "Checking Activity 3.2.1/3.2.2 - DevSecOps Software Factory..."
    log_info "  Note: Full DevSecOps requires CI/CD tooling. Checking AWS-native services."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 3.2-A: CodePipeline Exists
    ((activity_total++))
    local pipelines
    pipelines=$(aws_cmd codepipeline list-pipelines --query 'pipelines[].name' --output text 2>/dev/null || echo "")
    
    CODEPIPELINE_COUNT=0
    for _ in $pipelines; do
        ((CODEPIPELINE_COUNT++)) || true
    done
    
    if [[ "$CODEPIPELINE_COUNT" -gt 0 ]]; then
        log_pass "3.2-A: CodePipeline configured ($CODEPIPELINE_COUNT pipeline(s))"
        ((activity_pass++))
        log_info "  Pipelines: $pipelines"
    else
        log_finding "MEDIUM" "3.2-A" \
            "No CodePipeline pipelines found" \
            "Implement CI/CD pipelines for automated software delivery"
    fi
    
    # Check 3.2-B: CodeBuild Projects with Security Scanning
    ((activity_total++))
    local codebuild_projects
    codebuild_projects=$(aws_cmd codebuild list-projects --query 'projects' --output text 2>/dev/null || echo "")
    
    CODEBUILD_PROJECTS=()
    local projects_with_privileged=0
    
    for project in $codebuild_projects; do
        [[ -z "$project" ]] && continue
        CODEBUILD_PROJECTS+=("$project")
        
        # Check if project has privileged mode (needed for Docker builds)
        local privileged
        privileged=$(aws_cmd codebuild batch-get-projects --names "$project" \
            --query 'projects[0].environment.privilegedMode' --output text 2>/dev/null || echo "false")
        
        if [[ "$privileged" == "True" || "$privileged" == "true" ]]; then
            ((projects_with_privileged++)) || true
        fi
    done
    
    if [[ ${#CODEBUILD_PROJECTS[@]} -gt 0 ]]; then
        log_pass "3.2-B: CodeBuild configured (${#CODEBUILD_PROJECTS[@]} project(s))"
        ((activity_pass++))
        if [[ "$projects_with_privileged" -gt 0 ]]; then
            log_info "  $projects_with_privileged project(s) with privileged mode (Docker builds)"
        fi
    else
        log_finding "MEDIUM" "3.2-B" \
            "No CodeBuild projects found" \
            "Use CodeBuild for automated builds with security scanning"
    fi
    
    # Check 3.2-C: ECR Image Scanning Enabled
    ((activity_total++))
    local ecr_repos
    ecr_repos=$(aws_cmd ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null || echo "")
    
    ECR_REPOS_TOTAL=0
    ECR_REPOS_WITH_SCANNING=0
    local repos_without_scanning=()
    
    for repo in $ecr_repos; do
        [[ -z "$repo" ]] && continue
        ((ECR_REPOS_TOTAL++)) || true
        
        local scan_config
        scan_config=$(aws_cmd ecr describe-repositories --repository-names "$repo" \
            --query 'repositories[0].imageScanningConfiguration.scanOnPush' --output text 2>/dev/null || echo "false")
        
        if [[ "$scan_config" == "True" || "$scan_config" == "true" ]]; then
            ((ECR_REPOS_WITH_SCANNING++)) || true
        else
            repos_without_scanning+=("$repo")
        fi
    done
    
    if [[ "$ECR_REPOS_TOTAL" -eq 0 ]]; then
        log_info "3.2-C: No ECR repositories found (may use external registry)"
        ((activity_pass++))
    elif [[ ${#repos_without_scanning[@]} -eq 0 ]]; then
        log_pass "3.2-C: All $ECR_REPOS_TOTAL ECR repos have scan-on-push enabled"
        ((activity_pass++))
    else
        log_finding "HIGH" "3.2-C" \
            "ECR repos without scan-on-push: ${repos_without_scanning[*]}" \
            "Enable scanning: aws ecr put-image-scanning-configuration --repository-name REPO --image-scanning-configuration scanOnPush=true"
    fi
    
    # Check 3.2-D: CodeBuild Reports (SAST/DAST integration)
    ((activity_total++))
    local report_groups
    report_groups=$(aws_cmd codebuild list-report-groups --query 'reportGroups | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$report_groups" -gt 0 ]]; then
        log_pass "3.2-D: CodeBuild report groups configured ($report_groups)"
        ((activity_pass++))
        log_info "  Security test results can be tracked via reports"
    else
        if [[ ${#CODEBUILD_PROJECTS[@]} -gt 0 ]]; then
            log_finding "LOW" "3.2-D" \
                "No CodeBuild report groups configured" \
                "Configure report groups for SAST/DAST/test result tracking"
        else
            log_info "3.2-D: No CodeBuild projects - report groups N/A"
            ((activity_pass++))
        fi
    fi
    
    # Check 3.2-E: CodeArtifact for Approved Dependencies
    ((activity_total++))
    local codeartifact_domains
    codeartifact_domains=$(aws_cmd codeartifact list-domains --query 'domains | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$codeartifact_domains" -gt 0 ]]; then
        log_pass "3.2-E: CodeArtifact configured for dependency management"
        ((activity_pass++))
        
        local repos_count
        repos_count=$(aws_cmd codeartifact list-repositories --query 'repositories | length(@)' --output text 2>/dev/null || echo "0")
        log_info "  $codeartifact_domains domain(s), $repos_count repository(ies)"
    else
        log_finding "LOW" "3.2-E" \
            "CodeArtifact not configured" \
            "Consider CodeArtifact for approved package/dependency management"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 3.2 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 3.3.1/3.3.2 - Software Risk Management
# See docs/checks/3.3-software-risk.md for detailed documentation
# =============================================================================

check_3_3_software_risk() {
    log_info "Checking Activity 3.3.1/3.3.2 - Software Risk Management..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 3.3-A: Inspector Enabled (Vulnerability Management)
    ((activity_total++))
    local inspector_status
    inspector_status=$(aws_cmd inspector2 batch-get-account-status \
        --query 'accounts[0].state.status' --output text 2>/dev/null || echo "")
    
    if [[ "$inspector_status" == "ENABLED" ]]; then
        log_pass "3.3-A: Amazon Inspector enabled for vulnerability scanning"
        ((activity_pass++))
        INSPECTOR_ENABLED=true
        
        # Get coverage info
        local ecr_coverage
        ecr_coverage=$(aws_cmd inspector2 batch-get-account-status \
            --query 'accounts[0].resourceState.ecr.status' --output text 2>/dev/null || echo "")
        log_info "  ECR container scanning: $ecr_coverage"
    else
        log_finding "HIGH" "3.3-A" \
            "Amazon Inspector not enabled" \
            "Enable Inspector for vulnerability management: aws inspector2 enable --resource-types EC2 ECR LAMBDA"
        INSPECTOR_ENABLED=false
    fi
    
    # Check 3.3-B: Inspector ECR Findings (Container Vulnerabilities)
    ((activity_total++))
    if [[ "$INSPECTOR_ENABLED" == "true" ]]; then
        local ecr_critical
        ecr_critical=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}], "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        local ecr_high
        ecr_high=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}], "severity": [{"comparison": "EQUALS", "value": "HIGH"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$ecr_critical" -gt 0 ]]; then
            log_finding "BLOCKER" "3.3-B" \
                "$ecr_critical CRITICAL container image vulnerabilities" \
                "Review and remediate container vulnerabilities immediately"
        elif [[ "$ecr_high" -gt 0 ]]; then
            log_finding "HIGH" "3.3-B" \
                "$ecr_high HIGH container image vulnerabilities" \
                "Review and remediate high severity container findings"
        else
            log_pass "3.3-B: No CRITICAL/HIGH container vulnerabilities"
            ((activity_pass++))
        fi
    else
        log_info "3.3-B: Inspector not enabled - cannot check container findings"
        ((activity_pass++))
    fi
    
    # Check 3.3-C: ECR Lifecycle Policies (Approved Binaries Management)
    ((activity_total++))
    if [[ "$ECR_REPOS_TOTAL" -gt 0 ]]; then
        local repos_with_lifecycle=0
        local ecr_repos
        ecr_repos=$(aws_cmd ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null || echo "")
        
        for repo in $ecr_repos; do
            [[ -z "$repo" ]] && continue
            local lifecycle
            lifecycle=$(aws_cmd ecr get-lifecycle-policy --repository-name "$repo" \
                --query 'lifecyclePolicyText' --output text 2>/dev/null || echo "")
            
            if [[ -n "$lifecycle" && "$lifecycle" != "None" ]]; then
                ((repos_with_lifecycle++)) || true
            fi
        done
        
        if [[ "$repos_with_lifecycle" -eq "$ECR_REPOS_TOTAL" ]]; then
            log_pass "3.3-C: All ECR repos have lifecycle policies"
            ((activity_pass++))
        elif [[ "$repos_with_lifecycle" -gt 0 ]]; then
            log_finding "LOW" "3.3-C" \
                "$repos_with_lifecycle of $ECR_REPOS_TOTAL ECR repos have lifecycle policies" \
                "Add lifecycle policies to manage image retention"
        else
            log_finding "MEDIUM" "3.3-C" \
                "No ECR repos have lifecycle policies" \
                "Configure lifecycle policies for image retention management"
        fi
    else
        log_info "3.3-C: No ECR repos - lifecycle policies N/A"
        ((activity_pass++))
    fi
    
    # Check 3.3-D: Lambda Function Vulnerabilities
    ((activity_total++))
    if [[ "$INSPECTOR_ENABLED" == "true" ]]; then
        local lambda_critical
        lambda_critical=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"resourceType": [{"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}], "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        local lambda_high
        lambda_high=$(aws_cmd inspector2 list-findings \
            --filter-criteria '{"resourceType": [{"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}], "severity": [{"comparison": "EQUALS", "value": "HIGH"}]}' \
            --query 'findings | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$lambda_critical" -gt 0 ]]; then
            log_finding "BLOCKER" "3.3-D" \
                "$lambda_critical CRITICAL Lambda function vulnerabilities" \
                "Update Lambda function dependencies immediately"
        elif [[ "$lambda_high" -gt 0 ]]; then
            log_finding "HIGH" "3.3-D" \
                "$lambda_high HIGH Lambda function vulnerabilities" \
                "Review and update Lambda function dependencies"
        else
            log_pass "3.3-D: No CRITICAL/HIGH Lambda vulnerabilities"
            ((activity_pass++))
        fi
    else
        log_info "3.3-D: Inspector not enabled - cannot check Lambda findings"
        ((activity_pass++))
    fi
    
    # Check 3.3-E: SBOM Generation Capability (Inspector SBOM Export)
    ((activity_total++))
    if [[ "$INSPECTOR_ENABLED" == "true" ]]; then
        # Check if SBOM export is available (Inspector v2 feature)
        local sbom_formats
        sbom_formats=$(aws_cmd inspector2 list-coverage \
            --query 'coveredResources[0].resourceType' --output text 2>/dev/null || echo "")
        
        if [[ -n "$sbom_formats" && "$sbom_formats" != "None" ]]; then
            log_pass "3.3-E: Inspector SBOM generation available"
            ((activity_pass++))
            log_info "  Use: aws inspector2 create-sbom-export for SBOM generation"
        else
            log_info "3.3-E: Inspector coverage data not available"
            ((activity_pass++))
        fi
    else
        log_finding "MEDIUM" "3.3-E" \
            "Inspector not enabled - SBOM generation unavailable" \
            "Enable Inspector for SBOM generation capability"
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 3.3 Score: $activity_pass/$activity_total"
}

# =============================================================================
# Activity 3.4.1/3.4.3 - Resource Authorization
# See docs/checks/3.4-resource-authorization.md for detailed documentation
# =============================================================================

check_3_4_resource_authorization() {
    log_info "Checking Activity 3.4.1/3.4.3 - Resource Authorization..."
    
    local activity_pass=0
    local activity_total=0
    
    # Check 3.4-A: API Gateway with Authorization
    ((activity_total++))
    local rest_apis
    rest_apis=$(aws_cmd apigateway get-rest-apis --query 'items[].id' --output text 2>/dev/null || echo "")
    
    local apis_without_auth=()
    local api_count=0
    
    for api_id in $rest_apis; do
        [[ -z "$api_id" ]] && continue
        ((api_count++)) || true
        
        # Check if API has any authorizers
        local authorizers
        authorizers=$(aws_cmd apigateway get-authorizers --rest-api-id "$api_id" \
            --query 'items | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$authorizers" -eq 0 ]]; then
            local api_name
            api_name=$(aws_cmd apigateway get-rest-api --rest-api-id "$api_id" \
                --query 'name' --output text 2>/dev/null || echo "$api_id")
            apis_without_auth+=("$api_name")
        fi
    done
    
    # Also check HTTP APIs (API Gateway v2)
    local http_apis
    http_apis=$(aws_cmd apigatewayv2 get-apis --query 'Items[].ApiId' --output text 2>/dev/null || echo "")
    
    for api_id in $http_apis; do
        [[ -z "$api_id" ]] && continue
        ((api_count++)) || true
        
        local authorizers
        authorizers=$(aws_cmd apigatewayv2 get-authorizers --api-id "$api_id" \
            --query 'Items | length(@)' --output text 2>/dev/null || echo "0")
        
        if [[ "$authorizers" -eq 0 ]]; then
            local api_name
            api_name=$(aws_cmd apigatewayv2 get-api --api-id "$api_id" \
                --query 'Name' --output text 2>/dev/null || echo "$api_id")
            apis_without_auth+=("$api_name(v2)")
        fi
    done
    
    if [[ "$api_count" -eq 0 ]]; then
        log_info "3.4-A: No API Gateway APIs found"
        ((activity_pass++))
    elif [[ ${#apis_without_auth[@]} -eq 0 ]]; then
        log_pass "3.4-A: All $api_count API Gateway APIs have authorizers"
        ((activity_pass++))
    else
        log_finding "HIGH" "3.4-A" \
            "APIs without authorizers: ${apis_without_auth[*]}" \
            "Configure Lambda authorizers, Cognito, or IAM authorization"
    fi
    
    # Check 3.4-B: ALB with Authentication
    ((activity_total++))
    local albs
    albs=$(aws_cmd elbv2 describe-load-balancers \
        --query 'LoadBalancers[?Type==`application`].LoadBalancerArn' --output text 2>/dev/null || echo "")
    
    local albs_without_auth=()
    local alb_count=0
    
    for alb_arn in $albs; do
        [[ -z "$alb_arn" ]] && continue
        ((alb_count++)) || true
        
        # Check listeners for authenticate-cognito or authenticate-oidc actions
        local listeners
        listeners=$(aws_cmd elbv2 describe-listeners --load-balancer-arn "$alb_arn" \
            --query 'Listeners[].ListenerArn' --output text 2>/dev/null || echo "")
        
        local has_auth=false
        for listener_arn in $listeners; do
            [[ -z "$listener_arn" ]] && continue
            
            local auth_actions
            auth_actions=$(aws_cmd elbv2 describe-rules --listener-arn "$listener_arn" \
                --query "Rules[].Actions[?Type=='authenticate-cognito' || Type=='authenticate-oidc'] | length(@)" \
                --output text 2>/dev/null || echo "0")
            
            if [[ "$auth_actions" -gt 0 ]]; then
                has_auth=true
                break
            fi
        done
        
        if [[ "$has_auth" == "false" ]]; then
            local alb_name
            alb_name=$(basename "$alb_arn" | cut -d'/' -f2)
            albs_without_auth+=("$alb_name")
        fi
    done
    
    if [[ "$alb_count" -eq 0 ]]; then
        log_info "3.4-B: No Application Load Balancers found"
        ((activity_pass++))
    elif [[ ${#albs_without_auth[@]} -eq 0 ]]; then
        log_pass "3.4-B: All $alb_count ALBs have authentication configured"
        ((activity_pass++))
    else
        log_finding "MEDIUM" "3.4-B" \
            "ALBs without authentication: ${albs_without_auth[*]}" \
            "Consider ALB authentication with Cognito or OIDC for external apps"
    fi
    
    # Check 3.4-C: Lambda Functions with Resource-Based Policies
    ((activity_total++))
    local lambda_functions
    lambda_functions=$(aws_cmd lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null || echo "")
    
    local public_lambdas=()
    local lambda_count=0
    
    for func_name in $lambda_functions; do
        [[ -z "$func_name" ]] && continue
        ((lambda_count++)) || true
        
        # Check for overly permissive resource policies
        local policy
        policy=$(aws_cmd lambda get-policy --function-name "$func_name" \
            --query 'Policy' --output text 2>/dev/null || echo "")
        
        if [[ -n "$policy" && "$policy" != "None" ]]; then
            # Check for Principal: "*" without conditions
            if echo "$policy" | grep -q '"Principal"[[:space:]]*:[[:space:]]*"\*"'; then
                if ! echo "$policy" | grep -q '"Condition"'; then
                    public_lambdas+=("$func_name")
                fi
            fi
        fi
    done
    
    if [[ "$lambda_count" -eq 0 ]]; then
        log_info "3.4-C: No Lambda functions found"
        ((activity_pass++))
    elif [[ ${#public_lambdas[@]} -eq 0 ]]; then
        log_pass "3.4-C: No Lambda functions with unrestricted public access"
        ((activity_pass++))
    else
        log_finding "HIGH" "3.4-C" \
            "Lambda functions with Principal:* (no conditions): ${public_lambdas[*]}" \
            "Add conditions to Lambda resource policies or use API Gateway"
    fi
    
    # Check 3.4-D: EKS Clusters with OIDC Provider (for IRSA)
    ((activity_total++))
    local eks_clusters
    eks_clusters=$(aws_cmd eks list-clusters --query 'clusters' --output text 2>/dev/null || echo "")
    
    local clusters_without_oidc=()
    local eks_count=0
    
    for cluster in $eks_clusters; do
        [[ -z "$cluster" ]] && continue
        ((eks_count++)) || true
        
        local oidc_issuer
        oidc_issuer=$(aws_cmd eks describe-cluster --name "$cluster" \
            --query 'cluster.identity.oidc.issuer' --output text 2>/dev/null || echo "")
        
        if [[ -z "$oidc_issuer" || "$oidc_issuer" == "None" ]]; then
            clusters_without_oidc+=("$cluster")
        fi
    done
    
    if [[ "$eks_count" -eq 0 ]]; then
        log_info "3.4-D: No EKS clusters found"
        ((activity_pass++))
    elif [[ ${#clusters_without_oidc[@]} -eq 0 ]]; then
        log_pass "3.4-D: All $eks_count EKS clusters have OIDC provider"
        ((activity_pass++))
        log_info "  IAM Roles for Service Accounts (IRSA) available"
    else
        log_finding "MEDIUM" "3.4-D" \
            "EKS clusters without OIDC provider: ${clusters_without_oidc[*]}" \
            "Enable OIDC provider for IAM Roles for Service Accounts (IRSA)"
    fi
    
    # Check 3.4-E: CloudFormation StackSets (IaC/SDC)
    ((activity_total++))
    local stacksets
    stacksets=$(aws_cmd cloudformation list-stack-sets \
        --query 'Summaries[?Status==`ACTIVE`] | length(@)' --output text 2>/dev/null || echo "0")
    
    local stacks
    stacks=$(aws_cmd cloudformation list-stacks \
        --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
        --query 'StackSummaries | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$stacksets" -gt 0 || "$stacks" -gt 0 ]]; then
        log_pass "3.4-E: Infrastructure as Code in use ($stacks stacks, $stacksets stacksets)"
        ((activity_pass++))
        log_info "  SDC approach: CloudFormation manages infrastructure"
    else
        log_finding "LOW" "3.4-E" \
            "No CloudFormation stacks/stacksets found" \
            "Consider IaC (CloudFormation/Terraform) for SDC approach"
    fi
    
    # Check 3.4-F: Service Control Policies (Organization-level)
    ((activity_total++))
    local scp_count
    scp_count=$(aws_cmd organizations list-policies --filter SERVICE_CONTROL_POLICY \
        --query 'Policies | length(@)' --output text 2>/dev/null || echo "0")
    
    if [[ "$scp_count" -gt 0 ]]; then
        log_pass "3.4-F: Service Control Policies configured ($scp_count SCPs)"
        ((activity_pass++))
        log_info "  Organization-level resource authorization in place"
    else
        # Check if this is an org account
        local org_id
        org_id=$(aws_cmd organizations describe-organization \
            --query 'Organization.Id' --output text 2>/dev/null || echo "")
        
        if [[ -n "$org_id" && "$org_id" != "None" ]]; then
            log_finding "MEDIUM" "3.4-F" \
                "AWS Organization exists but no custom SCPs" \
                "Consider SCPs for organization-wide resource authorization"
        else
            log_info "3.4-F: Not an AWS Organization - SCPs N/A"
            ((activity_pass++))
        fi
    fi
    
    ((pass_count += activity_pass)) || true
    ((total_checks += activity_total)) || true
    log_info "Activity 3.4 Score: $activity_pass/$activity_total"
}
