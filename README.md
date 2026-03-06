# AWS ZIG Phase One Checker (Bash)

> ⚠️ **IMPORTANT DISCLAIMER - NOT PRODUCTION READY**
>
> This tool is provided **for educational and evaluation purposes only**. It has **NOT** undergone formal AWS security review and should **NOT** be considered production-ready software.
>
> **Use at your own risk.** This code:
> - Has not been reviewed or approved by AWS Security
> - May contain bugs, security vulnerabilities, or incomplete implementations
> - Should not be used as the sole basis for compliance decisions
> - Is not officially supported or maintained by AWS
>
> If you choose to use this tool, you are responsible for validating its output and ensuring it meets your organization's security requirements. Always consult with qualified security professionals before making compliance decisions.

---

NSA Zero Trust Implementation Guideline compliance checker for AWS accounts.

## Quick Start

```bash
# Run all checks
./zig-checker.sh --profile govcloud --region us-gov-west-1

# Run specific pillar
./zig-checker.sh --profile govcloud --region us-gov-west-1 --pillar user

# JSON output
./zig-checker.sh --profile govcloud --region us-gov-west-1 --output json

# Debug mode
./zig-checker.sh --profile govcloud --region us-gov-west-1 --debug
```

## Requirements

- AWS CLI v2
- jq
- bash 4.0+

## Testing

```bash
# Run all tests
./test/test_runner.sh

# Run a specific test file
./test/test_runner.sh test/test_utils.sh
```

The test framework is pure bash with zero external dependencies.

---

### Permissions

Read-only access required:

<details>
<summary>IAM Policy (click to expand)</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ZIGCheckerReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "iam:GenerateCredentialReport",
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:ListAllMyBuckets",
        "kms:List*",
        "kms:Describe*",
        "kms:GetKeyRotationStatus",
        "cloudtrail:Describe*",
        "cloudtrail:GetTrailStatus",
        "config:Describe*",
        "guardduty:List*",
        "guardduty:Get*",
        "securityhub:Get*",
        "securityhub:Describe*",
        "ssm:Describe*",
        "ssm:List*",
        "inspector2:List*",
        "inspector2:BatchGetAccountStatus",
        "logs:Describe*",
        "wafv2:List*",
        "rds:Describe*",
        "eks:List*",
        "eks:Describe*",
        "ecr:Describe*",
        "ecr:GetRepositoryPolicy",
        "lambda:List*",
        "lambda:GetPolicy",
        "accessanalyzer:List*",
        "macie2:GetMacieSession",
        "detective:ListGraphs",
        "events:ListRules",
        "sns:ListTopics",
        "cloudwatch:DescribeAlarms",
        "apigateway:GET",
        "apigatewayv2:GetApis",
        "codepipeline:ListPipelines",
        "organizations:Describe*",
        "organizations:List*",
        "sso-admin:ListInstances",
        "s3control:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

---

## Project Structure

```
aws-zig-check/
├── zig-checker.sh           # Main entry point
├── lib/
│   ├── config.sh            # Configuration and constants
│   ├── utils.sh             # Utility functions (logging, aws wrapper)
│   └── pillars/
│       ├── 1_user.sh        # Pillar 1: User
│       ├── 2_device.sh      # Pillar 2: Device
│       ├── 3_application.sh # Pillar 3: Application
│       ├── 4_data.sh        # Pillar 4: Data
│       ├── 5_network.sh     # Pillar 5: Network
│       ├── 6_automation.sh  # Pillar 6: Automation
│       └── 7_visibility.sh  # Pillar 7: Visibility
├── test/
│   ├── test_runner.sh       # Test framework (pure bash)
│   ├── test_config.sh       # Config tests
│   ├── test_utils.sh        # Utility function tests
│   ├── test_user_pillar.sh  # User pillar unit tests
│   └── test_integration.sh  # Integration tests
├── docs/
│   └── checks/              # Detailed check documentation
└── README.md
```

## Pillars & Activities

| Pillar | Activities | Status |
|--------|------------|--------|
| 1. User | 1.3.1, 1.4.1, 1.5.1, 1.7.1, 1.8.1, 1.8 | ✅ |
| 2. Device | 2.1.2, 2.4.1, 2.5.1, 2.6.1, 2.6.2, 2.7.1 | ✅ |
| 3. Application | 3.2.1, 3.2.2, 3.3.1, 3.3.2, 3.4.1, 3.4.3 | ✅ |
| 4. Data | 4.2.1, 4.3.1, 4.4.3, 4.5.1, 4.6.1 | ✅ |
| 5. Network | 5.1.2, 5.2.2, 5.3.1, 5.4.1 | ✅ |
| 6. Automation | 6.1.2, 6.5.2, 6.6.2, 6.7.1 | ✅ |
| 7. Visibility | 7.1.2, 7.2.1, 7.2.4, 7.3.1, 7.5.1 | ✅ |

All 7 pillars have been implemented with automated checks. See `docs/checks/` for detailed documentation on each activity.

## Severity Levels

- `BLOCKER` - Critical security gap, fix immediately
- `HIGH` - Significant risk, address this sprint  
- `MEDIUM` - Should improve, plan remediation
- `LOW` - Enhancement opportunity
- `PASS` - Requirement met

---

## Security & Compliance Notice

### Limitations

This tool provides automated checks against a subset of NSA ZIG Phase One requirements. It does **not** provide:

- Complete coverage of all ZIG requirements (many require manual review or external tools)
- Validation of organizational policies, procedures, or governance
- Assessment of third-party integrations or external identity providers
- Network traffic analysis or behavioral monitoring
- Penetration testing or vulnerability assessment

### AWS Service Limitations

Some ZIG requirements cannot be fully validated through AWS APIs alone:

- Identity Provider (IdP) MFA enforcement requires IdP-side verification
- Device compliance requires integration with MDM/UEM solutions
- Full DLP capabilities may require third-party tools (e.g., CASB)
- Behavioral analytics may require additional SIEM/SOAR integration

### Recommendations

1. Use this tool as a **starting point** for ZIG compliance assessment, not as a definitive audit
2. Supplement automated checks with manual review and professional security assessment
3. Consult the [NSA Zero Trust Guidance](https://www.nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance/) for authoritative requirements
4. Engage qualified security professionals for production compliance validation

### No Warranty

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHORS AND CONTRIBUTORS ARE NOT LIABLE FOR ANY DAMAGES OR SECURITY INCIDENTS ARISING FROM THE USE OF THIS TOOL.
