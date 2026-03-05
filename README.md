# AWS ZIG Phase One Checker (Bash)

NSA Zero Trust Implementation Guideline Phase One compliance checker for AWS GovCloud.

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
└── README.md
```

## Pillars & Activities

| Pillar | Activities | Status |
|--------|------------|--------|
| 1. User | 1.3.1, 1.4.1, 1.5.1, 1.7.1 | 🚧 |
| 2. Device | 2.1.2, 2.4.1, 2.5.1, 2.6.1, 2.6.2, 2.7.1 | 🚧 |
| 3. Application | 3.2.1, 3.2.2, 3.3.1, 3.3.2, 3.4.1, 3.4.3 | 🚧 |
| 4. Data | 4.2.1, 4.3.1, 4.4.3, 4.5.1, 4.6.1 | 🚧 |
| 5. Network | 5.1.2, 5.2.2, 5.3.1, 5.4.1 | 🚧 |
| 6. Automation | 6.1.2, 6.5.2, 6.6.2, 6.7.1 | 🚧 |
| 7. Visibility | 7.1.2, 7.2.1, 7.2.4, 7.3.1, 7.5.1 | 🚧 |

## Severity Levels

- `BLOCKER` - Critical security gap, fix immediately
- `HIGH` - Significant risk, address this sprint  
- `MEDIUM` - Should improve, plan remediation
- `LOW` - Enhancement opportunity
- `PASS` - Requirement met
