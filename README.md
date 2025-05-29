# AWS Bedrock Security Configuration Checker

A comprehensive Python script to audit AWS Bedrock configurations against security best practices. This tool helps identify potential security misconfigurations and provides actionable recommendations for improving your Bedrock security posture.

## Features

The script checks for the following security best practices:

- **Model Access Policies**: Validates least privilege access controls on custom models
- **Data Encryption**: Checks encryption settings for models and logs
- **Logging & Monitoring**: Verifies CloudTrail and model invocation logging configurations
- **VPC Endpoints**: Checks for private connectivity via VPC endpoints
- **IAM Permissions**: Audits IAM policies for overly permissive Bedrock permissions
- **Resource Tagging**: Ensures proper tagging for governance and cost allocation
- **Model Invocation Logging**: Validates logging configuration for model invocations

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-bedrock-security-config-check.git
cd aws-bedrock-security-config-check
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run the security checker with default settings:
```bash
python bedrock_security_checker.py
```

### Advanced Options

```bash
# Use a specific AWS profile
python bedrock_security_checker.py --profile production

# Check a specific region
python bedrock_security_checker.py --region us-west-2

# Output in JSON format
python bedrock_security_checker.py --output json

# Save report to file
python bedrock_security_checker.py --output-file security-report.json --output json
```

### Command Line Arguments

- `--profile`: AWS profile name to use (optional)
- `--region`: AWS region to check (optional)
- `--output`: Output format - 'text' (default) or 'json'
- `--output-file`: Save report to specified file (optional)

## Security Checks Performed

### 1. Model Access Policies
- Verifies custom models are encrypted with customer-managed KMS keys
- Checks for proper access controls on models

### 2. Data Encryption
- Validates CloudWatch log groups containing Bedrock data are encrypted
- Checks for encryption at rest configurations

### 3. Logging & Monitoring
- Ensures CloudTrail is logging Bedrock API calls
- Verifies model invocation logging is configured
- Checks both CloudWatch and S3 logging destinations

### 4. VPC Endpoints
- Checks for VPC endpoints for both Bedrock and Bedrock Runtime services
- Ensures private connectivity is available

### 5. IAM Permissions
- Identifies overly permissive IAM policies with wildcard actions
- Flags sensitive actions allowed on all resources
- Promotes least privilege access

### 6. Resource Tagging
- Validates required tags on custom models
- Checks for governance tags: Environment, Owner, CostCenter, DataClassification

### 7. Model Invocation Logging
- Verifies logging configuration for model invocations
- Checks both CloudWatch and S3 logging destinations

## Output Formats

### Text Format (Default)
Provides a human-readable report with:
- Summary of findings by severity
- Detailed findings with recommendations
- Clear categorization of issues

### JSON Format
Structured output containing:
- Account and region information
- Scan timestamp
- Complete findings with metadata
- Severity categorization

## Exit Codes

The script uses different exit codes based on findings:
- `0`: No issues or only LOW severity findings
- `1`: MEDIUM severity findings detected
- `2`: HIGH severity findings detected
- `3`: Error during execution

## Required IAM Permissions

The script requires the following AWS permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:List*",
                "bedrock:Get*",
                "bedrock:Describe*",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "logs:DescribeLogGroups",
                "ec2:DescribeVpcEndpoints",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Example Output

```
================================================================================
AWS BEDROCK SECURITY CONFIGURATION REPORT
================================================================================
Account: 123456789012
Region: us-east-1
Scan Time: 2024-01-15 10:30:45 UTC
Total Findings: 5

Findings by Severity:
  HIGH:   2
  MEDIUM: 2
  LOW:    1

--------------------------------------------------------------------------------
DETAILED FINDINGS
--------------------------------------------------------------------------------

[HIGH SEVERITY]

1. Logging - Model Invocation Logging
   Issue: Model invocation logging is not configured
   Recommendation: Enable model invocation logging for audit and compliance

2. IAM - Policy: BedrockAdminPolicy
   Issue: Policy contains wildcard Bedrock permissions
   Recommendation: Use specific Bedrock actions instead of wildcards for least privilege

[MEDIUM SEVERITY]

1. Network Security - VPC Endpoints
   Issue: No VPC endpoint found for Bedrock Runtime service
   Recommendation: Create VPC endpoint for com.amazonaws.region.bedrock-runtime for private model invocations

[LOW SEVERITY]

1. Governance - Model: my-custom-model
   Issue: Missing required tags: Environment, CostCenter
   Recommendation: Add all required tags for proper resource governance and cost allocation

================================================================================
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.