# AWS Bedrock Security Configuration Checker
## Enhanced with GenAI-Specific Security Features 🚀

A comprehensive security auditing tool for AWS Bedrock that combines traditional cloud security best practices with cutting-edge GenAI security capabilities. Perfect for organizations adopting generative AI while maintaining enterprise security standards.

## 🎯 Key Features for GenAI Security

### GenAI-Specific Security Checks
- **🛡️ Prompt Injection Detection**: Identifies vulnerabilities to prompt manipulation attacks
- **🔒 Data Privacy Compliance**: Detects PII exposure risks in model interactions
- **🧪 Model Poisoning Detection**: Monitors for signs of compromised training data
- **💰 Cost Anomaly Detection**: Alerts on unusual usage patterns indicating potential abuse
- **🎛️ Guardrail Validation**: Ensures content filtering and safety measures are in place

### User-Friendly Design
- **Beginner Mode** (default): Plain English explanations, actionable fixes
- **Expert Mode**: Technical details for security professionals
- **Learning Mode**: Educational content about each security check

## 🔐 Prerequisites & Setup

### AWS Authentication Setup

This tool requires AWS credentials to access your Bedrock resources. 

#### Quick Setup via AWS Console

1. **Create IAM User**
   - Go to [AWS IAM Console](https://console.aws.amazon.com/iam/)
   - Click "Users" → "Create user"
   - Name it `bedrock-security-checker`
   - Select "Programmatic access"

2. **Set Permissions**
   - Choose "Attach existing policies directly"
   - Either use "PowerUserAccess" OR create a custom policy with:

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
                "s3:GetBucketEncryption",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

3. **Save Credentials**
   - Download CSV or copy Access Key ID and Secret Access Key
   - ⚠️ You won't see the secret key again!

#### Configure Your Local Machine

**Option 1: AWS CLI (Recommended)**
```bash
aws configure
# Enter your Access Key ID
# Enter your Secret Access Key
# Enter default region: us-east-1
# Enter default output: json
```

**Option 2: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-access-key-here"
export AWS_SECRET_ACCESS_KEY="your-secret-key-here"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option 3: AWS Profile**
```bash
# Add to ~/.aws/credentials
[bedrock-checker]
aws_access_key_id = your-access-key
aws_secret_access_key = your-secret-key

# Use with: python bedrock_security_checker.py --profile bedrock-checker
```

### AWS CloudShell Setup (Alternative)

If you prefer using AWS CloudShell:

```bash
# In CloudShell, clone the repo
git clone https://github.com/yourusername/aws-bedrock-security-config-check.git
cd aws-bedrock-security-config-check

# Run the setup script
chmod +x cloudshell_quickstart.sh
./cloudshell_quickstart.sh
```

The script offers two options:
1. **Create IAM user** - Generates credentials for local testing
2. **Run in CloudShell** - Test directly in the browser

### Supported AWS Regions

Bedrock is available in:
- US East (N. Virginia) - `us-east-1`
- US West (Oregon) - `us-west-2`
- Asia Pacific (Singapore) - `ap-southeast-1`
- Asia Pacific (Tokyo) - `ap-northeast-1`
- Europe (Frankfurt) - `eu-central-1`
- Europe (Ireland) - `eu-west-1`

### Security Best Practices

- 🔒 Never commit AWS credentials to git
- 🔑 Use IAM roles when on AWS infrastructure
- 📋 Apply least privilege permissions
- 🔄 Rotate access keys every 90 days
- 🛡️ Enable MFA on your AWS account

## 🚀 Quick Start

### Installation

**Option 1: Install from PyPI (Recommended)**
```bash
pip install bedrock-security-checker

# Run directly from command line
bedrock-security-checker
```

**Option 2: Install from Source**
```bash
git clone https://github.com/ethantroy/aws-bedrock-security-config-check.git
cd aws-bedrock-security-config-check
pip install -e .

# Or manually install dependencies
pip install -r requirements.txt
python bedrock_security_checker.py
```

### Usage

```bash
# Run in beginner mode (default)
bedrock-security-checker

# Expert mode with technical details
bedrock-security-checker --expert

# Learning mode - understand the security checks
bedrock-security-checker --learn

# Output as JSON for CI/CD integration
bedrock-security-checker --output json

# Use specific AWS profile
bedrock-security-checker --profile production

# Check specific region
bedrock-security-checker --region us-west-2
```

## 📊 Example Output (Beginner Mode)

```
🔍 AWS Bedrock Security Check - Beginner Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Good News: 3 security best practices are properly configured
🛑 Critical: 1 high-risk issue needs immediate attention
⚠️  Attention Needed: 2 medium-risk issues found

🛑 CRITICAL ISSUES:
─────────────────────────
1. Policy allows unrestricted access to ALL Bedrock operations
   📍 Where: IAM Policy: BedrockAdminPolicy
   💡 Risk Score: 9/10
   
   What this means: This is like giving someone admin access to all your AI models
   
   To fix this, run:
   > aws iam create-policy-version --policy-arn arn:aws:iam::123456789012:policy/BedrockAdminPolicy --policy-document file://restricted-policy.json --set-as-default
```

## 🔒 Security Checks Performed

### Traditional Security
- ✅ IAM permission auditing
- ✅ Encryption validation
- ✅ Network security (VPC endpoints)
- ✅ Audit logging configuration
- ✅ Resource tagging compliance

### GenAI-Specific Security
- 🤖 Prompt injection vulnerability assessment
- 🔍 PII detection in model configurations
- 🛡️ Model access pattern analysis
- 📊 Usage anomaly detection setup
- 🚨 Real-time threat monitoring

## 🏗️ Architecture

The tool is designed with modularity and extensibility in mind:

```
bedrock_security_checker.py
├── Security Checks
│   ├── Traditional AWS Security
│   └── GenAI-Specific Security
├── Reporting Modes
│   ├── Beginner (default)
│   ├── Expert
│   └── Learning
└── Output Formats
    ├── Human-readable text
    └── JSON for automation
```

## 🔧 DevSecOps Integration

### CI/CD Pipeline Example

```yaml
# .github/workflows/bedrock-security.yml
name: Bedrock Security Audit
on: [push, pull_request]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Run Bedrock Security Audit
        run: |
          pip install -r requirements.txt
          python bedrock_security_checker.py --output json > security-report.json
          
          # Fail the build if critical issues found
          if [ $? -eq 2 ]; then
            echo "Critical security issues detected!"
            cat security-report.json
            exit 1
          fi
```

## 📈 Risk Scoring System

The tool uses a simple 1-10 risk scoring system:

- **9-10**: Critical - Immediate action required
- **7-8**: High - Address within 24 hours
- **4-6**: Medium - Plan remediation
- **1-3**: Low - Best practice improvements

## 🛡️ GenAI Threat Model Coverage

Based on OWASP Top 10 for LLMs and MITRE ATLAS:

| Threat Category | Coverage | Detection Method |
|----------------|----------|------------------|
| Prompt Injection | ✅ | Pattern matching & guardrail checks |
| Data Poisoning | ✅ | Training source validation |
| Model Theft | ✅ | Access pattern analysis |
| PII Leakage | ✅ | Content scanning |
| Denial of Service | ✅ | Cost & rate monitoring |
| Supply Chain | ⚠️ | Basic model source verification |

## 🎓 Learning Mode

To understand the security concepts and checks performed:

```bash
python bedrock_security_checker.py --learn
```

This explains:
- Prompt injection detection techniques
- PII pattern recognition
- Model access control principles
- Audit logging importance
- Network security for AI
- Cost monitoring for abuse detection

## 🤝 Contributing

We welcome contributions! Areas of interest:
- Additional GenAI attack patterns
- Integration with more AWS services
- Support for other cloud providers
- Enhanced remediation automation

## 📋 Required IAM Permissions

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
                "s3:GetBucketEncryption",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🏆 Why This Tool Stands Out

1. **Dual Focus**: Combines traditional cloud security with GenAI-specific risks
2. **Accessibility**: Beginner-friendly without sacrificing technical depth
3. **Actionable**: Provides exact commands to fix issues
4. **Educational**: Learning mode helps teams understand GenAI security
5. **Automated**: JSON output enables CI/CD integration
6. **Comprehensive**: Covers the full spectrum of Bedrock security concerns

## 🔧 Troubleshooting

### Common Issues

#### "Unable to locate credentials"
```bash
# Check if AWS CLI is configured
aws configure list

# If not configured, run:
aws configure
```

#### "You must specify a region"
```bash
# Set default region
export AWS_DEFAULT_REGION=us-east-1

# Or specify in command
python bedrock_security_checker.py --region us-east-1
```

#### "Access Denied" errors
Ensure your IAM user/role has the required permissions listed in the IAM Permissions section above.

#### Testing without AWS Account
While the main security checker requires AWS credentials, you can:
1. Use the learning mode to understand security concepts: `python bedrock_security_checker.py --learn`
2. Review the documentation in this README
3. Use the tool with read-only IAM credentials to explore safely

## 📄 License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the [LICENSE](LICENSE) file for details.

---

**Built with 🧪👽 by ET for the GenAI security community**