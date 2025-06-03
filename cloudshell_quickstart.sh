#!/bin/bash

# AWS CloudShell Quick Setup Script for Bedrock Security Checker
# Run this script in AWS CloudShell to test the security checker

echo "🚀 AWS Bedrock Security Checker - CloudShell Setup"
echo "=================================================="
echo ""

# Function to create IAM user for local testing
create_iam_user() {
    USER_NAME="bedrock-security-checker-$(date +%s)"
    echo "📝 Creating IAM user: $USER_NAME"
    echo ""
    
    # Create user
    echo "Creating user..."
    aws iam create-user --user-name $USER_NAME > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        # Create access key
        echo "Generating access keys..."
        KEYS=$(aws iam create-access-key --user-name $USER_NAME --output json)
        ACCESS_KEY=$(echo $KEYS | jq -r '.AccessKey.AccessKeyId')
        SECRET_KEY=$(echo $KEYS | jq -r '.AccessKey.SecretAccessKey')
        
        # Create and attach policy
        echo "Attaching required permissions..."
        POLICY_DOC='{
            "Version": "2012-10-17",
            "Statement": [{
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
            }]
        }'
        
        # Create inline policy
        aws iam put-user-policy \
            --user-name $USER_NAME \
            --policy-name BedrockCheckerPolicy \
            --policy-document "$POLICY_DOC" > /dev/null 2>&1
        
        echo ""
        echo "✅ IAM user created successfully!"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "📋 Copy and run these commands on your LOCAL machine:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "export AWS_ACCESS_KEY_ID=\"$ACCESS_KEY\""
        echo "export AWS_SECRET_ACCESS_KEY=\"$SECRET_KEY\""
        echo "export AWS_DEFAULT_REGION=\"us-east-1\""
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "Then run: python3 bedrock_security_checker.py"
        echo ""
        echo "⚠️  IMPORTANT - Save these cleanup commands for when you're done:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "aws iam delete-user-policy --user-name $USER_NAME --policy-name BedrockCheckerPolicy"
        echo "aws iam delete-access-key --user-name $USER_NAME --access-key-id $ACCESS_KEY"
        echo "aws iam delete-user --user-name $USER_NAME"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    else
        echo "❌ Failed to create IAM user. Please check your permissions."
        echo "   You need IAM permissions to create users and policies."
    fi
}

# Function to test directly in CloudShell
test_in_cloudshell() {
    echo "📝 Setting up to test directly in CloudShell..."
    echo ""
    
    # Check if we're already in the repo
    if [ -f "bedrock_security_checker.py" ]; then
        echo "✅ Already in the repository directory"
        git pull 2>/dev/null || echo "  (Not a git repository or no updates available)"
    elif [ -d "aws-bedrock-security-config-check" ]; then
        echo "Found existing directory, updating..."
        cd aws-bedrock-security-config-check
        git pull 2>/dev/null || echo "  (Not a git repository or no updates available)"
    else
        echo "Please provide your GitHub repository URL:"
        echo "(Example: https://github.com/yourusername/aws-bedrock-security-config-check)"
        read -p "GitHub URL: " REPO_URL
        
        if [ -z "$REPO_URL" ]; then
            echo "❌ No URL provided. Exiting."
            return 1
        fi
        
        echo "Cloning repository..."
        git clone $REPO_URL aws-bedrock-security-config-check
        
        if [ $? -ne 0 ]; then
            echo "❌ Failed to clone repository. Please check the URL."
            return 1
        fi
        
        cd aws-bedrock-security-config-check
    fi
    
    # Install dependencies
    echo ""
    echo "Installing dependencies..."
    pip3 install -r requirements.txt --quiet
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ Setup complete! You can now run the security checker."
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Try these commands:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "# Run in beginner mode (default)"
        echo "python3 bedrock_security_checker.py"
        echo ""
        echo "# Run with technical details"
        echo "python3 bedrock_security_checker.py --expert"
        echo ""
        echo "# Learn what each check does"
        echo "python3 bedrock_security_checker.py --learn"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    else
        echo "❌ Failed to install dependencies"
    fi
}

# Function to show current region and verify Bedrock availability
check_bedrock_availability() {
    CURRENT_REGION=$(aws configure get region || echo $AWS_DEFAULT_REGION)
    echo "📍 Current AWS Region: $CURRENT_REGION"
    
    # List of regions where Bedrock is available
    BEDROCK_REGIONS=("us-east-1" "us-west-2" "ap-southeast-1" "ap-northeast-1" "eu-central-1" "eu-west-1")
    
    if [[ " ${BEDROCK_REGIONS[@]} " =~ " ${CURRENT_REGION} " ]]; then
        echo "✅ Bedrock is available in this region"
    else
        echo "⚠️  Bedrock might not be available in $CURRENT_REGION"
        echo "   Available regions: ${BEDROCK_REGIONS[*]}"
        echo "   You may want to use --region flag when running the checker"
    fi
    echo ""
}

# Main menu
clear
echo "🚀 AWS Bedrock Security Checker - CloudShell Setup"
echo "=================================================="
echo ""
check_bedrock_availability
echo "Choose an option:"
echo ""
echo "1) Create IAM user for local testing"
echo "   - Generates access keys to use on your local machine"
echo "   - Best for testing on your own computer"
echo ""
echo "2) Test directly in CloudShell" 
echo "   - Runs the security checker right here in CloudShell"
echo "   - Quickest way to see results"
echo ""
read -p "Enter your choice (1-2): " choice

case $choice in
    1)
        create_iam_user
        ;;
    2)
        test_in_cloudshell
        ;;
    *)
        echo "Invalid choice. Please run the script again."
        ;;
esac