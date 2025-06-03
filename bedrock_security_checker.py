#!/usr/bin/env python3
"""
AWS Bedrock Security Configuration Checker
Enhanced with GenAI-specific security checks and beginner-friendly features

Copyright (C) 2024  Ethan Troy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Description: This script audits AWS Bedrock configurations for security 
best practices, with a focus on GenAI-specific risks and user-friendly 
reporting.
"""

import boto3
import json
import argparse
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
import sys
from enum import Enum
import os
from collections import defaultdict


class SecurityMode(Enum):
    BEGINNER = "beginner"
    EXPERT = "expert"
    LEARN = "learn"


class RiskLevel(Enum):
    CRITICAL = (9, "🛑", "CRITICAL")
    HIGH = (8, "🔴", "HIGH")
    MEDIUM = (6, "⚠️", "MEDIUM")
    LOW = (3, "🟡", "LOW")
    INFO = (1, "ℹ️", "INFO")
    
    def __init__(self, score, emoji, label):
        self.score = score
        self.emoji = emoji
        self.label = label


class BedrockSecurityChecker:
    """Enhanced AWS Bedrock Security Checker with GenAI focus."""
    
    # Common PII patterns for data privacy checks
    PII_PATTERNS = {
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'Phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    }
    
    # Common prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        "ignore previous instructions",
        "disregard all prior commands",
        "system prompt",
        "reveal your instructions",
        "what are your rules",
        "bypass security",
        "jailbreak",
        "DAN mode",
        "developer mode"
    ]
    
    def __init__(self, profile_name: str = None, region: str = None, mode: SecurityMode = SecurityMode.BEGINNER, demo: bool = False):
        """Initialize the enhanced security checker."""
        self.mode = mode
        self.demo = demo
        
        if demo:
            # Demo mode - no AWS credentials needed
            self.region = region or 'us-east-1'
            self.account_id = '123456789012'
            print(f"🎭 Running in DEMO mode - no AWS credentials required")
            print(f"   This shows simulated security findings for demonstration purposes\n")
        else:
            session_params = {}
            if profile_name:
                session_params['profile_name'] = profile_name
            if region:
                session_params['region_name'] = region
                
            try:
                self.session = boto3.Session(**session_params)
                self.bedrock = self.session.client('bedrock')
                self.bedrock_runtime = self.session.client('bedrock-runtime')
                self.iam = self.session.client('iam')
                self.cloudtrail = self.session.client('cloudtrail')
                self.cloudwatch = self.session.client('logs')
                self.ec2 = self.session.client('ec2')
                self.s3 = self.session.client('s3')
                
                self.region = self.session.region_name
                self.account_id = self.session.client('sts').get_caller_identity()['Account']
            except Exception as e:
                print(f"❌ Error initializing AWS session: {str(e)}")
                print("\n💡 Tip: Make sure you have AWS credentials configured.")
                print("   Run 'aws configure' or set AWS_PROFILE environment variable.")
                print("   Or use --demo flag to see a demonstration without AWS credentials.")
                sys.exit(3)
        
        self.findings = []
        self.good_practices = []
        self.available_models = []
        
    def add_finding(self, risk_level: RiskLevel, category: str, resource: str, 
                   issue: str, recommendation: str, fix_command: str = None,
                   learn_more: str = None, technical_details: str = None):
        """Add an enhanced security finding with risk scores and remediation."""
        finding = {
            'risk_level': risk_level,
            'risk_score': risk_level.score,
            'category': category,
            'resource': resource,
            'issue': issue,
            'recommendation': recommendation,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if fix_command:
            finding['fix_command'] = fix_command
        if learn_more:
            finding['learn_more'] = learn_more
        if technical_details and self.mode == SecurityMode.EXPERT:
            finding['technical_details'] = technical_details
            
        self.findings.append(finding)
    
    def add_good_practice(self, category: str, practice: str):
        """Track properly configured security practices."""
        self.good_practices.append({
            'category': category,
            'practice': practice
        })
    
    def check_prompt_injection_vulnerabilities(self) -> List[Dict]:
        """Check for prompt injection vulnerabilities in model configurations."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Prompt Injection Check")
            print("This check tests if your AI models are vulnerable to prompt injection attacks.")
            print("Prompt injection is when an attacker tries to override your model's instructions.")
            return []
            
        print("🔍 Checking for prompt injection vulnerabilities...")
        
        try:
            # List available models
            foundation_models = self.bedrock.list_foundation_models()
            
            # Check if any models are accessible without proper guardrails
            accessible_models = []
            for model in foundation_models.get('modelSummaries', []):
                model_id = model.get('modelId', '')
                if 'claude' in model_id.lower() or 'titan' in model_id.lower():
                    accessible_models.append(model_id)
                    self.available_models.append(model_id)
            
            if accessible_models:
                # Check for guardrails
                try:
                    # Note: Guardrails API might need specific permissions
                    guardrails = self.bedrock.list_guardrails()
                    if not guardrails.get('guardrails'):
                        self.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="GenAI Security",
                            resource="Model Guardrails",
                            issue="No guardrails configured to prevent prompt injection",
                            recommendation="Set up AWS Bedrock Guardrails to filter harmful prompts",
                            fix_command="aws bedrock create-guardrail --name 'SecurityGuardrail' --topic-policy-config file://guardrail-config.json",
                            learn_more="Guardrails help prevent prompt injection, jailbreaking, and harmful content generation",
                            technical_details="Without guardrails, models are vulnerable to prompt injection attacks that could bypass safety measures"
                        )
                    else:
                        self.add_good_practice("GenAI Security", "Guardrails are configured for prompt filtering")
                except:
                    # Guardrails might not be available in all regions
                    pass
                    
        except Exception as e:
            print(f"⚠️  Note: Could not complete prompt injection check: {str(e)}")
            
        return self.findings
    
    def check_data_privacy_compliance(self) -> List[Dict]:
        """Check for potential PII exposure in model configurations and logs."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Data Privacy Check")
            print("This check looks for potential Personal Identifiable Information (PII) exposure.")
            print("PII includes SSNs, emails, credit cards, etc. that could be logged or stored.")
            return []
            
        print("🔍 Checking data privacy compliance...")
        
        try:
            # Check if model invocation logs might contain PII
            logging_config = self.bedrock.get_model_invocation_logging_configuration()
            
            if logging_config.get('loggingConfig'):
                config = logging_config['loggingConfig']
                
                # Check if logs are encrypted
                s3_config = config.get('s3Config', {})
                if s3_config.get('bucketName'):
                    bucket_name = s3_config['bucketName']
                    
                    # Check bucket encryption
                    try:
                        encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                        self.add_good_practice("Data Privacy", f"S3 bucket {bucket_name} is encrypted for log storage")
                    except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                        self.add_finding(
                            risk_level=RiskLevel.HIGH,
                            category="Data Privacy",
                            resource=f"S3 Bucket: {bucket_name}",
                            issue="Model invocation logs stored in unencrypted S3 bucket",
                            recommendation="Enable encryption on the S3 bucket storing sensitive logs",
                            fix_command=f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration file://encryption-config.json",
                            learn_more="Unencrypted logs may expose sensitive user data or PII",
                            technical_details="S3 bucket lacks SSE-S3 or SSE-KMS encryption"
                        )
                
                # Warn about PII in logs
                self.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Data Privacy",
                    resource="Model Invocation Logs",
                    issue="Model logs might contain PII from user prompts",
                    recommendation="Implement PII filtering before logging or use data masking",
                    learn_more="User prompts often contain names, addresses, or other sensitive data",
                    technical_details="Consider implementing a PII detection Lambda function in the logging pipeline"
                )
                
        except Exception as e:
            print(f"⚠️  Note: Could not complete data privacy check: {str(e)}")
            
        return self.findings
    
    def check_model_access_audit(self) -> List[Dict]:
        """Enhanced model access audit with beginner-friendly explanations."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Model Access Audit")
            print("This check ensures only authorized users can invoke your AI models.")
            print("Think of it like checking who has keys to your house.")
            return []
            
        print("🔍 Auditing model access permissions...")
        
        try:
            # Check custom models
            custom_models = self.bedrock.list_custom_models()
            
            if not custom_models.get('modelSummaries'):
                print("ℹ️  No custom models found. Checking IAM policies for foundation model access...")
            else:
                for model in custom_models.get('modelSummaries', []):
                    model_name = model['modelName']
                    model_arn = model['modelArn']
                    
                    # Check if model has proper access controls
                    try:
                        model_details = self.bedrock.get_custom_model(modelIdentifier=model_name)
                        
                        # Check for encryption
                        if 'modelKmsKeyId' not in model_details:
                            self.add_finding(
                                risk_level=RiskLevel.HIGH,
                                category="Model Security",
                                resource=f"Model: {model_name}",
                                issue="Custom model not encrypted with your own encryption key",
                                recommendation="Use your own KMS key for better control over model encryption",
                                fix_command="aws bedrock create-custom-model --model-name <name> --model-kms-key-id <your-kms-key>",
                                learn_more="Using your own encryption key ensures only you can access the model",
                                technical_details="Model uses default AWS managed key instead of customer managed KMS key"
                            )
                        else:
                            self.add_good_practice("Model Security", f"Model {model_name} uses customer-managed encryption")
                            
                    except Exception as e:
                        print(f"⚠️  Could not check model {model_name}: {str(e)}")
            
            # Check IAM policies for overly permissive access
            self._check_bedrock_iam_permissions()
            
        except Exception as e:
            print(f"⚠️  Note: Could not complete model access audit: {str(e)}")
            
        return self.findings
    
    def _check_bedrock_iam_permissions(self):
        """Check IAM permissions with focus on Bedrock access."""
        try:
            # Check for overly permissive policies
            policies = self.iam.list_policies(Scope='Local', MaxItems=100)
            
            dangerous_count = 0
            for policy in policies.get('Policies', []):
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                try:
                    policy_version = self.iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_doc = policy_version['PolicyVersion']['Document']
                    
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            # Check for dangerous Bedrock permissions
                            if any('bedrock:*' in action or action == '*' for action in actions):
                                dangerous_count += 1
                                self.add_finding(
                                    risk_level=RiskLevel.CRITICAL,
                                    category="Access Control",
                                    resource=f"IAM Policy: {policy_name}",
                                    issue="Policy allows unrestricted access to ALL Bedrock operations",
                                    recommendation="Limit permissions to only necessary Bedrock actions",
                                    fix_command=f"aws iam create-policy-version --policy-arn {policy_arn} --policy-document file://restricted-policy.json --set-as-default",
                                    learn_more="This is like giving someone admin access to all your AI models",
                                    technical_details=f"Policy contains wildcard action: {actions}"
                                )
                                
                except Exception as e:
                    continue
            
            if dangerous_count == 0:
                self.add_good_practice("Access Control", "No overly permissive Bedrock IAM policies found")
                
        except Exception as e:
            print(f"⚠️  Could not check IAM policies: {str(e)}")
    
    def check_cost_anomaly_detection(self) -> List[Dict]:
        """Check for cost monitoring to detect potential abuse."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Cost Anomaly Detection")
            print("This checks if you're monitoring AI usage costs to detect potential abuse.")
            print("Unexpected high costs might indicate someone is misusing your models.")
            return []
            
        print("🔍 Checking cost anomaly detection...")
        
        try:
            # This is a simplified check - in reality, you'd check AWS Cost Anomaly Detection
            self.add_finding(
                risk_level=RiskLevel.MEDIUM,
                category="Cost Security",
                resource="Bedrock Usage Monitoring",
                issue="No automated cost alerts for unusual Bedrock usage",
                recommendation="Set up AWS Cost Anomaly Detection for Bedrock services",
                fix_command="aws ce create-anomaly-monitor --anomaly-monitor Name=BedrockMonitor,MonitorType=CUSTOM,MonitorSpecification={Tags:{Key=Service,Values=[bedrock]}}",
                learn_more="Unusual spikes in AI usage costs might indicate security breaches",
                technical_details="Enable AWS Cost Anomaly Detection with Bedrock-specific monitors"
            )
            
        except Exception as e:
            print(f"⚠️  Could not check cost monitoring: {str(e)}")
            
        return self.findings
    
    def run_all_checks(self) -> List[Dict]:
        """Run all security checks based on the selected mode."""
        print(f"\n🚀 Starting AWS Bedrock Security Check ({self.mode.value} mode)")
        print(f"Account: {self.account_id} | Region: {self.region}")
        print("━" * 60)
        
        # Original checks (modified for beginner-friendliness)
        self.check_model_access_audit()
        self.check_logging_monitoring()
        self.check_vpc_endpoints()
        self.check_resource_tagging()
        
        # New GenAI-specific checks
        self.check_prompt_injection_vulnerabilities()
        self.check_data_privacy_compliance()
        self.check_cost_anomaly_detection()
        
        return self.findings
    
    def check_logging_monitoring(self) -> List[Dict]:
        """Enhanced logging check with beginner-friendly explanations."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Logging & Monitoring")
            print("This ensures you're keeping records of who uses your AI models and how.")
            print("It's like having security cameras for your AI systems.")
            return []
            
        print("🔍 Checking logging and monitoring configurations...")
        
        try:
            # Check model invocation logging
            logging_config = self.bedrock.get_model_invocation_logging_configuration()
            
            if not logging_config.get('loggingConfig'):
                self.add_finding(
                    risk_level=RiskLevel.HIGH,
                    category="Audit & Compliance",
                    resource="Model Invocation Logging",
                    issue="AI model usage is not being logged",
                    recommendation="Enable logging to track who uses your models and detect abuse",
                    fix_command="aws bedrock put-model-invocation-logging-configuration --logging-config file://logging-config.json",
                    learn_more="Without logs, you can't detect if someone is misusing your AI",
                    technical_details="Model invocation logging is completely disabled"
                )
            else:
                self.add_good_practice("Audit & Compliance", "Model invocation logging is enabled")
                
                # Check if both CloudWatch and S3 logging are enabled
                config = logging_config['loggingConfig']
                if not config.get('cloudWatchConfig', {}).get('logGroupName'):
                    self.add_finding(
                        risk_level=RiskLevel.MEDIUM,
                        category="Audit & Compliance",
                        resource="Real-time Monitoring",
                        issue="No real-time monitoring of AI model usage",
                        recommendation="Enable CloudWatch logging for immediate alerts",
                        learn_more="Real-time logs help you spot problems as they happen",
                        technical_details="CloudWatch logging not configured for model invocations"
                    )
                    
        except Exception as e:
            print(f"⚠️  Could not check logging configuration: {str(e)}")
            
        return self.findings
    
    def check_vpc_endpoints(self) -> List[Dict]:
        """Check VPC endpoints with simplified explanations."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Network Security")
            print("This checks if your AI traffic stays within AWS's private network.")
            print("It's like having a private tunnel instead of using public roads.")
            return []
            
        print("🔍 Checking network security configurations...")
        
        try:
            endpoints = self.ec2.describe_vpc_endpoints()
            
            bedrock_endpoint_found = False
            bedrock_runtime_endpoint_found = False
            
            for endpoint in endpoints.get('VpcEndpoints', []):
                service_name = endpoint.get('ServiceName', '')
                if 'bedrock' in service_name and 'runtime' not in service_name:
                    bedrock_endpoint_found = True
                elif 'bedrock-runtime' in service_name:
                    bedrock_runtime_endpoint_found = True
            
            if not bedrock_runtime_endpoint_found:
                self.add_finding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Network Security",
                    resource="Private Connectivity",
                    issue="AI model traffic goes over the public internet",
                    recommendation="Create a VPC endpoint for private, secure connections",
                    fix_command=f"aws ec2 create-vpc-endpoint --service-name com.amazonaws.{self.region}.bedrock-runtime --vpc-id <your-vpc-id>",
                    learn_more="Private connections prevent data interception and are faster",
                    technical_details="Missing VPC endpoint for bedrock-runtime service"
                )
            else:
                self.add_good_practice("Network Security", "Private VPC endpoints configured for secure AI traffic")
                
        except Exception as e:
            print(f"⚠️  Could not check VPC endpoints: {str(e)}")
            
        return self.findings
    
    def check_resource_tagging(self) -> List[Dict]:
        """Simplified resource tagging check."""
        if self.mode == SecurityMode.LEARN:
            print("\n📚 Learning Mode: Resource Organization")
            print("This checks if your AI resources are properly labeled.")
            print("Tags help you track costs and manage permissions by project or team.")
            return []
            
        print("🔍 Checking resource organization...")
        
        try:
            custom_models = self.bedrock.list_custom_models()
            
            if custom_models.get('modelSummaries'):
                for model in custom_models.get('modelSummaries', []):
                    model_name = model['modelName']
                    
                    try:
                        tags_response = self.bedrock.list_tags_for_resource(resourceARN=model['modelArn'])
                        existing_tags = [tag['key'] for tag in tags_response.get('tags', [])]
                        
                        important_tags = ['Environment', 'Owner', 'Project']
                        missing_tags = [tag for tag in important_tags if tag not in existing_tags]
                        
                        if missing_tags:
                            self.add_finding(
                                risk_level=RiskLevel.LOW,
                                category="Resource Management",
                                resource=f"Model: {model_name}",
                                issue=f"Missing organizational tags: {', '.join(missing_tags)}",
                                recommendation="Add tags to track ownership and costs",
                                fix_command=f"aws bedrock tag-resource --resource-arn {model['modelArn']} --tags Key=Environment,Value=Production",
                                learn_more="Tags help you identify who owns what and control costs"
                            )
                        else:
                            self.add_good_practice("Resource Management", f"Model {model_name} is properly tagged")
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"⚠️  Could not check resource tagging: {str(e)}")
            
        return self.findings
    
    def generate_report(self, output_format: str = 'text') -> str:
        """Generate a security report based on the mode."""
        if output_format == 'json':
            return self._generate_json_report()
        else:
            if self.mode == SecurityMode.BEGINNER:
                return self._generate_beginner_report()
            elif self.mode == SecurityMode.EXPERT:
                return self._generate_expert_report()
            else:  # LEARN mode
                return self._generate_learn_report()
    
    def _generate_beginner_report(self) -> str:
        """Generate a beginner-friendly report with clear guidance."""
        report = []
        
        # Header
        report.append("\n🔍 AWS Bedrock Security Check - Beginner Mode")
        report.append("━" * 50)
        report.append(f"Account: {self.account_id} | Region: {self.region}")
        report.append("")
        
        # Summary with emojis
        critical_count = sum(1 for f in self.findings if f['risk_level'] == RiskLevel.CRITICAL)
        high_count = sum(1 for f in self.findings if f['risk_level'] == RiskLevel.HIGH)
        medium_count = sum(1 for f in self.findings if f['risk_level'] == RiskLevel.MEDIUM)
        low_count = sum(1 for f in self.findings if f['risk_level'] == RiskLevel.LOW)
        
        if self.good_practices:
            report.append(f"✅ Good News: {len(self.good_practices)} security best practices are properly configured")
        
        if critical_count > 0:
            report.append(f"🛑 Critical: {critical_count} high-risk issues need immediate attention")
        if high_count > 0:
            report.append(f"🔴 High Priority: {high_count} important issues to address")
        if medium_count > 0:
            report.append(f"⚠️  Attention Needed: {medium_count} medium-risk issues found")
        if low_count > 0:
            report.append(f"🟡 Minor Issues: {low_count} low-priority improvements suggested")
        
        # Good practices
        if self.good_practices:
            report.append("\n✅ WHAT'S WORKING WELL:")
            report.append("─" * 30)
            for practice in self.good_practices[:3]:  # Show top 3
                report.append(f"  • {practice['practice']}")
        
        # Issues by priority
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            level_findings = [f for f in self.findings if f['risk_level'] == risk_level]
            
            if level_findings:
                report.append(f"\n{risk_level.emoji} {risk_level.label} ISSUES:")
                report.append("─" * 30)
                
                for i, finding in enumerate(level_findings[:3], 1):  # Limit to top 3 per level
                    report.append(f"\n{i}. {finding['issue']}")
                    report.append(f"   📍 Where: {finding['resource']}")
                    report.append(f"   💡 Risk Score: {finding['risk_score']}/10")
                    report.append(f"   \n   What this means: {finding.get('learn_more', finding['recommendation'])}")
                    
                    if finding.get('fix_command'):
                        report.append(f"   \n   To fix this, run:")
                        report.append(f"   > {finding['fix_command']}")
                
                if len(level_findings) > 3:
                    report.append(f"\n   ... and {len(level_findings) - 3} more {risk_level.label.lower()} issues")
        
        # Footer
        report.append("\n" + "─" * 50)
        report.append("💡 Tips:")
        report.append("  • Fix critical issues first (🛑)")
        report.append("  • Run with --expert for technical details")
        report.append("  • Run with --learn to understand each check")
        report.append("  • Run with --fix <issue> for step-by-step remediation")
        
        return "\n".join(report)
    
    def _generate_expert_report(self) -> str:
        """Generate a detailed technical report."""
        report = []
        
        report.append("\n" + "=" * 80)
        report.append("AWS BEDROCK SECURITY CONFIGURATION REPORT - EXPERT MODE")
        report.append("=" * 80)
        report.append(f"Account: {self.account_id}")
        report.append(f"Region: {self.region}")
        report.append(f"Scan Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.findings)}")
        report.append(f"Good Practices: {len(self.good_practices)}")
        
        # Detailed findings
        if self.findings:
            report.append("\n" + "-" * 80)
            report.append("DETAILED FINDINGS")
            report.append("-" * 80)
            
            # Group by category
            findings_by_category = defaultdict(list)
            for finding in self.findings:
                findings_by_category[finding['category']].append(finding)
            
            for category, category_findings in findings_by_category.items():
                report.append(f"\n[{category}]")
                for finding in category_findings:
                    report.append(f"\n  Risk Level: {finding['risk_level'].label} (Score: {finding['risk_score']}/10)")
                    report.append(f"  Resource: {finding['resource']}")
                    report.append(f"  Issue: {finding['issue']}")
                    report.append(f"  Recommendation: {finding['recommendation']}")
                    
                    if finding.get('technical_details'):
                        report.append(f"  Technical Details: {finding['technical_details']}")
                    
                    if finding.get('fix_command'):
                        report.append(f"  Remediation Command: {finding['fix_command']}")
        
        # Good practices
        if self.good_practices:
            report.append("\n" + "-" * 80)
            report.append("PROPERLY CONFIGURED SECURITY CONTROLS")
            report.append("-" * 80)
            for practice in self.good_practices:
                report.append(f"  ✓ [{practice['category']}] {practice['practice']}")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)
    
    def _generate_learn_report(self) -> str:
        """Generate an educational report about the security checks."""
        report = []
        
        report.append("\n📚 AWS Bedrock Security - Learning Mode")
        report.append("━" * 50)
        report.append("\nThis mode explains what each security check does and why it matters.")
        report.append("\nRun without --learn to perform the actual security audit.")
        
        report.append("\n\n🔒 Security Checks Explained:\n")
        
        checks = [
            {
                "name": "Prompt Injection Protection",
                "description": "Prevents attackers from tricking your AI into ignoring its instructions",
                "example": "Like someone trying to convince a security guard to let them in",
                "why_important": "Protects your AI from generating harmful or inappropriate content"
            },
            {
                "name": "Data Privacy Compliance",
                "description": "Ensures personal information (PII) isn't exposed through AI logs or responses",
                "example": "Making sure credit card numbers or SSNs don't appear in logs",
                "why_important": "Helps you comply with privacy laws and protect user data"
            },
            {
                "name": "Model Access Control",
                "description": "Controls who can use your AI models and what they can do",
                "example": "Like having different keys for different rooms in a building",
                "why_important": "Prevents unauthorized use and potential abuse of your AI"
            },
            {
                "name": "Audit Logging",
                "description": "Keeps records of all AI model usage for security and compliance",
                "example": "Like security camera footage - you can review who did what",
                "why_important": "Helps detect abuse and provides evidence for investigations"
            },
            {
                "name": "Network Security",
                "description": "Ensures AI traffic uses private, encrypted connections",
                "example": "Like using a secure tunnel instead of shouting across a room",
                "why_important": "Protects sensitive data from interception"
            },
            {
                "name": "Cost Monitoring",
                "description": "Alerts you to unusual AI usage that might indicate abuse",
                "example": "Like getting a notification for unusual credit card charges",
                "why_important": "Helps detect compromised credentials or abuse early"
            }
        ]
        
        for i, check in enumerate(checks, 1):
            report.append(f"{i}. {check['name']}")
            report.append(f"   📖 What it does: {check['description']}")
            report.append(f"   🎯 Example: {check['example']}")
            report.append(f"   ⚡ Why it matters: {check['why_important']}")
            report.append("")
        
        report.append("─" * 50)
        report.append("Ready to run a real security check? Remove the --learn flag!")
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate a JSON report with all findings."""
        report_data = {
            'account_id': self.account_id,
            'region': self.region,
            'scan_time': datetime.utcnow().isoformat(),
            'mode': self.mode.value,
            'summary': {
                'total_findings': len(self.findings),
                'critical': sum(1 for f in self.findings if f['risk_level'] == RiskLevel.CRITICAL),
                'high': sum(1 for f in self.findings if f['risk_level'] == RiskLevel.HIGH),
                'medium': sum(1 for f in self.findings if f['risk_level'] == RiskLevel.MEDIUM),
                'low': sum(1 for f in self.findings if f['risk_level'] == RiskLevel.LOW),
                'good_practices': len(self.good_practices)
            },
            'findings': [
                {
                    'risk_level': f['risk_level'].label,
                    'risk_score': f['risk_score'],
                    'category': f['category'],
                    'resource': f['resource'],
                    'issue': f['issue'],
                    'recommendation': f['recommendation'],
                    'fix_command': f.get('fix_command'),
                    'learn_more': f.get('learn_more'),
                    'technical_details': f.get('technical_details')
                }
                for f in self.findings
            ],
            'good_practices': self.good_practices,
            'available_models': self.available_models
        }
        
        return json.dumps(report_data, indent=2, default=str)


def main():
    """Main function to run the enhanced security checker."""
    parser = argparse.ArgumentParser(
        description='AWS Bedrock Security Configuration Checker - GenAI Security Focus',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                     # Run in beginner mode (default)
  %(prog)s --expert           # Run with technical details
  %(prog)s --learn            # Learn what each check does
  %(prog)s --output json      # Output in JSON format
  %(prog)s --fix logging      # Get step-by-step fix for logging issues
        """
    )
    
    parser.add_argument('--profile', help='AWS profile name to use', default=None)
    parser.add_argument('--region', help='AWS region to check', default=None)
    parser.add_argument('--expert', action='store_true', help='Expert mode with technical details')
    parser.add_argument('--learn', action='store_true', help='Learning mode - explains each check')
    parser.add_argument('--fix', help='Get detailed remediation steps for a specific issue type')
    parser.add_argument('--output', choices=['json', 'text'], default='text', help='Output format')
    parser.add_argument('--output-file', help='Save report to file', default=None)
    
    args = parser.parse_args()
    
    # Determine mode
    if args.learn:
        mode = SecurityMode.LEARN
    elif args.expert:
        mode = SecurityMode.EXPERT
    else:
        mode = SecurityMode.BEGINNER
    
    # Handle fix mode
    if args.fix:
        print(f"\n🔧 Remediation Guide for: {args.fix}")
        print("This feature is coming soon!")
        print("For now, run the security check to see fix commands for each issue.")
        return
    
    try:
        # Initialize and run the checker
        checker = BedrockSecurityChecker(
            profile_name=args.profile,
            region=args.region,
            mode=mode
        )
        
        # Run all checks
        checker.run_all_checks()
        
        # Generate report
        report = checker.generate_report(output_format=args.output)
        
        # Output report
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            print(f"\n✅ Report saved to: {args.output_file}")
        else:
            print(report)
        
        # Exit with appropriate code
        if any(f['risk_level'] == RiskLevel.CRITICAL for f in checker.findings):
            sys.exit(2)
        elif any(f['risk_level'] == RiskLevel.HIGH for f in checker.findings):
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Check interrupted by user")
        sys.exit(3)
    except Exception as e:
        print(f"\n❌ Error running security checker: {str(e)}")
        if mode == SecurityMode.BEGINNER:
            print("\n💡 Troubleshooting tips:")
            print("  1. Check your AWS credentials: aws configure list")
            print("  2. Ensure you have the necessary IAM permissions")
            print("  3. Try specifying a region: --region us-east-1")
        sys.exit(3)


if __name__ == '__main__':
    main()