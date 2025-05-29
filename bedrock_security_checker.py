#!/usr/bin/env python3
"""
AWS Bedrock Security Configuration Checker

This script audits AWS Bedrock configurations for security best practices.
"""

import boto3
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Tuple
import sys


class BedrockSecurityChecker:
    """Check AWS Bedrock configurations for security best practices."""
    
    def __init__(self, profile_name: str = None, region: str = None):
        """Initialize the security checker with AWS credentials."""
        session_params = {}
        if profile_name:
            session_params['profile_name'] = profile_name
        if region:
            session_params['region_name'] = region
            
        self.session = boto3.Session(**session_params)
        self.bedrock = self.session.client('bedrock')
        self.bedrock_runtime = self.session.client('bedrock-runtime')
        self.iam = self.session.client('iam')
        self.cloudtrail = self.session.client('cloudtrail')
        self.cloudwatch = self.session.client('logs')
        self.ec2 = self.session.client('ec2')
        
        self.findings = []
        self.region = self.session.region_name
        self.account_id = self.session.client('sts').get_caller_identity()['Account']
    
    def add_finding(self, severity: str, category: str, resource: str, issue: str, recommendation: str):
        """Add a security finding to the results."""
        self.findings.append({
            'severity': severity,
            'category': category,
            'resource': resource,
            'issue': issue,
            'recommendation': recommendation,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def check_model_access_policies(self) -> List[Dict]:
        """Check model access policies for least privilege."""
        print("Checking model access policies...")
        
        try:
            # List custom models
            custom_models = self.bedrock.list_custom_models()
            
            for model in custom_models.get('modelSummaries', []):
                model_arn = model['modelArn']
                model_name = model['modelName']
                
                # Check if model has proper access controls
                try:
                    # Get model details
                    model_details = self.bedrock.get_custom_model(modelIdentifier=model_name)
                    
                    # Check for overly permissive policies
                    if 'modelKmsKeyId' not in model_details:
                        self.add_finding(
                            severity='HIGH',
                            category='Encryption',
                            resource=f'Model: {model_name}',
                            issue='Custom model not encrypted with customer-managed KMS key',
                            recommendation='Enable encryption with a customer-managed KMS key for better control'
                        )
                        
                except Exception as e:
                    print(f"Error checking model {model_name}: {str(e)}")
                    
        except Exception as e:
            print(f"Error listing custom models: {str(e)}")
            
        return self.findings
    
    def check_data_encryption(self) -> List[Dict]:
        """Check data encryption settings."""
        print("Checking data encryption configurations...")
        
        try:
            # Check for model invocation logs encryption
            log_groups = self.cloudwatch.describe_log_groups()
            
            for log_group in log_groups.get('logGroups', []):
                if 'bedrock' in log_group['logGroupName'].lower():
                    if 'kmsKeyId' not in log_group:
                        self.add_finding(
                            severity='MEDIUM',
                            category='Encryption',
                            resource=f"Log Group: {log_group['logGroupName']}",
                            issue='Bedrock-related CloudWatch log group not encrypted with KMS',
                            recommendation='Enable encryption for CloudWatch log groups containing Bedrock data'
                        )
                        
        except Exception as e:
            print(f"Error checking encryption settings: {str(e)}")
            
        return self.findings
    
    def check_logging_monitoring(self) -> List[Dict]:
        """Check logging and monitoring configurations."""
        print("Checking logging and monitoring settings...")
        
        try:
            # Check if CloudTrail is logging Bedrock API calls
            trails = self.cloudtrail.describe_trails()
            
            bedrock_logging_enabled = False
            for trail in trails.get('trailList', []):
                trail_name = trail['Name']
                
                # Get event selectors
                try:
                    event_selectors = self.cloudtrail.get_event_selectors(TrailName=trail_name)
                    
                    for selector in event_selectors.get('EventSelectors', []):
                        if selector.get('ReadWriteType') in ['All', 'ReadOnly']:
                            bedrock_logging_enabled = True
                            break
                            
                except Exception as e:
                    print(f"Error checking trail {trail_name}: {str(e)}")
                    
            if not bedrock_logging_enabled:
                self.add_finding(
                    severity='HIGH',
                    category='Logging',
                    resource='CloudTrail',
                    issue='Bedrock API calls may not be logged in CloudTrail',
                    recommendation='Ensure CloudTrail is configured to log all Bedrock API calls'
                )
                
            # Check for model invocation logging
            try:
                # Check if model invocation logging is configured
                # Note: This would require checking specific model configurations
                pass
            except Exception as e:
                print(f"Error checking invocation logging: {str(e)}")
                
        except Exception as e:
            print(f"Error checking logging configuration: {str(e)}")
            
        return self.findings
    
    def check_vpc_endpoints(self) -> List[Dict]:
        """Check if VPC endpoints are used for private connectivity."""
        print("Checking VPC endpoint configurations...")
        
        try:
            # List VPC endpoints
            endpoints = self.ec2.describe_vpc_endpoints()
            
            bedrock_endpoint_found = False
            bedrock_runtime_endpoint_found = False
            
            for endpoint in endpoints.get('VpcEndpoints', []):
                service_name = endpoint.get('ServiceName', '')
                
                if 'bedrock' in service_name and 'runtime' not in service_name:
                    bedrock_endpoint_found = True
                elif 'bedrock-runtime' in service_name:
                    bedrock_runtime_endpoint_found = True
                    
            if not bedrock_endpoint_found:
                self.add_finding(
                    severity='MEDIUM',
                    category='Network Security',
                    resource='VPC Endpoints',
                    issue='No VPC endpoint found for Bedrock service',
                    recommendation='Create VPC endpoint for com.amazonaws.region.bedrock for private connectivity'
                )
                
            if not bedrock_runtime_endpoint_found:
                self.add_finding(
                    severity='MEDIUM',
                    category='Network Security',
                    resource='VPC Endpoints',
                    issue='No VPC endpoint found for Bedrock Runtime service',
                    recommendation='Create VPC endpoint for com.amazonaws.region.bedrock-runtime for private model invocations'
                )
                
        except Exception as e:
            print(f"Error checking VPC endpoints: {str(e)}")
            
        return self.findings
    
    def check_iam_permissions(self) -> List[Dict]:
        """Check IAM permissions for least privilege."""
        print("Checking IAM permissions...")
        
        try:
            # List IAM policies
            policies = self.iam.list_policies(Scope='Local')
            
            for policy in policies.get('Policies', []):
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                try:
                    # Get policy document
                    policy_version = self.iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_doc = policy_version['PolicyVersion']['Document']
                    
                    # Check for overly permissive Bedrock permissions
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                                
                            # Check for wildcard actions
                            for action in actions:
                                if 'bedrock:*' in action:
                                    self.add_finding(
                                        severity='HIGH',
                                        category='IAM',
                                        resource=f'Policy: {policy_name}',
                                        issue='Policy contains wildcard Bedrock permissions',
                                        recommendation='Use specific Bedrock actions instead of wildcards for least privilege'
                                    )
                                    
                            # Check for sensitive actions
                            sensitive_actions = [
                                'bedrock:DeleteCustomModel',
                                'bedrock:DeleteModelInvocationLoggingConfiguration',
                                'bedrock:PutModelInvocationLoggingConfiguration'
                            ]
                            
                            for sensitive_action in sensitive_actions:
                                if sensitive_action in actions and '*' in str(statement.get('Resource', '')):
                                    self.add_finding(
                                        severity='MEDIUM',
                                        category='IAM',
                                        resource=f'Policy: {policy_name}',
                                        issue=f'Sensitive action {sensitive_action} allowed on all resources',
                                        recommendation='Restrict sensitive actions to specific resources'
                                    )
                                    
                except Exception as e:
                    print(f"Error checking policy {policy_name}: {str(e)}")
                    
        except Exception as e:
            print(f"Error checking IAM permissions: {str(e)}")
            
        return self.findings
    
    def check_resource_tagging(self) -> List[Dict]:
        """Check resource tagging for governance."""
        print("Checking resource tagging...")
        
        try:
            # Check custom models for proper tagging
            custom_models = self.bedrock.list_custom_models()
            
            required_tags = ['Environment', 'Owner', 'CostCenter', 'DataClassification']
            
            for model in custom_models.get('modelSummaries', []):
                model_name = model['modelName']
                
                try:
                    # Get model tags
                    tags_response = self.bedrock.list_tags_for_resource(
                        resourceARN=model['modelArn']
                    )
                    
                    existing_tags = [tag['key'] for tag in tags_response.get('tags', [])]
                    missing_tags = [tag for tag in required_tags if tag not in existing_tags]
                    
                    if missing_tags:
                        self.add_finding(
                            severity='LOW',
                            category='Governance',
                            resource=f'Model: {model_name}',
                            issue=f'Missing required tags: {", ".join(missing_tags)}',
                            recommendation='Add all required tags for proper resource governance and cost allocation'
                        )
                        
                except Exception as e:
                    print(f"Error checking tags for model {model_name}: {str(e)}")
                    
        except Exception as e:
            print(f"Error checking resource tagging: {str(e)}")
            
        return self.findings
    
    def check_model_invocation_logging(self) -> List[Dict]:
        """Check model invocation logging configuration."""
        print("Checking model invocation logging...")
        
        try:
            # Get model invocation logging configuration
            logging_config = self.bedrock.get_model_invocation_logging_configuration()
            
            if not logging_config.get('loggingConfig'):
                self.add_finding(
                    severity='HIGH',
                    category='Logging',
                    resource='Model Invocation Logging',
                    issue='Model invocation logging is not configured',
                    recommendation='Enable model invocation logging for audit and compliance'
                )
            else:
                config = logging_config['loggingConfig']
                
                # Check if both CloudWatch and S3 logging are enabled
                if not config.get('cloudWatchConfig', {}).get('logGroupName'):
                    self.add_finding(
                        severity='MEDIUM',
                        category='Logging',
                        resource='Model Invocation Logging',
                        issue='CloudWatch logging not enabled for model invocations',
                        recommendation='Enable CloudWatch logging for real-time monitoring'
                    )
                    
                if not config.get('s3Config', {}).get('bucketName'):
                    self.add_finding(
                        severity='MEDIUM',
                        category='Logging',
                        resource='Model Invocation Logging',
                        issue='S3 logging not enabled for model invocations',
                        recommendation='Enable S3 logging for long-term retention and analysis'
                    )
                    
        except self.bedrock.exceptions.ValidationException:
            # Logging configuration might not be set up
            self.add_finding(
                severity='HIGH',
                category='Logging',
                resource='Model Invocation Logging',
                issue='Model invocation logging is not configured',
                recommendation='Enable model invocation logging for audit and compliance'
            )
        except Exception as e:
            print(f"Error checking model invocation logging: {str(e)}")
            
        return self.findings
    
    def run_all_checks(self) -> List[Dict]:
        """Run all security checks."""
        print(f"\nStarting AWS Bedrock Security Configuration Check")
        print(f"Account: {self.account_id}")
        print(f"Region: {self.region}")
        print("-" * 60)
        
        # Run all checks
        self.check_model_access_policies()
        self.check_data_encryption()
        self.check_logging_monitoring()
        self.check_vpc_endpoints()
        self.check_iam_permissions()
        self.check_resource_tagging()
        self.check_model_invocation_logging()
        
        return self.findings
    
    def generate_report(self, output_format: str = 'json') -> str:
        """Generate a security report."""
        if output_format == 'json':
            return json.dumps({
                'account_id': self.account_id,
                'region': self.region,
                'scan_time': datetime.utcnow().isoformat(),
                'total_findings': len(self.findings),
                'findings_by_severity': self._count_by_severity(),
                'findings': self.findings
            }, indent=2)
        elif output_format == 'text':
            return self._generate_text_report()
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.findings:
            counts[finding['severity']] += 1
        return counts
    
    def _generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        report = []
        report.append("\n" + "=" * 80)
        report.append("AWS BEDROCK SECURITY CONFIGURATION REPORT")
        report.append("=" * 80)
        report.append(f"Account: {self.account_id}")
        report.append(f"Region: {self.region}")
        report.append(f"Scan Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report.append(f"Total Findings: {len(self.findings)}")
        
        severity_counts = self._count_by_severity()
        report.append(f"\nFindings by Severity:")
        report.append(f"  HIGH:   {severity_counts['HIGH']}")
        report.append(f"  MEDIUM: {severity_counts['MEDIUM']}")
        report.append(f"  LOW:    {severity_counts['LOW']}")
        
        if self.findings:
            report.append("\n" + "-" * 80)
            report.append("DETAILED FINDINGS")
            report.append("-" * 80)
            
            # Group findings by severity
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                severity_findings = [f for f in self.findings if f['severity'] == severity]
                if severity_findings:
                    report.append(f"\n[{severity} SEVERITY]")
                    for i, finding in enumerate(severity_findings, 1):
                        report.append(f"\n{i}. {finding['category']} - {finding['resource']}")
                        report.append(f"   Issue: {finding['issue']}")
                        report.append(f"   Recommendation: {finding['recommendation']}")
        else:
            report.append("\nNo security issues found! ✓")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)


def main():
    """Main function to run the security checker."""
    parser = argparse.ArgumentParser(
        description='Check AWS Bedrock configurations for security best practices'
    )
    parser.add_argument(
        '--profile',
        help='AWS profile name to use',
        default=None
    )
    parser.add_argument(
        '--region',
        help='AWS region to check',
        default=None
    )
    parser.add_argument(
        '--output',
        choices=['json', 'text'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output-file',
        help='Save report to file',
        default=None
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize and run the checker
        checker = BedrockSecurityChecker(
            profile_name=args.profile,
            region=args.region
        )
        
        # Run all checks
        checker.run_all_checks()
        
        # Generate report
        report = checker.generate_report(output_format=args.output)
        
        # Output report
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {args.output_file}")
        else:
            print(report)
            
        # Exit with appropriate code
        severity_counts = checker._count_by_severity()
        if severity_counts['HIGH'] > 0:
            sys.exit(2)  # Critical issues found
        elif severity_counts['MEDIUM'] > 0:
            sys.exit(1)  # Warning issues found
        else:
            sys.exit(0)  # All good or only low severity
            
    except Exception as e:
        print(f"\nError running security checker: {str(e)}")
        sys.exit(3)


if __name__ == '__main__':
    main()