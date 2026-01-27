#!/usr/bin/env python3
"""
Auto-Guardian Cloud Security Scanner
ماسح أمان البنية التحتية السحابية

الإصدار: 1.0.0
تاريخ التحديث: 2024-01-28

فحص شامل لأمان السحابة:
- AWS Security (IAM, S3, Security Groups)
- Azure Security (Storage, Network, IAM)
- GCP Security (IAM, Storage, Firewall)
- Kubernetes Security
- Infrastructure as Code (Terraform, CloudFormation)
"""

import os
import re
import json
import hashlib
import subprocess
import boto3
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import logging
import tempfile

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CloudProvider(Enum):
    """مزودو الخدمات السحابية"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """مستويات خطورة الثغرات"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(Enum):
    """فئات النتائج"""
    IAM = "identity_and_access_management"
    STORAGE = "storage_security"
    NETWORK = "network_security"
    COMPUTE = "compute_security"
    DATABASE = "database_security"
    CONTAINER = "container_security"
    ENCRYPTION = "encryption_and_key_management"
    MONITORING = "monitoring_and_logging"
    COMPLIANCE = "compliance_and_governance"


@dataclass
class CloudFinding:
    """نتيجة فحص السحابة"""
    finding_id: str
    category: FindingCategory
    provider: CloudProvider
    severity: SeverityLevel
    title: str
    description: str
    recommendation: str
    resource_type: str
    resource_name: str
    resource_id: str
    region: str
    evidence: Dict[str, Any]
    compliance_frameworks: List[str]
    created_at: str


@dataclass
class CloudScanResult:
    """نتيجة فحص السحابة"""
    scan_id: str
    scan_time: str
    scan_duration: float
    provider: CloudProvider
    target: str
    
    total_resources: int = 0
    total_findings: int = 0
    
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    
    findings: List[CloudFinding] = field(default_factory=list)
    
    risk_score: int = 100
    
    security_rating: str = "A"
    
    recommendations: List[str] = field(default_factory=list)
    
    compliance_summary: Dict[str, Dict] = field(default_factory=dict)


class AWSSecurityChecker:
    """فحص أمان AWS"""
    
    # فحوصات IAM
    IAM_CHECKS = [
        {
            "id": "IAM-001",
            "title": "مستخدم IAM بدون MFA",
            "severity": "high",
            "category": FindingCategory.IAM,
            "check": self._check_iam_users_mfa
        },
        {
            "id": "IAM-002",
            "title": "مفاتيح وصول قديمة",
            "severity": "critical",
            "category": FindingCategory.IAM,
            "check": self._check_old_access_keys
        },
        {
            "id": "IAM-003",
            "title": "سياسات IAM واسعة الصلاحيات",
            "severity": "critical",
            "category": FindingCategory.IAM,
            "check": self._check_wide_iam_policies
        },
        {
            "id": "IAM-004",
            "title": "دور بدون شروط MFA",
            "severity": "high",
            "category": FindingCategory.IAM,
            "check": self._check_role_mfa_requirement
        },
        {
            "id": "IAM-005",
            "title": "مستخدم جذر بدون MFA",
            "severity": "critical",
            "category": FindingCategory.IAM,
            "check": self._check_root_mfa
        },
    ]
    
    # فحوصات S3
    S3_CHECKS = [
        {
            "id": "S3-001",
            "title": "دلو S3 عام",
            "severity": "critical",
            "category": FindingCategory.STORAGE,
            "check": self._check_public_s3_bucket
        },
        {
            "id": "S3-002",
            "title": "دلو S3 بدون تشفير",
            "severity": "high",
            "category": FindingCategory.STORAGE,
            "check": self._check_unencrypted_s3_bucket
        },
        {
            "id": "S3-003",
            "title": "دلو S3 بدون Versioning",
            "severity": "medium",
            "category": FindingCategory.STORAGE,
            "check": self._check_s3_versioning
        },
        {
            "id": "S3-004",
            "title": "دلو S3 مع ACLs العامة",
            "severity": "critical",
            "category": FindingCategory.STORAGE,
            "check": self._check_s3_public_acls
        },
        {
            "id": "S3-005",
            "title": "دلو S3 بدون تسجيل",
            "severity": "medium",
            "category": FindingCategory.MONITORING,
            "check": self._check_s3_logging
        },
    ]
    
    # فحوصات Security Groups
    SG_CHECKS = [
        {
            "id": "SG-001",
            "title": "منفذ SSH (22) مفتوح للعالم",
            "severity": "critical",
            "category": FindingCategory.NETWORK,
            "check": self._check_ssh_open_world
        },
        {
            "id": "SG-002",
            "title": "منفذ RDP (3389) مفتوح للعالم",
            "severity": "critical",
            "category": FindingCategory.NETWORK,
            "check": self._check_rdp_open_world
        },
        {
            "id": "SG-003",
            "title": "منافذ غير مشفرة مكشوفة",
            "severity": "high",
            "category": FindingCategory.NETWORK,
            "check": self._check_unencrypted_ports
        },
        {
            "id": "SG-004",
            "title": "Security Group بدون قيود",
            "severity": "medium",
            "category": FindingCategory.NETWORK,
            "check": self._check_unrestricted_sg
        },
    ]
    
    def __init__(self, session: boto3.Session = None):
        self.session = session or boto3.Session()
        self.findings = []
    
    def _check_iam_users_mfa(self, client) -> List[Dict]:
        """فحص مستخدمين IAM بدون MFA"""
        findings = []
        try:
            users = client.list_users()['Users']
            for user in users:
                mfa_devices = client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                if not mfa_devices:
                    findings.append({
                        "resource_type": "IAM User",
                        "resource_name": user['UserName'],
                        "resource_id": user['Arn'],
                        "severity": "high",
                        "title": "مستخدم IAM بدون MFA",
                        "description": f"المستخدم {user['UserName']} لا يستخدم MFA للمصادقة",
                        "recommendation": "تفعيل MFA لجميع مستخدمي IAM",
                        "evidence": {"mfa_devices": len(mfa_devices)}
                    })
        except Exception as e:
            logger.warning(f"فشل فحص MFA: {e}")
        return findings
    
    def _check_old_access_keys(self, client) -> List[Dict]:
        """فحص مفاتيح الوصول القديمة"""
        findings = []
        try:
            users = client.list_users()['Users']
            for user in users:
                access_keys = client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                for key in access_keys:
                    # حساب عمر المفتاح
                    create_date = key['CreateDate']
                    age_days = (datetime.now(create_date.tzinfo) - create_date).days
                    
                    if age_days > 90:
                        findings.append({
                            "resource_type": "Access Key",
                            "resource_name": user['UserName'],
                            "resource_id": key['AccessKeyId'],
                            "severity": "high" if age_days > 180 else "medium",
                            "title": "مفتاح وصول قديم",
                            "description": f"مفتاح الوصول عمره {age_days} يوم",
                            "recommendation": "تدوير مفاتيح الوصول كل 90 يوم",
                            "evidence": {"age_days": age_days, "status": key['Status']}
                        })
        except Exception as e:
            logger.warning(f"فشل فحص مفاتيح الوصول: {e}")
        return findings
    
    def _check_wide_iam_policies(self, client) -> List[Dict]:
        """فحص السياسات ذات الصلاحيات الواسعة"""
        findings = []
        try:
            users = client.list_users()['Users']
            for user in users:
                attached_policies = client.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                for policy in attached_policies:
                    policy_version = client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    )['PolicyVersion']
                    
                    # فحص السياسات الخطرة
                    policy_doc = policy_version['Document']
                    statements = policy_doc.get('Statement', [])
                    
                    for stmt in statements:
                        if isinstance(statements, list):
                            stmt = stmt
                        
                        # فحص "*:*" Actions
                        actions = stmt.get('Action', [])
                        if actions == "*" or (isinstance(actions, list) and "*" in actions):
                            if stmt.get('Effect') == 'Allow':
                                findings.append({
                                    "resource_type": "IAM Policy",
                                    "resource_name": policy['PolicyName'],
                                    "resource_id": policy['PolicyArn'],
                                    "severity": "critical",
                                    "title": "سياسة IAM واسعة الصلاحيات",
                                    "description": "السياسة تسمح بجميع الإجراءات على جميع الموارد",
                                    "recommendation": "تطبيق مبدأ الحد الأدنى من الصلاحيات",
                                    "evidence": {"statement": stmt}
                                })
        except Exception as e:
            logger.warning(f"فحص سياسات IAM: {e}")
        return findings
    
    def _check_root_mfa(self, client) -> List[Dict]:
        """فحص MFA للمستخدم الجذر"""
        findings = []
        try:
            mfa_devices = client.list_mfa_devices()['MFADevices']
            if not mfa_devices:
                findings.append({
                    "resource_type": "Root Account",
                    "resource_name": "Root",
                    "resource_id": "AWS Root",
                    "severity": "critical",
                    "title": "المستخدم الجذر بدون MFA",
                    "description": "حساب AWS الجذر لا يستخدم MFA",
                    "recommendation": "تفعيل MFA فوراً على حساب الجذر",
                    "evidence": {"mfa_enabled": False}
                })
        except Exception as e:
            logger.warning(f"فحص MFA الجذر: {e}")
        return findings
    
    def _check_public_s3_bucket(self, client) -> List[Dict]:
        """فحص أحواض S3 العامة"""
        findings = []
        try:
            buckets = client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    acl = client.get_bucket_acl(Bucket=bucket['Name'])
                    for grant in acl['Grants']:
                        if grant.get('Grantee', {}).get('Type') == 'Group' and \
                           'AllUsers' in grant.get('Grantee', {}).get('URI', ''):
                            findings.append({
                                "resource_type": "S3 Bucket",
                                "resource_name": bucket['Name'],
                                "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                                "severity": "critical",
                                "title": "دلو S3 عام",
                                "description": f"دلو {bucket['Name']} قابل للقراءة من الجميع",
                                "recommendation": "تقييد الوصول إلى الدلو",
                                "evidence": {"grants": len(acl['Grants'])}
                            })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"فحص S3 العام: {e}")
        return findings
    
    def _check_unencrypted_s3_bucket(self, client) -> List[Dict]:
        """فحص أحواض S3 غير المشفرة"""
        findings = []
        try:
            buckets = client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    encryption = client.get_bucket_encryption(Bucket=bucket['Name'])
                    if 'ServerSideEncryptionConfiguration' not in encryption:
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket['Name'],
                            "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                            "severity": "high",
                            "title": "دلو S3 بدون تشفير",
                            "description": f"دلو {bucket['Name']} لا يستخدم تشفير SSE",
                            "recommendation": "تفعيل تشفير S3",
                            "evidence": {"encryption": "disabled"}
                        })
                except client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    findings.append({
                        "resource_type": "S3 Bucket",
                        "resource_name": bucket['Name'],
                        "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                        "severity": "high",
                        "title": "دلو S3 بدون تشفير",
                        "description": f"دلو {bucket['Name']} لا يستخدم تشفير SSE",
                        "recommendation": "تفعيل تشفير S3",
                        "evidence": {"encryption": "not configured"}
                    })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"فحص تشفير S3: {e}")
        return findings
    
    def _check_s3_versioning(self, client) -> List[Dict]:
        """فحص Versioning في S3"""
        findings = []
        try:
            buckets = client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    versioning = client.get_bucket_versioning(Bucket=bucket['Name'])
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket['Name'],
                            "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                            "severity": "medium",
                            "title": "دلو S3 بدون Versioning",
                            "description": f"دلو {bucket['Name']} لا يدعم Versioning",
                            "recommendation": "تفعيل Versioning لحماية البيانات",
                            "evidence": {"versioning_status": versioning.get('Status')}
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"فحص Versioning: {e}")
        return findings
    
    def _check_s3_public_acls(self, client) -> List[Dict]:
        """فحص ACLs العامة في S3"""
        findings = []
        try:
            buckets = client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    public_access_block = client.get_public_access_block(Bucket=bucket['Name'])
                    block_config = public_access_block['PublicAccessBlockConfiguration']
                    
                    if not all([block_config['BlockPublicAcls'], block_config['IgnorePublicAcls'],
                               block_config['BlockPublicPolicy'], block_config['RestrictPublicBuckets']]):
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket['Name'],
                            "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                            "severity": "critical",
                            "title": "دلو S3 بدون حظر الوصول العام",
                            "description": f"دلو {bucket['Name']} لا يحظر الوصول العام",
                            "recommendation": "تفعيل Public Access Block",
                            "evidence": {"block_config": block_config}
                        })
                except client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    findings.append({
                        "resource_type": "S3 Bucket",
                        "resource_name": bucket['Name'],
                        "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                        "severity": "critical",
                        "title": "دلو S3 بدون Public Access Block",
                        "description": f"دلو {bucket['Name']} لا يحتوي على Public Access Block",
                        "recommendation": "تفعيل Public Access Block",
                        "evidence": {"configured": False}
                    })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"فحص Public ACLs: {e}")
        return findings
    
    def _check_s3_logging(self, client) -> List[Dict]:
        """فحص تسجيل S3"""
        findings = []
        try:
            buckets = client.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    logging = client.get_bucket_logging(Bucket=bucket['Name'])
                    if 'LoggingEnabled' not in logging:
                        findings.append({
                            "resource_type": "S3 Bucket",
                            "resource_name": bucket['Name'],
                            "resource_id": f"arn:aws:s3:::{bucket['Name']}",
                            "severity": "medium",
                            "title": "دلو S3 بدون تسجيل",
                            "description": f"دلو {bucket['Name']} لا يسجل الوصول",
                            "recommendation": "تفعيل S3 Server Access Logging",
                            "evidence": {"logging_enabled": False}
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"فحص تسجيل S3: {e}")
        return findings
    
    def _check_ssh_open_world(self, ec2_client) -> List[Dict]:
        """فحص منفذ SSH المفتوح للعالم"""
        findings = []
        try:
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                for permission in sg.get('IpPermissions', []):
                    if permission.get('FromPort', 0) <= 22 <= permission.get('ToPort', 65535):
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                findings.append({
                                    "resource_type": "Security Group",
                                    "resource_name": sg['GroupName'],
                                    "resource_id": sg['GroupId'],
                                    "severity": "critical",
                                    "title": "منفذ SSH مفتوح للعالم",
                                    "description": f"Security Group {sg['GroupName']} يسمح بـ SSH من أي IP",
                                    "recommendation": "تقييد SSH إلى IPs محددة",
                                    "evidence": {"cidr": ip_range['CidrIp'], "port": 22}
                                })
        except Exception as e:
            logger.warning(f"فحص SSH: {e}")
        return findings
    
    def _check_rdp_open_world(self, ec2_client) -> List[Dict]:
        """فحص منفذ RDP المفتوح للعالم"""
        findings = []
        try:
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                for permission in sg.get('IpPermissions', []):
                    if permission.get('FromPort', 0) <= 3389 <= permission.get('ToPort', 65535):
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                findings.append({
                                    "resource_type": "Security Group",
                                    "resource_name": sg['GroupName'],
                                    "resource_id": sg['GroupId'],
                                    "severity": "critical",
                                    "title": "منفذ RDP مفتوح للعالم",
                                    "description": f"Security Group {sg['GroupName']} يسمح بـ RDP من أي IP",
                                    "recommendation": "تقييد RDP إلى IPs محددة",
                                    "evidence": {"cidr": ip_range['CidrIp'], "port": 3389}
                                })
        except Exception as e:
            logger.warning(f"فحص RDP: {e}")
        return findings
    
    def _check_unencrypted_ports(self, ec2_client) -> List[Dict]:
        """فحص المنافذ غير المشفرة"""
        findings = []
        try:
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            unencrypted_ports = [21, 23, 80, 1433, 3306, 5432, 6379]
            
            for sg in security_groups:
                for permission in sg.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = permission.get('FromPort', 0)
                            if port in unencrypted_ports:
                                findings.append({
                                    "resource_type": "Security Group",
                                    "resource_name": sg['GroupName'],
                                    "resource_id": sg['GroupId'],
                                    "severity": "high",
                                    "title": "منفذ غير مشفر مكشوف",
                                    "description": f"Security Group {sg['GroupName']} يكشف منفذ {port} غير مشفر",
                                    "recommendation": "استخدام HTTPS/SSL بدلاً من HTTP",
                                    "evidence": {"port": port, "cidr": "0.0.0.0/0"}
                                })
        except Exception as e:
            logger.warning(f"فحص المنافذ: {e}")
        return findings
    
    def _check_unrestricted_sg(self, ec2_client) -> List[Dict]:
        """فحص Security Groups بدون قيود"""
        findings = []
        try:
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                if not sg.get('IpPermissions') and not sg.get('IpPermissionsEgress'):
                    findings.append({
                        "resource_type": "Security Group",
                        "resource_name": sg['GroupName'],
                        "resource_id": sg['GroupId'],
                        "severity": "medium",
                        "title": "Security Group بدون قواعد",
                        "description": f"Security Group {sg['GroupName']} ليس له قواعد",
                        "recommendation": "إضافة قواعد أمان مناسبة",
                        "evidence": {"rules_count": 0}
                    })
        except Exception as e:
            logger.warning(f"فحص SG: {e}")
        return findings
    
    def run_checks(self, regions: List[str] = None) -> List[CloudFinding]:
        """تشغيل جميع الفحوصات"""
        all_findings = []
        
        for region in (regions or ['us-east-1']):
            try:
                iam_client = self.session.client('iam', region_name=region)
                s3_client = self.session.client('s3', region_name=region)
                ec2_client = self.session.client('ec2', region_name=region)
                
                # فحوصات IAM
                for check in self.IAM_CHECKS:
                    findings = check['check'](iam_client)
                    for finding in findings:
                        all_findings.append(self._create_finding(check, finding, region, CloudProvider.AWS))
                
                # فحوصات S3
                for check in self.S3_CHECKS:
                    findings = check['check'](s3_client)
                    for finding in findings:
                        all_findings.append(self._create_finding(check, finding, region, CloudProvider.AWS))
                
                # فحوصات Security Groups
                for check in self.SG_CHECKS:
                    findings = check['check'](ec2_client)
                    for finding in findings:
                        all_findings.append(self._create_finding(check, finding, region, CloudProvider.AWS))
                        
            except Exception as e:
                logger.warning(f"فشل الفحص في المنطقة {region}: {e}")
        
        return all_findings
    
    def _create_finding(self, check: Dict, finding: Dict, region: str, provider: CloudProvider) -> CloudFinding:
        """إنشاء نتيجة فحص"""
        return CloudFinding(
            finding_id=f"{check['id']}-{hashlib.md5(finding['resource_id'][:8].encode()).hexdigest()[:6]}",
            category=check['category'],
            provider=provider,
            severity=SeverityLevel(check['severity']),
            title=check['title'],
            description=finding['description'],
            recommendation=finding['recommendation'],
            resource_type=finding['resource_type'],
            resource_name=finding['resource_name'],
            resource_id=finding['resource_id'],
            region=region,
            evidence=finding.get('evidence', {}),
            compliance_frameworks=["CIS-AWS", "PCI-DSS"]
        )


class TerraformScanner:
    """ماسح Terraform Infrastructure as Code"""
    
    # أنماط Terraform الخطرة
    TERRAFORM_VULNERABILITIES = [
        {
            "id": "TF-001",
            "pattern": r'resource\s*"aws_s3_bucket"\s*"[^"]+"\s*\{[^}]*acl\s*=\s*"public-read',
            "severity": "critical",
            "title": "دلو S3 عام في Terraform",
            "description": "تم تعريف دلو S3 مع ACL عام",
            "recommendation": "إزالة ACL العام واستخدام سياسات IAM",
            "category": FindingCategory.STORAGE
        },
        {
            "id": "TF-002",
            "pattern": r'resource\s*"aws_instance"\s*"[^"]+"\s*\{[^}]*key_name\s*=\s*"[^"]*',
            "severity": "high",
            "title": "مفتاح SSH في Terraform",
            "description": "تم تحديد مفتاح SSH في تعريف EC2",
            "recommendation": "إدارة مفاتيح SSH بشكل منفصل",
            "category": FindingCategory.COMPUTE
        },
        {
            "id": "TF-003",
            "pattern": r'resource\s*"aws_security_group"\s*"[^"]+"\s*\{[^}]*ingress[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
            "severity": "critical",
            "title": "Security Group مفتوح للعالم",
            "description": "Security Group يسمح بالوصول من 0.0.0.0/0",
            "recommendation": "تقييد CIDR blocks إلى IPs المطلوبة",
            "category": FindingCategory.NETWORK
        },
        {
            "id": "TF-004",
            "pattern": r'provider\s*"aws"\s*\{[^}]*region\s*=\s*"us-east-1',
            "severity": "info",
            "title": "منطقة غير مناسبة",
            "description": "استخدام منطقة us-east-1 قد لا يكون مناسباً",
            "recommendation": "اختيار المنطقة المناسبة للبيانات",
            "category": FindingCategory.COMPLIANCE
        },
        {
            "id": "TF-005",
            "pattern": r'resource\s*"aws_db_instance"\s*"[^"]+"\s*\{[^}]*storage_encrypted\s*=\s*false',
            "severity": "high",
            "title": "قاعدة بيانات غير مشفرة",
            "description": "قاعدة البيانات لا تستخدم تشفير",
            "recommendation": "تفعيل تشفير storage_encrypted = true",
            "category": FindingCategory.DATABASE
        },
        {
            "id": "TF-006",
            "pattern": r'(password|secret|api_key|token)\s*=\s*"[^"]{8,}"',
            "severity": "critical",
            "title": "بيانات حساسة في الكود",
            "description": "تم وضع بيانات حساسة مباشرة في الكود",
            "recommendation": "استخدام متغيرات البيئة أو AWS Secrets Manager",
            "category": FindingCategory.IAM
        },
        {
            "id": "TF-007",
            "pattern": r'resource\s*"aws_iam_user"\s*"[^"]+"\s*\{[^}]*policy\s*=\s*<<-EOF\s*\*',
            "severity": "critical",
            "title": "سياسة IAM واسعة",
            "description": "سياسة IAM تسمح بـ *:*",
            "recommendation": "تطبيق مبدأ الحد الأدنى من الصلاحيات",
            "category": FindingCategory.IAM
        },
        {
            "id": "TF-008",
            "pattern": r'resource\s*"kubernetes_pod"\s*"[^"]+"\s*\{[^}]*privileged\s*=\s*true',
            "severity": "critical",
            "title": "Pod في وضع Privileged",
            "description": "Pod يعمل بصلاحيات الجذر",
            "recommendation": "تجنب استخدام privileged = true",
            "category": FindingCategory.CONTAINER
        },
        {
            "id": "TF-009",
            "pattern": r'resource\s*"azurerm_storage_container"\s*"[^"]+"\s*\{[^}]*container_access_type\s*=\s*"blob',
            "severity": "high",
            "title": "حاوية Azure Storage عامة",
            "description": "حاوية التخزين عامة",
            "recommendation": "استخدام private access_type",
            "category": FindingCategory.STORAGE
        },
        {
            "id": "TF-010",
            "pattern": r'resource\s*"google_storage_bucket"\s*"[^"]+"\s*\{[^}]*location\s*=\s*"US',
            "severity": "info",
            "title": "موقع بيانات في US",
            "description": "تخزين البيانات في موقع US قد يخضع لقوانين معينة",
            "recommendation": "اختيار موقع مناسب لمتطلبات البيانات",
            "category": FindingCategory.COMPLIANCE
        },
    ]
    
    def scan_directory(self, directory: str) -> List[CloudFinding]:
        """فحص مجلد Terraform"""
        findings = []
        
        tf_files = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.endswith(('.tf', '.tfvars')):
                    tf_files.append(os.path.join(root, file))
        
        for tf_file in tf_files:
            try:
                with open(tf_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for vuln in self.TERRAFORM_VULNERABILITIES:
                    matches = re.finditer(vuln['pattern'], content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_no = content[:match.start()].count('\n') + 1
                        
                        finding = CloudFinding(
                            finding_id=f"{vuln['id']}-{hashlib.md5(tf_file.encode()).hexdigest()[:6]}",
                            category=FindingCategory(vuln['category']),
                            provider=CloudProvider.UNKNOWN,
                            severity=SeverityLevel(vuln['severity']),
                            title=vuln['title'],
                            description=f"{vuln['description']} في الملف {tf_file}",
                            recommendation=vuln['recommendation'],
                            resource_type="Terraform Resource",
                            resource_name=os.path.basename(tf_file),
                            resource_id=tf_file,
                            region="N/A",
                            evidence={
                                "file": tf_file,
                                "line": line_no,
                                "matched_text": match.group()[:200]
                            },
                            compliance_frameworks=["CIS-Cloud", "PCI-DSS"]
                        )
                        
                        findings.append(finding)
                        
            except Exception as e:
                logger.warning(f"فشل قراءة ملف {tf_file}: {e}")
        
        return findings


class CloudSecurityScanner:
    """الماسح الرئيسي لأمان السحابة"""
    
    def __init__(self):
        self.terraform_scanner = TerraformScanner()
        self.aws_checker = None
        self.session = None
    
    def _init_aws(self) -> bool:
        """تهيئة اتصال AWS"""
        try:
            self.session = boto3.Session()
            self.aws_checker = AWSSecurityChecker(self.session)
            sts_client = self.session.client('sts')
            sts_client.get_caller_identity()
            return True
        except Exception as e:
            logger.warning(f"无法连接到 AWS: {e}")
            return False
    
    def scan_aws(self, regions: List[str] = None) -> CloudScanResult:
        """فحص AWS"""
        import time
        start_time = time.time()
        
        result = CloudScanResult(
            scan_id=hashlib.md5(f"aws-{time.time()}".encode()).hexdigest()[:8],
            scan_time=datetime.now().isoformat(),
            scan_duration=0,
            provider=CloudProvider.AWS,
            target="AWS Account"
        )
        
        if not self._init_aws():
            logger.error("无法连接到 AWS")
            return result
        
        # تشغيل الفحوصات
        findings = self.aws_checker.run_checks(regions)
        result.findings = findings
        
        # تحديث الإحصائيات
        for finding in findings:
            result.total_findings += 1
            result.findings_by_severity[finding.severity.value] += 1
            result.findings_by_category[finding.category.value] = \
                result.findings_by_category.get(finding.category.value, 0) + 1
        
        # حساب النتيجة
        self._calculate_score(result)
        result.scan_duration = time.time() - start_time
        
        return result
    
    def scan_terraform(self, directory: str = ".") -> CloudScanResult:
        """فحص Terraform"""
        import time
        start_time = time.time()
        
        result = CloudScanResult(
            scan_id=hashlib.md5(f"terraform-{time.time()}".encode()).hexdigest()[:8],
            scan_time=datetime.now().isoformat(),
            scan_duration=0,
            provider=CloudProvider.UNKNOWN,
            target=f"Terraform: {directory}"
        )
        
        # فحص Terraform
        findings = self.terraform_scanner.scan_directory(directory)
        result.findings = findings
        result.total_resources = len(findings)
        
        # تحديث الإحصائيات
        for finding in findings:
            result.total_findings += 1
            result.findings_by_severity[finding.severity.value] += 1
            result.findings_by_category[finding.category.value] = \
                result.findings_by_category.get(finding.category.value, 0) + 1
        
        # حساب النتيجة
        self._calculate_score(result)
        result.scan_duration = time.time() - start_time
        
        return result
    
    def _calculate_score(self, result: CloudScanResult):
        """حساب نقاط المخاطر"""
        deductions = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1
        }
        
        total_deduction = 0
        for severity, count in result.findings_by_severity.items():
            total_deduction += count * deductions.get(severity, 5)
        
        result.risk_score = max(0, min(100, 100 - total_deduction))
        
        # التقييم الأمني
        if result.risk_score >= 90:
            result.security_rating = "A+"
        elif result.risk_score >= 80:
            result.security_rating = "A"
        elif result.risk_score >= 70:
            result.security_rating = "B"
        elif result.risk_score >= 60:
            result.security_rating = "C"
        elif result.risk_score >= 50:
            result.security_rating = "D"
        else:
            result.security_rating = "F"
        
        # التوصيات
        result.recommendations = self._generate_recommendations(result)
    
    def _generate_recommendations(self, result: CloudScanResult) -> List[str]:
        """توليد التوصيات"""
        recommendations = []
        
        if result.findings_by_severity["critical"] > 0:
            recommendations.append("🔴 الأولوية القصوى: إصلاح الثغرات الحرجة فوراً")
        
        if result.findings_by_severity["high"] > 0:
            recommendations.append("🟠 معالجة الثغرات العالية خلال أسبوع")
        
        if result.findings_by_category.get(FindingCategory.IAM.value, 0) > 0:
            recommendations.append("👤 مراجعة سياسات IAM وتطبيق مبدأ الحد الأدنى من الصلاحيات")
        
        if result.findings_by_category.get(FindingCategory.NETWORK.value, 0) > 0:
            recommendations.append("🌐 مراجعة Security Groups وتقييد الوصول")
        
        if result.findings_by_category.get(FindingCategory.STORAGE.value, 0) > 0:
            recommendations.append("💾 تفعيل التشفير لجميع خدمات التخزين")
        
        if result.risk_score < 70:
            recommendations.append("📊 إجراء مراجعة أمنية شاملة للبنية التحتية")
        
        return recommendations
    
    def save_results(self, result: CloudScanResult, output_path: str = None):
        """حفظ النتائج"""
        if output_path is None:
            output_path = "public/data/cloud_scan_results.json"
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        result_dict = {
            "scan_id": result.scan_id,
            "scan_time": result.scan_time,
            "scan_duration_seconds": round(result.scan_duration, 2),
            "provider": result.provider.value,
            "target": result.target,
            "total_resources": result.total_resources,
            "total_findings": result.total_findings,
            "risk_score": result.risk_score,
            "security_rating": result.security_rating,
            "findings_by_severity": result.findings_by_severity,
            "findings_by_category": result.findings_by_category,
            "recommendations": result.recommendations,
            "findings": [
                {
                    "id": f.finding_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "resource_id": f.resource_id,
                    "region": f.region,
                    "evidence": f.evidence,
                    "compliance_frameworks": f.compliance_frameworks
                }
                for f in result.findings
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=4, ensure_ascii=False)
        
        logger.info(f"تم حفظ النتائج في: {output_path}")


def main():
    """البرنامج الرئيسي"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Auto-Guardian Cloud Security Scanner"
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["aws", "terraform"],
        default="terraform",
        help="مزود السحابة للفحص"
    )
    parser.add_argument(
        "--directory", "-d",
        default=".",
        help="المجلد للفحص (للـ Terraform)"
    )
    parser.add_argument(
        "--regions", "-r",
        nargs="+",
        help="مناطق AWS للفحص"
    )
    parser.add_argument(
        "--output", "-o",
        help="مسار حفظ النتائج"
    )
    
    args = parser.parse_args()
    
    scanner = CloudSecurityScanner()
    
    if args.provider == "aws":
        # فحص AWS
        result = scanner.scan_aws(args.regions)
    else:
        # فحص Terraform
        result = scanner.scan_terraform(args.directory)
    
    # حفظ النتائج
    output_path = args.output or f"public/data/cloud_{args.provider}_scan_results.json"
    scanner.save_results(result, output_path)
    
    print(f"""
╔════════════════════════════════════════════════════════════╗
║        ☁️ Auto-Guardian Cloud Security Scanner             ║
╠════════════════════════════════════════════════════════════╣
║  المستهدف: {result.target[:45]:<45} ║
║  الفحص: {result.provider.value:<50} ║
╠════════════════════════════════════════════════════════════╣
║  📊 نقاط الأمان: {result.risk_score}/100 ({result.security_rating}){' '*28} ║
║  الموارد المفحوصة: {result.total_resources:<37} ║
║  الثغرات المكتشفة: {result.total_findings:<37} ║
╠════════════════════════════════════════════════════════════╣
║  🔴 حرج: {result.findings_by_severity['critical']:<5}  🟠 عالي: {result.findings_by_severity['high']:<5}  🟡 متوسط: {result.findings_by_severity['medium']:<4}  🔵 منخفض: {result.findings_by_severity['low']:<4} ║
╠════════════════════════════════════════════════════════════╣
║  ⏱️ مدة الفحص: {result.scan_duration:.2f} ثانية{' '*33} ║
╚════════════════════════════════════════════════════════════╝
    """)


if __name__ == "__main__":
    main()
