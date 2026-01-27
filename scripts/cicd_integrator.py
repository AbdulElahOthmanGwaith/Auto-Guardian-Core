#!/usr/bin/env python3
"""
Auto-Guardian CI/CD Integration Script
سكربت التكامل مع أنظمة CI/CD لنظام الحارس التلقائي للأمن

الإصدار: 1.0.0
تاريخ التحديث: 2024-01-28

يدعم هذا السكربت التكامل مع:
- GitHub Actions
- GitLab CI
- Jenkins
- CircleCI
- Azure DevOps
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CIPlatform(Enum):
    """منصات CI/CD المدعومة"""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    AZURE_DEVOPS = "azure_devops"
    UNKNOWN = "unknown"


@dataclass
class ScanConfig:
    """تكوين الفحص"""
    target: str = "."
    severity_threshold: str = "medium"
    fail_on_critical: bool = True
    fail_on_high: bool = True
    output_format: str = "json"
    save_results: bool = True
    generate_report: bool = True


@dataclass
class ScanResult:
    """نتيجة الفحص"""
    success: bool = True
    exit_code: int = 0
    risk_score: int = 100
    total_vulnerabilities: int = 0
    by_severity: Dict[str, int] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.by_severity is None:
            self.by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        if self.errors is None:
            self.errors = []


class CICDIntegrator:
    """متكامل CI/CD"""
    
    # متغيرات البيئة لكل منصة
    PLATFORM_ENV_VARS = {
        CIPlatform.GITHUB_ACTIONS: ["GITHUB_ACTIONS", "GITHUB_RUN_ID"],
        CIPlatform.GITLAB_CI: ["GITLAB_CI", "CI_COMMIT_SHA"],
        CIPlatform.JENKINS: ["JENKINS_HOME", "BUILD_NUMBER"],
        CIPlatform.CIRCLECI: ["CIRCLECI", "CIRCLE_BUILD_NUM"],
        CIPlatform.AZURE_DEVOPS: ["SYSTEM_ACCESSTOKEN", "BUILD_BUILDID"],
    }
    
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        self.result = ScanResult()
        self.platform = self._detect_platform()
    
    def _detect_platform(self) -> CIPlatform:
        """اكتشاف منصة CI/CD الحالية"""
        for platform, env_vars in self.PLATFORM_ENV_VARS.items():
            if any(os.environ.get(var) for var in env_vars):
                logger.info(f"تم اكتشاف منصة: {platform.value}")
                return platform
        return CIPlatform.UNKNOWN
    
    def run_scan(self) -> ScanResult:
        """تشغيل الفحص الأمني"""
        logger.info("بدء الفحص الأمني...")
        
        try:
            # استيراد الماسح الأمني المُحسّن
            from scripts.enhanced_security_scanner import EnhancedSecurityScanner
            
            config = {
                "min_severity": self.config.severity_threshold.upper()
            }
            
            scanner = EnhancedSecurityScanner(self.config.target, config)
            scan_result = scanner.scan()
            
            # حفظ النتائج
            if self.config.save_results:
                scanner.save_results()
            
            # إنشاء التقرير
            if self.config.generate_report:
                scanner.generate_report()
            
            # تحويل النتيجة
            self.result.risk_score = scan_result.risk_score
            self.result.total_vulnerabilities = scan_result.total_vulnerabilities
            self.result.by_severity = scan_result.vulnerabilities_by_severity
            
            logger.info(f"اكتمل الفحص. نقاط المخاطر: {self.result.risk_score}")
            
        except Exception as e:
            logger.error(f"فشل الفحص: {e}")
            self.result.success = False
            self.result.errors.append(str(e))
        
        return self.result
    
    def check_exit_conditions(self) -> bool:
        """التحقق من شروط الخروج"""
        should_fail = False
        failure_reason = ""
        
        if self.config.fail_on_critical and self.result.by_severity.get("critical", 0) > 0:
            should_fail = True
            failure_reason = f"تم اكتشاف {self.result.by_severity['critical']} ثغرة حرجة"
        
        if self.config.fail_on_high and self.result.by_severity.get("high", 0) > 0:
            should_fail = True
            if failure_reason:
                failure_reason += " و "
            failure_reason += f"تم اكتشاف {self.result.by_severity['high']} ثغرة عالية"
        
        if should_fail:
            logger.error(f"🚫 فشل البناء: {failure_reason}")
            self.result.exit_code = 1
        else:
            logger.info("✅ اجتاز الفحص الأمني بنجاح")
            self.result.exit_code = 0
        
        return not should_fail
    
    def generate_output(self) -> Dict[str, Any]:
        """توليد مخرجات الفحص"""
        output = {
            "success": self.result.success,
            "exit_code": self.result.exit_code,
            "platform": self.platform.value,
            "scan_config": {
                "target": self.config.target,
                "severity_threshold": self.config.severity_threshold,
                "fail_on_critical": self.config.fail_on_critical,
                "fail_on_high": self.config.fail_on_high
            },
            "results": {
                "risk_score": self.result.risk_score,
                "total_vulnerabilities": self.result.total_vulnerabilities,
                "by_severity": self.result.by_severity,
                "errors": self.result.errors
            },
            "annotations": self._generate_annotations()
        }
        
        return output
    
    def _generate_annotations(self) -> List[Dict[str, Any]]:
        """توليد ملاحظات للفحص (لـ GitHub Actions)"""
        annotations = []
        
        severity_to_level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "notice"
        }
        
        # قراءة نتائج الفحص
        results_path = "public/data/enhanced_security_scan.json"
        if os.path.exists(results_path):
            with open(results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for vuln in data.get("vulnerabilities", [])[:50]:  # Limit to 50 annotations
                level = severity_to_level.get(vuln.get("severity"), "notice")
                annotations.append({
                    "path": vuln.get("file", "unknown"),
                    "start_line": vuln.get("line", 1),
                    "end_line": vuln.get("line", 1),
                    "level": level,
                    "message": f"{vuln.get('title', 'ثغرة أمنية')}: {vuln.get('description', '')}"
                })
        
        return annotations
    
    def set_outputs(self):
        """تعيين مخرجات GitHub Actions"""
        if self.platform == CIPlatform.GITHUB_ACTIONS:
            # تعيين مخرجات GitHub Actions
            outputs = self.generate_output()
            
            # كتابة ملف المخرجات
            output_file = os.environ.get("GITHUB_OUTPUT", "/tmp/github_output.txt")
            with open(output_file, "a") as f:
                f.write(f"risk_score={outputs['results']['risk_score']}\n")
                f.write(f"total_vulnerabilities={outputs['results']['total_vulnerabilities']}\n")
                f.write(f"scan_success={str(outputs['success']).lower()}\n")
            
            logger.info("تم تعيين مخرجات GitHub Actions")
    
    def print_summary(self):
        """طباعة ملخص الفحص"""
        print(f"""
╔════════════════════════════════════════════════════════════╗
║         🛡️ Auto-Guardian CI/CD Scan Summary                 ║
╠════════════════════════════════════════════════════════════╣
║  المنصة: {self.platform.value:<45} ║
║  نقاط المخاطر: {self.result.risk_score}/100{' '*35} ║
║  إجمالي الثغرات: {self.result.total_vulnerabilities}{' '*32} ║
╠════════════════════════════════════════════════════════════╣
║  التوزيع حسب الخطورة:                                      ║
║  🔴 حرج: {self.result.by_severity.get('critical', 0):<5}  🟠 عالي: {self.result.by_severity.get('high', 0):<5}    ║
║  🟡 متوسط: {self.result.by_severity.get('medium', 0):<4}  🔵 منخفض: {self.result.by_severity.get('low', 0):<4}    ║
╠════════════════════════════════════════════════════════════╣
║  حالة الخروج: {self.result.exit_code}{' '*38} ║
╚════════════════════════════════════════════════════════════╝
        """)


def create_github_workflow():
    """إنشاء ملف GitHub Actions Workflow"""
    workflow_content = """name: Auto-Guardian Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # فحص أسبوعي

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
      
      - name: Run Auto-Guardian Security Scan
        run: |
          python scripts/enhanced_security_scanner.py .
          python scripts/cicd_integrator.py .
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: public/data/
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: public/data/security_scan_sarif.json
"""
    
    workflow_path = Path(".github/workflows/security-scan.yml")
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(workflow_path, 'w', encoding='utf-8') as f:
        f.write(workflow_content)
    
    logger.info(f"تم إنشاء ملف GitHub Actions في: {workflow_path}")


def create_gitlab_ci():
    """إنشاء ملف GitLab CI"""
    ci_content = """stages:
  - security
  - test
  - build

security_scan:
  stage: security
  image: python:3.11-slim
  before_script:
    - pip install --upgrade pip
    - pip install -r requirements.txt
  script:
    - python scripts/enhanced_security_scanner.py .
    - python scripts/cicd_integrator.py .
  artifacts:
    paths:
      - public/data/
    expire_in: 1 week
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - schedule
    
variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"
"""
    
    ci_path = Path(".gitlab-ci.yml")
    
    with open(ci_path, 'w', encoding='utf-8') as f:
        f.write(ci_content)
    
    logger.info(f"تم إنشاء ملف GitLab CI في: {ci_path}")


def main():
    """البرنامج الرئيسي"""
    parser = argparse.ArgumentParser(
        description="Auto-Guardian CI/CD Integration"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="المجلد المراد فحصه"
    )
    parser.add_argument(
        "--severity",
        "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="medium",
        help="الحد الأدنى للخطورة (افتراضي: medium)"
    )
    parser.add_argument(
        "--fail-critical",
        action="store_true",
        help="الفشل عند اكتشاف ثغرات حرجة"
    )
    parser.add_argument(
        "--fail-high",
        action="store_true",
        help="الفشل عند اكتشاف ثغرات عالية"
    )
    parser.add_argument(
        "--github-workflow",
        action="store_true",
        help="إنشاء ملف GitHub Actions"
    )
    parser.add_argument(
        "--gitlab-ci",
        action="store_true",
        help="إنشاء ملف GitLab CI"
    )
    
    args = parser.parse_args()
    
    # إنشاء ملفات CI/CD
    if args.github_workflow:
        create_github_workflow()
        return
    
    if args.gitlab_ci:
        create_gitlab_ci()
        return
    
    # تشغيل الفحص
    config = ScanConfig(
        target=args.target,
        severity_threshold=args.severity,
        fail_on_critical=args.fail_critical,
        fail_on_high=args.fail_high
    )
    
    integrator = CICDIntegrator(config)
    integrator.run_scan()
    integrator.check_exit_conditions()
    integrator.set_outputs()
    integrator.print_summary()
    
    sys.exit(integrator.result.exit_code)


if __name__ == "__main__":
    main()
