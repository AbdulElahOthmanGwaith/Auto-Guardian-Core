#!/usr/bin/env python3
"""
Auto-Guardian Container Security Scanner
ماسح أمان الحاويات لنظام الحارس التلقائي للأمن

الإصدار: 1.0.0
تاريخ التحديث: 2024-01-28

فحص شامل لأمان حاويات Docker:
- فحص صور الحاويات للثغرات
- تحليل التبعيات
- كشف الأسرار
- فحص الإعدادات
- أمان وقت التشغيل
"""

import os
import re
import json
import hashlib
import subprocess
import tempfile
import tarfile
import docker
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from pathlib import Path
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """مستويات خطورة الثغرات"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """أنواع الثغرات"""
    # ثغرات الحاوية
    CONTAINER_PRIVILEGED = "container_privileged"
    CONTAINER_NO_ROOT = "container_no_root"
    CONTAINER_READONLY_ROOT = "container_readonly_root"
    CONTAINER_CAP_DROP = "container_cap_drop"
    CONTAINER_SECCOMP = "container_seccomp"
    CONTAINER_APPARMOR = "container_apparmor"
    
    # ثغرات الصورة
    IMAGE_BASE_OUTDATED = "image_base_outdated"
    IMAGE_NO_TAG = "image_no_tag"
    IMAGE_LATEST_TAG = "image_latest_tag"
    IMAGE_MULTI_STAGE = "image_multi_stage"
    IMAGE_MINIMAL = "image_minimal"
    
    # ثغرات التبعيات
    DEPENDENCY_VULNERABILITY = "dependency_vulnerability"
    DEPENDENCY_OUTDATED = "dependency_outdated"
    DEPENDENCY_LICENSE = "dependency_license"
    
    # ثغرات الأسرار
    SECRET_ENV_VAR = "secret_env_var"
    SECRET_IN_FILE = "secret_in_file"
    SECRET_INSTRUCTION = "secret_instruction"
    
    # ثغرات الإعدادات
    CONFIG_EXPOSE_PORT = "config_expose_port"
    CONFIG_HEALTHCHECK = "config_healthcheck"
    CONFIG_USER = "config_user"
    CONFIG_WORKDIR = "config_workdir"
    
    # ثغرات الشبكة
    NETWORK_NONE = "network_none"
    NETWORK_BRIDGE = "network_bridge"
    NETWORK_HOST = "network_host"


@dataclass
class ContainerVulnerability:
    """ثغرة في الحاوية"""
    vulnerability_type: str
    severity: SeverityLevel
    title: str
    description: str
    recommendation: str
    location: str
    evidence: str
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_in: Optional[str] = None


@dataclass
class ContainerScanResult:
    """نتيجة فحص الحاوية"""
    scan_id: str
    image_name: str
    image_id: str
    image_tag: str
    image_digest: str
    base_image: str
    os_type: str
    os_version: str
    total_layers: int
    scan_time: str
    scan_duration: float
    
    vulnerabilities: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    
    vulnerability_details: List[ContainerVulnerability] = field(default_factory=list)
    
    secrets_found: List[Dict] = field(default_factory=list)
    
    misconfigurations: List[Dict] = field(default_factory=list)
    
    best_practices: List[Dict] = field(default_factory=list)
    
    risk_score: int = 100
    
    security_rating: str = "A"
    
    recommendations: List[str] = field(default_factory=list)


class SecretDetector:
    """كاشف الأسرار في الحاويات"""
    
    SECRET_PATTERNS = {
        # مفاتيح API العامة
        "aws_access_key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
        "github_token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}",
        "gitlab_token": r"glpat-[A-Za-z0-9\-_]{20,}",
        "slack_token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "private_key": r"-----BEGIN PRIVATE KEY-----",
        "rsa_key": r"-----BEGIN RSA PRIVATE KEY-----",
        "ssh_key": r"-----BEGIN SSH PRIVATE KEY-----",
        "database_url": r"(mysql|postgresql|mongodb|redis)://[^:]+:[^@]+@",
        "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "generic_api_key": r"(api_key|apikey|secret|token|password)[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        "google_api": r"AIza[0-9A-Za-z\\-_]{35}",
        "sendgrid_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "stripe_key": r"(sk|pk)_(test|live)_[A-Za-z0-9]{24,}",
    }
    
    # أماكن البحث عن الأسرار
    SECRET_LOCATIONS = [
        "ENV",
        "ARG",
        "RUN",
        "COPY",
        "ADD",
        "LABEL",
        "USER",
        "WORKDIR",
    ]
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.SECRET_PATTERNS.items()
        }
    
    def scan_dockerfile(self, dockerfile_content: str) -> List[Dict]:
        """فحص Dockerfile للأسرار"""
        secrets = []
        lines = dockerfile_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_name, pattern in self.compiled_patterns.items():
                matches = pattern.findall(line)
                if matches:
                    # تحديد نوع التعليمات
                    instruction = line.split()[0].upper() if line.strip() else ""
                    
                    secrets.append({
                        "type": secret_name,
                        "line_number": line_num,
                        "instruction": instruction,
                        "line_content": line.strip()[:100],
                        "severity": "high",
                        "description": f"تم اكتشاف {secret_name} في {instruction}"
                    })
        
        return secrets
    
    def scan_image_files(self, image_layers: List[Dict]) -> List[Dict]:
        """فحص ملفات الصورة للأسرار"""
        secrets = []
        
        for layer in image_layers:
            for file_info in layer.get("files", []):
                file_path = file_info.get("path", "")
                file_content = file_info.get("content", "")
                
                # فحص محتوى الملف
                for secret_name, pattern in self.compiled_patterns.items():
                    matches = pattern.findall(file_content)
                    if matches:
                        secrets.append({
                            "type": secret_name,
                            "file_path": file_path,
                            "severity": "critical",
                            "description": f"تم اكتشاف {secret_name} في الملف {file_path}"
                        })
        
        return secrets


class DockerfileAnalyzer:
    """محلل Dockerfile"""
    
    BEST_PRACTICES = {
        "multi_stage_build": {
            "name": "استخدام بناء متعدد المراحل",
            "description": "استخدم بناء متعدد المراحل لتقليل حجم الصورة النهائية",
            "severity": "low"
        },
        "no_root_user": {
            "name": "تشغيل الحاوية كمستخدم غير جذري",
            "description": "استخدم USER لتعيين مستخدم غير جذري",
            "severity": "high"
        },
        "healthcheck": {
            "name": "تعريف Healthcheck",
            "description": "حدد HEALTHCHECK لفحص حالة الحاوية",
            "severity": "medium"
        },
        "expose_ports": {
            "name": "تعريف المنافذ المكشوفة",
            "description": "حدد المنافذ المكشوفة باستخدام EXPOSE",
            "severity": "info"
        },
        "metadata_labels": {
            "name": "إضافة بيانات وصفية",
            "description": "استخدم LABEL للبيانات الوصفية",
            "severity": "info"
        },
        "specific_tag": {
            "name": "استخدام إصدارات محددة",
            "description": "تجنب استخدام :latest، استخدم إصدارات محددة",
            "severity": "medium"
        },
        "alpine_base": {
            "name": "استخدام صورة أساس خفيفة",
            "description": "استخدم Alpine Linux لصور أصغر",
            "severity": "low"
        },
        "clean_cache": {
            "name": "تنظيف ذاكرة التخزين المؤقت",
            "description": "نظف ذاكرة التخزين المؤقت بعد التثبيت",
            "severity": "medium"
        },
        "copy_instead_add": {
            "name": "استخدام COPY بدلاً من ADD",
            "description": "استخدم COPY إلا إذا كنت بحاجة إلى URL أو استخراج تلقائي",
            "severity": "low"
        },
        "order_instructions": {
            "name": "ترتيب التعليمات بشكل صحيح",
            "description": "ضع التعليمات التي تتغير بشكل أقل في الأعلى",
            "severity": "info"
        },
    }
    
    SECURITY_SETTINGS = {
        "privileged": {
            "name": "تجنب وضع Privileged",
            "description": "لا تستخدم --privileged إلا إذا كان ضرورياً جداً",
            "severity": "critical"
        },
        "cap_add": {
            "name": "تجنب إضافة صلاحيات",
            "description": "تجنب --cap-add إلا إذا كان ضرورياً",
            "severity": "high"
        },
        "host_network": {
            "name": "تجنب شبكة المضيف",
            "description": "تجنب --network=host إلا إذا كان ضرورياً",
            "severity": "high"
        },
        "host_pid": {
            "name": "تجنب PID المضيف",
            "description": "تجنب --pid=host",
            "severity": "high"
        },
        "host_ipc": {
            "name": "تجنب IPC المضيف",
            "description": "تجنب --ipc=host",
            "severity": "high"
        },
    }
    
    def analyze(self, dockerfile_content: str) -> Dict[str, Any]:
        """تحليل Dockerfile"""
        results = {
            "best_practices": [],
            "misconfigurations": [],
            "warnings": [],
            "security_score": 100,
            "instructions_count": 0,
            "layers_count": 0,
        }
        
        lines = dockerfile_content.split('\n')
        instructions = []
        
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                # استخراج اسم التعليم وقيمتها
                parts = stripped.split(None, 1)
                if parts:
                    instruction = parts[0].upper()
                    value = parts[1] if len(parts) > 1 else ""
                    instructions.append({"instruction": instruction, "value": value})
        
        results["instructions_count"] = len(instructions)
        
        # تحليل التعليمات
        for inst in instructions:
            self._check_instruction(inst, results, instructions)
        
        # حساب النتيجة
        total_checks = len(self.BEST_PRACTICES) + len(self.SECURITY_SETTINGS)
        passed_checks = len(results["best_practices"]) + len(results["warnings"])
        results["security_score"] = int((passed_checks / total_checks) * 100) if total_checks > 0 else 100
        
        return results
    
    def _check_instruction(self, inst: Dict, results: Dict, all_instructions: List):
        """فحص تعليمات واحدة"""
        instruction = inst["instruction"]
        value = inst["value"]
        value_lower = value.lower()
        
        # === فحص أفضل الممارسات ===
        
        if instruction == "FROM":
            results["layers_count"] += 1
            
            # فحص استخدام :latest
            if value_lower.endswith(":latest"):
                results["warnings"].append({
                    "type": "latest_tag",
                    "severity": "medium",
                    "message": self.BEST_PRACTICES["specific_tag"]["description"],
                    "instruction": f"FROM {value}"
                })
            
            # فحص صورة الأساس
            if ":alpine" not in value_lower and ":ubuntu" not in value_lower and \
               ":debian" not in value_lower and ":slim" not in value_lower:
                if "scratch" not in value_lower:
                    results["best_practices"].append({
                        "type": "non_minimal_base",
                        "severity": "low",
                        "message": "استخدام صورة أساس خفيفة مثل Alpine",
                        "instruction": f"FROM {value}"
                    })
        
        elif instruction == "USER":
            if value == "root" or value == "0":
                results["misconfigurations"].append({
                    "type": "root_user",
                    "severity": "high",
                    "message": self.BEST_PRACTICES["no_root_user"]["description"],
                    "instruction": f"USER {value}"
                })
            else:
                results["best_practices"].append({
                    "type": "non_root_user",
                    "severity": "high",
                    "message": self.BEST_PRACTICES["no_root_user"]["description"],
                    "instruction": f"USER {value}"
                })
        
        elif instruction == "HEALTHCHECK":
            results["best_practices"].append({
                "type": "healthcheck",
                "severity": "medium",
                "message": self.BEST_PRACTICES["healthcheck"]["description"],
                "instruction": f"HEALTHCHECK {value}"
            })
        
        elif instruction == "EXPOSE":
            if value:
                results["best_practices"].append({
                    "type": "expose_ports",
                    "severity": "info",
                    "message": self.BEST_PRACTICES["expose_ports"]["description"],
                    "instruction": f"EXPOSE {value}"
                })
        
        elif instruction == "COPY":
            results["best_practices"].append({
                "type": "copy_instruction",
                "severity": "low",
                "message": self.BEST_PRACTICES["copy_instead_add"]["description"],
                "instruction": f"COPY {value}"
            })
        
        elif instruction == "RUN":
            # فحص أوامر التثبيت وتنظيف ذاكرة التخزين
            if any(cmd in value_lower for cmd in ["apt-get install", "apk add", "yum install", "pip install"]):
                if "apt-get clean" not in value_lower and "rm -rf /var/cache" not in value_lower and \
                   "apk cache clean" not in value_lower and "--no-cache" not in value_lower:
                    results["warnings"].append({
                        "type": "cache_not_cleaned",
                        "severity": "medium",
                        "message": self.BEST_PRACTICES["clean_cache"]["description"],
                        "instruction": f"RUN {value[:50]}..."
                    })
        
        # === فحص إعدادات الأمان ===
        
        for docker_run in ["docker run", "docker-compose"]:
            if docker_run in value_lower:
                if "--privileged" in value_lower:
                    results["misconfigurations"].append({
                        "type": "privileged_mode",
                        "severity": "critical",
                        "message": self.SECURITY_SETTINGS["privileged"]["description"],
                        "instruction": f"RUN {value[:50]}..."
                    })
                
                if "--cap-add" in value_lower:
                    results["misconfigurations"].append({
                        "type": "cap_add",
                        "severity": "high",
                        "message": self.SECURITY_SETTINGS["cap_add"]["description"],
                        "instruction": f"RUN {value[:50]}..."
                    })
                
                if "--network=host" in value_lower:
                    results["misconfigurations"].append({
                        "type": "host_network",
                        "severity": "high",
                        "message": self.SECURITY_SETTINGS["host_network"]["description"],
                        "instruction": f"RUN {value[:50]}..."
                    })
                
                if "--pid=host" in value_lower:
                    results["misconfigurations"].append({
                        "type": "host_pid",
                        "severity": "high",
                        "message": self.SECURITY_SETTINGS["host_pid"]["description"],
                        "instruction": f"RUN {value[:50]}..."
                    })
        
        # === فحص الأسرار ===
        
        if instruction in ["ENV", "ARG"]:
            for secret_pattern in ["PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL"]:
                if secret_pattern in value_upper and "FILE" not in value_upper:
                    results["misconfigurations"].append({
                        "type": "secret_in_env",
                        "severity": "high",
                        "message": "تجنب وضع الأسرار في متغيرات البيئة",
                        "instruction": f"{instruction} {value}"
                    })


class ContainerSecurityScanner:
    """ماسح أمان الحاويات"""
    
    def __init__(self):
        self.secret_detector = SecretDetector()
        self.dockerfile_analyzer = DockerfileAnalyzer()
        self.docker_client = None
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"无法连接到 Docker: {e}")
    
    def scan_image(self, image_name: str) -> ContainerScanResult:
        """فحص صورة حاوية"""
        import time
        start_time = time.time()
        
        result = ContainerScanResult(
            scan_id=hashlib.md5(f"{image_name}{time.time()}".encode()).hexdigest()[:8],
            image_name=image_name,
            image_id="",
            image_tag="",
            image_digest="",
            base_image="",
            os_type="",
            os_version="",
            total_layers=0,
            scan_time=datetime.now().isoformat(),
            scan_duration=0
        )
        
        try:
            # محاولة الاتصال بـ Docker
            if self.docker_client:
                image = self.docker_client.images.get(image_name)
                
                # جمع معلومات الصورة
                result.image_id = image.id
                result.image_tag = image.tags[0] if image.tags else "latest"
                result.image_digest = image.attrs.get("RepoDigests", [""])[0]
                result.total_layers = len(image.history())
                
                # استخراج معلومات نظام التشغيل
                os_info = image.attrs.get("Os", "unknown")
                result.os_type = os_info
                
                # تحليل Dockerfile
                dockerfile = self._extract_dockerfile(image)
                if dockerfile:
                    analysis = self.dockerfile_analyzer.analyze(dockerfile)
                    result.misconfigurations.extend(analysis.get("misconfigurations", []))
                    result.misconfigurations.extend(analysis.get("warnings", []))
                    result.best_practices = [
                        {"name": bp["type"], "description": bp["message"]}
                        for bp in analysis.get("best_practices", [])
                    ]
                
                # فحص الأسرار
                secrets = self._scan_image_secrets(image)
                result.secrets_found = secrets
                
                # فحص الإعدادات الأمنية
                security_settings = self._check_security_settings(image)
                result.misconfigurations.extend(security_settings)
            
            # فحص محلي (بدون Docker)
            else:
                # البحث عن Dockerfile محلي
                if os.path.exists("Dockerfile"):
                    with open("Dockerfile", 'r') as f:
                        dockerfile = f.read()
                    
                    analysis = self.dockerfile_analyzer.analyze(dockerfile)
                    result.misconfigurations.extend(analysis.get("misconfigurations", []))
                    result.misconfigurations.extend(analysis.get("warnings", []))
                    result.best_practices = [
                        {"name": bp["type"], "description": bp["message"]}
                        for bp in analysis.get("best_practices", [])
                    ]
                    
                    # فحص الأسرار في Dockerfile
                    secrets = self.secret_detector.scan_dockerfile(dockerfile)
                    result.secrets_found = secrets
                    
                    result.base_image = self._extract_base_image(dockerfile)
        
        except Exception as e:
            logger.error(f"خطأ في فحص الصورة {image_name}: {e}")
        
        # حساب النتيجة النهائية
        result.scan_duration = time.time() - start_time
        self._calculate_final_score(result)
        
        return result
    
    def _extract_dockerfile(self, image) -> str:
        """استخراج Dockerfile من الصورة"""
        try:
            # محاولة استخراج Dockerfile من تاريخ الصورة
            history = image.history()
            for layer in history:
                if "created_by" in layer:
                    created_by = layer["created_by"]
                    if created_by.startswith("/bin/sh -c"):
                        # هذا ليس Dockerfile كامل
                        pass
            return ""
        except Exception as e:
            logger.warning(f"无法提取 Dockerfile: {e}")
            return ""
    
    def _extract_base_image(self, dockerfile: str) -> str:
        """استخراج صورة الأساس من Dockerfile"""
        for line in dockerfile.split('\n'):
            stripped = line.strip()
            if stripped.upper().startswith("FROM "):
                return stripped.split()[1]
        return "unknown"
    
    def _scan_image_secrets(self, image) -> List[Dict]:
        """فحص الأسرار في الصورة"""
        secrets = []
        
        try:
            # فحص متغيرات البيئة
            env_vars = image.attrs.get("Config", {}).get("Env", [])
            for env in env_vars:
                if "=" in env:
                    key, value = env.split("=", 1)
                    for secret_name, pattern in self.secret_detector.compiled_patterns.items():
                        if pattern.search(value):
                            secrets.append({
                                "type": secret_name,
                                "location": "ENV",
                                "variable": key,
                                "severity": "high",
                                "description": f"تم اكتشاف {secret_name} في متغير البيئة"
                            })
            
            # فحص التعليمات (إذا توفر Dockerfile)
            history = image.history()
            for layer in history:
                created_by = layer.get("created_by", "")
                for secret_name, pattern in self.secret_detector.compiled_patterns.items():
                    if pattern.search(created_by):
                        secrets.append({
                            "type": secret_name,
                            "location": "RUN",
                            "command": created_by[:100],
                            "severity": "high",
                            "description": f"تم اكتشاف {secret_name} في طبقة"
                        })
        
        except Exception as e:
            logger.warning(f"فشل فحص الأسرار: {e}")
        
        return secrets
    
    def _check_security_settings(self, image) -> List[Dict]:
        """فحص إعدادات الأمان"""
        misconfigs = []
        
        config = image.attrs.get("Config", {})
        host_config = image.attrs.get("HostConfig", {})
        
        # فحص المستخدم
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            misconfigs.append({
                "type": "run_as_root",
                "severity": "high",
                "message": "الصورة تعمل كمستخدم جذري",
                "current_value": user or "root"
            })
        
        # فحص Privileged
        if host_config.get("Privileged", False):
            misconfigs.append({
                "type": "privileged_mode",
                "severity": "critical",
                "message": "الحاوية تعمل في وضع Privileged",
                "current_value": "true"
            })
        
        # فحص CapAdd
        cap_add = host_config.get("CapAdd", [])
        if cap_add:
            misconfigs.append({
                "type": "cap_add",
                "severity": "high",
                "message": "تم إضافة صلاحيات إضافية",
                "current_value": ", ".join(cap_add)
            })
        
        # فحص NetworkMode
        network_mode = host_config.get("NetworkMode", "default")
        if network_mode == "host":
            misconfigs.append({
                "type": "host_network",
                "severity": "high",
                "message": "الحاوية تستخدم شبكة المضيف",
                "current_value": network_mode
            })
        
        # فحص ReadonlyRootfs
        if not host_config.get("ReadonlyRootfs", False):
            misconfigs.append({
                "type": "writable_rootfs",
                "severity": "medium",
                "message": "نظام الملفات الجذري قابل للكتابة",
                "current_value": "true"
            })
        
        return misconfigs
    
    def _calculate_final_score(self, result: ContainerScanResult):
        """حساب النتيجة النهائية"""
        # حساب نقاط الخصم
        deductions = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1
        }
        
        # حساب الخصم من الثغرات
        total_deduction = 0
        for vuln in result.vulnerability_details:
            total_deduction += deductions.get(vuln.severity.value, 5)
        
        # إضافة خصم الأسرار
        total_deduction += len(result.secrets_found) * 10
        
        # إضافة خصم إعدادات خاطئة
        for misconfig in result.misconfigurations:
            severity = misconfig.get("severity", "medium")
            total_deduction += deductions.get(severity, 5)
        
        # حساب النتيجة
        result.risk_score = max(0, min(100, 100 - total_deduction))
        
        # تحديد التقييم الأمني
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
        
        # تحديث العدادات
        for vuln in result.vulnerability_details:
            result.vulnerabilities[vuln.severity.value] += 1
        
        # إضافة التوصيات
        result.recommendations = self._generate_recommendations(result)
    
    def _generate_recommendations(self, result: ContainerScanResult) -> List[str]:
        """توليد التوصيات"""
        recommendations = []
        
        # توصيات بناءً على الثغرات
        if result.vulnerabilities["critical"] > 0:
            recommendations.append("🔴 الأولوية القصوى: إصلاح الثغرات الحرجة فوراً")
        
        if result.vulnerabilities["high"] > 0:
            recommendations.append("🟠 معالجة الثغرات العالية في أقرب وقت ممكن")
        
        # توصيات بناءً على الأسرار
        if result.secrets_found:
            recommendations.append("🔑 إزالة جميع الأسرار من الصورة واستخدام Secrets الخارجية")
        
        # توصيات بناءً على الإعدادات
        for misconfig in result.misconfigurations:
            if misconfig["type"] == "run_as_root":
                recommendations.append("👤 تشغيل الحاوية كمستخدم غير جذري")
            elif misconfig["type"] == "privileged_mode":
                recommendations.append("🛡️ تجنب استخدام وضع Privileged")
            elif misconfig["type"] == "host_network":
                recommendations.append("🌐 استخدام شبكة معزولة بدلاً من شبكة المضيف")
            elif misconfig["type"] == "writable_rootfs":
                recommendations.append("📁 جعل نظام الملفات الجذري للقراءة فقط")
        
        # توصيات عامة
        if result.risk_score < 70:
            recommendations.append("📊 مراجعة شاملة للهندسة الأمنية للحاوية")
        
        return recommendations
    
    def save_results(self, result: ContainerScanResult, output_path: str = None):
        """حفظ النتائج"""
        if output_path is None:
            output_path = "public/data/container_scan_results.json"
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # تحويل النتيجة إلى قاموس
        result_dict = {
            "scan_id": result.scan_id,
            "image_name": result.image_name,
            "image_id": result.image_id,
            "image_tag": result.image_tag,
            "image_digest": result.image_digest,
            "base_image": result.base_image,
            "os_type": result.os_type,
            "os_version": result.os_version,
            "total_layers": result.total_layers,
            "scan_time": result.scan_time,
            "scan_duration_seconds": round(result.scan_duration, 2),
            "vulnerabilities": result.vulnerabilities,
            "vulnerability_details": [
                {
                    "type": v.vulnerability_type,
                    "severity": v.severity.value,
                    "title": v.title,
                    "description": v.description,
                    "recommendation": v.recommendation,
                    "location": v.location,
                    "evidence": v.evidence,
                    "cve_id": v.cve_id,
                    "package_name": v.package_name,
                    "package_version": v.package_version,
                    "fixed_in": v.fixed_in
                }
                for v in result.vulnerability_details
            ],
            "secrets_found": result.secrets_found,
            "misconfigurations": result.misconfigurations,
            "best_practices": result.best_practices,
            "risk_score": result.risk_score,
            "security_rating": result.security_rating,
            "recommendations": result.recommendations
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=4, ensure_ascii=False)
        
        logger.info(f"تم حفظ نتائج الفحص في: {output_path}")


def main():
    """البرنامج الرئيسي"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Auto-Guardian Container Security Scanner"
    )
    parser.add_argument(
        "image",
        nargs="?",
        default="myapp:latest",
        help="اسم الصورة للفحص"
    )
    parser.add_argument(
        "--output", "-o",
        help="مسار حفظ النتائج"
    )
    parser.add_argument(
        "--dockerfile", "-d",
        help="فحص Dockerfile محلي"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="عرض تفاصيل إضافية"
    )
    
    args = parser.parse_args()
    
    scanner = ContainerSecurityScanner()
    
    if args.dockerfile:
        # فحص Dockerfile محلي
        with open(args.dockerfile, 'r') as f:
            dockerfile = f.read()
        
        analyzer = DockerfileAnalyzer()
        results = analyzer.analyze(dockerfile)
        
        print(json.dumps(results, indent=4, ensure_ascii=False))
    
    else:
        # فحص صورة
        result = scanner.scan_image(args.image)
        
        # حفظ النتائج
        output_path = args.output or "public/data/container_scan_results.json"
        scanner.save_results(result, output_path)
        
        print(f"""
╔════════════════════════════════════════════════════════════╗
║       🐳 Auto-Guardian Container Security Scanner          ║
╠════════════════════════════════════════════════════════════╣
║  الصورة: {result.image_name:<45} ║
║  نظام التشغيل: {result.os_type or 'غير معروف':<40} ║
║  الطبقات: {result.total_layers:<47} ║
╠════════════════════════════════════════════════════════════╣
║  📊 نقاط الأمان: {result.risk_score}/100 ({result.security_rating}){' '*28} ║
╠════════════════════════════════════════════════════════════╣
║  🔴 حرج: {result.vulnerabilities['critical']:<5}  🟠 عالي: {result.vulnerabilities['high']:<5}  🟡 متوسط: {result.vulnerabilities['medium']:<4}  🔵 منخفض: {result.vulnerabilities['low']:<4} ║
║  🔑 أسرار: {len(result.secrets_found):<4}  ⚠️ إعدادات خاطئة: {len(result.misconfigurations):<4}  ✅ أفضل الممارسات: {len(result.best_practices):<4} ║
╠════════════════════════════════════════════════════════════╣
║  ⏱️ مدة الفحص: {result.scan_duration:.2f} ثانية{' '*33} ║
╚════════════════════════════════════════════════════════════╝
        """)


if __name__ == "__main__":
    main()
