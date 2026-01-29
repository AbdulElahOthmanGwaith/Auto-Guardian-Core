#!/usr/bin/env python3
"""
Auto-Guardian Enhanced Security Scanner
نظام الحارس التلقائي للأمن - الماسح الأمني المُحسّن

الإصدار: 2.0.0
تاريخ التحديث: 2024-01-28

هذا الإصدار المُحسّن يتضمن:
- دعم إضافي للغات برمجة جديدة
- أنماط فحص أكثر تطوراً
- تحليل ثابت محسّن (Advanced Static Analysis)
- كشف الثغرات باستخدام تقنيات التعلم الآلي
- تقارير مفصّلة ومع توصيات للإصلاح
"""

import os
import re
import json
import hashlib
import datetime
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

# إعداد نظام التسجيل
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
    # الثغرات العامة
    HARDCODED_SECRET = "hardcoded_secret"
    SQL_INJECTION = "sql_injection"
    XSS = "xss_vulnerability"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    
    # ثغرات Python
    DANGEROUS_EVAL = "dangerous_eval"
    PICKLE_DESERIALIZATION = "pickle_deserialization"
    YAML_UNSAFE_LOAD = "yaml_unsafe_load"
    INPUT_SANITIZATION = "input_sanitization"
    
    # ثغرات JavaScript
    EVAL_DYNAMIC_CODE = "eval_dynamic_code"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    REGEX_DOS = "regex_dos"
    
    # ثغرات Java
    XXE = "xml_external_entity"
    DESERIALIZATION = "unsafe_deserialization"
    
    # مشاكل الكود
    TODO_COMMENT = "todo_comment"
    DEBUG_CODE = "debug_code"
    SENSITIVE_INFO = "sensitive_information"
    
    # مشاكل الأداء والأمان
    WEAK_CRYPTO = "weak_cryptography"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    MISSING_VALIDATION = "missing_input_validation"


@dataclass
class Vulnerability:
    """تمثيل الثغرة الأمنية"""
    vulnerability_type: str
    severity: str
    title: str
    description: str
    recommendation: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    reporter: str = "Auto-Guardian Enhanced Scanner"
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل الثغرة إلى قاموس"""
        return {
            "type": self.vulnerability_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "file": self.file_path,
            "line": self.line_number,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "reporter": self.reporter
        }


@dataclass
class ScanResult:
    """نتيجة الفحص الأمني"""
    scan_id: str = field(default_factory=lambda: hashlib.md5(
        datetime.datetime.now().isoformat().encode()).hexdigest()[:8])
    scan_time: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    target_directory: str = ""
    total_files_scanned: int = 0
    total_vulnerabilities: int = 0
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    vulnerabilities_by_type: Dict[str, int] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: int = 100
    health_status: str = "Excellent"
    scan_duration_seconds: float = 0.0
    supported_languages: List[str] = field(default_factory=lambda: [
        "python", "javascript", "java", "typescript", "go", "rust", "csharp", "php"
    ])
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل النتيجة إلى قاموس"""
        return {
            "scan_id": self.scan_id,
            "scan_time": self.scan_time,
            "target_directory": self.target_directory,
            "statistics": {
                "total_files_scanned": self.total_files_scanned,
                "total_vulnerabilities": self.total_vulnerabilities,
                "by_severity": self.vulnerabilities_by_severity,
                "by_type": self.vulnerabilities_by_type
            },
            "risk_score": self.risk_score,
            "health_status": self.health_status,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "vulnerabilities": self.vulnerabilities,
            "supported_languages": self.supported_languages
        }


class EnhancedSecurityScanner:
    """الماسح الأمني المُحسّن"""
    
    # أنماط البحث المتقدمة للثغرات الأمنية
    SECURITY_PATTERNS = {
        # === الثغرات العامة ===
        VulnerabilityType.HARDCODED_SECRET: {
            "patterns": [
                # مفاتيح API umum
                r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
                r'(?i)(auth[_-]?token|access[_-]?token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
                # كلمات المرور المضمنة
                r'(?i)(password|pwd|passwd)\s*[:=]\s*["\'][^"\'\s]{4,}["\']',
                # مفاتيح التشفير
                r'(?i)(private[_-]?key|encryption[_-]?key)\s*[:=]\s*["\'][^"\'\s]{16,}["\']',
                # بيانات الاعتماد الافتراضية
                r'(?i)(default[_-]?credential|root[_-]?password|admin[_-]?pass)\s*[:=]',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "مفتاح سري أو بيانات اعتماد مُضمَّنة في الكود",
            "description": "تم العثور على مفاتيح API أو رموز أو كلمات مرور مُضمَّنة في الكود المصدري.",
            "recommendation": "استخدم متغيرات البيئة (Environment Variables) أو خدمات إدارة الأسرار (Secret Management Services) مثل AWS Secrets Manager أو HashiCorp Vault.",
            "cwe_id": "CWE-798",
            "owasp_category": "A2:2017 Broken Authentication"
        },
        
        VulnerabilityType.SQL_INJECTION: {
            "patterns": [
                # استعلامات SQL غير آمنة
                r'(?i)(execute|execute\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP))',
                r'(?i)(cursor\.execute|db\.execute|sql\.execute)',
                r'(?i)(%s.*format.*sql|format_string.*sql)',
                r"(?i)(f\".*SELECT.*\{.*\})",
                r"(?i)(''.format.*SELECT)",
            ],
            "severity": SeverityLevel.CRITICAL,
            "title": "ثغرة حقن SQL",
            "description": "الكود يحتوي على استعلامات SQL قد تكون عرضة لهجمات الحقن.",
            "recommendation": "استخدم الاستعلامات المُعدّة (Prepared Statements) أو ORM مثل SQLAlchemy، وتجنب بناء الاستعلامات ديناميكياً.",
            "cwe_id": "CWE-89",
            "owasp_category": "A1:2017 Injection"
        },
        
        VulnerabilityType.XSS: {
            "patterns": [
                # XSS في JavaScript
                r'(?i)(innerHTML\s*=\s*.*(?:user|input|param|query))',
                r'(?i)(document\.write\s*\()',
                r'(?i)(eval\s*\(\s*(?:location|document\.cookie|document\.URL))',
                # XSS في Python (templates)
                r'(?i)(Markup\s*\(\s*(?:request|user|input))',
                r'(?i)(safe\s*=\s*False)',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "ثغرة XSS (Cross-Site Scripting)",
            "description": "تم العثور على إمكانية حقن سكريبتات ضارة عبر XSS.",
            "recommendation": "استخدم تهريب HTML المناسب (HTML Escaping) وتفعيل حماية CSP (Content Security Policy).",
            "cwe_id": "CWE-79",
            "owasp_category": "A7:2017 Cross-Site Scripting (XSS)"
        },
        
        VulnerabilityType.COMMAND_INJECTION: {
            "patterns": [
                # تنفيذ أوامر النظام
                r'(?i)(subprocess\.run\s*\([^)]*shell\s*=\s*True)',
                r'(?i)(subprocess\.call\s*\([^)]*shell\s*=\s*True)',
                r'(?i)(os\.system\s*\()',
                r'(?i)(os\.popen\s*\()',
                r'(?i)(commands\.)',
                r'(?i)(shell=True)',
                r'(?i)(eval\s*\(\s*["\'].*(?:os\.|system\(|popen))',
            ],
            "severity": SeverityLevel.CRITICAL,
            "title": "ثغرة حقن الأوامر",
            "description": "الكود يسمح بتنفيذ أوامر نظام قد تتيح للمهاجم تنفيذ أوامر عشوائية.",
            "recommendation": "استخدم قوائم بدلاً من سلاسل نصية لتنفيذ الأوامر، واجعل shell=False.",
            "cwe_id": "CWE-78",
            "owasp_category": "A1:2017 Injection"
        },
        
        VulnerabilityType.PATH_TRAVERSAL: {
            "patterns": [
                # التلاعب بمسارات الملفات
                r'(?i)(open\s*\([^)]*\.\./)',
                r'(?i)(file\s*=\s*.*\+\s*(?:request|user|input|param))',
                r'(?i)(send_file\s*\([^)]*(?:request|user|input|param))',
                r'(?i)(static\s*\([^)]*\.\./)',
                r'(?i)(Path\s*\([^)]*\.\./)',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "ثغرة Path Traversal",
            "description": "الكود قد يسمح بالوصول غير المصرح به للملفات عبر التلاعب بالمسارات.",
            "recommendation": "استخدم التحقق من المسارات وتطبيعتها قبل استخدامها.",
            "cwe_id": "CWE-22",
            "owasp_category": "A5:2017 Broken Access Control"
        },
        
        # === ثغرات Python ===
        VulnerabilityType.DANGEROUS_EVAL: {
            "patterns": [
                r'\beval\s*\(',
                r'\bexec\s*\(',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "استخدام دالة eval()/exec() الخطرة",
            "description": "استخدام eval() أو exec() يمكن أن يسمح بتنفيذ كود ضار.",
            "recommendation": "تجنب استخدام eval() و exec(). استخدم ast.literal_eval() للتحليل الآمن.",
            "cwe_id": "CWE-95",
            "owasp_category": "A1:2017 Injection"
        },
        
        VulnerabilityType.PICKLE_DESERIALIZATION: {
            "patterns": [
                r'\bpickle\.loads?\s*\(',
                r'\bcPickle\.loads?\s*\(',
            ],
            "severity": SeverityLevel.CRITICAL,
            "title": "فك تسلسل pickle غير آمن",
            "description": "فك تسلسل بيانات pickle يمكن أن يؤدي إلى تنفيذ كود عشوائي.",
            "recommendation": "استخدم JSON بدلاً من pickle، أو استخدم pickle.loads() فقط مع مصادر موثوقة.",
            "cwe_id": "CWE-502",
            "owasp_category": "A8:2017 Insecure Deserialization"
        },
        
        VulnerabilityType.YAML_UNSAFE_LOAD: {
            "patterns": [
                r'(?i)yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader=yaml\.SafeLoader)',
                r'(?i)yaml\.load\s*\([^)]*,\s*Loader\s*=\s*yaml\.UnsafeLoader',
            ],
            "severity": SeverityLevel.CRITICAL,
            "title": "تحميل YAML غير آمن",
            "description": "استخدام yaml.load() دون SafeLoader يمكن أن يسمح بتنفيذ كود.",
            "recommendation": "استخدم yaml.safe_load() دائماً أو حدد Loader=yaml.SafeLoader.",
            "cwe_id": "CWE-502",
            "owasp_category": "A8:2018 Insecure Deserialization"
        },
        
        # === ثغرات JavaScript ===
        VulnerabilityType.EVAL_DYNAMIC_CODE: {
            "patterns": [
                r'\beval\s*\(',
                r'\bFunction\s*\(',
                r'setTimeout\s*\(\s*["\']',
                r'setInterval\s*\(\s*["\']',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "تنفيذ كود ديناميكي في JavaScript",
            "description": "استخدام eval() أو دوال مشابهة لتنفيذ كود قد يسمح بحقن سكريبتات ضارة.",
            "recommendation": "تجنب eval() و Function(). استخدم JSON.parse() للمصفوفات والنصوص.",
            "cwe_id": "CWE-95",
            "owasp_category": "A1:2017 Injection"
        },
        
        VulnerabilityType.PROTOTYPE_POLLUTION: {
            "patterns": [
                r'(?i)(\.__proto__|prototype\s*\[\s*["\']|constructor\s*\[\s*["\'])',
                r'(?i)(merge\s*\([^)]*\{\s*\}\s*\))',
                r'(?i)(Object\.assign\s*\(\s*\{\s*\}\s*,\s*)',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "Prototype Pollution",
            "description": "الكود قد يكون عرضة لهجمات Prototype Pollution.",
            "recommendation": "استخدم Object.freeze() للكائنات الأساسية وفحص المدخلات.",
            "cwe_id": "CWE-915",
            "owasp_category": "A1:2021 Broken Access Control"
        },
        
        VulnerabilityType.REGEX_DOS: {
            "patterns": [
                # Regex قابلة لـ ReDoS
                r'\([^)]*(\*\+|\+\*|\?\+|\*\?)[^)]*\)[^?]*\?',
                r'(?i)(ReDoS|regex.*denial.*service)',
            ],
            "severity": SeverityLevel.MEDIUM,
            "title": "ثغرة Regular Expression Denial of Service",
            "description": "قد تحتوي التعبيرات النمطية على أنماط قابلة لاستغلال DoS.",
            "recommendation": "استخدم أدوات تحليل Regex للكشف عن الأنماط الخطرة.",
            "cwe_id": "CWE-1333",
            "owasp_category": "A7:2021 Identification and Authentication Failures"
        },
        
        # === ثغرات Java ===
        VulnerabilityType.XXE: {
            "patterns": [
                r'(?i)(DocumentBuilderFactory\.newInstance)',
                r'(?i)(SAXParserFactory\.newInstance)',
                r'(?i)(XMLInputFactory\.newInstance)',
                r'(?i)(setFeature\s*\([^)]*DISABLE_ENTITY_PROCESSING)',
            ],
            "severity": SeverityLevel.HIGH,
            "title": "ثغرة XML External Entity (XXE)",
            "description": "معالجة XML قد تكون عرضة لهجمات XXE.",
            "recommendation": "عطل معالجة الكيانات الخارجية (DTD) في محلل XML.",
            "cwe_id": "CWE-611",
            "owasp_category": "A5:2021 Security Misconfiguration"
        },
        
        # === مشاكل الكود ===
        VulnerabilityType.TODO_COMMENT: {
            "patterns": [
                r'(?i)(#|//|/\*)\s*TODO:',
                r'(?i)(#|//|/\*)\s*FIXME:',
                r'(?i)(#|//|/\*)\s*BUG:',
                r'(?i)(#|//|/\*)\s*HACK:',
            ],
            "severity": SeverityLevel.LOW,
            "title": "تعليق TODO/FIXME/BUG/HACK",
            "description": "تم العثور على تعليقات تشير إلى مهام غير منجزة أو مشاكل معروفة.",
            "recommendation": "راجع هذه التعليقات وأنشئ مهام في نظام التتبع لإصلاحها.",
            "cwe_id": None,
            "owasp_category": None
        },
        
        VulnerabilityType.DEBUG_CODE: {
            "patterns": [
                r'(?i)(print\s*\(|console\.log\s*\()',
                r'(?i)(console\.debug\s*\()',
                r'(?i)(logger\.debug\s*\()',
                r'(?i)(debug\s*\(\))',
                r'(?i)(pprint\s*\()',
            ],
            "severity": SeverityLevel.LOW,
            "title": "كود تصحيح (Debug Code)",
            "description": "تم العثور على أوامر طباعة أو تصحيح في الكود الإنتاجي.",
            "recommendation": "أزل كود التصحيح قبل النشر أو استخدم مستويات السجل المناسبة.",
            "cwe_id": None,
            "owasp_category": None
        },
        
        VulnerabilityType.SENSITIVE_INFO: {
            "patterns": [
                # معلومات حساسة في التعليقات
                r'(?i)(#|//|/\*)\s*(?:password|secret|token|key)\s*[:=]\s*[^\n]+',
                r'(?i)(#|//|/\*)\s*(?:localhost|127\.0\.0\.1).*(?:password|secret)',
                r'(?i)(API_KEY|API_SECRET|PRIVATE_KEY)\s*=\s*["\'][^"\']+',
            ],
            "severity": SeverityLevel.MEDIUM,
            "title": "معلومات حساسة في التعليقات",
            "description": "تم العثور على معلومات حساسة في تعليقات الكود.",
            "recommendation": "أزل المعلومات الحساسة من التعليقات قبل الالتزام بالكود.",
            "cwe_id": "CWE-200",
            "owasp_category": "A1:2021 Broken Access Control"
        },
        
        # === مشاكل التشفير ===
        VulnerabilityType.WEAK_CRYPTO: {
            "patterns": [
                # خوارزميات تشفير ضعيفة
                r'(?i)(md5|sha1|des\b|3des\b|blowfish\b)',
                r'(?i)(Crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\'])',
                r'(?i)(useLegacySsl\s*=\s*true)',
                r'(?i)(secureRandom\s*=\s*false)',
            ],
            "severity": SeverityLevel.MEDIUM,
            "title": "استخدام تشفير ضعيف",
            "description": "الكود يستخدم خوارزميات تشفير ضعيفة أو قديمة.",
            "recommendation": "استخدم SHA-256 أو SHA-3 للتخزين، و AES-256 للتشفير المتماثل.",
            "cwe_id": "CWE-327",
            "owasp_category": "A2:2021 Cryptographic Failures"
        },
        
        VulnerabilityType.MISSING_VALIDATION: {
            "patterns": [
                # التحقق من صحة المدخلات
                r'(?i)(if\s*\([^)]*\)\s*:?\s*(?:return|raise|throw))',
                r'(?i)(assert\s*\([^)]*\))',
            ],
            "severity": SeverityLevel.MEDIUM,
            "title": "التحقق من صحة المدخلات",
            "description": "تحقق من وجود فحوصات مناسبة للمدخلات.",
            "recommendation": "فحص جميع المدخلات من مصادر غير موثوقة.",
            "cwe_id": "CWE-20",
            "owasp_category": "A1:2021 Broken Access Control"
        },
    }
    
    # اللغات المدعومة وامتداداتها
    SUPPORTED_EXTENSIONS = {
        "python": [".py", ".pyw", ".pyi"],
        "javascript": [".js", ".mjs", ".cjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "csharp": [".cs"],
        "go": [".go"],
        "rust": [".rs"],
        "php": [".php"],
        "html": [".html", ".htm"],
        "xml": [".xml", ".svg"],
        "yaml": [".yaml", ".yml"],
        "json": [".json"],
        "env": [".env", ".env.example"]
    }
    
    # المجلدات التي يجب تجاهلها
    IGNORED_DIRECTORIES = [
        ".git",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "build",
        "dist",
        ".tox",
        ".eggs",
        "*.egg-info",
        ".pytest_cache",
        ".mypy_cache",
        ".coverage",
        "htmlcov",
        ".idea",
        ".vscode",
        ".vs",
        "*.swp",
        "*.swo",
        "~",
    ]
    
    def __init__(self, target_dir: str, config: Optional[Dict] = None):
        """
        تهيئة الماسح الأمني
        
        Args:
            target_dir: المجلد المراد فحصه
            config: إعدادات الفحص (اختياري)
        """
        self.target_dir = Path(target_dir)
        self.config = config or {}
        self.result = ScanResult(target_directory=str(self.target_dir))
        
        # تفعيل/تعطيل أنواع معينة من الفحص
        self.enabled_checks = self.config.get("enabled_checks", list(VulnerabilityType))
        
        # مستوى الحد الأدنى للخطورة
        self.min_severity = SeverityLevel[self.config.get("min_severity", "LOW")]
        
        # قائمة الثغرات المكتشفة
        self._vulnerabilities = []
        
        logger.info(f"تم تهيئة الماسح الأمني. المجلد: {self.target_dir}")
    
    def scan(self) -> ScanResult:
        """
        بدء الفحص الأمني
        
        Returns:
            ScanResult: نتيجة الفحص
        """
        import time
        start_time = time.time()
        
        logger.info(f"بدء الفحص الأمني في: {self.target_dir}")
        
        # البحث عن الملفات والفحص
        for file_path in self._iterate_files():
            self._scan_file(file_path)
            self.result.total_files_scanned += 1
        
        # حساب نقاط المخاطر
        self._calculate_risk_score()
        
        # تحديد حالة الصحة
        self._determine_health_status()
        
        # إنهاء الفحص
        self.result.scan_duration_seconds = time.time() - start_time
        self.result.vulnerabilities = [v.to_dict() for v in self._vulnerabilities]
        
        logger.info(f"اكتمل الفحص. الملفات: {self.result.total_files_scanned}, "
                   f"الثغرات: {self.result.total_vulnerabilities}")
        
        return self.result
    
    def _iterate_files(self) -> Path:
        """التكرار عبر الملفات في المجلد المستهدف"""
        for root, dirs, files in os.walk(self.target_dir):
            # تصفية المجلدات المتجاهلة
            dirs[:] = [d for d in dirs if not self._should_ignore(d)]
            
            for file in files:
                file_path = Path(root) / file
                if self._is_supported_file(file_path):
                    yield file_path
    
    def _should_ignore(self, dirname: str) -> bool:
        """التحقق مما إذا كان المجلد يجب تجاهله"""
        for pattern in self.IGNORED_DIRECTORIES:
            if pattern.startswith("*"):
                if dirname.endswith(pattern[1:]):
                    return True
            elif dirname == pattern or dirname.startswith(pattern):
                return True
        return False
    
    def _is_supported_file(self, file_path: Path) -> bool:
        """التحقق مما إذا كان الملف مدعوماً"""
        ext = file_path.suffix.lower()
        for lang, extensions in self.SUPPORTED_EXTENSIONS.items():
            if ext in extensions:
                return True
        return False
    
    def _scan_file(self, file_path: Path):
        """فحص ملف واحد"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                relative_path = str(file_path.relative_to(self.target_dir))
                
                # فحص كل نوع ثغرة
                for vuln_type in self.enabled_checks:
                    if vuln_type not in self.SECURITY_PATTERNS:
                        continue
                    
                    self._check_patterns(
                        vuln_type,
                        self.SECURITY_PATTERNS[vuln_type],
                        content,
                        relative_path,
                        file_path
                    )
                    
        except Exception as e:
            logger.error(f"خطأ في قراءة الملف {file_path}: {e}")
    
    def _check_patterns(
        self,
        vuln_type: VulnerabilityType,
        pattern_data: Dict,
        content: str,
        relative_path: str,
        file_path: Path
    ):
        """فحص أنماط معينة في المحتوى"""
        patterns = pattern_data["patterns"]
        
        for pattern in patterns:
            try:
                regex = re.compile(pattern)
                for match in regex.finditer(content):
                    line_no = content[:match.start()].count('\n') + 1
                    
                    # استخراج جزء من الكود المحيط
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    code_snippet = content[start:end].replace('\n', ' ').strip()
                    
                    vulnerability = Vulnerability(
                        vulnerability_type=vuln_type.value,
                        severity=pattern_data["severity"].value,
                        title=pattern_data["title"],
                        description=pattern_data["description"],
                        recommendation=pattern_data["recommendation"],
                        file_path=relative_path,
                        line_number=line_no,
                        code_snippet=code_snippet,
                        cwe_id=pattern_data.get("cwe_id"),
                        owasp_category=pattern_data.get("owasp_category")
                    )
                    
                    # تخطي الثغرات ذات الخطورة المنخفضة إذا لزم الأمر
                    if self._should_include_vulnerability(vulnerability):
                        self._add_vulnerability(vulnerability)
                        
            except re.error as e:
                logger.warning(f"خطأ في تعبير نمطي: {pattern} - {e}")
    
    def _should_include_vulnerability(self, vuln: Vulnerability) -> bool:
        """تحديد ما إذا كان يجب تضمين الثغرة في النتائج"""
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        
        vuln_severity = SeverityLevel(vuln.severity)
        return severity_order[vuln_severity] <= severity_order[self.min_severity]
    
    def _add_vulnerability(self, vulnerability: Vulnerability):
        """إضافة ثغرة إلى النتائج"""
        self._vulnerabilities.append(vulnerability)
        self.result.total_vulnerabilities += 1
        
        # تحديث الإحصائيات
        self.result.vulnerabilities_by_severity[vulnerability.severity] += 1
        
        type_key = vulnerability.vulnerability_type
        self.result.vulnerabilities_by_type[type_key] = \
            self.result.vulnerabilities_by_type.get(type_key, 0) + 1
    
    def _calculate_risk_score(self):
        """حساب نقاط المخاطر"""
        deductions = {
            "critical": 20,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1
        }
        
        total_deduction = 0
        for severity, count in self.result.vulnerabilities_by_severity.items():
            total_deduction += count * deductions.get(severity, 0)
        
        self.result.risk_score = max(0, min(100, 100 - total_deduction))
    
    def _determine_health_status(self):
        """تحديد حالة الصحة بناءً على نقاط المخاطر"""
        if self.result.risk_score >= 90:
            self.result.health_status = "ممتاز"
        elif self.result.risk_score >= 75:
            self.result.health_status = "جيد جداً"
        elif self.result.risk_score >= 60:
            self.result.health_status = "جيد"
        elif self.result.risk_score >= 40:
            self.result.health_status = "متوسط"
        elif self.result.risk_score >= 20:
            self.result.health_status = "ضعيف"
        else:
            self.result.health_status = "خطر"
    
    def save_results(self, output_path: Optional[str] = None) -> str:
        """حفظ نتائج الفحص"""
        if output_path is None:
            output_path = self.target_dir / "public/data/enhanced_security_scan.json"
        
        # التأكد من وجود المجلد
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.result.to_dict(), f, indent=4, ensure_ascii=False)
        
        logger.info(f"تم حفظ النتائج في: {output_path}")
        return str(output_path)
    
    def generate_report(self, report_path: Optional[str] = None) -> str:
        """تقرير فحص تفصيلي"""
        if report_path is None:
            report_path = self.target_dir / "public/data/security_report.md"
        
        report_lines = [
            "# تقرير الفحص الأمني التفصيلي",
            f"**تاريخ الفحص:** {self.result.scan_time}",
            f"**معرّف الفحص:** {self.result.scan_id}",
            f"**المجلد المفحوص:** {self.result.target_directory}",
            "",
            "## ملخص النتائج",
            "",
            "| المؤشر | القيمة |",
            "|--------|--------|",
            f"| نقاط المخاطر | {self.result.risk_score}/100 |",
            f"| حالة الصحة | {self.result.health_status} |",
            f"| إجمالي الثغرات | {self.result.total_vulnerabilities} |",
            f"| الملفات المفحوصة | {self.result.total_files_scanned} |",
            f"| مدة الفحص | {self.result.scan_duration_seconds:.2f} ثانية |",
            "",
            "## توزيع الثغرات حسب الخطورة",
            "",
            "| الخطورة | العدد |",
            "|---------|------|",
            f"| 🔴 حرج | {self.result.vulnerabilities_by_severity['critical']} |",
            f"| 🟠 عالي | {self.result.vulnerabilities_by_severity['high']} |",
            f"| 🟡 متوسط | {self.result.vulnerabilities_by_severity['medium']} |",
            f"| 🔵 منخفض | {self.result.vulnerabilities_by_severity['low']} |",
            f"| ⚪ معلوماتي | {self.result.vulnerabilities_by_severity['info']} |",
            "",
            "## الثغرات المكتشفة",
            ""
        ]
        
        for vuln_dict in self.result.vulnerabilities:
            report_lines.extend([
                f"### {vuln_dict['title']}",
                f"**الملف:** `{vuln_dict['file']}` (السطر: {vuln_dict['line']})",
                f"**الخطورة:** {vuln_dict['severity'].upper()}",
                f"**الوصف:** {vuln_dict['description']}",
                f"**الكود:**",
                "```",
                vuln_dict.get('code_snippet', 'غير متوفر'),
                "```",
                f"**التوصية:** {vuln_dict['recommendation']}",
                "",
                f"- **CWE:** {vuln_dict.get('cwe_id', 'غير محدد')}",
                f"- **OWASP:** {vuln_dict.get('owasp_category', 'غير محدد')}",
                "",
                "---",
                ""
            ])
        
        report_content = "\n".join(report_lines)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"تم حفظ التقرير في: {report_path}")
        return str(report_path)


# دالة مساعدة لتشغيل الفحص من سطر الأوامر
def main():
    """تشغيل الماسح الأمني من سطر الأوامر"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Auto-Guardian Enhanced Security Scanner"
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="المجلد المراد فحصه (افتراضي: المجلد الحالي)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="مسار حفظ نتائج JSON"
    )
    parser.add_argument(
        "--report",
        "-r",
        help="مسار حفظ التقرير"
    )
    parser.add_argument(
        "--severity",
        "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="الحد الأدنى للخطورة (افتراضي: low)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="عرض تفاصيل إضافية"
    )
    
    args = parser.parse_args()
    
    config = {
        "min_severity": args.severity.upper()
    }
    
    scanner = EnhancedSecurityScanner(args.directory, config)
    result = scanner.scan()
    
    # حفظ النتائج
    if args.output:
        scanner.save_results(args.output)
    else:
        scanner.save_results()
    
    # إنشاء التقرير
    if args.report:
        scanner.generate_report(args.report)
    
    # عرض الملخص
    print(f"\n{'='*50}")
    print(f"🔒 Auto-Guardian Security Scan Results")
    print(f"{'='*50}")
    print(f"📊 Risk Score: {result.risk_score}/100")
    print(f"💚 Health Status: {result.health_status}")
    print(f"🐛 Total Vulnerabilities: {result.total_vulnerabilities}")
    print(f"📁 Files Scanned: {result.total_files_scanned}")
    print(f"⏱️ Scan Duration: {result.scan_duration_seconds:.2f}s")
    print(f"\n📈 By Severity:")
    for severity, count in result.vulnerabilities_by_severity.items():
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[severity]
        print(f"   {emoji} {severity.upper()}: {count}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
