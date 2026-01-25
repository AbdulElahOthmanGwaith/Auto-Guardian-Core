import os
import json
import datetime
import re

class SecurityScanner:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.results = {
            "scan_time": str(datetime.datetime.now()),
            "vulnerabilities": [],
            "summary": {"high": 0, "medium": 0, "low": 0},
            "risk_score": 100,
            "health_status": "Excellent",
            "recommendations": []
        }
        # أنماط البحث المتقدمة
        self.patterns = {
            "hardcoded_api_key": {
                "regex": r'(?i)(api_key|secret|password|token|auth)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
                "severity": "high",
                "desc": "تم العثور على مفتاح API أو رمز سري مخزن بشكل ثابت.",
                "recommendation": "استخدم متغيرات البيئة (Environment Variables) لتخزين المفاتيح الحساسة."
            },
            "insecure_eval": {
                "regex": r'eval\(',
                "severity": "high",
                "desc": "استخدام دالة eval() غير الآمنة.",
                "recommendation": "تجنب استخدام eval()؛ استخدم بدائل أكثر أماناً مثل ast.literal_eval() في Python."
            },
            "insecure_subprocess": {
                "regex": r'subprocess\.run\(.*shell=True.*\)',
                "severity": "medium",
                "desc": "تشغيل أوامر النظام مع shell=True قد يؤدي لهجمات حقن الأوامر.",
                "recommendation": "اجعل shell=False ومرر الأوامر كقائمة (List)."
            },
            "todo_comment": {
                "regex": r'#\s*TODO:',
                "severity": "low",
                "desc": "تعليق TODO لم يتم حله.",
                "recommendation": "راجع التعليقات المعلقة وقم بإنهاء المهام المطلوبة."
            }
        }

    def scan_files(self):
        print(f"Starting advanced security scan on: {self.target_dir}")
        for root, dirs, files in os.walk(self.target_dir):
            if any(ignored in root for ignored in ['.git', '__pycache__', 'node_modules', 'venv']):
                continue
                
            for file in files:
                if file.endswith(('.py', '.js', '.html', '.env', '.yml', '.yaml')):
                    self._check_file(os.path.join(root, file))
        
        self._calculate_risk_score()
        self._generate_recommendations()
        self._save_results()

    def _calculate_risk_score(self):
        # حساب نقاط المخاطر (تبدأ من 100 وتنقص بناءً على الثغرات)
        deductions = {
            "high": 15,
            "medium": 5,
            "low": 2
        }
        
        total_deduction = (self.results["summary"]["high"] * deductions["high"] +
                           self.results["summary"]["medium"] * deductions["medium"] +
                           self.results["summary"]["low"] * deductions["low"])
        
        self.results["risk_score"] = max(0, 100 - total_deduction)
        
        if self.results["risk_score"] > 80:
            self.results["health_status"] = "ممتاز"
        elif self.results["risk_score"] > 50:
            self.results["health_status"] = "جيد"
        else:
            self.results["health_status"] = "خطر"

    def _check_file(self, file_path):
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for key, data in self.patterns.items():
                    matches = re.finditer(data["regex"], content)
                    for match in matches:
                        line_no = content.count('\n', 0, match.start()) + 1
                        self.results["vulnerabilities"].append({
                            "file": os.path.relpath(file_path, self.target_dir),
                            "line": line_no,
                            "issue": key,
                            "severity": data["severity"],
                            "description": data["desc"]
                        })
                        self.results["summary"][data["severity"]] += 1
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")

    def _generate_recommendations(self):
        seen_issues = set()
        for vuln in self.results["vulnerabilities"]:
            issue_key = vuln["issue"]
            if issue_key not in seen_issues:
                self.results["recommendations"].append({
                    "issue": issue_key,
                    "recommendation": self.patterns[issue_key]["recommendation"]
                })
                seen_issues.add(issue_key)

    def _save_results(self):
        # حفظ في المسارين لضمان التوافق مع لوحة التحكم
        output_paths = [
            os.path.join(self.target_dir, 'public/data/security_scan_latest.json'),
            os.path.join(self.target_dir, 'dashboard/public/data/latest.json')
        ]
        
        for path in output_paths:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
        
        print(f"Scan complete. Results saved.")

if __name__ == "__main__":
    scanner = SecurityScanner('.')
    scanner.scan_files()
