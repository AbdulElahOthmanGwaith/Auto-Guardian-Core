import re
import json
import os
from datetime import datetime

class LogAnalyzer:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        self.stats = {
            "total_entries": 0,
            "errors": 0,
            "warnings": 0,
            "suspicious_activities": [],
            "last_analysis": ""
        }
        # أنماط الكشف في السجلات
        self.patterns = {
            "auth_failure": r"Failed password for .* from ([\d\.]+)",
            "sql_injection": r"SELECT .* FROM .* WHERE .*=.*",
            "root_login": r"Accepted password for root from ([\d\.]+)"
        }

    def analyze_logs(self):
        """محاكاة تحليل سجلات النظام"""
        print(f"Analyzing logs in: {self.log_dir}")
        
        # محاكاة بيانات في حال عدم وجود ملفات سجلات حقيقية
        self.stats["total_entries"] = 1542
        self.stats["errors"] = 12
        self.stats["warnings"] = 45
        self.stats["last_analysis"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # إضافة نشاط مشبوه وهمي للتدريب
        self.stats["suspicious_activities"].append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "type": "Multiple Auth Failures",
            "source_ip": "192.168.1.105",
            "severity": "high"
        })
        
        self._save_stats()
        return self.stats

    def _save_stats(self):
        output_path = "public/data/log_analysis.json"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.stats, f, indent=4, ensure_ascii=False)
        print(f"Log analysis saved to {output_path}")

if __name__ == "__main__":
    analyzer = LogAnalyzer()
    analyzer.analyze_logs()
