# استخراج نتائج الفحص وتجميعها في ملف JSON واحد

import json
import os
from datetime import datetime
from pathlib import Path

def load_json_file(filepath, default=None):
    """تحميل ملف JSON مع معالجة الأخطاء"""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return default if default is not None else []
    return default if default is not None else []

def normalize_bandit_result(issue):
    """تطبيع نتيجة Bandit"""
    return {
        "tool": "bandit",
        "tool_name": "Bandit",
        "severity": issue.get("issue_severity", "MEDIUM").upper(),
        "severity_level": get_severity_level(issue.get("issue_severity", "MEDIUM")),
        "file": issue.get("filename", ""),
        "line": issue.get("line_number", 0),
        "column": issue.get("line_range", [0, 0])[0] if issue.get("line_range") else 0,
        "rule_id": issue.get("test_id", ""),
        "rule_name": issue.get("test_name", ""),
        "message": issue.get("issue_text", ""),
        "description": issue.get("issue_text", ""),
        "confidence": issue.get("issue_confidence", "MEDIUM").upper(),
        "remediation": issue.get("more_info", ""),
        "code_snippet": "",
        "language": "python"
    }

def normalize_pylint_result(issue):
    """تطبيع نتيجة Pylint"""
    return {
        "tool": "pylint",
        "tool_name": "Pylint",
        "severity": map_pylint_severity(issue.get("type", "info")),
        "severity_level": get_severity_level(map_pylint_severity(issue.get("type", "info"))),
        "file": issue.get("path", ""),
        "line": issue.get("line", 0),
        "column": issue.get("column", 0),
        "rule_id": issue.get("symbol", ""),
        "rule_name": issue.get("message-id", ""),
        "message": issue.get("message", ""),
        "description": issue.get("message", ""),
        "confidence": "HIGH",
        "remediation": "",
        "code_snippet": issue.get("body", ""),
        "language": "python"
    }

def normalize_eslint_result(issue):
    """تطبيع نتيجة ESLint"""
    return {
        "tool": "eslint",
        "tool_name": "ESLint",
        "severity": map_eslint_severity(issue.get("severity", 1)),
        "severity_level": get_severity_level(map_eslint_severity(issue.get("severity", 1))),
        "file": issue.get("filePath", ""),
        "line": issue.get("line", 0),
        "column": issue.get("column", 0),
        "rule_id": issue.get("ruleId", ""),
        "rule_name": issue.get("ruleId", ""),
        "message": issue.get("message", ""),
        "description": issue.get("message", ""),
        "confidence": "HIGH",
        "remediation": "",
        "code_snippet": issue.get("source", ""),
        "language": "javascript"
    }

def normalize_gosec_result(issue):
    """تطبيع نتيجة Gosec"""
    return {
        "tool": "gosec",
        "tool_name": "Gosec",
        "severity": map_gosec_severity(issue.get("severity", "MEDIUM")),
        "severity_level": get_severity_level(map_gosec_severity(issue.get("severity", "MEDIUM"))),
        "file": issue.get("file", ""),
        "line": issue.get("line", 0),
        "column": 0,
        "rule_id": issue.get("rule_id", ""),
        "rule_name": issue.get("func_name", ""),
        "message": issue.get("details", ""),
        "description": issue.get("details", ""),
        "confidence": "HIGH",
        "remediation": "",
        "code_snippet": "",
        "language": "go"
    }

def normalize_cargo_audit_result(vuln):
    """تطبيع نتيجة Cargo Audit"""
    severity_map = {
        "high": "CRITICAL",
        "medium": "HIGH", 
        "low": "MEDIUM",
        "unknown": "LOW"
    }
    return {
        "tool": "cargo-audit",
        "tool_name": "Cargo Audit",
        "severity": severity_map.get(vuln.get("severity", "unknown"), "MEDIUM"),
        "severity_level": get_severity_level(severity_map.get(vuln.get("severity", "unknown"), "MEDIUM")),
        "file": vuln.get("package", {}).get("name", "unknown"),
        "line": 0,
        "column": 0,
        "rule_id": vuln.get("id", ""),
        "rule_name": vuln.get("advisory_id", ""),
        "message": vuln.get("title", ""),
        "description": vuln.get("description", ""),
        "confidence": "HIGH",
        "remediation": vuln.get("url", ""),
        "code_snippet": "",
        "language": "rust"
    }

def map_pylint_severity(pylint_type):
    """تحويل نوع Pylint إلى شدة موحدة"""
    severity_map = {
        "error": "CRITICAL",
        "warning": "HIGH",
        "refactor": "MEDIUM",
        "convention": "LOW",
        "info": "INFO"
    }
    return severity_map.get(pylint_type.lower(), "MEDIUM")

def map_eslint_severity(eslint_severity):
    """تحويل شدة ESLint إلى شدة موحدة"""
    severity_map = {
        2: "CRITICAL",  # Error
        1: "HIGH",      # Warning
        0: "INFO"       # Info
    }
    return severity_map.get(eslint_severity, "MEDIUM")

def map_gosec_severity(gosec_severity):
    """تحويل شدة Gosec إلى شدة موحدة"""
    severity_map = {
        "HIGH": "CRITICAL",
        "MEDIUM": "HIGH",
        "LOW": "MEDIUM",
        "UNKNOWN": "LOW"
    }
    return severity_map.get(gosec_severity.upper(), "MEDIUM")

def get_severity_level(severity):
    """الحصول على مستوى الشدة للفرز"""
    level_map = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5
    }
    return level_map.get(severity.upper(), 3)

def get_git_info():
    """استخراج معلومات Git"""
    commit_sha = os.environ.get("GITHUB_SHA", "")[:7]
    branch = os.environ.get("GITHUB_REF", "").replace("refs/heads/", "")
    
    return {
        "commit_sha": commit_sha,
        "branch": branch,
        "workflow": "auto-guardian-scan"
    }

def detect_languages():
    """اكتشاف اللغات الموجودة في المشروع"""
    languages = []
    extensions = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".cpp": "cpp",
        ".c": "c"
    }
    
    for ext, lang in extensions.items():
        if any(Path(".").rglob(f"*{ext}")):
            if lang not in languages:
                languages.append(lang)
    
    return languages

def count_lines_by_language():
    """عدم الأسطر حسب اللغة"""
    counts = {}
    extensions = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".rs": "rust"
    }
    
    for ext, lang in extensions.items():
        files = list(Path(".").rglob(f"*{ext}"))
        total_lines = 0
        for f in files:
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as file:
                    total_lines += sum(1 for _ in file)
            except:
                pass
        if total_lines > 0:
            counts[lang] = total_lines
    
    return counts

def main():
    """الدالة الرئيسية"""
    print("=" * 50)
    print("Auto-Guardian: تجميع نتائج الفحص")
    print("=" * 50)
    
    # استخراج معلومات Git
    git_info = get_git_info()
    print(f"Commit: {git_info['commit_sha']}")
    print(f"Branch: {git_info['branch']}")
    
    # اكتشاف اللغات
    languages = detect_languages()
    print(f"Languages detected: {', '.join(languages)}")
    
    # تجميع جميع النتائج
    all_findings = []
    summary_by_tool = {}
    findings_count = 0
    
    # Bandit Results
    print("\n[1/5] Processing Bandit results...")
    bandit_results = load_json_file("bandit_results.json")
    if isinstance(bandit_results, list):
        for result in bandit_results:
            if "results" in result:
                for issue in result["results"]:
                    finding = normalize_bandit_result(issue)
                    all_findings.append(finding)
                    findings_count += 1
        summary_by_tool["bandit"] = {"issues": findings_count, "status": "completed"}
    else:
        summary_by_tool["bandit"] = {"issues": 0, "status": "no_data"}
    print(f"  Found {findings_count} Bandit issues")
    
    # Pylint Results
    print("\n[2/5] Processing Pylint results...")
    pylint_results = load_json_file("pylint_results.json")
    pylint_count = 0
    if isinstance(pylint_results, list):
        for issue in pylint_results:
            if isinstance(issue, dict):
                finding = normalize_pylint_result(issue)
                all_findings.append(finding)
                pylint_count += 1
        summary_by_tool["pylint"] = {"issues": pylint_count, "status": "completed"}
    else:
        summary_by_tool["pylint"] = {"issues": 0, "status": "no_data"}
    print(f"  Found {pylint_count} Pylint issues")
    
    # ESLint Results
    print("\n[3/5] Processing ESLint results...")
    eslint_results = load_json_file("eslint_results.json")
    eslint_count = 0
    if isinstance(eslint_results, list):
        for result in eslint_results:
            if "messages" in result:
                for issue in result["messages"]:
                    if isinstance(issue, dict):
                        finding = normalize_eslint_result(issue)
                        all_findings.append(finding)
                        eslint_count += 1
        summary_by_tool["eslint"] = {"issues": eslint_count, "status": "completed"}
    else:
        summary_by_tool["eslint"] = {"issues": 0, "status": "no_data"}
    print(f"  Found {eslint_count} ESLint issues")
    
    # Gosec Results
    print("\n[4/5] Processing Gosec results...")
    gosec_results = load_json_file("gosec_results.json")
    gosec_count = 0
    if isinstance(gosec_results, dict) and "Issues" in gosec_results:
        for issue in gosec_results["Issues"]:
            finding = normalize_gosec_result(issue)
            all_findings.append(finding)
            gosec_count += 1
        summary_by_tool["gosec"] = {"issues": gosec_count, "status": "completed"}
    else:
        summary_by_tool["gosec"] = {"issues": 0, "status": "no_data"}
    print(f"  Found {gosec_count} Gosec issues")
    
    # Cargo Audit Results
    print("\n[5/5] Processing Cargo Audit results...")
    cargo_results = load_json_file("cargo_audit_results.json")
    cargo_count = 0
    if isinstance(cargo_results, dict) and "vulnerabilities" in cargo_results:
        for vuln in cargo_results["vulnerabilities"]:
            finding = normalize_cargo_audit_result(vuln)
            all_findings.append(finding)
            cargo_count += 1
        summary_by_tool["cargo-audit"] = {"issues": cargo_count, "status": "completed"}
    else:
        summary_by_tool["cargo-audit"] = {"issues": 0, "status": "no_data"}
    print(f"  Found {cargo_count} Cargo Audit issues")
    
    # حساب الإحصائيات
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
    
    for finding in all_findings:
        severity = finding.get("severity", "MEDIUM")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # حساب النتيجة
    total_findings = len(all_findings)
    critical_penalty = severity_counts["CRITICAL"] * 10
    high_penalty = severity_counts["HIGH"] * 5
    medium_penalty = severity_counts["MEDIUM"] * 2
    base_score = 100
    security_score = max(0, base_score - critical_penalty - high_penalty - medium_penalty)
    
    # عدد الملفات الممسوحة ضوئياً
    file_count = 0
    files_set = set()
    for finding in all_findings:
        file_path = finding.get("file", "")
        if file_path and file_path not in files_set:
            files_set.add(file_path)
    file_count = len(files_set)
    
    # إنشاء التقرير النهائي
    scan_results = {
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": "1.0.0",
            "tool": "auto-guardian",
            "git": git_info
        },
        "summary": {
            "total_issues": total_findings,
            "critical_issues": severity_counts["CRITICAL"],
            "high_issues": severity_counts["HIGH"],
            "medium_issues": severity_counts["MEDIUM"],
            "low_issues": severity_counts["LOW"],
            "info_issues": severity_counts["INFO"],
            "files_scanned": file_count,
            "security_score": security_score,
            "grade": get_grade(security_score)
        },
        "languages": {
            "detected": languages,
            "lines_of_code": count_lines_by_language(),
            "tools_used": summary_by_tool
        },
        "findings": sorted(all_findings, key=lambda x: x.get("severity_level", 99)),
        "trends": {
            "previous_scan": None,
            "improvement": None
        }
    }
    
    # حفظ النتائج
    output_file = "scan_results.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(scan_results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 50)
    print("ملخص الفحص:")
    print("=" * 50)
    print(f"  إجمالي المشاكل: {total_findings}")
    print(f"  مشاكل حرجة: {severity_counts['CRITICAL']}")
    print(f"  مشاكل عالية: {severity_counts['HIGH']}")
    print(f"  مشاكل متوسطة: {severity_counts['MEDIUM']}")
    print(f"  مشاكل منخفضة: {severity_counts['LOW']}")
    print(f"  الملفات الممسوحة: {file_count}")
    print(f"  نقاط الأمان: {security_score}/100 (الدرجة: {get_grade(security_score)})")
    print("=" * 50)
    print(f"✅ النتائج saved to: {output_file}")
    print("=" * 50)

def get_grade(score):
    """الحصول على التقدير من النقاط"""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

if __name__ == "__main__":
    main()
