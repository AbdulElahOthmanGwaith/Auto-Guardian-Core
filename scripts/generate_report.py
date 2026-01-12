#!/usr/bin/env python3
# سكريبت إنشاء تقارير الأمان

import json
import os
from datetime import datetime

def load_json_file(filepath):
    """تحميل ملف JSON"""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def generate_markdown_report(data):
    """إنشاء تقرير Markdown"""
    if not data:
        return None
    
    summary = data.get('summary', {})
    findings = data.get('findings', [])
    metadata = data.get('metadata', {})
    
    # تصنيف المشاكل حسب الشدة
    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    high = [f for f in findings if f.get('severity') == 'HIGH']
    medium = [f for f in findings if f.get('severity') == 'MEDIUM']
    low = [f for f in findings if f.get('severity') == 'LOW']
    
    report = f"""# تقرير الأمان - Auto-Guardian

## معلومات التقرير

- **تاريخ الفحص:** {metadata.get('timestamp', 'غير متوفر')}
- **الالتزام:** {metadata.get('git', {}).get('commit_sha', 'غير متوفر')}
- **الفرع:** {metadata.get('git', {}).get('branch', 'غير متوفر')}
- **إصدار الأداة:** {metadata.get('version', '1.0.0')}

---

## ملخص النتائج

| المقياس | القيمة |
|---------|--------|
| **نتيجة الأمان** | {summary.get('security_score', 0)}/100 |
| **التقدير** | {summary.get('grade', '-')} |
| **إجمالي المشاكل** | {summary.get('total_issues', 0)} |
| **ملفات مفحوصة** | {summary.get('files_scanned', 0)} |
| **مشاكل حرجة** | {len(critical)} |
| **مشاكل عالية** | {len(high)} |
| **مشاكل متوسطة** | {len(medium)} |
| **مشاكل منخفضة** | {len(low)} |

---

## المشاكل الحرجة ({len(critical)})

"""
    
    if critical:
        for i, finding in enumerate(critical, 1):
            report += f"""### {i}. {finding.get('rule_name', finding.get('rule_id', 'غير معروف'))}

- **الملف:** `{finding.get('file', 'غير معروف')}:{finding.get('line', 0)}`
- **الأداة:** {finding.get('tool_name', finding.get('tool', 'غير معروف'))}
- **الوصف:** {finding.get('message', finding.get('description', 'غير متوفر'))}
- **مستوى الثقة:** {finding.get('confidence', 'غير معروف')}
- **اللغة:** {finding.get('language', 'غير معروفة')}

"""
    else:
        report += "لا توجد مشاكل حرجة! ممتاز! 🎉\n\n"

    report += f"""---

## المشاكل العالية ({len(high)})

"""

    if high:
        for i, finding in enumerate(high, 1):
            report += f"""### {i}. {finding.get('rule_name', finding.get('rule_id', 'غير معروف'))}

- **الملف:** `{finding.get('file', 'غير معروف')}:{finding.get('line', 0)}`
- **الأداة:** {finding.get('tool_name', finding.get('tool', 'غير معروف'))}
- **الوصف:** {finding.get('message', finding.get('description', 'غير متوفر'))}

"""
    else:
        report += "لا توجد مشاكل عالية! 🎉\n\n"

    report += f"""---

## التوصيات

"""

    # إضافة توصيات بناءً على النتائج
    if len(critical) > 0:
        report += "1. **أولوية قصوى:** معالجة المشاكل الحرجة المكتشفة فوراً.\n"
    if len(high) > 0:
        report += "2. **أولوية عالية:** حل المشاكل العالية في أقرب وقت ممكن.\n"
    if len(medium) > 0:
        report += "3. **أولوية متوسطة:** جدولة حل المشاكل المتوسطة في الدورة القادمة.\n"
    if len(low) > 0:
        report += "4. **أولوية منخفضة:** يمكن معالجة المشاكل منخفضة عند توفر الوقت.\n"

    report += """
---

## اللغات المفحوصة

"""

    languages = data.get('languages', {})
    for lang in languages.get('detected', []):
        lines = languages.get('lines_of_code', {}).get(lang, 0)
        tools = languages.get('tools_used', {}).get(lang, {})
        report += f"- **{lang}:** {lines:,} سطر من الكود (فحص بـ {tools.get('issues', 0)} مشاكل)\n"

    report += f"""

---

## أدوات الفحص المستخدمة

"""

    tools_used = languages.get('tools_used', {})
    for tool, info in tools_used.items():
        report += f"- **{tool}:** {info.get('issues', 0)} مشاكل مكتشفة (الحالة: {info.get('status', 'غير معروف')})\n"

    report += f"""

---

*تم إنشاء هذا التقرير تلقائياً بواسطة Auto-Guardian في {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

"""

    return report

def main():
    """الدالة الرئيسية"""
    print("=" * 50)
    print("Auto-Guardian: إنشاء تقرير الأمان")
    print("=" * 50)
    
    # تحميل بيانات الفحص
    data = load_json_file('scan_results.json')
    
    if not data:
        print("❌ لم يتم العثور على بيانات الفحص!")
        print("   يرجى تشغيل aggregate_results.py أولاً")
        return
    
    # إنشاء التقرير
    report = generate_markdown_report(data)
    
    if report:
        # حفظ التقرير
        output_file = 'reports/security_report.md'
        os.makedirs('reports', exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ تم إنشاء التقرير بنجاح!")
        print(f"   الملف: {output_file}")
        print("=" * 50)
    else:
        print("❌ فشل في إنشاء التقرير")

if __name__ == "__main__":
    main()
