import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailNotifier:
    def __init__(self, config_path='docs/configuration.md'):
        self.admin_email = "fcab8090@gmail.com"
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        
    def send_security_alert(self, scan_results):
        """إرسال تنبيه أمني في حال وجود ثغرات عالية الخطورة"""
        high_vulns = [v for v in scan_results.get('vulnerabilities', []) if v['severity'] == 'high']
        
        if not high_vulns:
            print("No high severity vulnerabilities found. Skipping email.")
            return

        subject = f"⚠️ تنبيه أمني: تم اكتشاف {len(high_vulns)} ثغرات خطيرة في Auto-Guardian"
        
        body = f"""
        <html>
        <body dir="rtl">
            <h2 style="color: #d32f2f;">تنبيه أمني عاجل</h2>
            <p>تم الانتهاء من فحص النظام واكتشاف ثغرات تتطلب تدخلكم الفوري:</p>
            <table border="1" style="border-collapse: collapse; width: 100%;">
                <tr style="background-color: #f2f2f2;">
                    <th>الملف</th>
                    <th>المشكلة</th>
                    <th>السطر</th>
                </tr>
        """
        
        for v in high_vulns:
            body += f"""
                <tr>
                    <td>{v['file']}</td>
                    <td>{v['description']}</td>
                    <td>{v['line']}</td>
                </tr>
            """
            
        body += f"""
            </table>
            <p>درجة المخاطرة الحالية: <b>{scan_results.get('risk_score', 'N/A')}</b></p>
            <p>يرجى مراجعة لوحة التحكم لاتخاذ الإجراءات اللازمة.</p>
            <hr>
            <p style="font-size: 0.8em; color: #666;">تم إرسال هذا التنبيه تلقائياً بواسطة نظام Auto-Guardian-Core.</p>
        </body>
        </html>
        """

        # ملاحظة: في بيئة الإنتاج، يجب استخدام متغيرات البيئة لكلمة المرور
        print(f"Simulating email send to: {self.admin_email}")
        print(f"Subject: {subject}")
        # هنا يتم وضع كود الإرسال الحقيقي عند توفر الصلاحيات
        
    def update_config_email(self, new_email):
        self.admin_email = new_email
        print(f"Admin email updated to: {self.admin_email}")

if __name__ == "__main__":
    # تجربة الوحدة ببيانات وهمية
    notifier = EmailNotifier()
    sample_data = {
        "risk_score": 65,
        "vulnerabilities": [
            {"file": "app.py", "description": "Hardcoded API Key", "line": 12, "severity": "high"}
        ]
    }
    notifier.send_security_alert(sample_data)
