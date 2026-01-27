#!/usr/bin/env python3
"""
Auto-Guardian Notification Service
خدمة الإشعارات لنظام الحارس التلقائي للأمن

الإصدار: 1.0.0
تاريخ التحديث: 2024-01-28

تدعم هذه الخدمة الإشعارات عبر:
- البريد الإلكتروني (SMTP)
- Slack
- Discord
- Webhooks عامة
"""

import os
import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """قنوات الإشعار"""
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"


@dataclass
class NotificationConfig:
    """إعدادات الإشعار"""
    channel: str
    enabled: bool = True
    # إعدادات البريد الإلكتروني
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = ""
    to_emails: List[str] = None
    # إعدادات Slack
    slack_webhook_url: str = ""
    slack_channel: str = ""
    # إعدادات Discord
    discord_webhook_url: str = ""
    # إعدادات Webhook عامة
    webhook_url: str = ""
    webhook_headers: Dict = None

    def __post_init__(self):
        if self.to_emails is None:
            self.to_emails = []
        if self.webhook_headers is None:
            self.webhook_headers = {}


@dataclass
class SecurityAlert:
    """تنبيه أمني"""
    scan_id: str
    risk_score: int
    health_status: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    timestamp: str = ""
    details_url: str = ""

    def __post_init__(self):
        self.timestamp = self.timestamp or datetime.now().isoformat()


class NotificationService:
    """خدمة الإشعارات"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_config()
        self.channel_configs = self._parse_channel_configs()

    def _load_config(self) -> Dict[str, Any]:
        """تحميل الإعدادات من المتغيرات البيئية"""
        return {
            "email": {
                "enabled": os.environ.get("EMAIL_NOTIFICATIONS_ENABLED", "false").lower() == "true",
                "smtp_server": os.environ.get("SMTP_SERVER", "smtp.gmail.com"),
                "smtp_port": int(os.environ.get("SMTP_PORT", "587")),
                "smtp_user": os.environ.get("SMTP_USER", ""),
                "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
                "from_email": os.environ.get("FROM_EMAIL", "security@example.com"),
                "to_emails": os.environ.get("TO_EMAILS", "").split(",")
            },
            "slack": {
                "enabled": os.environ.get("SLACK_NOTIFICATIONS_ENABLED", "false").lower() == "true",
                "webhook_url": os.environ.get("SLACK_WEBHOOK_URL", ""),
                "channel": os.environ.get("SLACK_CHANNEL", "#security-alerts")
            },
            "discord": {
                "enabled": os.environ.get("DISCORD_NOTIFICATIONS_ENABLED", "false").lower() == "true",
                "webhook_url": os.environ.get("DISCORD_WEBHOOK_URL", "")
            },
            "webhook": {
                "enabled": os.environ.get("WEBHOOK_NOTIFICATIONS_ENABLED", "false").lower() == "true",
                "url": os.environ.get("WEBHOOK_URL", ""),
                "headers": self._parse_headers()
            }
        }

    def _parse_headers(self) -> Dict[str, str]:
        """تحليل رؤوس HTTP المخصصة"""
        headers_str = os.environ.get("WEBHOOK_HEADERS", "")
        headers = {}
        if headers_str:
            for header in headers_str.split(","):
                if ":" in header:
                    key, value = header.split(":", 1)
                    headers[key.strip()] = value.strip()
        return headers

    def _parse_channel_configs(self) -> Dict[str, NotificationConfig]:
        """تحليل إعدادات القنوات"""
        configs = {}

        # إعدادات البريد الإلكتروني
        configs["email"] = NotificationConfig(
            channel="email",
            enabled=self.config["email"]["enabled"],
            smtp_server=self.config["email"]["smtp_server"],
            smtp_port=self.config["email"]["smtp_port"],
            smtp_user=self.config["email"]["smtp_user"],
            smtp_password=self.config["email"]["smtp_password"],
            from_email=self.config["email"]["from_email"],
            to_emails=self.config["email"]["to_emails"]
        )

        # إعدادات Slack
        configs["slack"] = NotificationConfig(
            channel="slack",
            enabled=self.config["slack"]["enabled"],
            slack_webhook_url=self.config["slack"]["webhook_url"],
            slack_channel=self.config["slack"]["channel"]
        )

        # إعدادات Discord
        configs["discord"] = NotificationConfig(
            channel="discord",
            enabled=self.config["discord"]["enabled"],
            discord_webhook_url=self.config["discord"]["webhook_url"]
        )

        # إعدادات Webhook عامة
        configs["webhook"] = NotificationConfig(
            channel="webhook",
            enabled=self.config["webhook"]["enabled"],
            webhook_url=self.config["webhook"]["url"],
            webhook_headers=self.config["webhook"]["headers"]
        )

        return configs

    def send_security_alert(self, alert: SecurityAlert) -> Dict[str, Any]:
        """إرسال تنبيه أمني"""
        results = {}

        for channel_name, config in self.channel_configs.items():
            if not config.enabled:
                logger.info(f"قناة {channel_name} معطلة، تخطي...")
                continue

            try:
                if channel_name == "email":
                    self._send_email_alert(config, alert)
                elif channel_name == "slack":
                    self._send_slack_alert(config, alert)
                elif channel_name == "discord":
                    self._send_discord_alert(config, alert)
                elif channel_name == "webhook":
                    self._send_webhook_alert(config, alert)

                results[channel_name] = {"success": True, "message": "تم إرسال الإشعار بنجاح"}

            except Exception as e:
                logger.error(f"فشل إرسال إشعار عبر {channel_name}: {e}")
                results[channel_name] = {"success": False, "error": str(e)}

        return results

    def _send_email_alert(self, config: NotificationConfig, alert: SecurityAlert):
        """إرسال إشعار عبر البريد الإلكتروني"""
        if not config.to_emails:
            logger.warning("لم يتم تحديد مستلمي البريد الإلكتروني")
            return

        # إنشاء رسالة البريد
        msg = MIMEMultipart()
        msg['From'] = config.from_email
        msg['To'] = ", ".join(config.to_emails)
        msg['Subject'] = f"🚨 تنبيه أمني: {alert.health_status} - نقاط المخاطر: {alert.risk_score}"

        # محتوى الرسالة
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; direction: rtl; text-align: right; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #ddd; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat {{ text-align: center; padding: 15px; border-radius: 8px; min-width: 80px; }}
                .critical {{ background: #fee2e2; color: #dc2626; }}
                .high {{ background: #ffedd5; color: #ea580c; }}
                .medium {{ background: #fef3c7; color: #d97706; }}
                .low {{ background: #d1fae5; color: #059669; }}
                .footer {{ background: #f3f4f6; padding: 15px; text-align: center; border-radius: 0 0 10px 10px; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Auto-Guardian</h1>
                    <h2>تنبيه أمني</h2>
                </div>
                <div class="content">
                    <h3>حالة الفحص: {alert.health_status}</h3>
                    <p><strong>معرّف الفحص:</strong> {alert.scan_id}</p>
                    <p><strong>التاريخ والوقت:</strong> {alert.timestamp}</p>
                    <p><strong>نقاط المخاطر:</strong> {alert.risk_score}/100</p>
                    
                    <h4>توزيع الثغرات:</h4>
                    <div class="stats">
                        <div class="stat critical">
                            <h3>{alert.critical_count}</h3>
                            <p>حرجة</p>
                        </div>
                        <div class="stat high">
                            <h3>{alert.high_count}</h3>
                            <p>عالية</p>
                        </div>
                        <div class="stat medium">
                            <h3>{alert.medium_count}</h3>
                            <p>متوسطة</p>
                        </div>
                        <div class="stat low">
                            <h3>{alert.low_count}</h3>
                            <p>منخفضة</p>
                        </div>
                    </div>
                    
                    <p><strong>إجمالي الثغرات:</strong> {alert.total_vulnerabilities}</p>
                    
                    <p style="background: #fee2e2; padding: 15px; border-radius: 8px; text-align: center;">
                        ⚠️ <strong>إجراء مطلوب:</strong> راجع نتائج الفحص واتخذ الإجراءات اللازمة
                    </p>
                </div>
                <div class="footer">
                    <p>تم إرسال هذا الإشعار تلقائياً من نظام Auto-Guardian</p>
                </div>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html_content, 'html', 'utf-8'))

        # إرسال البريد
        try:
            with smtplib.SMTP(config.smtp_server, config.smtp_port) as server:
                server.starttls()
                server.login(config.smtp_user, config.smtp_password)
                server.send_message(msg)

            logger.info(f"تم إرسال إشعار البريد إلى {config.to_emails}")

        except Exception as e:
            logger.error(f"فشل إرسال البريد: {e}")
            raise

    def _send_slack_alert(self, config: NotificationConfig, alert: SecurityAlert):
        """إرسال إشعار عبر Slack"""
        if not config.slack_webhook_url:
            logger.warning("لم يتم تحديد Slack Webhook URL")
            return

        # تحديد لون الإشعار
        color = "danger" if alert.critical_count > 0 else "warning" if alert.high_count > 0 else "good"

        payload = {
            "attachments": [{
                "color": color,
                "title": "🛡️ Auto-Guardian Security Alert",
                "title_link": alert.details_url,
                "fields": [
                    {"title": "Health Status", "value": alert.health_status, "short": True},
                    {"title": "Risk Score", "value": f"{alert.risk_score}/100", "short": True},
                    {"title": "🔴 Critical", "value": str(alert.critical_count), "short": True},
                    {"title": "🟠 High", "value": str(alert.high_count), "short": True},
                    {"title": "🟡 Medium", "value": str(alert.medium_count), "short": True},
                    {"title": "🔵 Low", "value": str(alert.low_count), "short": True},
                    {"title": "Total Vulnerabilities", "value": str(alert.total_vulnerabilities), "short": True}
                ],
                "footer": "Auto-Guardian",
                "ts": int(datetime.now().timestamp())
            }]
        }

        response = requests.post(
            config.slack_webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        response.raise_for_status()
        logger.info("تم إرسال إشعار Slack بنجاح")

    def _send_discord_alert(self, config: NotificationConfig, alert: SecurityAlert):
        """إرسال إشعار عبر Discord"""
        if not config.discord_webhook_url:
            logger.warning("لم يتم تحديد Discord Webhook URL")
            return

        # تحديد لون الـ Embed
        color = 0xFF0000 if alert.critical_count > 0 else 0xFFA500 if alert.high_count > 0 else 0x00FF00

        embed = {
            "title": "🛡️ Auto-Guardian Security Alert",
            "description": f"**Health Status:** {alert.health_status}\n**Scan ID:** {alert.scan_id}",
            "color": color,
            "fields": [
                {"name": "Risk Score", "value": f"{alert.risk_score}/100", "inline": True},
                {"name": "Total Vulnerabilities", "value": str(alert.total_vulnerabilities), "inline": True},
                {"name": "🔴 Critical", "value": str(alert.critical_count), "inline": True},
                {"name": "🟠 High", "value": str(alert.high_count), "inline": True},
                {"name": "🟡 Medium", "value": str(alert.medium_count), "inline": True},
                {"name": "🔵 Low", "value": str(alert.low_count), "inline": True}
            ],
            "footer": {"text": "Auto-Guardian Security System"},
            "timestamp": alert.timestamp
        }

        payload = {"embeds": [embed]}

        response = requests.post(
            config.discord_webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        response.raise_for_status()
        logger.info("تم إرسال إشعار Discord بنجاح")

    def _send_webhook_alert(self, config: NotificationConfig, alert: SecurityAlert):
        """إرسال إشعار عبر Webhook عامة"""
        if not config.webhook_url:
            logger.warning("لم يتم تحديد Webhook URL")
            return

        payload = {
            "source": "auto-guardian",
            "type": "security_alert",
            "scan_id": alert.scan_id,
            "timestamp": alert.timestamp,
            "risk_score": alert.risk_score,
            "health_status": alert.health_status,
            "vulnerabilities": {
                "total": alert.total_vulnerabilities,
                "critical": alert.critical_count,
                "high": alert.high_count,
                "medium": alert.medium_count,
                "low": alert.low_count
            },
            "details_url": alert.details_url
        }

        headers = {"Content-Type": "application/json"}
        headers.update(config.webhook_headers)

        response = requests.post(
            config.webhook_url,
            json=payload,
            headers=headers
        )

        response.raise_for_status()
        logger.info("تم إرسال إشعار Webhook بنجاح")


def main():
    """البرنامج الرئيسي"""
    import argparse

    parser = argparse.ArgumentParser(description="Auto-Guardian Notification Service")
    parser.add_argument("--config", "-c", help="مسار ملف الإعدادات")
    parser.add_argument("--test", "-t", action="store_true", help="إرسال إشعار اختبار")

    args = parser.parse_args()

    service = NotificationService()

    if args.test:
        # إرسال إشعار اختبار
        test_alert = SecurityAlert(
            scan_id="test-scan-001",
            risk_score=85,
            health_status="جيد جداً",
            total_vulnerabilities=5,
            critical_count=0,
            high_count=1,
            medium_count=2,
            low_count=2
        )

        results = service.send_security_alert(test_alert)

        print("\n📊 نتائج إرسال الإشعارات:")
        for channel, result in results.items():
            status = "✅" if result["success"] else "❌"
            print(f"  {status} {channel}: {result.get('message', result.get('error', 'خطأ غير معروف'))}")

    else:
        # الاستماع للإشعارات من نتائج الفحص
        logger.info("جاري مراقبة نتائج الفحص...")

        # تحميل نتائج الفحص الأخيرة
        results_path = "public/data/enhanced_security_scan.json"
        if os.path.exists(results_path):
            with open(results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            alert = SecurityAlert(
                scan_id=data.get("scan_id", "unknown"),
                risk_score=data.get("risk_score", 100),
                health_status=data.get("health_status", "Unknown"),
                total_vulnerabilities=data.get("total_vulnerabilities", 0),
                critical_count=data.get("vulnerabilities_by_severity", {}).get("critical", 0),
                high_count=data.get("vulnerabilities_by_severity", {}).get("high", 0),
                medium_count=data.get("vulnerabilities_by_severity", {}).get("medium", 0),
                low_count=data.get("vulnerabilities_by_severity", {}).get("low", 0)
            )

            service.send_security_alert(alert)


if __name__ == "__main__":
    main()
