# 🛡️ Auto-Guardian Security System | نظام الحارس التلقائي للأمن

<div align="center">

![Auto-Guardian Logo](assets/logo.svg)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Enabled-purple?style=for-the-badge)
![Dashboard](https://img.shields.io/badge/Dashboard-Web_Interface-orange?style=for-the-badge)
![API Server](https://img.shields.io/badge/API_Server-RESTful-blue?style=for-the-badge)
![CI/CD](https://img.shields.io/badge/CI%2FCD-Integrated-purple?style=for-the-badge)

**نظام متكامل لفحص الكود البرمائي وكشف الثغرات الأمنية بشكل تلقائي**

*Automated Code Security Scanning and Vulnerability Detection System*

</div>

---

## 📋 نظرة عامة | Overview

**نظام Auto-Guardian** هو أداة متكاملة مصممة لتعزيز الأمان في مشاريع البرمجة من خلال فحص الكود آلياً واكتشاف الثغرات الأمنية قبل دمجها في الكود الرئيسي. يجمع النظام بين قوة أدوات التحليل الثابت (Static Analysis) وسهولة الاستخدام من خلال لوحة تحكم ويب متجاوبة تدعم اللغتين العربية والإنجليزية.

يهدف هذا المشروع إلى تمكين فرق التطوير من تبني ممارسات **DevSecOps** بسهولة، حيث يتم دمج الفحص الأمني تلقائياً ضمن دورة حياة التطوير. يوفر النظام تقارير تفصيلية عن الثغرات المكتشفة مع تصنيفها حسب مستوى الخطورة، مما يساعد المطورين على تحديد أولويات الإصلاح بكفاءة عالية.

**الإصدار الحالي: 2.0.0** مع ميزات جديدة متقدمة تشمل خادم API و CI/CD ومتابعة Prometheus.

---

## ✨ الميزات الرئيسية | Key Features

### 🔍 فحص أمني متقدم | Advanced Security Scanning
يستخدم النظام مجموعة متكاملة من أدوات التحليل الأمني للكشف عن الثغرات الشائعة في الكود البرمجي. يدعم النظام فحص مشاريع **Python** و **JavaScript** و **Java** و **TypeScript** و **Go** و **Rust** و **C#** و **PHP**.

**الثغرات المكتشفة تشمل:**
- 🔴 ثغرات الحقن (SQL Injection, Command Injection)
- 🔴 تسلسل الكائنات غير الآمن (Unsafe Deserialization)
- 🟠 مفاتيح API وبيانات اعتماد مُضمَّنة
- 🟠 Cross-Site Scripting (XSS)
- 🟡 استخدام تشفير ضعيف (MD5, SHA1)
- 🟡 Prototype Pollution في JavaScript
- 🔵 تعليقات TODO/BUG/FIXME
- 🔵 كود التصحيح في الإنتاج

### 📊 لوحة تحكم تفاعلية | Interactive Dashboard
توفر لوحة التحكم واجهة ويب متجاوبة بالكامل تعرض إحصائيات الأمان بشكل لحظي ومباشر. تدعم اللوحة اللغتين العربية والإنجليزية مع دعم كامل للاتجاه من اليمين لليسار (RTL).

### 🌐 خادم REST API | REST API Server
واجهة برمجية متكاملة للتكامل مع أنظمة أخرى. يدعم جميع عمليات الفحص والمراقبة برمجياً.

### 🔄 تكامل CI/CD | CI/CD Integration
دعم كامل لمنصات التكامل المستمر:
- **GitHub Actions**
- **GitLab CI**
- **Jenkins**
- **CircleCI**
- **Azure DevOps**

### 📈 مراقبة Prometheus | Prometheus Monitoring
دعم كامل لمقاييس Prometheus ومخططات Grafana.

### 🔔 نظام الإشعارات | Notification System
إشعارات متعددة القنوات:
- 📧 البريد الإلكتروني (SMTP)
- 💬 Slack
- 🎮 Discord
- 🔗 Webhooks عامة

### 🐳 Docker Support | دعم Docker
حاويات جاهزة للتشغيل باستخدام Docker Compose مع جميع الخدمات.

---

## 🏗️ هيكل المشروع | Project Structure

```
Auto-Guardian-Core/
├── 📄 index.html                # لوحة التحكم الرئيسية (GitHub Pages)
├── 📄 docker-compose.yml        # إعدادات Docker الأساسية
├── 📄 docker-compose.production.yml  # إعدادات الإنتاج
├── 📄 requirements.txt          # متطلبات Python
├── 📄 prometheus.yml            # إعدادات Prometheus
│
├── 📂 scripts/                  # سكربتات الإدارة والفحص
│   ├── 📄 enhanced_security_scanner.py   # الماسح الأمني المُحسّن (جديد)
│   ├── 📄 api_server.py         # خادم REST API (جديد)
│   ├── 📄 cicd_integrator.py    # تكامل CI/CD (جديد)
│   ├── 📄 notification_service.py        # خدمة الإشعارات (جديد)
│   ├── 📄 security_scanner.py   # الماسح الأمني الأصلي
│   ├── 📄 log_analyzer.py       # محلل السجلات
│   ├── 📄 backup.sh             # النسخ الاحتياطي
│   ├── 📄 maintenance.sh        # الصيانة
│   └── 📄 upgrade.sh            # الترقية
│
├── 📂 Dockerfiles/              # ملفات Docker (جديد)
│   ├── 📄 Dockerfile.api        # خادم API
│   ├── 📄 Dockerfile.scanner    # الماسح الأمني
│   ├── 📄 Dockerfile.dashboard  # لوحة التحكم
│   └── 📄 Dockerfile.notifications  # خدمة الإشعارات
│
├── 📂 docs/                     # التوثيق التقني
│   ├── 📂 api/                  # توثيق OpenAPI
│   └── 📄 configuration.md      # إعدادات النظام
│
├── 📂 grafana/                  # إعدادات Grafana (جديد)
│   └── 📂 provisioning/
│
├── 📂 public/data/              # نتائج الفحص
├── 📂 dashboard/                # لوحة التحكم
├── 📂 assets/                   # الأصول المرئية والشعارات
├── 📂 .github/                  # قوالب GitHub و workflows
└── 📂 .gitlab-ci.yml            # تكوين GitLab CI (جديد)
```

---

## 🚀 البدء السريع | Quick Start

### المتطلبات | Requirements
- Python 3.9 أو أحدث
- Docker و Docker Compose (اختياري)
- Git

### التشغيل المحلي | Local Installation

```bash
# استنساخ المستودع
git clone https://github.com/AbdulElahOthmanGwaith/Auto-Guardian-Core.git
cd Auto-Guardian-Core

# تثبيت المتطلبات
pip install -r requirements.txt

# تشغيل لوحة التحكم
python -m http.server 8000
```

### التشغيل عبر Docker (موصى به)

```bash
# التشغيل الأساسي
docker-compose up -d

# التشغيل الكامل (جميع الخدمات)
docker-compose -f docker-compose.production.yml up -d

# عرض الخدمات
docker-compose ps
```

### تشغيل خدمات محددة

```bash
# تشغيل الماسح الأمني فقط
docker-compose run security-scanner

# تشغيل خادم API فقط
docker-compose run api-server

# تشغيل خدمة الإشعارات
docker-compose run notifications
```

---

## 📖 الاستخدام | Usage

### الماسح الأمني | Security Scanner

```bash
# فحص مجلد محدد
python scripts/enhanced_security_scanner.py /path/to/project

# تحديد مستوى الخطورة
python scripts/enhanced_security_scanner.py . --severity high

# حفظ النتائج
python scripts/enhanced_security_scanner.py . -o results.json

# إنشاء تقرير Markdown
python scripts/enhanced_security_scanner.py . -r report.md
```

### خادم API | API Server

```bash
# تشغيل الخادم
python scripts/api_server.py

# الخادم على منفذ محدد
python scripts/api_server.py 8080

# الوصول للـ API
curl http://localhost:8000/api/health
curl http://localhost:8000/api/scan?target=.&severity=medium
curl http://localhost:8000/api/statistics
```

### تكامل CI/CD | CI/CD Integration

```bash
# فحص في CI/CD
python scripts/cicd_integrator.py .

# مع خيارات محددة
python scripts/cicd_integrator.py . --severity high --fail-critical

# إنشاء ملف GitHub Actions
python scripts/cicd_integrator.py --github-workflow

# إنشاء ملف GitLab CI
python scripts/cicd_integrator.py --gitlab-ci
```

### خدمة الإشعارات | Notification Service

```bash
# تشغيل خدمة الإشعارات
python scripts/notification_service.py

# إرسال إشعار اختبار
python scripts/notification_service.py --test
```

---

## 🌐 نقاط الوصول API | API Endpoints

| الطريقة | المسار | الوصف |
|---------|--------|-------|
| GET | `/api/health` | حالة الخادم |
| GET | `/api/scan` | بدء فحص |
| POST | `/api/scan` | بدء فحص مع بيانات |
| GET | `/api/results` | نتائج الفحص |
| GET | `/api/statistics` | الإحصائيات |
| GET | `/api/vulnerabilities` | قائمة الثغرات |
| GET | `/api/repositories` | المستودعات |

---

## ⚙️ الإعدادات | Configuration

### متغيرات البيئة | Environment Variables

```bash
# البريد الإلكتروني
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your-email@gmail.com
export SMTP_PASSWORD=your-password
export FROM_EMAIL=security@example.com
export TO_EMAILS=admin@example.com

# Slack
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
export SLACK_CHANNEL=#security-alerts

# Discord
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx

# Webhook عامة
export WEBHOOK_URL=https://your-webhook.com/endpoint
export WEBHOOK_HEADERS=Authorization:Bearer xxx,Content-Type:application/json
```

---

## 📦 الخدمات | Services

عند استخدام `docker-compose.production.yml`، يتم تشغيل الخدمات التالية:

| الخدمة | المنفذ | الوصف |
|--------|--------|-------|
| `security-scanner` | - | الماسح الأمني الرئيسي |
| `api-server` | 8000 | خادم REST API |
| `dashboard` | 80 | لوحة التحكم الويب |
| `prometheus` | 9090 | خادم المراقبة |
| `grafana` | 3000 | واجهة المراقبة |
| `notifications` | - | خدمة الإشعارات |
| `cicd-scanner` | - | فحص CI/CD |

---

## 🧪 الاختبارات | Testing

```bash
# تشغيل جميع الاختبارات
pytest

# تشغيل مع تغطية الكود
pytest --cov=scripts --cov-report=html

# تشغيل اختبار محدد
pytest tests/test_security_scanner.py -v
```

---

## 📝 الترخيص | License
هذا المشروع مرخص تحت **رخصة MIT**. راجع ملف [LICENSE](LICENSE) لمزيد من التفاصيل.

---

## 🤝 المساهمة | Contributing

نرحب بمساهماتكم! يرجى قراءة [CONTRIBUTING.md](CONTRIBUTING.md) للمزيد من التفاصيل.

---

## 📧 الدعم | Support

- **المستودع:** https://github.com/AbdulElahOthmanGwaith/Auto-Guardian-Core
- **الوحة التحكم:** https://abdulelahothmangwaith.github.io/Auto-Guardian-Core/
- **الأسئلة:** افتح Issue في المستودع

---

<div align="center">

**صُنع بـ ❤️ بواسطة Auto-Guardian Team**

*نظام أمان شامل لحماية مشاريعك البرمجية*

</div>
