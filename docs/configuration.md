# دليل إعدادات نظام الحارس التلقائي
# Auto Guardian System Configuration Guide
# ==========================================

## نظرة عامة

يحتوي ملف `config/settings.yaml` على جميع إعدادات نظام الحارس التلقائي. هذا الدليل يشرح كل خيار بالتفصيل مع أمثلة عملية. يُرجى قراءة هذا الدليل بعناية قبل تعديل الإعدادات.

---

## هيكل ملف الإعدادات

```
config/
├── settings.yaml          # الإعدادات الرئيسية
├── rules.yaml             # قواعد الكشف عن التهديدات
├── alerts.yaml            # قوالب التنبيهات
└── whitelist.yaml         # قائمة العناوكات المسموح بها
```

---

## القسم الأول: الإعدادات العامة

```yaml
# config/settings.yaml - القسم العام

general:
  # وضع التشغيل: development, testing, production
  mode: development
  
  # مستوى التسجيل: DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_level: INFO
  
  # المنطقة الزمنية (استخدم تنسيق tzdata)
  timezone: UTC
  
  # مسار ملفات السجلات
  log_path: logs/
  
  # تفعيل وضع التحسينات (Production فقط)
  optimizations: false
```

### شرح الخيارات

| الخيار | القيم الممكنة | الافتراضي | الوصف |
|--------|---------------|-----------|-------|
| mode | development, testing, production | development | يحدد بيئة التشغيل |
| log_level | DEBUG, INFO, WARNING, ERROR, CRITICAL | INFO | يتحكم في كمية السجلات |
| timezone | أي منطقة زمنية صالحة | UTC | المنطقة الزمنية للسجلات |
| log_path | مسار مجلد | logs/ | مكان تخزين السجلات |
| optimizations | true, false | false | تفعيل تحسينات الأداء |

---

## القسم الثاني: إعدادات المراقبة

```yaml
# config/settings.yaml - قسم المراقبة

monitoring:
  # تفعيل المراقبة
  enabled: true
  
  # مصادر السجلات للمراقبة
  log_sources:
    - /var/log/auth.log           # سجلات المصادقة
    - /var/log/syslog             # سجلات النظام العامة
    - /var/log/nginx/access.log   # سجلات خادم الويب
  
  # الفاصل الزمني للفحص (بالثواني)
  scan_interval: 5
  
  # تفعيل الفحص العميق (أبطأ لكنه أكثر دقة)
  deep_scan: false
  
  # الأنماط المشبوهة للكشف (قاعدة منفصلة)
  patterns_file: config/rules.yaml
  
  # تفعيل المراقبة في الوقت الفعلي
  realtime_monitoring: true
  
  # حجم ذاكرة التخزين المؤقت للأحداث
  event_buffer_size: 1000
```

### شرح الخيارات

| الخيار | القيم الممكنة | الافتراضي | الوصف |
|--------|---------------|-----------|-------|
| enabled | true, false | true | تفعيل أو إلغاء المراقبة |
| log_sources | قائمة مسارات | - | مصادر السجلات للمراقبة |
| scan_interval | رقم (ثواني) | 5 | الفاصل بين عمليات الفحص |
| deep_scan | true, false | false | فحص أعمق وأدق |
| realtime_monitoring | true, false | true | مراقبة في الوقت الفعلي |
| event_buffer_size | رقم | 1000 | حجم التخزين المؤقت |

---

## القسم الثالث: قواعد الكشف

```yaml
# config/rules.yaml - قواعد الكشف

# أنماط هجوم القوة الغاشبة
brute_force:
  enabled: true
  threshold: 5              # عدد المحاولات
  time_window: 60           # بالم seconds
  ports: [22, 2222]         # المنافذ المستهدفة

# أنماط المسح الضوئي للمنافذ
port_scan:
  enabled: true
  min_ports: 3              # الحد الأدنى للمنافذ
  time_window: 30           # بالم seconds
  severity: high

# أنماط حقن SQL
sql_injection:
  enabled: true
  severity: critical
  auto_block: true

# أنماط XSS
xss:
  enabled: true
  severity: high
  auto_block: false

# أنماط الوصول غير المصرح به
unauthorized_access:
  enabled: true
  severity: critical
  auto_block: true
```

---

## القسم الرابع: إعدادات الحظر

```yaml
# config/settings.yaml - قسم الحظر

blocking:
  # تفعيل الحظر التلقائي
  enabled: true
  
  # عدد المحاولات قبل الحظر
  threshold: 5
  
  # الفترة الزمنية للمحاولات (بالثواني)
  time_window: 60
  
  # تفعيل IPTables للحظر
  use_iptables: true
  
  # تفعيل firewalld للحظر
  use_firewalld: false
  
  # تفعيل الحظر في Cloudflare
  use_cloudflare: false
  
  # قائمة السماح (عناوكات لا تُحظر)
  whitelist:
    - 127.0.0.1
    - 192.168.1.1
    - 10.0.0.1
  
  # قائمة الحظر الدائم
  blacklist: []
  
  # مدة الحظر الافتراضية (بالدقائق، 0 = دائم)
  default_duration: 0
  
  # إرسال إشعار عند الحظر
  notify_on_block: true
```

### شرح الخيارات

| الخيار | القيم الممكنة | الافتراضي | الوصف |
|--------|---------------|-----------|-------|
| enabled | true, false | true | تفعيل الحظر التلقائي |
| threshold | رقم | 5 | عدد المحاولات قبل الحظر |
| time_window | رقم (ثواني) | 60 | الفترة الزمنية |
| use_iptables | true, false | true | استخدام IPTables |
| whitelist | قائمة IPs | [] | عناوين لا تُحظر |
| default_duration | رقم (دقائق) | 0 | مدة الحظر الافتراضية |

---

## القسم الخامس: إعدادات الإشعارات

```yaml
# config/settings.yaml - قسم الإشعارات

notifications:
  # تفعيل الإشعارات
  enabled: true
  
  # عنوان المرسل
  sender_name: "Auto-Guardian System"
  
  # ---- Slack ----
  slack:
    enabled: false
    webhook_url: ""
    channel: "security-alerts"
    username: "Auto-Guardian"
    icon_emoji: ":shield:"
  
  # ---- Discord ----
  discord:
    enabled: false
    webhook_url: ""
    username: "Auto-Guardian"
    avatar_url: ""
  
  # ---- البريد الإلكتروني ----
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: ""
    password: ""
    from_address: "noreply@autoguardian.local"
    to_addresses:
      - "fcab8090@gmail.com"
  
  # ---- عام ----
  # تفعيل الإشعارات للتهديدات الحرجة فقط
  critical_only: false
  
  # وقت عدم الإرسال (بالساعات، 0 = نش)
  quietط دائماً_hours: 0
```

---

## القسم السادس: إعدادات Prometheus

```yaml
# config/settings.yaml - قسم Prometheus

prometheus:
  # تفعيل Prometheus
  enabled: true
  
  # منفذ الاستماع
  port: 9090
  
  # مسار /metrics
  metrics_path: /metrics
  
  # تفعيل جمع السجلات
  include_logs: true
  
  # تضمين معلومات النظام
  include_system_info: true
  
  # تضمين معلومات التهديدات
  include_threat_info: true
```

### مقاييس Prometheus المتاحة

| المقياس | النوع | الوصف |
|---------|-------|-------|
| autoguardian_threats_total | Counter | إجمالي التهديدات |
| autoguardian_blocked_ips | Gauge | عدد العناوكات المحظورة |
| autoguardian_blocked_ips_active | Gauge | العناوكات النشطة |
| autoguardian_success_rate | Gauge | معدل النجاح |
| autoguardian_response_time_seconds | Histogram | زمن الاستجابة |
| autoguardian_alerts_sent | Counter | التنبيهات المرسلة |

---

## القسم السابع: إعدادات الأمان

```yaml
# config/settings.yaml - قسم الأمان

security:
  # تفعيل التحقق من التحديثات الأمنية
  security_checks: true
  
  # فترة التحقق من التحديثات (بالساعات)
  check_interval: 24
  
  # تفعيل تسجيل التدقيق
  audit_logging: true
  
  # مسار ملف سجل التدقيق
  audit_log_path: logs/audit.log
  
  # تفعيل HTTPS
  use_https: false
  
  # ملف الشهادة (للإنتاج)
  ssl_cert: ""
  ssl_key: ""
  
  # فترة انتهاء الجلسة (بالساعات)
  session_timeout: 24
```

---

## أمثلة التكوين

### تكوين التطوير

```yaml
# config/settings.yaml - وضع التطوير

general:
  mode: development
  log_level: DEBUG
  timezone: UTC

monitoring:
  enabled: true
  scan_interval: 5
  deep_scan: false

blocking:
  enabled: false  # لا تحظر في التطوير

notifications:
  enabled: false  # لا ترسل إشعارات في التطوير

prometheus:
  enabled: false
```

### تكوين الإنتاج

```yaml
# config/settings.yaml - وضع الإنتاج

general:
  mode: production
  log_level: WARNING
  timezone: Asia/Riyadh

monitoring:
  enabled: true
  scan_interval: 1
  deep_scan: true

blocking:
  enabled: true
  threshold: 3
  time_window: 30
  use_iptables: true
  default_duration: 360  # 6 ساعات

notifications:
  enabled: true
  slack:
    enabled: true
    webhook_url: ${SLACK_WEBHOOK_URL}
  discord:
    enabled: true
    webhook_url: ${DISCORD_WEBHOOK_URL}

prometheus:
  enabled: true
  port: 9090

security:
  security_checks: true
  audit_logging: true
  use_https: true
  ssl_cert: /etc/ssl/certs/cert.pem
  ssl_key: /etc/ssl/private/key.pem
  session_timeout: 8
```

---

## متغيرات البيئة

يمكن تجاوز إعدادات YAML باستخدام متغيرات البيئة:

| متغير البيئة | المقابل في YAML |
|--------------|-----------------|
| AG_MODE | general.mode |
| AG_LOG_LEVEL | general.log_level |
| AG_BLOCKING_ENABLED | blocking.enabled |
| AG_SLACK_WEBHOOK_URL | notifications.slack.webhook_url |
| AG_PROMETHEUS_PORT | prometheus.port |

مثال:

```bash
export AG_MODE=production
export AG_LOG_LEVEL=WARNING
export AG_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## التحقق من الإعدادات

للتحقق من صحة ملف الإعدادات:

```bash
python -c "
import yaml
with open('config/settings.yaml') as f:
    config = yaml.safe_load(f)
    print('✅ الإعدادات صالحة')
    print(f'وضع التشغيل: {config[\"general\"][\"mode\"]}')
    print(f'المسار: {config[\"monitoring\"][\"enabled\"]}')
"
```

---

## الدعم

للمساعدة في الإعدادات:

- **المستندات:** راجع التوثيق الكامل
- **GitHub Issues:** أبلغ عن مشكلة
- **البريد:** support@autoguardian.local
