#!/usr/bin/env python3
"""
Auto-Guardian API Server
خادم واجهة برمجة التطبيقات لنظام الحارس التلقائي للأمن

الإصدار: 1.0.0
تاريخ التحديث: 2024-01-28

يوفر هذا الخادم واجهة REST API للفحص الأمني وإدارة الثغرات
"""

import json
import os
import hashlib
import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional, List
from scripts.enhanced_security_scanner import EnhancedSecurityScanner, ScanResult


class APIHandler(SimpleHTTPRequestHandler):
    """معالج طلبات API"""
    
    # MIME types للتحميل الصحيح
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".json": "application/json",
        ".html": "text/html",
        ".js": "application/javascript",
        ".css": "text/css",
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def _send_json_response(self, data: Dict[str, Any], status: int = 200):
        """إرسال استجابة JSON"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=4, ensure_ascii=False).encode('utf-8'))
    
    def _send_error(self, message: str, status: int = 400):
        """إرسال رسالة خطأ"""
        self._send_json_response({
            "success": False,
            "error": message,
            "timestamp": datetime.datetime.now().isoformat()
        }, status)
    
    def _parse_json_body(self) -> Optional[Dict]:
        """解析 JSON من جسم الطلب"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body.decode('utf-8'))
        except Exception as e:
            pass
        return None
    
    def do_OPTIONS(self):
        """معالجة طلبات OPTIONS"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_GET(self):
        """معالجة طلبات GET"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        # تحويل معلمات الاستعلام إلى قائمة بسيطة
        query_params = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}
        
        try:
            if path == "/api/health":
                self._api_health()
            elif path == "/api/scan":
                self._api_scan(query_params)
            elif path == "/api/results":
                self._api_results(query_params)
            elif path == "/api/statistics":
                self._api_statistics()
            elif path == "/api/vulnerabilities":
                self._api_vulnerabilities(query_params)
            elif path == "/api/repositories":
                self._api_repositories(query_params)
            else:
                # خدمة الملفات الثابتة
                file_path = path.lstrip("/")
                if not file_path:
                    file_path = "index.html"
                
                if os.path.exists(file_path):
                    super().do_GET()
                else:
                    self._send_error("المسار غير موجود", 404)
                    
        except Exception as e:
            self._send_error(f"خطأ داخلي: {str(e)}", 500)
    
    def do_POST(self):
        """معالجة طلبات POST"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            if path == "/api/scan":
                self._api_scan_post()
            elif path == "/api/scan/config":
                self._api_scan_config()
            else:
                self._send_error("المسار غير موجود", 404)
                
        except Exception as e:
            self._send_error(f"خطأ داخلي: {str(e)}", 500)
    
    def _api_health(self):
        """فحص حالة الخادم"""
        self._send_json_response({
            "success": True,
            "status": "healthy",
            "service": "Auto-Guardian API",
            "version": "1.0.0",
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    def _api_scan(self, params: Dict):
        """بدء فحص جديد"""
        target = params.get("target", ".")
        min_severity = params.get("severity", "low")
        
        try:
            config = {"min_severity": min_severity.upper()}
            scanner = EnhancedSecurityScanner(target, config)
            result = scanner.scan()
            scanner.save_results()
            
            self._send_json_response({
                "success": True,
                "message": "اكتمل الفحص بنجاح",
                "scan_id": result.scan_id,
                "result": result.to_dict()
            })
        except Exception as e:
            self._send_error(f"فشل الفحص: {str(e)}")
    
    def _api_scan_post(self):
        """بدء فحص جديد عبر POST"""
        body = self._parse_json_body()
        if not body:
            self._send_error("لم يتم إرسال بيانات")
            return
        
        target = body.get("target", ".")
        severity = body.get("severity", "low")
        
        try:
            config = {"min_severity": severity.upper()}
            scanner = EnhancedSecurityScanner(target, config)
            result = scanner.scan()
            scanner.save_results()
            
            self._send_json_response({
                "success": True,
                "message": "اكتمل الفحص بنجاح",
                "scan_id": result.scan_id,
                "result": result.to_dict()
            })
        except Exception as e:
            self._send_error(f"فشل الفحص: {str(e)}")
    
    def _api_scan_config(self):
        """تكوين الفحص"""
        body = self._parse_json_body()
        if not body:
            self._send_error("لم يتم إرسال بيانات")
            return
        
        # حفظ التكوين
        config_path = "api_config.json"
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(body, f, indent=4, ensure_ascii=False)
        
        self._send_json_response({
            "success": True,
            "message": "تم حفظ التكوين بنجاح",
            "config": body
        })
    
    def _api_results(self, params: Dict):
        """استرجاع نتائج الفحص"""
        scan_id = params.get("scan_id")
        
        # البحث عن ملف النتائج
        results_path = "public/data/enhanced_security_scan.json"
        
        if os.path.exists(results_path):
            with open(results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._send_json_response({
                "success": True,
                "data": data
            })
        else:
            self._send_error("لا توجد نتائج متاحة", 404)
    
    def _api_statistics(self):
        """استرجاع الإحصائيات"""
        results_path = "public/data/enhanced_security_scan.json"
        
        if os.path.exists(results_path):
            with open(results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            stats = {
                "total_scans": 1,
                "risk_score": data.get("risk_score", 100),
                "health_status": data.get("health_status", "Unknown"),
                "total_vulnerabilities": data.get("total_vulnerabilities", 0),
                "by_severity": data.get("vulnerabilities_by_severity", {}),
                "scan_duration": data.get("scan_duration_seconds", 0)
            }
            
            self._send_json_response({
                "success": True,
                "statistics": stats
            })
        else:
            self._send_json_response({
                "success": True,
                "statistics": {
                    "total_scans": 0,
                    "risk_score": 100,
                    "health_status": "Unknown",
                    "total_vulnerabilities": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "scan_duration": 0
                }
            })
    
    def _api_vulnerabilities(self, params: Dict):
        """استرجاع الثغرات"""
        severity = params.get("severity")
        vuln_type = params.get("type")
        limit = int(params.get("limit", 100))
        
        results_path = "public/data/enhanced_security_scan.json"
        
        if os.path.exists(results_path):
            with open(results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            # تصفية الثغرات
            if severity:
                vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity]
            if vuln_type:
                vulnerabilities = [v for v in vulnerabilities if v.get("type") == vuln_type]
            
            # تحديد النتائج
            vulnerabilities = vulnerabilities[:limit]
            
            self._send_json_response({
                "success": True,
                "count": len(vulnerabilities),
                "vulnerabilities": vulnerabilities
            })
        else:
            self._send_json_response({
                "success": True,
                "count": 0,
                "vulnerabilities": []
            })
    
    def _api_repositories(self, params: Dict):
        """استرجاع معلومات المستودعات"""
        # بيانات تجريبية للمستودعات
        repos = [
            {
                "name": "auto-guardian-system",
                "full_name": "AbdulElahOthmanGwaith/Auto-Guardian-Core",
                "stars": 124,
                "forks": 45,
                "open_issues": 3,
                "language": "Python",
                "status": "active"
            },
            {
                "name": "payment-gateway-api",
                "full_name": "example/payment-gateway-api",
                "stars": 89,
                "forks": 32,
                "open_issues": 5,
                "language": "JavaScript",
                "status": "warning"
            },
            {
                "name": "user-management-service",
                "full_name": "example/user-management-service",
                "stars": 56,
                "forks": 18,
                "open_issues": 1,
                "language": "Python",
                "status": "active"
            }
        ]
        
        self._send_json_response({
            "success": True,
            "count": len(repos),
            "repositories": repos
        })
    
    def log_message(self, format, *args):
        """تسجيل رسائل الخادم"""
        print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {args[0]}")


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """تشغيل خادم API"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, APIHandler)
    
    print(f"""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   🛡️  Auto-Guardian API Server                             ║
║   =======================================                   ║
║                                                            ║
║   🌐 الخادم يعمل على: http://{host}:{port}                ║
║                                                            ║
║   📋 نقاط الوصول (API Endpoints):                          ║
║   ├─ GET  /api/health         - حالة الخادم                ║
║   ├─ GET  /api/scan           - بدء فحص                    ║
║   ├─ POST /api/scan           - بدء فحص (مع بيانات)        ║
║   ├─ GET  /api/results        - نتائج الفحص                ║
║   ├─ GET  /api/statistics     - الإحصائيات                 ║
║   ├─ GET  /api/vulnerabilities- الثغرات                    ║
║   └─ GET  /api/repositories   - المستودعات                 ║
║                                                            ║
║   اضغط Ctrl+C لإيقاف الخادم                               ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 تم إيقاف الخادم")
        httpd.shutdown()


if __name__ == "__main__":
    import sys
    
    host = "0.0.0.0"
    port = 8000
    
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    if len(sys.argv) > 2:
        host = sys.argv[2]
    
    run_server(host, port)
