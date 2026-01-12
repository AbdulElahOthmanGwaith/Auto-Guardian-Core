#!/usr/bin/env python3
"""
سكريبت التحقق والتجميد لنظام الحارس التلقائي
Auto Guardian System Verification and Packaging Script
"""

import os
import sys
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# الألوان للطباعة
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
NC = '\033[0m'

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{text:^60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")


def print_success(text):
    print(f"{Colors.OKGREEN}✓{Colors.ENDC} {text}")


def print_error(text):
    print(f"{Colors.FAIL}✗{Colors.ENDC} {text}")


def print_info(text):
    print(f"{Colors.OKBLUE}ℹ{Colors.ENDC} {text}")


def print_warning(text):
    print(f"{Colors.WARNING}⚠{Colors.ENDC} {text}")


class ProjectVerifier:
    """متحقق صحة المشروع"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.errors = []
        self.warnings = []
        self.success = []
        
    def check_file_exists(self, filepath):
        """التحقق من وجود الملف"""
        path = self.project_root / filepath
        if path.exists():
            print_success(f"الملف موجود: {filepath}")
            self.success.append(filepath)
            return True
        else:
            print_error(f"الملف مفقود: {filepath}")
            self.errors.append(f"Missing: {filepath}")
            return False
    
    def validate_svg(self, filepath):
        """التحقق من صحة ملف SVG"""
        path = self.project_root / filepath
        try:
            ET.parse(path)
            print_success(f"SVG صالح: {filepath}")
            return True
        except ET.ParseError as e:
            print_error(f"خطأ في SVG {filepath}: {e}")
            self.errors.append(f"SVG Error: {filepath}")
            return False
        except Exception as e:
            print_warning(f"تحذير في {filepath}: {e}")
            return False
    
    def validate_yaml(self, filepath):
        """التحقق من صحة ملف YAML"""
        path = self.project_root / filepath
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            print_success(f"YAML صالح: {filepath}")
            return True
        except ImportError:
            print_info(f"PyYAML غير مثبت - تخطي التحقق: {filepath}")
            return True
        except yaml.YAMLError as e:
            print_error(f"خطأ في YAML {filepath}: {e}")
            self.errors.append(f"YAML Error: {filepath}")
            return False
        except Exception as e:
            print_warning(f"تحذير في {filepath}: {e}")
            return False
    
    def validate_makefile(self, filepath):
        """التحقق من صحة ملف Makefile"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص وجود أهداف أساسية
                required_targets = ['help', 'install', 'test']
                missing = [t for t in required_targets if f'{t}:' not in content]
                if not missing:
                    print_success(f"Makefile صالح: {filepath}")
                    return True
                else:
                    print_warning(f"Makefile ينقصه أهداف: {missing}")
                    return True  # ليس خطأ حرج
        except Exception as e:
            print_error(f"خطأ في Makefile {filepath}: {e}")
            self.errors.append(f"Makefile Error: {filepath}")
            return False
    
    def validate_markdown(self, filepath):
        """التحقق من صحة ملف Markdown"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص البنية الأساسية
                if '# ' in content:
                    print_success(f"Markdown صالح: {filepath}")
                    return True
                else:
                    print_warning(f"Markdown قد ينقصه عنوان: {filepath}")
                    return True
        except Exception as e:
            print_error(f"خطأ في Markdown {filepath}: {e}")
            self.errors.append(f"Markdown Error: {filepath}")
            return False
    
    def validate_editorconfig(self, filepath):
        """التحقق من صحة ملف .editorconfig"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'root = true' in content and '[*]' in content:
                    print_success(f".editorconfig صالح: {filepath}")
                    return True
                else:
                    print_warning(f".editorconfig قد ينقصه إعدادات: {filepath}")
                    return True
        except Exception as e:
            print_error(f"خطأ في .editorconfig {filepath}: {e}")
            self.errors.append(f"EditorConfig Error: {filepath}")
            return False
    
    def verify_all(self):
        """التحقق من جميع الملفات"""
        print_header("بدء التحقق من صحة المشروع")
        
        # التحقق من الملفات الأساسية
        print_info("التحقق من الملفات الأساسية...")
        files_to_check = [
            ('README.md', 'validate_markdown'),
            ('CHANGELOG.md', 'validate_markdown'),
            ('SECURITY.md', 'validate_markdown'),
            ('CODE_OF_CONDUCT.md', 'validate_markdown'),
            ('CONTRIBUTING.md', 'validate_markdown'),
            ('docker-compose.yml', 'validate_yaml'),
            ('Makefile', 'validate_makefile'),
            ('.editorconfig', 'validate_editorconfig'),
        ]
        
        svg_files = [
            'assets/banner.svg',
            'assets/dashboard.svg',
            'assets/slack-alert.svg',
            'assets/discord-alert.svg',
        ]
        
        # تشغيل الفحوصات
        all_valid = True
        for filename, validate_method in files_to_check:
            if not getattr(self, validate_method)(filename):
                all_valid = False
        
        for svg_file in svg_files:
            if not self.check_file_exists(svg_file):
                all_valid = False
            elif not self.validate_svg(svg_file):
                all_valid = False
        
        return all_valid
    
    def print_summary(self):
        """طباعة ملخص النتائج"""
        print_header("ملخص النتائج")
        
        print(f"{Colors.OKGREEN}نجاح: {len(self.success)}{Colors.ENDC}")
        print(f"{Colors.WARNING}تحذيرات: {len(self.warnings)}{Colors.ENDC}")
        print(f"{Colors.FAIL}أخطاء: {len(self.errors)}{Colors.ENDC}")
        
        if self.errors:
            print_error("\nالأخطاء:")
            for error in self.errors:
                print(f"  - {error}")
            return False
        
        print_success("\n✅ اجتاز المشروع جميع الفحوصات!")
        return True


class ProjectPacker:
    """مجمّع المشروع لملف ZIP"""
    
    def __init__(self, project_root):
        self.project_root = Path(project_root)
        
    def create_zip(self, output_filename=None):
        """إنشاء ملف ZIP للمشروع"""
        print_header("إنشاء ملف ZIP")
        
        # تحديد اسم الملف
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"auto-guardian-system-docs_{timestamp}.zip"
        
        # الملفات والمجلدات المراد تضمينها
        include_patterns = [
            'README.md',
            'CHANGELOG.md',
            'SECURITY.md',
            'CODE_OF_CONDUCT.md',
            'CONTRIBUTING.md',
            'docker-compose.yml',
            'Makefile',
            '.editorconfig',
            'assets/',
        ]
        
        # الملفات المراد استبعادها
        exclude_patterns = [
            '.git*',
            '*.pyc',
            '__pycache__',
            '*.egg-info',
            'build',
            'dist',
            'htmlcov',
            '.hypothesis',
            'venv',
            'node_modules',
            '.DS_Store',
            '*.log',
            'logs',
            'backups',
            '.vscode',
            '.idea',
            '*.zip',
            '.coverage',
            '.coverage.*',
        ]
        
        def should_include(path):
            """تحديد ما إذا كان يجب تضمين المسار"""
            name = os.path.basename(path)
            
            # استبعاد المجلدات
            if os.path.isdir(path):
                return name not in ['.git', '__pycache__', 'build', 'dist', 'htmlcov', '.hypothesis', 'venv', 'node_modules', 'logs', 'backups', '.vscode', '.idea']
            
            # فحص الأنماط المستبعدة
            for pattern in exclude_patterns:
                if pattern.startswith('*'):
                    if name.endswith(pattern[1:]):
                        return False
                elif name == pattern:
                    return False
            
            return True
        
        def add_to_zip(zip_file, base_path, current_path):
            """إضافة الملفات إلى ZIP بشكل rekursif"""
            for item in os.listdir(current_path):
                item_path = os.path.join(current_path, item)
                relative_path = os.path.relpath(item_path, base_path)
                
                if should_include(item_path):
                    if os.path.isdir(item_path):
                        zip_file.write(item_path, relative_path)
                        add_to_zip(zip_file, base_path, item_path)
                    else:
                        try:
                            zip_file.write(item_path, relative_path)
                            print_success(f"أُضيف: {relative_path}")
                        except Exception as e:
                            print_warning(f"خطأ في إضافة {relative_path}: {e}")
        
        # إنشاء ملف ZIP
        output_path = self.project_root / output_filename
        
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                print_info("جاري إضافة الملفات...")
                add_to_zip(zip_file, str(self.project_root), str(self.project_root))
                
                # إضافة معلومات إضافية
                manifest_content = self._create_manifest()
                zip_file.writestr('MANIFEST.txt', manifest_content)
                print_success("أُضيف: MANIFEST.txt")
            
            # عرض معلومات الملف
            file_size = os.path.getsize(output_path)
            print_success(f"\n✅ تم إنشاء الملف: {output_filename}")
            print_info(f"الحجم: {file_size / 1024:.2f} KB")
            print_info(f"المسار: {output_path.absolute()}")
            
            return output_path
            
        except Exception as e:
            print_error(f"خطأ في إنشاء ZIP: {e}")
            return None
    
    def _create_manifest(self):
        """إنشاء ملف Manifest"""
        return """# MANIFEST - Auto Guardian System Documentation Package
# =========================================

Generated: {timestamp}
Version: 1.3.0

Files Included:
--------------
1. README.md - الملف التعريفي الرئيسي
2. CHANGELOG.md - سجل التغييرات
3. SECURITY.md - سياسة الأمان
4. CODE_OF_CONDUCT.md - مدونة السلوك
5. CONTRIBUTING.md - دليل المساهمة
6. docker-compose.yml - تكوين Docker Compose
7. Makefile - أوامر التطوير
8. .editorconfig - إعدادات المحرر
9. assets/ - ملفات الوسائط (SVG)

How to Use:
----------
1. استخرج الملفات من الأرشيف
2. انسخ الملفات إلى مجلد المشروع الرئيسي
3. استخدم الأمر `make help` للحصول على قائمة الأوامر
4. راجع CONTRIBUTING.md للمشاركة في التطوير

Verification:
------------
Run `python verify.py` to verify all files are valid.

For more information, visit:
https://github.com/AbdulElahOthmanGwaith/auto-guardian-system

---
Generated by Auto Guardian System Documentation Generator
""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def main():
    """الدالة الرئيسية"""
    print_header("نظام الحارس التلقائي - أداة التحقق والتجميد")
    
    # تحديد مسار المشروع
    project_root = Path(__file__).parent.absolute()
    print_info(f"مسار المشروع: {project_root}")
    
    # التحقق من الملفات
    verifier = ProjectVerifier(project_root)
    is_valid = verifier.verify_all()
    
    if not is_valid:
        print_error("فشل التحقق! يرجى تصحيح الأخطاء أولاً.")
        sys.exit(1)
    
    # طباعة الملخص
    verifier.print_summary()
    
    # إنشاء ملف ZIP
    packer = ProjectPacker(project_root)
    zip_path = packer.create_zip()
    
    if zip_path:
        print_header("اكتمل العمل بنجاح!")
        print(f"لإضافة الملفات إلى مشروعك:")
        print(f"  1. حمل ملف ZIP: {zip_path.name}")
        print(f"  2. استخرج الملفات")
        print(f"  3. انسخ الملفات إلى مجلد auto-guardian-system/")
        print(f"  4. استخدم: git add . && git commit -m 'docs: إضافة ملفات التوثيق'")
    else:
        print_error("فشل في إنشاء ملف ZIP")
        sys.exit(1)


if __name__ == '__main__':
    main()
