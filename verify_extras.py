#!/usr/bin/env python3
"""
سكريبت التحقق والتجميد الشامل لنظام الحارس التلقائي
Comprehensive Verification and Packaging Script for Auto Guardian System
"""

import os
import sys
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional

# الألوان للطباعة
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_header(text: str) -> None:
    """طباعة عنوان"""
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{text:^70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}\n")


def print_status(text: str) -> None:
    """طباعة حالة"""
    print(f"{Colors.OKBLUE}ℹ{Colors.ENDC} {text}")


def print_success(text: str) -> None:
    """طباعة نجاح"""
    print(f"{Colors.OKGREEN}✓{Colors.ENDC} {text}")


def print_error(text: str) -> None:
    """طباعة خطأ"""
    print(f"{Colors.FAIL}✗{Colors.ENDC} {text}")


def print_warning(text: str) -> None:
    """طباعة تحذير"""
    print(f"{Colors.WARNING}⚠{Colors.ENDC} {text}")


class FileValidator:
    """متحقق صحة الملفات"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.success: List[str] = []
        self.valid_files: List[str] = []
    
    def validate_svg(self, filepath: str) -> bool:
        """التحقق من صحة ملف SVG"""
        path = self.project_root / filepath
        try:
            ET.parse(path)
            self.success.append(f"SVG صالح: {filepath}")
            return True
        except ET.ParseError as e:
            self.errors.append(f"خطأ في SVG {filepath}: {e}")
            return False
        except Exception as e:
            self.warnings.append(f"تحذير SVG {filepath}: {e}")
            return True  # ليس خطأ حرج
    
    def validate_yaml(self, filepath: str) -> bool:
        """التحقق من صحة ملف YAML"""
        path = self.project_root / filepath
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            self.success.append(f"YAML صالح: {filepath}")
            return True
        except ImportError:
            self.warnings.append("PyYAML غير مثبت - تخطي فحص YAML")
            return True
        except yaml.YAMLError as e:
            self.errors.append(f"خطأ في YAML {filepath}: {e}")
            return False
        except Exception as e:
            self.warnings.append(f"تحذير YAML {filepath}: {e}")
            return True
    
    def validate_json(self, filepath: str) -> bool:
        """التحقق من صحة ملف JSON"""
        path = self.project_root / filepath
        try:
            import json
            with open(path, 'r', encoding='utf-8') as f:
                json.load(f)
            self.success.append(f"JSON صالح: {filepath}")
            return True
        except ImportError:
            self.warnings.append("PyYAML غير مثبت - تخطي فحص JSON")
            return True
        except json.JSONDecodeError as e:
            self.errors.append(f"خطأ في JSON {filepath}: {e}")
            return False
        except Exception as e:
            self.warnings.append(f"تحذير JSON {filepath}: {e}")
            return True
    
    def validate_markdown(self, filepath: str) -> bool:
        """التحقق من صحة ملف Markdown"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص البنية الأساسية
                if '# ' in content or '---' in content:
                    self.success.append(f"Markdown صالح: {filepath}")
                    return True
                else:
                    self.warnings.append(f"Markdown قد ينقصه عنوان: {filepath}")
                    return True
        except Exception as e:
            self.errors.append(f"خطأ في Markdown {filepath}: {e}")
            return False
    
    def validate_makefile(self, filepath: str) -> bool:
        """التحقق من صحة ملف Makefile"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص وجود أهداف أساسية
                required_targets = ['help:', 'install:', 'test:']
                for target in required_targets:
                    if target not in content:
                        self.warnings.append(f"Makefile ينقصه هدف: {target}")
                self.success.append(f"Makefile صالح: {filepath}")
                return True
        except Exception as e:
            self.errors.append(f"خطأ في Makefile {filepath}: {e}")
            return False
    
    def validate_github_workflow(self, filepath: str) -> bool:
        """التحقق من صحة ملف GitHub Actions Workflow"""
        path = self.project_root / filepath
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                # التحقق من البنية الأساسية
                # ملاحظة: المفتاح 'on' قد يُفسر كـ True في YAML 1.1
                # لذا نفحص وجود المفاتيح الأساسية بطرق مختلفة
                has_name = 'name' in content or 1 in content
                has_jobs = 'jobs' in content or 'jobs' in str(content)
                
                # التحقق من وجود 'on' أو 'on' كـ True
                has_on = 'on' in content or True in content or 'on' in str(content)
                
                if has_name and has_jobs and has_on:
                    self.success.append(f"GitHub Workflow صالح: {filepath}")
                    return True
                else:
                    missing = []
                    if not has_name:
                        missing.append('name')
                    if not has_jobs:
                        missing.append('jobs')
                    if not has_on:
                        missing.append('on')
                    self.errors.append(f"GitHub Workflow ينقصه: {', '.join(missing)}")
                    return False
        except Exception as e:
            self.errors.append(f"خطأ في GitHub Workflow {filepath}: {e}")
            return False
    
    def validate_editorconfig(self, filepath: str) -> bool:
        """التحقق من صحة ملف .editorconfig"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'root = true' in content and '[*]' in content:
                    self.success.append(f".editorconfig صالح: {filepath}")
                    return True
                else:
                    self.warnings.append(f".editorconfig قد ينقصه إعدادات: {filepath}")
                    return True
        except Exception as e:
            self.errors.append(f"خطأ في .editorconfig {filepath}: {e}")
            return False
    
    def validate_bash_script(self, filepath: str) -> bool:
        """التحقق من صحة سكريبت Bash"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص shebang
                if content.startswith('#!/bin/bash') or content.startswith('#!/usr/bin/env bash'):
                    # فحص الأخطاء الأساسية
                    if 'set -e' in content or 'set -o errexit' in content:
                        self.success.append(f"Bash Script صالح: {filepath}")
                        return True
                    else:
                        self.warnings.append(f"Bash Script ينقصه 'set -e': {filepath}")
                        return True
                else:
                    self.warnings.append(f"Bash Script قد ينقصه shebang: {filepath}")
                    return True
        except Exception as e:
            self.errors.append(f"خطأ في Bash Script {filepath}: {e}")
            return False
    
    def validate_requirements(self, filepath: str) -> bool:
        """التحقق من صحة ملف requirements.txt"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
                valid = True
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # فحص التنسيق الأساسي
                    if '>=' not in line and '<=' not in line and '==' not in line and '>' not in line and '<' not in line and '!=' not in line:
                        if 'git+' not in line and '-e git+' not in line:
                            self.warnings.append(f"requirements.txt:{i} - قد يكون التنسيق غير قياسي: {line}")
                self.success.append(f"requirements.txt صالح: {filepath}")
                return True
        except Exception as e:
            self.errors.append(f"خطأ في requirements.txt {filepath}: {e}")
            return False
    
    def validate_gitignore(self, filepath: str) -> bool:
        """التحقق من صحة ملف .gitignore"""
        path = self.project_root / filepath
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                # فحص وجود بعض الأنماط الأساسية
                required_patterns = ['__pycache__', '*.log', '.gitignore']
                for pattern in required_patterns:
                    if pattern not in content:
                        self.warnings.append(f".gitignore قد ينقصه: {pattern}")
                self.success.append(f".gitignore صالح: {filepath}")
                return True
        except Exception as e:
            self.errors.append(f"خطأ في .gitignore {filepath}: {e}")
            return False
    
    def validate_openapi(self, filepath: str) -> bool:
        """التحقق من صحة ملف OpenAPI"""
        path = self.project_root / filepath
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                # التحقق من البنية الأساسية
                if 'openapi' in content and 'info' in content and 'paths' in content:
                    self.success.append(f"OpenAPI صالح: {filepath}")
                    return True
                else:
                    self.errors.append(f"OpenAPI غير مكتمل: {filepath}")
                    return False
        except Exception as e:
            self.errors.append(f"خطأ في OpenAPI {filepath}: {e}")
            return False
    
    def validate_all(self) -> bool:
        """التحقق من جميع الملفات"""
        print_header("بدء التحقق من صحة المشروع")
        
        # تعريف الملفات للفحص
        files_to_check = [
            # Markdown files
            ('README.md', 'validate_markdown'),
            ('CHANGELOG.md', 'validate_markdown'),
            ('SECURITY.md', 'validate_markdown'),
            ('CODE_OF_CONDUCT.md', 'validate_markdown'),
            ('CONTRIBUTING.md', 'validate_markdown'),
            ('docs/configuration.md', 'validate_markdown'),
            
            # YAML files
            ('docker-compose.yml', 'validate_yaml'),
            ('.env.example', 'validate_yaml'),
            
            # GitHub Actions
            ('.github/workflows/ci-cd.yml', 'validate_github_workflow'),
            
            # Issue Templates
            ('.github/ISSUE_TEMPLATE/bug_report.md', 'validate_markdown'),
            ('.github/ISSUE_TEMPLATE/feature_request.md', 'validate_markdown'),
            ('.github/ISSUE_TEMPLATE/security_report.md', 'validate_markdown'),
            
            # PR Template
            ('.github/pull_request_template.md', 'validate_markdown'),
            
            # Other files
            ('requirements.txt', 'validate_requirements'),
            ('.gitignore', 'validate_gitignore'),
            ('.editorconfig', 'validate_editorconfig'),
            ('Makefile', 'validate_makefile'),
            
            # Scripts
            ('scripts/backup.sh', 'validate_bash_script'),
            ('scripts/maintenance.sh', 'validate_bash_script'),
            ('scripts/upgrade.sh', 'validate_bash_script'),
            
            # OpenAPI
            ('docs/api/openapi.yaml', 'validate_openapi'),
        ]
        
        svg_files = [
            'assets/banner.svg',
            'assets/dashboard.svg',
            'assets/slack-alert.svg',
            'assets/discord-alert.svg',
        ]
        
        all_valid = True
        
        # تشغيل فحوصات الملفات
        print_status("التحقق من ملفات التوثيق والتكوين...")
        for filename, validate_method in files_to_check:
            path = self.project_root / filename
            if path.exists():
                if not getattr(self, validate_method)(filename):
                    all_valid = False
            else:
                self.warnings.append(f"الملف غير موجود: {filename}")
        
        # فحص ملفات SVG
        print_status("التحقق من ملفات SVG...")
        for svg_file in svg_files:
            path = self.project_root / svg_file
            if path.exists():
                if not self.validate_svg(svg_file):
                    all_valid = False
            else:
                self.errors.append(f"ملف SVG مفقود: {svg_file}")
                all_valid = False
        
        return all_valid
    
    def print_summary(self) -> bool:
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
        
        if self.warnings:
            print_warning("\nالتحذيرات:")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        print_success("\n✅ اجتاز المشروع جميع الفحوصات الأساسية!")
        return True


class ProjectPacker:
    """مجمّع المشروع"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
    
    def create_zip(self, output_filename: Optional[str] = None) -> Optional[Path]:
        """إنشاء ملف ZIP للمشروع"""
        print_header("إنشاء ملف ZIP")
        
        # تحديد اسم الملف
        if output_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"auto-guardian-system-extras_{timestamp}.zip"
        
        # الملفات والمجلدات المراد تضمينها
        include_patterns = [
            '.editorconfig',
            '.env.example',
            '.gitignore',
            'requirements.txt',
            'Makefile',
            'docker-compose.yml',
            'README.md',
            'CHANGELOG.md',
            'SECURITY.md',
            'CODE_OF_CONDUCT.md',
            'CONTRIBUTING.md',
            'docs/',
            'scripts/',
            'assets/',
            '.github/',
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
            'verify.py',
            '*.tar.gz',
        ]
        
        def should_include(path: str) -> bool:
            """تحديد ما إذا كان يجب تضمين المسار"""
            name = os.path.basename(path)
            
            # استبعاد المجلدات
            if os.path.isdir(path):
                dir_name = os.path.basename(path)
                excluded_dirs = ['.git', '__pycache__', 'build', 'dist', 'htmlcov', '.hypothesis', 
                               'venv', 'node_modules', 'logs', 'backups', '.vscode', '.idea']
                if dir_name in excluded_dirs:
                    return False
                return True
            
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
                print_status("جاري إضافة الملفات...")
                add_to_zip(zip_file, str(self.project_root), str(self.project_root))
                
                # إضافة معلومات إضافية
                manifest_content = self._create_manifest()
                zip_file.writestr('MANIFEST.txt', manifest_content)
                print_success("أُضيف: MANIFEST.txt")
            
            # عرض معلومات الملف
            file_size = os.path.getsize(output_path)
            print_success(f"\n✅ تم إنشاء الملف: {output_filename}")
            print_status(f"الحجم: {file_size / 1024:.2f} KB")
            print_status(f"المسار: {output_path.absolute()}")
            
            return output_path
            
        except Exception as e:
            print_error(f"خطأ في إنشاء ZIP: {e}")
            return None
    
    def _create_manifest(self) -> str:
        """إنشاء ملف Manifest"""
        return f"""# MANIFEST - Auto Guardian System Extra Features Package
# ========================================================

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Version: 1.3.0

Package Contents:
-----------------

1. GitHub Actions CI/CD
   - .github/workflows/ci-cd.yml
     سير عمل متكامل للاختبارات والفحص الأمني

2. GitHub Issue Templates
   - .github/ISSUE_TEMPLATE/bug_report.md
   - .github/ISSUE_TEMPLATE/feature_request.md
   - .github/ISSUE_TEMPLATE/security_report.md
     قوالب Issues منظمة للإبلاغ عن المشاكل والميزات والثغرات

3. GitHub PR Template
   - .github/pull_request_template.md
     قالب طلبات الدمج لضمان جودة المساهمات

4. Configuration Files
   - requirements.txt
     متطلبات Python الأساسية والإضافية
   - .env.example
     نموذج إعدادات البيئة
   - .gitignore
     استبعاد الملفات من Git
   - .editorconfig
     إعدادات محرر الكود الموحدة
   - docker-compose.yml
     تكوين Docker للنشر السريع

5. Scripts
   - scripts/backup.sh
     سكريبت النسخ الاحتياطي
   - scripts/maintenance.sh
     سكريبت الصيانة
   - scripts/upgrade.sh
     سكريبت الترقية

6. Documentation
   - docs/configuration.md
     دليل الإعدادات الشامل
   - docs/api/openapi.yaml
     توثيق API بمعايير OpenAPI 3.0

7. Assets
   - assets/*.svg
     رسومات توضيحية للمشروع

How to Use:
-----------
1. استخرج الملفات من الأرشيف
2. انسخ الملفات إلى مجلد المشروع الرئيسي
3. راجع كل ملف وتأكد من إعداداته
4. للمشاركة: git add . && git commit -m "feat: إضافة ميزات إضافية"

GitHub Actions:
---------------
- لتشغيل CI/CD: Push إلى الفرع الرئيسي
- للفحص الأمني: يعمل تلقائياً أو عند الطلب

Scripts Usage:
--------------
- ./scripts/backup.sh backup     - إنشاء نسخة احتياطية
- ./scripts/maintenance.sh all   - تشغيل الصيانة
- ./scripts/upgrade.sh git       - الترقية من Git

For more information, visit:
https://github.com/AbdulElahOthmanGwaith/auto-guardian-system

---
Generated by Auto Guardian System Documentation Generator
"""


def main():
    """الدالة الرئيسية"""
    print_header("نظام الحارس التلقائي - أداة التحقق والتجميد الشاملة")
    
    # تحديد مسار المشروع
    try:
        project_root = Path(__file__).parent.absolute()
    except NameError:
        # عند التشغيل باستخدام exec() أو -c
        import os
        project_root = Path(os.getcwd())
    
    print_status(f"مسار المشروع: {project_root}")
    
    # التحقق من الملفات
    validator = FileValidator(project_root)
    is_valid = validator.validate_all()
    
    if not is_valid:
        print_error("فشل التحقق! يرجى تصحيح الأخطاء أولاً.")
        sys.exit(1)
    
    # طباعة الملخص
    validator.print_summary()
    
    # إنشاء ملف ZIP
    packer = ProjectPacker(project_root)
    zip_path = packer.create_zip()
    
    if zip_path:
        print_header("اكتمل العمل بنجاح!")
        print("لإضافة الملفات إلى مشروعك:")
        print(f"  1. حمل ملف ZIP: {zip_path.name}")
        print(f"  2. استخرج الملفات")
        print(f"  3. انسخ الملفات إلى مجلد auto-guardian-system/")
        print(f"  4. استخدم: git add . && git commit -m 'feat: إضافة ميزات إضافية'")
    else:
        print_error("فشل في إنشاء ملف ZIP")
        sys.exit(1)


if __name__ == '__main__':
    main()
