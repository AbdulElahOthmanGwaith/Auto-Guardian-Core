# Makefile لنظام الحارس التلقائي
# Auto Guardian System Makefile

# إعدادات افتراضية
SHELL := /bin/bash
PYTHON := python3
PIP := pip3
VENV := venv
VENV_ACTIVATE := $(VENV)/bin/activate

# المسارات
SRC := src
TESTS := tests
CONFIG := config
DOCS := docs
ASSETS := assets

# ملفات مهمة
REQUIREMENTS := requirements.txt
README := README.md
DOCKER_COMPOSE := docker-compose.yml

# ألوان للطباعة
GREEN := \033[0;32m
BLUE := \033[0;34m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# دوال مساعدة
define print_status
	@echo -e "$(BLUE)[INFO]$(NC) $(1)"
endef

define print_success
	@echo -e "$(GREEN)[SUCCESS]$(NC) $(1)"
endef

define print_warning
	@echo -e "$(YELLOW)[WARNING]$(NC) $(1)"
endef

define print_error
	@echo -e "$(RED)[ERROR]$(NC) $(1)"
endef

.PHONY: help install dev-install test test-cov lint format check clean clean-pyc clean-build clean-docker docker-build docker-run docker-stop docker-logs logs zip upload docs docs-serve

# ========================================
# الهدف الافتراضي - عرض المساعدة
# ========================================
help:
	@echo ""
	@echo -e "$(GREEN)╔════════════════════════════════════════════════════════════╗$(NC)"
	@echo -e "$(GREEN)║         نظام الحارس التلقائي - أوامر التطوير              ║$(NC)"
	@echo -e "$(GREEN)╚════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "الأوامر المتاحة:"
	@echo ""
	@echo "  $(GREEN)التثبيت والإعداد$(NC)"
	@echo "    make install           - تثبيت التبعيات الأساسية"
	@echo "    make dev-install       - تثبيت التبعيات مع أدوات التطوير"
	@echo "    make update            - تحديث التبعيات"
	@echo ""
	@echo "  $(GREEN)الاختبارات$(NC)"
	@echo "    make test              - تشغيل جميع الاختبارات"
	@echo "    make test-coverage     - تشغيل الاختبارات مع تقرير التغطية"
	@echo "    make test-unit         - تشغيل اختبارات الوحدة فقط"
	@echo "    make test-integration  - تشغيل اختبارات التكامل"
	@echo ""
	@echo "  $(GREEN)جودة الكود$(NC)"
	@echo "    make lint              - فحص الكود باستخدام linters"
	@echo "    make format            - تنسيق الكود تلقائياً"
	@echo "    make check             - التحقق من جودة الكود"
	@echo ""
	@echo "  $(GREEN)التنظيف$(NC)"
	@echo "    make clean             - تنظيف ملفات البناء"
	@echo "    make clean-pyc         - تنظيف ملفات Python المؤقتة"
	@echo "    clean-all             - تنظيف كل شيء"
	@echo ""
	@echo "  $(GREEN)Docker$(NC)"
	@echo "    make docker-build     - بناء صورة Docker"
	@echo "    make docker-run       - تشغيل الحاويات"
	@echo "    make docker-stop      - إيقاف الحاويات"
	@echo "    make docker-logs      - عرض سجلات Docker"
	@echo ""
	@echo "  $(GREEN)النظام$(NC)"
	@echo "    make run              - تشغيل النظام"
	@echo "    make logs             - عرض سجلات النظام"
	@echo ""
	@echo "  $(GREEN)الأرشفة$(NC)"
	@echo "    make zip              - إنشاء ملف ZIP للمشروع"
	@echo ""
	@echo "  $(GREEN)التوثيق$(NC)"
	@echo "    make docs             - بناء التوثيق"
	@echo "    make docs-serve       - عرض التوثيق محلياً"
	@echo ""
	@echo "للحصول على تفاصيل إضافية، راجع ملف CONTRIBUTING.md"
	@echo ""

# ========================================
# قسم التثبيت
# ========================================
install:
	$(call print_status,"جاري تثبيت التبعيات...")
	@if [ ! -f $(REQUIREMENTS) ]; then $(call print_error,"ملف requirements.txt غير موجود"); exit 1; fi
	$(PIP) install -r $(REQUIREMENTS)
	$(call print_success,"تم تثبيت التبعيات بنجاح")

dev-install: install
	$(call print_status,"جاري تثبيت أدوات التطوير...")
	$(PIP) install pytest pytest-cov pytest-mock pytest-cov coveralls
	$(PIP) install black flake8 mypy isort pre-commit
	$(PIP) install sphinx sphinx-rtd-theme
	$(call print_success,"تم تثبيت أدوات التطوير")

update:
	$(call print_status,"جاري تحديث التبعيات...")
	$(PIP) install --upgrade -r $(REQUIREMENTS)
	$(call print_success,"تم تحديث التبعيات")

# ========================================
# قسم الاختبارات
# ========================================
test:
	$(call print_status,"جاري تشغيل الاختبارات...")
	@if [ ! -d "$(TESTS)" ]; then $(call print_error,"مجلد الاختبارات غير موجود"); exit 1; fi
	$(PYTHON) -m pytest $(TESTS) -v --tb=short
	$(call print_success,"اكتمل تشغيل الاختبارات")

test-coverage:
	$(call print_status,"جاري تشغيل الاختبارات مع التغطية...")
	$(PYTHON) -m pytest $(TESTS) --cov=$(SRC) --cov-report=html --cov-report=term-missing
	$(call print_success,"تم إنشاء تقرير التغطية في مجلد htmlcov/")

test-unit:
	$(call print_status,"جاري تشغيل اختبارات الوحدة...")
	$(PYTHON) -m pytest $(TESTS)/test_*.py -v

test-integration:
	$(call print_status,"جاري تشغيل اختبارات التكامل...")
	$(PYTHON) -m pytest $(TESTS)/test_*integration*.py -v -s

# ========================================
# قسم جودة الكود
# ========================================
lint:
	$(call print_status,"جاري فحص الكود...")
	@echo "--- Flake8 ---"
	@flake8 $(SRC) --max-line-length=100 --extend-ignore=E203
	@echo "--- Mypy ---"
	@mypy $(SRC) --ignore-missing-imports --strict-optional
	$(call print_success,"اكتمل فحص الكود")

format:
	$(call print_status,"جاري تنسيق الكود...")
	@echo "--- Black ---"
	@black $(SRC) $(TESTS) --line-length 100
	@echo "--- isort ---"
	@isort $(SRC) $(TESTS) --profile black
	$(call print_success,"تم تنسيق الكود")

check:
	$(call print_status,"جاري التحقق من جودة الكود...")
	@echo "--- التحقق من التنسيق ---"
	@black --check $(SRC) $(TESTS) --line-length 100
	@echo "--- التحقق من الاستيرادات ---"
	@isort --check-only $(SRC) $(TESTS) --profile black
	@echo "--- Flake8 ---"
	@flake8 $(SRC) --max-line-length=100 --extend-ignore=E203
	$(call print_success,"اجتاز جميع فحوصات الجودة")

# ========================================
# قسم التنظيف
# ========================================
clean:
	$(call print_status,"جاري تنظيف ملفات البناء...")
	@rm -rf build/ dist/ *.egg-info/
	@rm -rf htmlcov/ .coverage .coverage.*
	$(call print_success,"تم تنظيف ملفات البناء")

clean-pyc:
	$(call print_status,"جاري تنظيف ملفات Python المؤقتة...")
	@find . -type d -name __pycache__ -exec rm -rf {} +
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name ".pyc" -delete
	@rm -rf $(VENV)
	$(call print_success,"تم تنظيف ملفات Python")

clean-all: clean clean-pyc
	$(call print_status,"جاري تنظيف كل شيء...")
	@rm -rf logs/*.log
	@rm -rf .hypothesis/
	$(call print_success,"تم تنظيف كل شيء")

# ========================================
# قسم Docker
# ========================================
docker-build:
	$(call print_status,"جاري بناء صورة Docker...")
	@if [ ! -f "Dockerfile" ]; then $(call print_error,"ملف Dockerfile غير موجود"); exit 1; fi
	docker-compose build
	$(call print_success,"تم بناء الصورة")

docker-run:
	$(call print_status,"جاري تشغيل الحاويات...")
	@if [ ! -f "$(DOCKER_COMPOSE)" ]; then $(call print_error,"ملف docker-compose.yml غير موجود"); exit 1; fi
	docker-compose up -d
	$(call print_success,"تم تشغيل الحاويات. الخدمات متاحة على:")
	@echo "  - النظام الرئيسي: http://localhost:8000"
	@echo "  - Prometheus: http://localhost:9090"
	@echo "  - Grafana: http://localhost:3000"

docker-stop:
	$(call print_status,"جاري إيقاف الحاويات...")
	docker-compose down
	$(call print_success,"تم إيقاف الحاويات")

docker-logs:
	$(call print_status,"جاري عرض السجلات...")
	docker-compose logs -f auto-guardian

# ========================================
# قسم تشغيل النظام
# ========================================
run:
	$(call print_status,"جاري تشغيل نظام الحارس التلقائي...")
	$(PYTHON) -m $(SRC).main
	$(call print_success,"تم تشغيل النظام")

logs:
	$(call print_status,"جاري عرض سجلات النظام...")
	@if [ -d "logs" ]; then tail -f logs/*.log; else $(call print_warning,"مجلد السجلات غير موجود"); fi

# ========================================
# قسم الأرشفة
# ========================================
zip:
	$(call print_status,"جاري إنشاء ملف ZIP...")
	@VERSION=$$(git describe --tags 2>/dev/null || echo "1.3.0"); \
	FILENAME="auto-guardian-system-$${VERSION}.zip"; \
	if [ -f "$$FILENAME" ]; then rm "$$FILENAME"; fi \
	zip -r "$$FILENAME" . \
		--exclude="*.git*" \
		--exclude="*.pyc" \
		--exclude="__pycache__/*" \
		--exclude="*.egg-info/*" \
		--exclude="build/*" \
		--exclude="dist/*" \
		--exclude="htmlcov/*" \
		--exclude=".hypothesis/*" \
		--exclude="venv/*" \
		--exclude="node_modules/*" \
		--exclude=".DS_Store" \
		--exclude="*.log" \
		--exclude="logs/*" \
		--exclude="backups/*"
	$(call print_success,"تم إنشاء الملف: $$FILENAME")
	@ls -lh "$$FILENAME"

# ========================================
# قسم التوثيق
# ========================================
docs:
	$(call print_status,"جاري بناء التوثيق...")
	@if [ ! -d "$(DOCS)" ]; then $(call print_error,"مجلد التوثيق غير موجود"); exit 1; fi
	$(PYTHON) -m sphinx -b html $(DOCS) $(DOCS)/_build/html
	$(call print_success,"تم بناء التوثيق في $(DOCS)/_build/html/")

docs-serve:
	$(call print_status,"جاري تشغيل خادم التوثيق...")
	@if [ ! -d "$(DOCS)/_build/html" ]; then make docs; fi
	$(PYTHON) -m http.server 8080 -d $(DOCS)/_build/html
