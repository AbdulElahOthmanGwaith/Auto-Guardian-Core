#!/bin/bash
# سكريبت صيانة نظام الحارس التلقائي
# Auto Guardian System Maintenance Script
# =========================================

# إعداداتColors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# إعدادات
LOG_FILE="logs/maintenance.log"
DATA_DIR="data"
LOGS_DIR="logs"

# دوال مساعدة
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

print_header() {
    echo ""
    echo "=============================================="
    echo "  نظام الحارس التلقائي - الصيانة"
    echo "=============================================="
    echo ""
}

# إنشاء مجلد السجلات إن لم يوجد
mkdir -p "$(dirname "$LOG_FILE")" "$DATA_DIR" "$LOGS_DIR"

# دالة تنظيف ملفات Python المؤقتة
clean_pycache() {
    print_info "جاري تنظيف ملفات Python المؤقتة..."
    
    local count=0
    
    # حذف مجلدات __pycache__
    while IFS= read -r -d '' dir; do
        rm -rf "$dir"
        print_info "حُذف: $dir"
        ((count++))
    done < <(find . -type d -name "__pycache__" -print0 2>/dev/null)
    
    # حذف ملفات .pyc
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++))
    done < <(find . -name "*.pyc" -print0 2>/dev/null)
    
    # حذف ملفات .pyo
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++))
    done < <(find . -name "*.pyo" -print0 2>/dev/null)
    
    # حذف مجلدات .pytest_cache
    rm -rf .pytest_cache/ 2>/dev/null
    ((count++))
    
    # حذف مجلدات .hypothesis
    rm -rf .hypothesis/ 2>/dev/null
    ((count++))
    
    print_success "تم تنظيف $count عنصر"
}

# دالة تنظيف السجلات القديمة
clean_logs() {
    print_info "جاري تنظيف السجلات القديمة (أقدم من 14 يوماً)..."
    
    local count=0
    local size_freed=0
    
    # البحث عن ملفات السجلات القديمة
    while IFS= read -r -d '' file; do
        local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
        size_freed=$((size_freed + file_size))
        rm -f "$file"
        print_info "حُذف: $(basename "$file")"
        ((count++))
    done < <(find "$LOGS_DIR" -name "*.log" -mtime +14 -print0 2>/dev/null)
    
    if [ $count -gt 0 ]; then
        print_success "حُذفت $count ملف سجل ($(echo "scale=2; $size_freed/1048576" | bc) MB)"
    else
        print_info "لا توجد ملفات سجل قديمة للحذف"
    fi
}

# دالة تنظيف ملفات الاختبار
clean_tests() {
    print_info "جاري تنظيف ملفات الاختبار..."
    
    # حذف تقارير التغطية القديمة
    rm -rf htmlcov/ .coverage .coverage.* 2>/dev/null
    local count=1
    
    # حذف تقارير pytest
    rm -rf pytest-results/ 2>/dev/null || true
    
    print_success "تم تنظيف ملفات الاختبار"
}

# دالة تنظيف ملفات البناء
clean_build() {
    print_info "جاري تنظيف ملفات البناء..."
    
    # مجلدات البناء
    rm -rf build/ dist/ *.egg-info/ 2>/dev/null
    local count=3
    
    # ملفات .egg
    rm -rf *.egg 2>/dev/null
    
    # ملفات Wheel
    rm -rf *.whl 2>/dev/null
    
    print_success "تم تنظيف ملفات البناء"
}

# دالة تنظيف ملفات التخزين المؤقت
clean_cache() {
    print_info "جاري تنظيف ملفات التخزين المؤقت..."
    
    # حذف ذاكرة التخزين المؤقت لـ pip
    pip cache purge 2>/dev/null || true
    
    # حذف مجلدات ذاكرة التخزين المؤقت
    rm -rf ~/.cache/pip 2>/dev/null || true
    
    # حذف ذاكرة التخزين المؤقت لـ mypy
    rm -rf .mypy_cache/ 2>/dev/null || true
    
    # حذف ذاكرة التخزين المؤقت لـ ruff
    rm -rf .ruff_cache/ 2>/dev/null || true
    
    print_success "تم تنظيف ملفات التخزين المؤقت"
}

# دالة التحقق من مساحة القرص
check_disk_space() {
    print_info "جاري التحقق من مساحة القرص..."
    
    local disk_usage=$(df -h . | tail -1 | awk '{print $5}' | sed 's/%//')
    local disk_available=$(df -h . | tail -1 | awk '{print $4}')
    
    echo ""
    echo "معلومات مساحة القرص:"
    echo "--------------------"
    df -h . | tail -1
    echo ""
    
    if [ "$disk_usage" -gt 80 ]; then
        print_warning "تحذير: استخدام القرص مرتفع ($disk_usage%)"
        print_info "المساحة المتاحة: $disk_available"
    else
        print_success "مساحة القرص كافية (사용량: $disk_usage%)"
    fi
}

# دالة التحقق من حالة Git
check_git_status() {
    print_info "جاري التحقق من حالة Git..."
    
    # التحقق من وجود Git
    if ! command -v git &> /dev/null; then
        print_warning "Git غير مثبت"
        return
    fi
    
    # التحقق من حالة المستودع
    cd "$(dirname "$0")/.." 2>/dev/null
    
    if [ -d ".git" ]; then
        # الفروع المحلية
        echo ""
        echo "الفروع المحلية:"
        git branch --color=never 2>/dev/null | head -5
        
        # حالة المستودع
        local status=$(git status --short 2>/dev/null | wc -l)
        if [ "$status" -gt 0 ]; then
            print_warning "توجد تغييرات غير ملتزم بها ($status ملف)"
        else
            print_success "المستودع نظيف"
        fi
        
        # التحقق من التحديثات
        git fetch origin 2>/dev/null
        
        local behind=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
        if [ "$behind" -gt 0 ]; then
            print_info "يوجد تحديث متاح ($behind commits behind)"
        else
            print_success "المستودع محدث"
        fi
    else
        print_info "المستودع ليس Git"
    fi
}

# دالة التحقق من التبعيات
check_dependencies() {
    print_info "جاري التحقق من التبعيات..."
    
    # التحقق من Python
    if command -v python3 &> /dev/null; then
        print_success "Python مثبت: $(python3 --version)"
    else
        print_error "Python غير مثبت!"
    fi
    
    # التحقق من الحزم المهمة
    echo ""
    echo "حالة الحزم:"
    echo "----------"
    
    for pkg in requests pyyaml pytest; do
        if python3 -c "import $pkg" 2>/dev/null; then
            print_success "$pkg ✓"
        else
            print_warning "$pkg ✗ (غير مثبت)"
        fi
    done
}

# دالة إنشاء تقارير الحالة
generate_status_report() {
    print_info "جاري إنشاء تقرير الحالة..."
    
    local report_file="logs/status_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "============================================="
        echo "  تقرير حالة نظام الحارس التلقائي"
        echo "============================================="
        echo ""
        echo "التاريخ: $(date)"
        echo ""
        echo "بيئة التشغيل:"
        echo "------------"
        echo "Python: $(python3 --version 2>&1)"
        echo "النظام: $(uname -a)"
        echo ""
        echo "مساحة القرص:"
        echo "-----------"
        df -h . | tail -1
        echo ""
        echo "حالة Git:"
        echo "--------"
        git status --short 2>/dev/null || echo "غير متاح"
        echo ""
        echo "============================================="
    } > "$report_file"
    
    print_success "تم إنشاء التقرير: $report_file"
}

# دالة إصلاح الأذونات
fix_permissions() {
    print_info "جاري إصلاح أذونات الملفات..."
    
    # تصحيح أذونات الملفات التنفيذية
    chmod +x scripts/*.sh 2>/dev/null || true
    
    # تصحيح أذونات الملفات المهمة
    chmod 600 config/*.yaml 2>/dev/null || true
    
    # تصحيح أذونات المجلدات
    find . -type d -exec chmod 755 {} \; 2>/dev/null || true
    
    print_success "تم إصلاح الأذونات"
}

# دالة حذف الملفات المؤقتة
clean_temp() {
    print_info "جاري حذف الملفات المؤقتة..."
    
    local count=0
    
    # حذف ملفات ~
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++))
    done < <(find . -name "*~" -print0 2>/dev/null)
    
    # حذف ملفات .swp
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++))
    done < <(find . -name "*.swp" -print0 2>/dev/null)
    
    # حذف ملفات .swo
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((count++))
    done < <(find . -name "*.swo" -print0 2>/dev/null)
    
    # حذف ملفات .tmp
    rm -f *.tmp 2>/dev/null
    rm -f tmp/* 2>/dev/null || true
    
    print_success "تم حذف $count ملف مؤقت"
}

# دالة عرض المساعدة
show_help() {
    echo ""
    echo "استخدام: $0 [الخيار]"
    echo ""
    echo "خيارات الصيانة:"
    echo ""
    echo "  all             - تشغيل جميع عمليات الصيانة"
    echo "  pycache         - تنظيف ملفات Python المؤقتة"
    echo "  logs            - تنظيف السجلات القديمة"
    echo "  tests           - تنظيف ملفات الاختبار"
    echo "  build           - تنظيف ملفات البناء"
    echo "  cache           - تنظيف ملفات التخزين المؤقت"
    echo "  temp            - حذف الملفات المؤقتة"
    echo "  permissions     - إصلاح أذونات الملفات"
    echo "  disk            - التحقق من مساحة القرص"
    echo "  git             - التحقق من حالة Git"
    echo "  deps            - التحقق من التبعيات"
    echo "  report          - إنشاء تقرير الحالة"
    echo "  help            - عرض هذه المساعدة"
    echo ""
}

# ========================================
# البرنامج الرئيسي
# ========================================

print_header

# التحقق من الوسائط
case "${1:-all}" in
    all)
        echo "جاري تشغيل جميع عمليات الصيانة..."
        echo ""
        
        clean_pycache
        echo ""
        
        clean_logs
        echo ""
        
        clean_tests
        echo ""
        
        clean_build
        echo ""
        
        clean_cache
        echo ""
        
        clean_temp
        echo ""
        
        fix_permissions
        echo ""
        
        check_disk_space
        echo ""
        
        generate_status_report
        ;;
        
    pycache)
        clean_pycache
        ;;
        
    logs)
        clean_logs
        ;;
        
    tests)
        clean_tests
        ;;
        
    build)
        clean_build
        ;;
        
    cache)
        clean_cache
        ;;
        
    temp)
        clean_temp
        ;;
        
    permissions)
        fix_permissions
        ;;
        
    disk)
        check_disk_space
        ;;
        
    git)
        check_git_status
        ;;
        
    deps)
        check_dependencies
        ;;
        
    report)
        generate_status_report
        ;;
        
    help|--help|-h)
        show_help
        ;;
        
    *)
        print_error "خيار غير معروف: $1"
        show_help
        exit 1
        ;;
esac

echo ""
print_success "اكتمل العمل بنجاح!"
echo ""
