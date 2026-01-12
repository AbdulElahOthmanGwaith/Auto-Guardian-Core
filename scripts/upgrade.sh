#!/bin/bash
# سكريبت ترقية نظام الحارس التلقائي
# Auto Guardian System Upgrade Script
# =====================================

# إعداداتColors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# إعدادات
LOG_FILE="logs/upgrade.log"
BACKUP_DIR="backups"
CONFIG_BACKUP="config.backup.$(date +%Y%m%d_%H%M%S)"

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
    echo "  نظام الحارس التلقائي - الترقية"
    echo "=============================================="
    echo ""
}

# إنشاء مجلد السجلات إن لم يوجد
mkdir -p "$(dirname "$LOG_FILE")" "$BACKUP_DIR"

# دالة النسخ الاحتياطي للإعدادات
backup_config() {
    print_info "جاري إنشاء نسخة احتياطية من الإعدادات..."
    
    if [ -d "config" ]; then
        cp -r "config" "$CONFIG_BACKUP"
        print_success "حُفظت الإعدادات في: $CONFIG_BACKUP"
        return 0
    else
        print_warning "مجلد الإعدادات غير موجود"
        return 1
    fi
}

# دالة التحقق من المتطلبات
check_requirements() {
    print_info "جاري التحقق من المتطلبات..."
    
    # التحقق من Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 غير مثبت! يرجى تثبيت Python 3.8 أو أحدث."
        return 1
    fi
    
    local python_version=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
    local major=$(echo "$python_version" | cut -d. -f1)
    local minor=$(echo "$python_version" | cut -d. -f2)
    
    if [ "$major" -lt 3 ] || ([ "$major" -eq 3 ] && [ "$minor" -lt 8 ]); then
        print_error "Python 3.8 أو أحدث مطلوب! الإصدار الحالي: $python_version"
        return 1
    fi
    
    print_success "Python $python_version ✓"
    
    # التحقق من Git
    if ! command -v git &> /dev/null; then
        print_error "Git غير مثبت! يرجى تثبيت Git."
        return 1
    fi
    
    print_success "Git ✓"
    
    # التحقق من Git repository
    if [ ! -d ".git" ]; then
        print_warning "المستودع ليس Git. لن يتم استخدام Git للترقية."
        return 2
    fi
    
    return 0
}

# دالة جلب التحديثات من Git
git_pull() {
    print_info "جاري جلب التحديثات من Git..."
    
    # جلب التحديثات
    git fetch origin
    
    # الحصول على الفرع الحالي
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    print_info "الفرع الحالي: $current_branch"
    
    # جلب التغييرات
    if git pull origin "$current_branch" --no-edit; then
        print_success "تم جلب التحديثات"
        return 0
    else
        print_error "فشل في جلب التحديثات"
        return 1
    fi
}

# دالة الترقية من ZIP
upgrade_from_zip() {
    local zip_file=$1
    
    if [ -z "$zip_file" ]; then
        print_error "يرجى تحديد ملف ZIP"
        return 1
    fi
    
    if [ ! -f "$zip_file" ]; then
        print_error "الملف غير موجود: $zip_file"
        return 1
    fi
    
    print_info "جاري الترقية من: $zip_file"
    
    # إنشاء مجلد مؤقت
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # استخراج الملفات
    unzip -q "$zip_file" -d "$temp_dir"
    
    # التحقق من المحتوى
    if [ ! -f "$temp_dir/README.md" ]; then
        print_error "الملف ZIP ليس لتحديث نظام الحارس التلقائي"
        return 1
    fi
    
    # نسخ الملفات (مع تجاوز)
    print_info "جاري نسخ الملفات..."
    cp -r "$temp_dir"/* .
    
    print_success "تم الترقية من ملف ZIP"
}

# دالة تحديث التبعيات
update_dependencies() {
    print_info "جاري تحديث التبعيات..."
    
    # التحقق من ملف requirements.txt
    if [ ! -f "requirements.txt" ]; then
        print_warning "ملف requirements.txt غير موجود"
        return 1
    fi
    
    # ترقية pip
    print_info "تحديث pip..."
    python3 -m pip install --upgrade pip wheel setuptools
    
    # ترقية التبعيات
    print_info "تحديث التبعيات..."
    if python3 -m pip install -r requirements.txt --upgrade; then
        print_success "تم تحديث التبعيات"
    else
        print_error "فشل في تحديث التبعيات"
        return 1
    fi
}

# دالة تشغيل التهجير
run_migrations() {
    print_info "جاري تشغيل التهجير..."
    
    # التحقق من وجود سكريبت التهجير
    if [ -f "scripts/migrate.py" ]; then
        python3 scripts/migrate.py
    elif [ -f "migrate.py" ]; then
        python3 migrate.py
    else
        print_info "لا توجد تهجيرات للترقية"
    fi
}

# دالة التحقق من الإعدادات الجديدة
check_new_config() {
    print_info "جاري التحقق من الإعدادات الجديدة..."
    
    # التحقق من وجود نموذج الإعدادات
    if [ -f "config/settings.example.yaml" ]; then
        if [ ! -f "config/settings.yaml" ]; then
            print_warning "تم إنشاء ملف إعدادات جديد"
            cp config/settings.example.yaml config/settings.yaml
        fi
        
        # عرض الإعدادات الجديدة
        print_info "راجع الإعدادات الجديدة في config/settings.yaml"
        print_info "راجع التغييرات في config/settings.example.yaml"
    fi
}

# دالة التحقق من الإضافات في GitHub Actions
check_github_actions() {
    print_info "جاري التحقق من GitHub Actions..."
    
    if [ -d ".github/workflows" ]; then
        print_success "GitHub Actions موجود"
        
        # عرض سير العمل الجديد
        local new_workflows=$(git diff --name-only HEAD@{1}..HEAD .github/workflows/ 2>/dev/null | wc -l)
        if [ "$new_workflows" -gt 0 ]; then
            print_info "يوجد $new_workflows سير عمل جديد أو معدل"
        fi
    fi
}

# دالة إعادة تشغيل الخدمة
restart_service() {
    print_info "جاري إعادة تشغيل الخدمة..."
    
    # التحقق من systemd
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet autoguardian 2>/dev/null; then
            print_info "إعادة تشغيل الخدمة عبر systemd..."
            sudo systemctl restart autoguardian
            print_success "تم إعادة تشغيل الخدمة"
            return 0
        fi
    fi
    
    # التحقق من Docker
    if [ -f "docker-compose.yml" ]; then
        print_info "إعادة تشغيل الحاويات..."
        docker-compose restart auto-guardian
        print_success "تم إعادة تشغيل الحاويات"
        return 0
    fi
    
    # الطريقة اليدوية
    print_info "جاري إيقاف النظام..."
    pkill -f "python.*src.main" 2>/dev/null || true
    
    print_info "جاري تشغيل النظام..."
    nohup python3 -m src.main > logs/auto-guardian.log 2>&1 &
    
    sleep 2
    
    if pgrep -f "python.*src.main" > /dev/null; then
        print_success "تم تشغيل النظام"
    else
        print_error "فشل في تشغيل النظام"
        return 1
    fi
}

# دالة عرض ملخص الترقية
show_upgrade_summary() {
    local new_version=$1
    
    echo ""
    echo "=============================================="
    echo "  ملخص الترقية"
    echo "=============================================="
    echo ""
    
    echo -e "${GREEN}✓${NC} تم إنشاء نسخة احتياطية من الإعدادات"
    echo -e "${GREEN}✓${NC} تم تحديث التبعيات"
    echo ""
    
    if [ -n "$new_version" ]; then
        echo -e "الإصدار الجديد: ${BOLD}$new_version${NC}"
    fi
    
    echo ""
    echo "الخطوات التالية:"
    echo "----------------"
    echo "1. راجع ملف CHANGELOG.md لمعرفة التغييرات"
    echo "2. راجع ملف requirements.txt للتعرف على التبعيات الجديدة"
    echo "3. حدّث إعداداتك إذا لزم الأمر"
    echo "4. شغل النظام: python3 -m src.main"
    echo ""
    
    echo "للإبلاغ عن المشاكل:"
    echo "- GitHub Issues: https://github.com/AbdulElahOthmanGwaith/auto-guardian-system/issues"
    echo "- البريد: support@autoguardian.local"
    echo ""
}

# دالة عرض المساعدة
show_help() {
    echo ""
    echo "استخدام: $0 [الخيار] [الوسيطة]"
    echo ""
    echo "خيارات الترقية:"
    echo ""
    echo "  git             - الترقية من Git (الوضع الافتراضي)"
    echo "  zip <file>      - الترقية من ملف ZIP"
    echo "  check           - التحقق من التحديثات فقط"
    echo "  backup          - إنشاء نسخة احتياطية فقط"
    echo "  deps            - تحديث التبعيات فقط"
    echo "  restart         - إعادة تشغيل الخدمة فقط"
    echo "  help            - عرض هذه المساعدة"
    echo ""
    echo "أمثلة:"
    echo "  $0 git                    # الترقية من Git"
    echo "  $0 zip update.zip         # الترقية من ZIP"
    echo "  $0 check                  # التحقق من التحديثات"
    echo "  $0 restart                # إعادة تشغيل الخدمة"
    echo ""
}

# ========================================
# البرنامج الرئيسي
# ========================================

print_header

# التحقق من الوسائط
case "${1:-git}" in
    git)
        echo "وضع الترقية: Git"
        echo ""
        
        # النسخ الاحتياطي للإعدادات
        backup_config
        
        # التحقق من المتطلبات
        if ! check_requirements; then
            if [ $? -eq 2 ]; then
                print_warning "استمرار بدون Git"
            else
                print_error "فشل في التحقق من المتطلبات"
                exit 1
            fi
        fi
        
        # جلب التحديثات
        if [ -d ".git" ]; then
            git_pull
        fi
        
        # تحديث التبعيات
        update_dependencies
        
        # التحقق من الإعدادات الجديدة
        check_new_config
        
        # التحقق من GitHub Actions
        check_github_actions
        
        # عرض الملخص
        local new_version=$(git describe --tags 2>/dev/null || echo "1.3.0")
        show_upgrade_summary "$new_version"
        ;;
        
    zip)
        echo "وضع الترقية: ملف ZIP"
        echo ""
        
        # النسخ الاحتياطي للإعدادات
        backup_config
        
        # الترقية من ZIP
        upgrade_from_zip "${2:-}"
        
        # تحديث التبعيات
        update_dependencies
        
        # التحقق من الإعدادات الجديدة
        check_new_config
        
        show_upgrade_summary
        ;;
        
    check)
        echo "التحقق من التحديثات..."
        echo ""
        
        check_requirements || true
        
        if [ -d ".git" ]; then
            git fetch origin
            
            local current_commit=$(git rev-parse HEAD)
            local remote_commit=$(git rev-parse origin/main)
            
            if [ "$current_commit" != "$remote_commit" ]; then
                local commits_behind=$(git rev-list --count HEAD..origin/main)
                print_info "يوجد تحديث متاح ($commits_behind commits behind)"
                echo ""
                git log --oneline HEAD..origin/main | head -10
            else
                print_success "المستودع محدث"
            fi
        fi
        ;;
        
    backup)
        echo "إنشاء نسخة احتياطية..."
        echo ""
        backup_config
        ;;
        
    deps)
        echo "تحديث التبعيات..."
        echo ""
        update_dependencies
        ;;
        
    restart)
        echo "إعادة تشغيل الخدمة..."
        echo ""
        restart_service
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
