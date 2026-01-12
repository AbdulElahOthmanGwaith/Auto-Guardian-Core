#!/bin/bash
# سكريبت النسخ الاحتياطي لنظام الحارس التلقائي
# Auto Guardian System Backup Script
# ======================================

# إعداداتColors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# إعدادات النسخ الاحتياطي
BACKUP_DIR="backups"
BACKUP_PREFIX="auto-guardian"
RETENTION_DAYS=30
LOG_FILE="logs/backup.log"

# دوال مساعدة
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_message() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$LOG_FILE"
}

# إنشاء مجلد السجلات إن لم يوجد
mkdir -p "$(dirname "$LOG_FILE")"

print_header() {
    echo ""
    echo "=============================================="
    echo "  نظام الحارس التلقائي - النسخ الاحتياطي"
    echo "=============================================="
    echo ""
}

# دالة إنشاء نسخة احتياطية
create_backup() {
    print_info "جاري إنشاء نسخة احتياطية..."
    
    # إنشاء مجلد النسخ الاحتياطي إن لم يوجد
    mkdir -p "$BACKUP_DIR"
    
    # إنشاء اسم الملف مع التاريخ والوقت
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_filename="${BACKUP_PREFIX}_${timestamp}"
    local backup_path="${BACKUP_DIR}/${backup_filename}"
    local tar_filename="${backup_filename}.tar.gz"
    
    log_message "INFO" "بدء إنشاء نسخة احتياطية: $tar_filename"
    
    # إنشاء مجلد مؤقت للنسخة الاحتياطية
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    print_info "جاري تجميع الملفات..."
    
    # نسخ الإعدادات
    print_info "نسخ الإعدادات..."
    mkdir -p "$temp_dir/config"
    cp config/settings.yaml "$temp_dir/config/" 2>/dev/null || true
    cp config/rules.yaml "$temp_dir/config/" 2>/dev/null || true
    cp config/alerts.yaml "$temp_dir/config/" 2>/dev/null || true
    cp config/whitelist.yaml "$temp_dir/config/" 2>/dev/null || true
    cp .env.example "$temp_dir/" 2>/dev/null || true
    
    # نسخ السجلات (آخر 7 أيام)
    print_info "نسخ السجلات..."
    mkdir -p "$temp_dir/logs"
    find logs/ -name "*.log" -mtime -7 -exec cp {} "$temp_dir/logs/" \; 2>/dev/null || true
    
    # نسخ قاعدة البيانات إن وجدت
    print_info "نسخ قاعدة البيانات..."
    if [ -f "data/autoguardian.db" ]; then
        mkdir -p "$temp_dir/data"
        cp data/autoguardian.db "$temp_dir/data/"
    fi
    
    # نسخ قائمة العناوكات المحظورة
    print_info "نسخ قائمة العناوكات المحظورة..."
    if [ -f "data/blocked_ips.json" ]; then
        mkdir -p "$temp_dir/data"
        cp data/blocked_ips.json "$temp_dir/data/"
    fi
    
    # نسخ معلومات الإصدار
    print_info "نسخ معلومات الإصدار..."
    echo "{
        \"backup_date\": \"$(date -Iseconds)\",
        \"version\": \"$(git describe --tags 2>/dev/null || echo '1.3.0')\",
        \"git_branch\": \"$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')\",
        \"git_commit\": \"$(git rev-parse HEAD 2>/dev/null || echo 'unknown')\"
    }" > "$temp_dir/backup_info.json"
    
    # ضغط الملفات
    print_info "ضغط الملفات..."
    tar -czf "$BACKUP_DIR/$tar_filename" -C "$temp_dir" .
    
    # حذف المجلد المؤقت
    rm -rf "$temp_dir"
    
    # التحقق من نجاح الضغط
    if [ -f "$BACKUP_DIR/$tar_filename" ]; then
        local file_size=$(du -h "$BACKUP_DIR/$tar_filename" | cut -f1)
        print_success "تم إنشاء النسخة الاحتياطية: $tar_filename ($file_size)"
        log_message "INFO" "اكتمل النسخ الاحتياطي بنجاح: $tar_filename ($file_size)"
        
        # إنشاء ملف فهرس
        echo "$tar_filename $(date -Iseconds) $(git describe --tags 2>/dev/null || echo 'unknown')" >> "$BACKUP_DIR/backup_index.txt"
        
        return 0
    else
        print_error "فشل في إنشاء النسخة الاحتياطية"
        log_message "ERROR" "فشل في إنشاء النسخة الاحتياطية"
        return 1
    fi
}

# دالة حذف النسخ القديمة
cleanup_old_backups() {
    print_info "جاري حذف النسخ الاحتياطية القديمة (أقدم من $RETENTION_DAYS يوماً)..."
    
    local deleted_count=0
    local deleted_size=0
    
    # البحث عن الملفات القديمة
    while IFS= read -r -d '' file; do
        local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
        deleted_size=$((deleted_size + file_size))
        rm -f "$file"
        ((deleted_count++))
        print_info "حُذف: $(basename "$file")"
    done < <(find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*.tar.gz" -mtime +$RETENTION_DAYS -print0)
    
    if [ $deleted_count -gt 0 ]; then
        print_success "حُذفت $deleted_count نسخة احتياطية (حوالي $(echo "scale=2; $deleted_size/1048576" | bc) MB)"
        log_message "INFO" "حُذفت $deleted_count نسخة احتياطية"
    else
        print_info "لا توجد نسخ احتياطية قديمة للحذف"
    fi
}

# دالة عرض النسخ الاحتياطية المتاحة
list_backups() {
    echo ""
    echo "النسخ الاحتياطية المتاحة:"
    echo "----------------------------"
    
    if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
        print_warning "لا توجد نسخ احتياطية"
        return 1
    fi
    
    local total_size=0
    local count=0
    
    while IFS= read -r -d '' file; do
        local filename=$(basename "$file")
        local filesize=$(du -h "$file" | cut -f1)
        local filedate=$(stat -c %y "$file" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1 || stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null)
        
        echo "  $filename"
        echo "    الحجم: $filesize | التاريخ: $filedate"
        echo ""
        
        total_size=$((total_size + $(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)))
        ((count++))
    done < <(find "$BACKUP_DIR" -name "${BACKUP_PREFIX}_*.tar.gz" -print0 | sort -rz)
    
    echo "----------------------------"
    echo "إجمالي النسخ: $count"
    echo "الحجم الإجمالي: $(echo "scale=2; $total_size/1048576" | bc) MB"
}

# دالة استعادة نسخة احتياطية
restore_backup() {
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        print_error "يرجى تحديد ملف النسخ الاحتياطية"
        echo "الاستخدام: $0 restore <backup_file>"
        return 1
    fi
    
    # التحقق من وجود الملف
    if [ ! -f "$backup_file" ]; then
        # البحث في مجلد النسخ الاحتياطية
        if [ -f "$BACKUP_DIR/$backup_file" ]; then
            backup_file="$BACKUP_DIR/$backup_file"
        else
            # البحث عن ملف يبدأ بالاسم
            backup_file=$(find "$BACKUP_DIR" -name "${backup_file}*.tar.gz" -o -name "*${backup_file}*.tar.gz" 2>/dev/null | head -1)
            if [ -z "$backup_file" ]; then
                print_error "الملف غير موجود: $backup_file"
                return 1
            fi
        fi
    fi
    
    print_warning "سيتم استعادة النسخة الاحتياطية: $(basename "$backup_file")"
    print_warning "سيتم الكتابة فوق الإعدادات الحالية!"
    
    read -p "هل تريد المتابعة؟ (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        print_info "تم الإلغاء"
        return 0
    fi
    
    print_info "جاري استعادة النسخة الاحتياطية..."
    
    # إنشاء مجلد مؤقت
    local temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # استخراج الملفات
    tar -xzf "$backup_file" -C "$temp_dir"
    
    # التحقق من وجود ملف المعلومات
    if [ -f "$temp_dir/backup_info.json" ]; then
        print_info "معلومات النسخة الاحتياطية:"
        cat "$temp_dir/backup_info.json"
        echo ""
    fi
    
    # استعادة الإعدادات
    if [ -f "$temp_dir/config/settings.yaml" ]; then
        cp "$temp_dir/config/settings.yaml" config/settings.yaml
        print_success "استُعيدت الإعدادات"
    fi
    
    # استعادة السجلات
    if [ -d "$temp_dir/logs" ]; then
        cp -r "$temp_dir/logs/"* logs/ 2>/dev/null || true
        print_success "استُعيدت السجلات"
    fi
    
    # استعادة قاعدة البيانات
    if [ -f "$temp_dir/data/autoguardian.db" ]; then
        mkdir -p data
        cp "$temp_dir/data/autoguardian.db" data/
        print_success "استُعيدت قاعدة البيانات"
    fi
    
    # استعادة قائمة العناوكات المحظورة
    if [ -f "$temp_dir/data/blocked_ips.json" ]; then
        mkdir -p data
        cp "$temp_dir/data/blocked_ips.json" data/
        print_success "استُعيدت قائمة العناوكات المحظورة"
    fi
    
    print_success "اكتمل استعادة النسخة الاحتياطية"
    log_message "INFO" "استُعيدت النسخة الاحتياطية: $(basename "$backup_file")"
}

# دالة إنشاء نسخة احتياطية للسجلات فقط
backup_logs_only() {
    print_info "جاري إنشاء نسخة احتياطية للسجلات فقط..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_filename="${BACKUP_PREFIX}_logs_${timestamp}.tar.gz"
    
    if [ -d "logs" ] && [ "$(ls -A logs 2>/dev/null)" ]; then
        tar -czf "$BACKUP_DIR/$backup_filename" logs/
        print_success "تم إنشاء: $backup_filename"
    else
        print_warning "لا توجد سجلات للنسخ الاحتياطي"
    fi
}

# دالة عرض المساعدة
show_help() {
    echo ""
    echo "استخدام: $0 [الأمر]"
    echo ""
    echo "الأوامر المتاحة:"
    echo ""
    echo "  backup          - إنشاء نسخة احتياطية كاملة"
    echo "  backup-logs     - إنشاء نسخة احتياطية للسجلات فقط"
    echo "  list            - قائمة النسخ الاحتياطية المتاحة"
    echo "  restore <file>  - استعادة نسخة احتياطية"
    echo "  cleanup         - حذف النسخ القديمة"
    echo "  help            - عرض هذه المساعدة"
    echo ""
    echo "أمثلة:"
    echo "  $0 backup"
    echo "  $0 list"
    echo "  $0 restore auto-guardian_20241013_120000.tar.gz"
    echo "  $0 cleanup"
    echo ""
}

# ========================================
# البرنامج الرئيسي
# ========================================

print_header

# التحقق من الوسائط
case "${1:-backup}" in
    backup)
        create_backup
        cleanup_old_backups
        ;;
    backup-logs)
        backup_logs_only
        ;;
    list)
        list_backups
        ;;
    restore)
        restore_backup "${2:-}"
        ;;
    cleanup)
        cleanup_old_backups
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "أمر غير معروف: $1"
        show_help
        exit 1
        ;;
esac

echo ""
print_success "اكتمل العمل بنجاح!"
echo ""
