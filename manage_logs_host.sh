#!/bin/bash
# Gestión de Logs Suricata - Directamente en HOST
# Ejecutar desde: /home/pablo/code/vulndb-5g
# Los logs están en: ./runtime/suricata/logs/

set -e

LOG_DIR="./runtime/suricata/logs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}=========================================="
    echo -e "$1"
    echo -e "==========================================${NC}"
    echo ""
}

print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Función: Verificar que estamos en el directorio correcto
check_dir() {
    if [ ! -d "$LOG_DIR" ]; then
        print_error "No se encuentra el directorio: $LOG_DIR"
        print_error "Ejecuta este script desde: /home/pablo/code/vulndb-5g"
        exit 1
    fi
}

# Función: Análisis de logs
check_logs() {
    print_header "ANÁLISIS DE LOGS - HOST"
    
    echo "Directorio: $(realpath $LOG_DIR)"
    echo ""
    
    echo "Tamaño total:"
    du -sh $LOG_DIR
    
    echo ""
    echo "Desglose por archivo:"
    du -h $LOG_DIR/* 2>/dev/null | sort -rh
    
    echo ""
    echo "Detalle con fecha de modificación:"
    ls -lht $LOG_DIR/
    
    echo ""
    echo "Número de líneas:"
    for file in fast.log eve.json stats.log suricata.log; do
        if [ -f "$LOG_DIR/$file" ]; then
            lines=$(wc -l < "$LOG_DIR/$file")
            size=$(du -h "$LOG_DIR/$file" | cut -f1)
            echo "  $file: $lines líneas ($size)"
        fi
    done
    
    echo ""
    echo "Archivos comprimidos existentes:"
    ls -lh $LOG_DIR/*.gz 2>/dev/null | wc -l
    echo "  Total: $(ls $LOG_DIR/*.gz 2>/dev/null | wc -l) archivos"
    
    echo ""
    echo "Espacio disponible en disco:"
    df -h . | tail -1
}

# Función: Rotación manual
rotate_logs() {
    print_header "ROTACIÓN MANUAL DE LOGS"
    
    check_dir
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    print_status "Timestamp: $TIMESTAMP"
    
    cd $LOG_DIR
    
    # Comprimir cada archivo si existe y no está vacío
    for file in fast.log eve.json stats.log suricata.log; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            print_status "Comprimiendo $file..."
            gzip -c "$file" > "${file}.${TIMESTAMP}.gz"
            
            # Truncar el archivo original
            > "$file"
            
            compressed_size=$(du -h "${file}.${TIMESTAMP}.gz" | cut -f1)
            print_status "  → ${file}.${TIMESTAMP}.gz creado ($compressed_size)"
        else
            print_warning "$file vacío o no existe, omitiendo"
        fi
    done
    
    # Señal a Suricata para reabrir logs
    print_status "Enviando señal a Suricata para reabrir archivos..."
    docker exec vulndb_suricata pkill -USR2 suricata 2>/dev/null || print_warning "No se pudo enviar señal (container puede estar detenido)"
    
    echo ""
    print_status "✓ Rotación completada"
    
    echo ""
    echo "Archivos comprimidos en $LOG_DIR:"
    ls -lht *.gz 2>/dev/null | head -5
}

# Función: Limpiar logs antiguos
clean_old_logs() {
    print_header "LIMPIEZA DE LOGS ANTIGUOS"
    
    check_dir
    
    echo "Archivos comprimidos existentes:"
    ls -lht $LOG_DIR/*.gz 2>/dev/null || echo "  (ninguno)"
    
    echo ""
    read -p "¿Cuántos días de logs quieres mantener? (default: 7): " DAYS
    DAYS=${DAYS:-7}
    
    print_warning "Se eliminarán archivos .gz con más de $DAYS días"
    read -p "¿Continuar? (y/n): " CONFIRM
    
    if [[ "$CONFIRM" != "y" ]]; then
        echo "Cancelado"
        return
    fi
    
    cd $LOG_DIR
    
    # Buscar y eliminar
    OLD_FILES=$(find . -name "*.gz" -type f -mtime +$DAYS)
    
    if [ -z "$OLD_FILES" ]; then
        print_status "No hay archivos antiguos para eliminar"
    else
        echo "Archivos a eliminar:"
        echo "$OLD_FILES"
        echo ""
        
        SIZE_BEFORE=$(du -sh . | cut -f1)
        
        find . -name "*.gz" -type f -mtime +$DAYS -delete
        
        SIZE_AFTER=$(du -sh . | cut -f1)
        
        print_status "Archivos eliminados"
        echo "  Antes: $SIZE_BEFORE"
        echo "  Después: $SIZE_AFTER"
    fi
}

# Función: Limpieza de emergencia
emergency_clean() {
    print_header "LIMPIEZA DE EMERGENCIA"
    
    check_dir
    
    echo "Estado actual:"
    du -sh $LOG_DIR
    ls -lh $LOG_DIR/
    
    echo ""
    print_warning "¡ATENCIÓN! Esta operación:"
    echo "  - Eliminará TODOS los archivos .gz"
    echo "  - Truncará los logs actuales a 0 bytes"
    echo "  - NO se puede deshacer"
    echo ""
    
    read -p "¿Estás SEGURO? Escribe 'YES' para confirmar: " CONFIRM
    
    if [[ "$CONFIRM" != "YES" ]]; then
        echo "Cancelado"
        return
    fi
    
    cd $LOG_DIR
    
    SIZE_BEFORE=$(du -sh . | cut -f1)
    
    print_status "Eliminando archivos .gz..."
    rm -f *.gz
    
    print_status "Truncando logs actuales..."
    > fast.log
    > eve.json
    > stats.log
    > suricata.log
    
    SIZE_AFTER=$(du -sh . | cut -f1)
    
    print_status "Enviando señal a Suricata..."
    docker exec vulndb_suricata pkill -USR2 suricata 2>/dev/null || true
    
    echo ""
    print_status "✓ Limpieza completada"
    echo "  Espacio liberado: $SIZE_BEFORE → $SIZE_AFTER"
}

# Función: Configurar cron para rotación automática
setup_cron() {
    print_header "CONFIGURAR ROTACIÓN AUTOMÁTICA (CRON)"
    
    check_dir
    
    SCRIPT_PATH="$(realpath $0)"
    PROJECT_DIR="$(realpath .)"
    
    print_status "Se configurará un cron job que:"
    echo "  - Se ejecuta diariamente a las 3:00 AM"
    echo "  - Comprime y rota logs automáticamente"
    echo "  - Elimina logs comprimidos >7 días"
    echo ""
    echo "Script: $SCRIPT_PATH"
    echo "Proyecto: $PROJECT_DIR"
    echo ""
    
    read -p "¿Continuar? (y/n): " CONFIRM
    if [[ "$CONFIRM" != "y" ]]; then
        echo "Cancelado"
        return
    fi
    
    # Crear entrada de cron
    CRON_ENTRY="0 3 * * * cd $PROJECT_DIR && $SCRIPT_PATH rotate-auto >> $PROJECT_DIR/runtime/suricata/rotation.log 2>&1"
    
    # Verificar si ya existe
    if crontab -l 2>/dev/null | grep -q "suricata.*rotation.log"; then
        print_warning "Ya existe una entrada de cron para rotación de logs"
        read -p "¿Reemplazar? (y/n): " REPLACE
        if [[ "$REPLACE" == "y" ]]; then
            # Eliminar entrada anterior
            crontab -l 2>/dev/null | grep -v "suricata.*rotation.log" | crontab -
        else
            echo "Cancelado"
            return
        fi
    fi
    
    # Añadir nueva entrada
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    
    print_status "✓ Cron job configurado"
    
    echo ""
    echo "Crontab actual:"
    crontab -l | grep suricata || echo "(ninguno)"
    
    echo ""
    print_status "La rotación se ejecutará automáticamente cada día a las 3 AM"
}

# Función: Rotación automática (llamada por cron)
rotate_auto() {
    echo "=== $(date) - Inicio rotación automática ==="
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    cd $LOG_DIR
    
    # Comprimir y truncar
    for file in fast.log eve.json stats.log suricata.log; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            gzip -c "$file" > "${file}.${TIMESTAMP}.gz" && > "$file"
            echo "$(date): $file rotado"
        fi
    done
    
    # Eliminar archivos antiguos
    find . -name "*.gz" -type f -mtime +7 -delete
    echo "$(date): Archivos antiguos eliminados"
    
    # Señal a Suricata
    docker exec vulndb_suricata pkill -USR2 suricata 2>/dev/null || true
    
    echo "=== $(date) - Rotación completada ==="
    echo ""
}

# Función: Ver logs de rotación
view_rotation_log() {
    print_header "LOGS DE ROTACIÓN AUTOMÁTICA"
    
    ROTATION_LOG="./runtime/suricata/rotation.log"
    
    if [ -f "$ROTATION_LOG" ]; then
        tail -50 "$ROTATION_LOG"
    else
        echo "No hay logs de rotación automática todavía"
        echo "Se crearán cuando se ejecute el cron job"
    fi
}

# Menú principal
show_menu() {
    clear
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║   GESTIÓN DE LOGS SURICATA - HOST        ║"
    echo "║   Directorio: runtime/suricata/logs      ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "1) Ver estado actual de logs"
    echo "2) Rotar logs manualmente (comprimir + truncar)"
    echo "3) Limpiar logs antiguos (>N días)"
    echo "4) Configurar rotación automática (cron)"
    echo "5) Ver logs de rotación automática"
    echo "6) Limpieza de EMERGENCIA (borrar todo)"
    echo "7) Salir"
    echo ""
}

# Main
check_dir

if [[ $# -eq 0 ]]; then
    # Modo interactivo
    while true; do
        show_menu
        read -p "Selecciona una opción [1-7]: " choice
        echo ""
        
        case $choice in
            1) check_logs ;;
            2) rotate_logs ;;
            3) clean_old_logs ;;
            4) setup_cron ;;
            5) view_rotation_log ;;
            6) emergency_clean ;;
            7) echo "Saliendo..."; exit 0 ;;
            *) print_error "Opción inválida" ;;
        esac
        
        echo ""
        read -p "Presiona Enter para continuar..."
    done
else
    # Modo comando
    case $1 in
        check) check_logs ;;
        rotate) rotate_logs ;;
        rotate-auto) rotate_auto ;;  # Para cron
        clean) clean_old_logs ;;
        setup-cron) setup_cron ;;
        emergency) emergency_clean ;;
        *) 
            echo "Uso: $0 [check|rotate|clean|setup-cron|emergency]"
            exit 1
            ;;
    esac
fi