#!/bin/bash
# scripts/5g_manager.sh
# Gestión de la infraestructura 5G Open5GS

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

function log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

function log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

function log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

function log_error() {
    echo -e "${RED}❌ $1${NC}"
}

function check_prerequisites() {
    log_info "Verificando prerequisitos..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose no está instalado"
        exit 1
    fi

    if ! docker network ls | grep -q docker_open5gs_default; then
        log_warning "Red docker_open5gs_default no existe, creándola..."
        docker network create \
            --driver=bridge \
            --subnet=172.22.0.0/16 \
            docker_open5gs_default
        log_success "Red creada"
    fi

    log_success "Prerequisitos verificados"
}

function setup_directories() {
    log_info "Configurando directorios..."

    mkdir -p logs/open5gs
    mkdir -p data/mongodb-5g
    mkdir -p config/open5gs
    mkdir -p config/ueransim

    log_success "Directorios creados"
}

function start_core() {
    log_info "Iniciando 5G Core Network..."

    docker-compose -f docker-compose.yml -f docker-compose.5g.yml up -d \
        open5gs-mongodb-5g \
        open5gs-nrf \
        open5gs-scp \
        open5gs-amf \
        open5gs-smf \
        open5gs-ausf \
        open5gs-udm \
        open5gs-udr \
        open5gs-pcf \
        open5gs-nssf \
        open5gs-bsf \
        open5gs-upf \
        open5gs-webui

    log_success "5G Core iniciado"
    log_info "Esperando 10s para que los servicios se estabilicen..."
    sleep 10
}

function start_ran() {
    log_info "Iniciando RAN (gNB y UEs)..."

    docker-compose -f docker-compose.yml -f docker-compose.5g.yml up -d \
        ueransim-gnb \
        ueransim-ue-1 \
        ueransim-ue-2

    log_success "RAN iniciado"
}

function stop_all() {
    log_info "Deteniendo infraestructura 5G..."

    docker-compose -f docker-compose.yml -f docker-compose.5g.yml down

    log_success "Infraestructura 5G detenida"
}

function show_status() {
    echo -e "\n${BLUE}📊 Estado de la Infraestructura 5G${NC}\n"

    docker-compose -f docker-compose.yml -f docker-compose.5g.yml ps

    echo -e "\n${BLUE}🌐 Endpoints importantes:${NC}"
    echo "  - WebUI: http://localhost:9999 (admin/1423)"
    echo "  - NRF:   http://172.22.0.10:7777"
    echo "  - AMF:   172.22.0.12:38412 (NGAP)"
    echo "  - SMF:   172.22.0.13:7777 (SBI)"
    echo "  - UPF:   172.22.0.20:8805 (PFCP)"
}

function add_subscriber() {
    local IMSI=$1
    local KEY=${2:-"465B5CE8B199B49FAA5F0A2EE238A6BC"}
    local OPC=${3:-"E8ED289DEBA952E4283B54E88E6183CA"}

    log_info "Añadiendo suscriptor IMSI: $IMSI"

    docker exec -it open5gs-webui /bin/bash -c "
        mongo 172.22.0.9/open5gs --eval \"
            db.subscribers.insertOne({
                imsi: '$IMSI',
                security: {
                    k: '$KEY',
                    opc: '$OPC',
                    amf: '8000',
                    sqn: NumberLong(0)
                },
                ambr: {
                    downlink: {value: 1, unit: 3},
                    uplink: {value: 1, unit: 3}
                },
                slice: [{
                    sst: 1,
                    default_indicator: true,
                    session: [{
                        name: 'internet',
                        type: 3,
                        qos: { index: 9 }
                    }]
                }],
                __v: 0
            })
        \"
    "

    log_success "Suscriptor añadido"
}

function register_assets() {
    log_info "Registrando assets 5G en el inventario..."

    while ! curl -s http://localhost:5000/api/v1/assets/list > /dev/null 2>&1; do
        log_info "Esperando a que la API esté disponible..."
        sleep 2
    done

    # NRF
    curl -X POST http://localhost:5000/api/v1/assets/register \
        -H "Content-Type: application/json" \
        -d '{
            "ip": "172.22.0.10",
            "hostname": "nrf",
            "role": "Network Repository Function",
            "owner": "5g-core-team",
            "component_5g": "NRF",
            "software": "Open5GS",
            "criticality": "HIGH"
        }'

    # AMF
    curl -X POST http://localhost:5000/api/v1/assets/register \
        -H "Content-Type: application/json" \
        -d '{
            "ip": "172.22.0.12",
            "hostname": "amf",
            "role": "Access and Mobility Management",
            "owner": "5g-core-team",
            "component_5g": "AMF",
            "software": "Open5GS",
            "criticality": "CRITICAL"
        }'

    # SMF  ❗ FIX AQUÍ
    curl -X POST http://localhost:5000/api/v1/assets/register \
        -H "Content-Type: application/json" \
        -d '{
            "ip": "172.22.0.13",
            "hostname": "smf",
            "role": "Session Management Function",
            "owner": "5g-core-team",
            "component_5g": "SMF",
            "software": "Open5GS",
            "criticality": "CRITICAL"
        }'

    # UPF
    curl -X POST http://localhost:5000/api/v1/assets/register \
        -H "Content-Type: application/json" \
        -d '{
            "ip": "172.22.0.20",
            "hostname": "upf",
            "role": "User Plane Function",
            "owner": "5g-core-team",
            "component_5g": "UPF",
            "software": "Open5GS",
            "criticality": "CRITICAL"
        }'

    log_success "Assets registrados"
}

function menu() {
    echo "1) Iniciar todo"
    echo "2) Detener todo"
    echo "3) Estado"
    echo "4) Registrar assets"
    echo "5) Salir"
    read -p "Opción: " option

    case $option in
        1) check_prerequisites; setup_directories; start_core; start_ran; register_assets; show_status ;;
        2) stop_all ;;
        3) show_status ;;
        4) register_assets ;;
        5) exit 0 ;;
        *) log_error "Opción inválida" ;;
    esac
}

if [ $# -eq 0 ]; then
    menu
else
    case $1 in
        start) check_prerequisites; setup_directories; start_core; start_ran; register_assets; show_status ;;
        stop) stop_all ;;
        status) show_status ;;
        register) register_assets ;;
        *) echo "Uso: $0 {start|stop|status|register}" ;;
    esac
fi
