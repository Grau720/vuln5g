#!/bin/bash
set -e

echo "🚀 Iniciando Suricata con Traffic Mirroring..."
echo "=============================================="

# Instalar dependencias (Alpine Linux)
echo "📦 Instalando dependencias..."
apk add --no-cache \
    bash \
    bridge-utils \
    iproute2 \
    tcpdump \
    net-tools \
    iputils \
    curl \
    >/dev/null 2>&1

echo "✅ Dependencias instaladas"

# Ejecutar configuración de mirror
echo ""
echo "🔧 Configurando traffic mirror..."
bash /scripts/setup-mirror.sh

# Verificar que la interfaz mirror existe
MIRROR_IF="mirror1"
if ! ip link show $MIRROR_IF &>/dev/null; then
    echo "❌ Error: Interfaz $MIRROR_IF no existe"
    exit 1
fi

echo "✅ Interfaz $MIRROR_IF lista"
echo ""

# Mostrar configuración
echo "📊 Estado de interfaces:"
ip link show | grep -E "mirror|br-"
echo ""

# Test rápido de captura
echo "🧪 Test de captura (3 segundos)..."
timeout 3 tcpdump -i $MIRROR_IF -c 5 -n 2>/dev/null || echo "  (esperando tráfico...)"
echo ""

# Iniciar Suricata
echo "🔥 Iniciando Suricata en $MIRROR_IF..."
echo "=============================================="
exec suricata -i $MIRROR_IF \
  -S /etc/suricata/rules/generated.rules \
  -l /var/log/suricata \
  --set interface.0.promisc=true \
  --set outputs.1.fast.enabled=yes \
  -vvv