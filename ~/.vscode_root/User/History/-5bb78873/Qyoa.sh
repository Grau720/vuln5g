#!/bin/bash
set -e

echo "🔧 Configurando Traffic Mirroring para Suricata..."

# Descubrir el bridge real
NETWORK_NAME="docker_open5gs_default"
BRIDGE=$(docker network inspect $NETWORK_NAME -f '{{.Id}}' 2>/dev/null | cut -c1-12)

if [ -z "$BRIDGE" ]; then
    echo "❌ No se pudo encontrar la red $NETWORK_NAME"
    exit 1
fi

BRIDGE="br-${BRIDGE}"
MIRROR_IF="mirror1"

echo "🌉 Bridge detectado: $BRIDGE"

# Verificar que el bridge existe
if ! ip link show $BRIDGE &>/dev/null; then
    echo "❌ Bridge $BRIDGE no existe"
    echo "Bridges disponibles:"
    brctl show
    exit 1
fi

echo "✅ Bridge $BRIDGE encontrado"

# Limpiar configuración previa
echo "🧹 Limpiando configuración previa..."
tc qdisc del dev $BRIDGE ingress 2>/dev/null || true
tc qdisc del dev $BRIDGE root 2>/dev/null || true
ip link del mirror0 2>/dev/null || true

# Crear par de interfaces virtuales
echo "📡 Creando interfaces mirror..."
ip link add mirror0 type veth peer name $MIRROR_IF
ip link set mirror0 up
ip link set $MIRROR_IF up
ip link set mirror0 promisc on
ip link set $MIRROR_IF promisc on

# Añadir mirror0 al bridge
echo "🔗 Conectando mirror0 al bridge $BRIDGE..."
brctl addif $BRIDGE mirror0 || {
    echo "⚠️ No se pudo usar brctl, intentando con ip..."
    ip link set mirror0 master $BRIDGE
}

# Configurar tc para copiar TODO el tráfico
echo "🪞 Configurando traffic mirroring..."

# Ingress (tráfico entrante)
tc qdisc add dev $BRIDGE ingress
tc filter add dev $BRIDGE parent ffff: \
   protocol all u32 match u8 0 0 \
   action mirred egress mirror dev mirror1

# Egress (tráfico saliente)
tc qdisc add dev $BRIDGE root handle 1: prio
tc filter add dev $BRIDGE parent 1: \
   protocol all u32 match u8 0 0 \
   action mirred egress mirror dev mirror1

echo "✅ Traffic mirroring configurado correctamente"
echo ""
echo "📊 Configuración:"
echo "  - Bridge: $BRIDGE"
echo "  - Mirror interface: $MIRROR_IF"
echo ""
echo "🔍 Verificación tc:"
tc -s qdisc show dev $BRIDGE
echo ""
echo "🎯 Suricata escuchará en: $MIRROR_IF"