#!/bin/bash
set -e

echo "🔧 Configurando Traffic Mirroring para Suricata..."

# Variables
BRIDGE="br-vulndb"
MIRROR_IF="mirror1"

# Esperar a que el bridge exista
echo "⏳ Esperando bridge $BRIDGE..."
for i in {1..30}; do
    if ip link show $BRIDGE &>/dev/null; then
        echo "✅ Bridge $BRIDGE encontrado"
        break
    fi
    sleep 1
done

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

# Añadir mirror0 al bridge Docker
echo "🔗 Conectando mirror0 al bridge..."
brctl addif $BRIDGE mirror0

# Configurar tc para copiar TODO el tráfico
echo "🪞 Configurando traffic mirroring..."

# Ingress (tráfico entrante al bridge)
tc qdisc add dev $BRIDGE ingress
tc filter add dev $BRIDGE parent ffff: \
   protocol all u32 match u8 0 0 \
   action mirred egress mirror dev mirror1

# Egress (tráfico saliente del bridge)
tc qdisc add dev $BRIDGE root handle 1: prio
tc filter add dev $BRIDGE parent 1: \
   protocol all u32 match u8 0 0 \
   action mirred egress mirror dev mirror1

echo "✅ Traffic mirroring configurado correctamente"
echo "📊 Interfaces:"
ip link show | grep -E "mirror|$BRIDGE"
echo ""
echo "🎯 Suricata escuchará en: $MIRROR_IF"