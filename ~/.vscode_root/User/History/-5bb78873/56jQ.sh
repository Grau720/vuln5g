#!/bin/bash
set -e

echo "🔧 Configurando Traffic Mirroring para Suricata..."

# Descubrir el bridge real
NETWORK_NAME="docker_open5gs_default"

# Intentar obtener el ID de la red
BRIDGE_ID=$(docker network inspect $NETWORK_NAME -f '{{.Id}}' 2>/dev/null | cut -c1-12)

if [ -z "$BRIDGE_ID" ]; then
    echo "⚠️ No se pudo obtener el ID de la red via Docker API"
    echo "🔍 Buscando bridge manualmente..."
    
    # Listar todos los bridges y buscar el que corresponde
    BRIDGES=$(brctl show 2>/dev/null | grep "^br-" | awk '{print $1}')
    
    if [ -z "$BRIDGES" ]; then
        echo "❌ No se encontraron bridges Docker"
        exit 1
    fi
    
    echo "Bridges encontrados:"
    echo "$BRIDGES"
    
    # Usar el primer bridge br-* que encuentre
    BRIDGE=$(echo "$BRIDGES" | head -1)
    echo "📡 Usando bridge: $BRIDGE"
else
    BRIDGE="br-${BRIDGE_ID}"
    echo "🌉 Bridge detectado: $BRIDGE"
fi

MIRROR_IF="mirror1"

# Verificar que el bridge existe
if ! ip link show $BRIDGE &>/dev/null; then
    echo "❌ Bridge $BRIDGE no existe"
    echo "Bridges disponibles:"
    brctl show 2>/dev/null || ip link show | grep "^[0-9]" | grep "br-"
    exit 1
fi

echo "✅ Bridge $BRIDGE encontrado"

# Limpiar configuración previa
echo "🧹 Limpiando configuración previa..."
tc qdisc del dev $BRIDGE ingress 2>/dev/null || true
tc qdisc del dev $BRIDGE root 2>/dev/null || true
ip link del mirror0 2>/dev/null || true
ip link del mirror1 2>/dev/null || true

# Crear par de interfaces virtuales
echo "📡 Creando interfaces mirror..."
ip link add mirror0 type veth peer name $MIRROR_IF

if [ $? -ne 0 ]; then
    echo "❌ Error creando interfaces veth"
    exit 1
fi

ip link set mirror0 up
ip link set $MIRROR_IF up
ip link set mirror0 promisc on
ip link set $MIRROR_IF promisc on

echo "✅ Interfaces mirror creadas"

# Añadir mirror0 al bridge
echo "🔗 Conectando mirror0 al bridge $BRIDGE..."

# Intentar con brctl primero
if brctl addif $BRIDGE mirror0 2>/dev/null; then
    echo "✅ Conectado con brctl"
else
    echo "⚠️ brctl falló, intentando con ip..."
    if ip link set mirror0 master $BRIDGE 2>/dev/null; then
        echo "✅ Conectado con ip link"
    else
        echo "❌ No se pudo conectar mirror0 al bridge"
        exit 1
    fi
fi

# Configurar tc para copiar TODO el tráfico
echo "🪞 Configurando traffic mirroring..."

# Ingress (tráfico entrante)
if tc qdisc add dev $BRIDGE ingress 2>/dev/null; then
    tc filter add dev $BRIDGE parent ffff: \
       protocol all u32 match u8 0 0 \
       action mirred egress mirror dev mirror1
    echo "✅ Ingress mirror configurado"
else
    echo "⚠️ Error configurando ingress mirror"
fi

# Egress (tráfico saliente)
if tc qdisc add dev $BRIDGE root handle 1: prio 2>/dev/null; then
    tc filter add dev $BRIDGE parent 1: \
       protocol all u32 match u8 0 0 \
       action mirred egress mirror dev mirror1
    echo "✅ Egress mirror configurado"
else
    echo "⚠️ Error configurando egress mirror"
fi

echo ""
echo "✅ Traffic mirroring configurado correctamente"
echo ""
echo "📊 Configuración:"
echo "  - Bridge: $BRIDGE"
echo "  - Mirror interface: $MIRROR_IF"
echo ""

# Verificar configuración tc
echo "🔍 Verificación tc:"
tc -s qdisc show dev $BRIDGE 2>/dev/null || echo "  (tc no disponible en este contexto)"
echo ""

# Verificar interfaces
echo "🔍 Interfaces mirror:"
ip link show mirror0 2>/dev/null || echo "  mirror0: error"
ip link show mirror1 2>/dev/null || echo "  mirror1: error"
echo ""

echo "🎯 Suricata escuchará en: $MIRROR_IF"