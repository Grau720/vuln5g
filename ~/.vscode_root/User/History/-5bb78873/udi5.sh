#!/bin/bash

# Interfaz del bridge Docker
BRIDGE="br-vulndb"
SURICATA_IP="${VULNDB_SURICATA_IP}"

# Crear interfaz virtual para mirror
ip link add mirror0 type veth peer name mirror1
ip link set mirror0 up
ip link set mirror1 up

# Conectar mirror0 al bridge
brctl addif $BRIDGE mirror0

# Configurar tc para copiar tráfico
tc qdisc add dev $BRIDGE ingress
tc filter add dev $BRIDGE parent ffff: \
   protocol all u32 match u8 0 0 \
   action mirred egress mirror dev mirror1

echo "✅ Mirror configurado: $BRIDGE -> mirror1"