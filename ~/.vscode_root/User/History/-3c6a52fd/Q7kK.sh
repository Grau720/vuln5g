#!/bin/bash

echo "🧪 Test de Suricata con Red Externa"
echo "===================================="

# Detectar el bridge
NETWORK_NAME="docker_open5gs_default"
BRIDGE=$(docker network inspect $NETWORK_NAME -f '{{.Id}}' 2>/dev/null | cut -c1-12)
BRIDGE="br-${BRIDGE}"

echo "🌉 Bridge detectado: $BRIDGE"
echo "🎯 Target API: http://${VULNDB_API_IP}:5000"
echo ""

# Esperar a Suricata
echo "⏳ Esperando a Suricata..."
sleep 8

# Limpiar logs
docker exec vulndb_suricata sh -c "echo '' > /var/log/suricata/fast.log" 2>/dev/null

echo "🔥 Generando 10 peticiones maliciosas desde HOST..."
for i in $(seq 1 10); do
  curl -s "http://${VULNDB_API_IP}:5000/api/v1/test?cmd=whoami" -m 2 2>/dev/null &
done

sleep 3
wait

echo "✅ Tráfico generado"
echo ""

echo "📊 Verificación de mirror:"
docker exec vulndb_suricata tc -s qdisc show dev $BRIDGE 2>/dev/null || echo "  (no disponible dentro del contenedor)"

echo ""
echo "🔍 Interfaces mirror:"
docker exec vulndb_suricata ip link show 2>/dev/null | grep mirror || echo "  (verificar logs de Suricata)"

echo ""
echo "🚨 ALERTAS DETECTADAS:"
echo "====================="
docker exec vulndb_suricata tail -50 /var/log/suricata/fast.log 2>/dev/null || {
    echo "⚠️ No se pudieron leer los logs"
    echo "Ver logs con: docker logs vulndb_suricata"
}

echo ""
ALERT_COUNT=$(docker exec vulndb_suricata wc -l < /var/log/suricata/fast.log 2>/dev/null || echo "0")
echo "📈 Total de alertas: $ALERT_COUNT"

if [ "$ALERT_COUNT" -eq "0" ]; then
    echo ""
    echo "⚠️  No se detectaron alertas. Diagnóstico:"
    echo "1. Ver logs de Suricata: docker logs vulndb_suricata"
    echo "2. Verificar rules: ls -la runtime/suricata/rules/"
    echo "3. Test manual: docker exec vulndb_suricata tcpdump -i mirror1 -c 10"
fi