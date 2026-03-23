#!/bin/bash
echo "========================================="
echo "ICMP Tunnel Client"
echo "========================================="

# Verificar que se proporcionó la IP del servidor
if [ -z "$SERVER_IP" ]; then
    echo "Error: SERVER_IP no está definida"
    echo "Usa: docker run -e SERVER_IP=<ip_del_servidor> icmp-client"
    exit 1
fi

echo "Conectando al servidor: $SERVER_IP"
echo "========================================="

# Ejecutar el cliente con permisos de root (necesario para ICMP raw)
exec python3 cliente_icmp.py $SERVER_IP