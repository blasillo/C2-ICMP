#!/bin/bash
echo "========================================="
echo "ICMP Tunnel Server"
echo "========================================="
echo "Servidor iniciado en modo interactivo"
echo "Puedes escribir comandos para enviar a los clientes"
echo "========================================="

# Ejecutar el servidor con permisos de root (necesario para ICMP raw)
exec python3 servidor_icmp.py