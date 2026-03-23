FROM alpine:3.19
 
# Instalar Python y dependencias
RUN apk add --no-cache python3 py3-pip iputils net-tools
 
RUN apk add --no-cache python3 py3-pip iputils-ping net-tools
 
WORKDIR /app
 
COPY cliente_icmp.py .
 
ENV PYTHONUNBUFFERED=1
 
# Usar CMD en lugar de entrypoint.sh
CMD ["sh", "-c", "python3 -u cliente_icmp.py $SERVER_IP"]