FROM alpine:3.19

RUN apk add --no-cache python3 py3-pip iputils-ping net-tools
 
WORKDIR /app
 
COPY servidor_icmp.py .
 
ENV PYTHONUNBUFFERED=1
 
CMD ["python3", "-u", "servidor_icmp.py"]