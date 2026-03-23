FROM mcr.microsoft.com/powershell:lts-alpine
 
WORKDIR /app
 
COPY cliente_icmp.ps1 .
 
ENV PYTHONUNBUFFERED=1
 
CMD ["pwsh", "-File", "cliente_icmp.ps1"]