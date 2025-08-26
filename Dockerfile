# Usar imagen base oficial de Python 3.12 slim para mejor rendimiento
FROM python:3.12-slim

# Metadatos del contenedor
LABEL maintainer="VaultGuard Payment System"
LABEL description="Secure Payment Decoder API with PostgreSQL"
LABEL version="1.0.0"

# Variables de entorno para Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app" \
    PORT=8002

# Instalar dependencias del sistema necesarias para PostgreSQL
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Crear usuario no-root para seguridad
RUN useradd --create-home --shell /bin/bash app

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias primero para aprovechar cache de Docker
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Hacer ejecutable el script de inicio
RUN chmod +x start.sh

# Crear directorio para logs
RUN mkdir -p /app/logs

# Cambiar propiedad de archivos al usuario app
RUN chown -R app:app /app

# Cambiar a usuario no-root
USER app

# Exponer puerto
EXPOSE $PORT

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Comando por defecto usando el script de inicio
CMD ["./start.sh"]
