#!/bin/bash
set -e

echo "🚀 Iniciando Secure Payment Decoder API..."
echo "📅 $(date)"
echo "🐳 Ejecutándose en contenedor Docker"

# Verificar variables de entorno críticas
if [ -z "$DATABASE_URL" ]; then
    echo "⚠️  ADVERTENCIA: DATABASE_URL no está configurada"
    echo "🔗 Usando configuración por defecto (puede fallar)"
else
    echo "✅ DATABASE_URL configurada"
fi

# Verificar conexión a base de datos
echo "🔍 Verificando conexión a base de datos..."
python -c "
from database import engine
from sqlalchemy import text
try:
    with engine.connect() as conn:
        result = conn.execute(text('SELECT 1'))
        print('✅ Conexión a base de datos exitosa')
except Exception as e:
    print(f'❌ Error conectando a base de datos: {e}')
    exit(1)
"

# Crear tablas si no existen
echo "📋 Creando tablas de base de datos..."
python -c "
from database import create_tables
try:
    create_tables()
    print('✅ Tablas creadas/verificadas correctamente')
except Exception as e:
    print(f'❌ Error creando tablas: {e}')
    exit(1)
"

echo "🎯 Iniciando servidor FastAPI..."
echo "🌐 Puerto: ${PORT:-8000}"
echo "🔧 Host: 0.0.0.0"

# Ejecutar el servidor
exec python -m uvicorn main:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers ${WORKERS:-1} \
    --log-level ${LOG_LEVEL:-info} \
    --access-log \
    --use-colors
