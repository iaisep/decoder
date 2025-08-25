# Secure Payment Decoder API

Una API construida con FastAPI para descifrar de forma segura datos de tarjetas de crédito cifrados desde el frontend con almacenamiento en PostgreSQL.

## Características

- **FastAPI**: Framework web moderno y de alto rendimiento para Python
- **Cifrado AES-256-CBC**: Descifrado seguro de datos sensibles
- **Autenticación por API Key**: Acceso seguro mediante tokens de autorización
- **Base de datos PostgreSQL**: Almacenamiento seguro de transacciones
- **Validación de datos**: Usando Pydantic para validación automática
- **Documentación automática**: Swagger UI y ReDoc incluidos
- **Endpoints de salud**: Para monitoreo del servicio
- **Integración Odoo**: Campo id_odoo para vincular clientes

## Instalación

1. Clona este repositorio:
```bash
git clone <repository-url>
cd decoder
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Configura las variables de entorno:
```bash
# Crea un archivo .env en la raíz del proyecto
DATABASE_URL=postgresql://usuario:contraseña@host:puerto/contable
SECRET_KEY=tu_clave_secreta_aqui
API_KEY_1=vault-api-key-2024-secure
API_KEY_2=dev-api-key-12345
API_KEY_3=prod-api-key-67890
```

## Uso

### Ejecutar el servidor

```bash
python main.py
```

O usando uvicorn directamente:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

El servidor estará disponible en `http://localhost:8000`

### Documentación de la API

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Autenticación

La API requiere una API Key válida para acceder a los endpoints sensibles. 

### API Keys disponibles (desarrollo):
- `vault-api-key-2024-secure` - VaultGuard Payment System
- `dev-api-key-12345` - Development Access  
- `prod-api-key-67890` - Production Access

### Cómo usar la API Key:

**Header requerido:**
```
Authorization: Bearer vault-api-key-2024-secure
```

**Ejemplo con curl:**
```bash
curl -X POST "http://localhost:8000/webhook/securepayment" \
     -H "Authorization: Bearer vault-api-key-2024-secure" \
     -H "Content-Type: application/json" \
     -d '{"encryptedData": "...", "iv": "...", "timestamp": "...", "algorithm": "..."}'
```

## Endpoints

### `GET /` 
Endpoint de bienvenida que devuelve información básica de la API. **No requiere autenticación**.

### `GET /health`  
Endpoint de verificación de salud del servicio. **No requiere autenticación**.

### `GET /api/info` 🔐
Información sobre el cliente autorizado y permisos. **Requiere API Key**.

### `POST /webhook/securepayment` 🔐
Procesa pagos seguros descifrando los datos de tarjetas cifrados. **Requiere API Key**. NO guarda en base de datos.

### `POST /webhook/securepayment/save` 🔐 💾
Procesa pagos seguros, descifra los datos Y los guarda en la base de datos PostgreSQL. **Requiere API Key**.

**Headers requeridos:**
```
Authorization: Bearer tu-api-key-aqui
Content-Type: application/json
```

**Cuerpo de la petición:**
```json
{
  "payment_data": {
    "encryptedData": "datos_cifrados_en_base64",
    "iv": "vector_inicializacion_en_hex",
    "timestamp": "2024-01-01T12:00:00Z",
    "algorithm": "AES-256-CBC"
  },
  "cardholder_data": {
    "id_odoo": 12345,
    "notes": "Cliente VIP - Pago recurrente"
  }
}
```

**Respuesta exitosa:**
```json
{
  "status": "success",
  "message": "Pago procesado y guardado correctamente",
  "transaction_id": "txn_2024-01-01T12:00:00Z_VaultGuard_Payment_System",
  "database_id": 1,
  "client_authorized": "VaultGuard Payment System",
  "card_data": {
    "cardNumber": "1234 5678 9012 3456",
    "expiryDate": "12/25",
    "cardHolder": "JUAN PÉREZ",
    "cvv": "123"
  },
  "cardholder_info": {
    "id_odoo": 12345,
    "notes": "Cliente VIP - Pago recurrente"
  },
  "processing_info": {
    "timestamp": "2024-01-01T12:00:00Z",
    "algorithm": "AES-256-CBC",
    "saved_at": "2024-08-25T10:30:45.123456"
  }
}
```

### `GET /transactions` 🔐 📊
Lista las transacciones guardadas con paginación. **Requiere API Key**.

**Parámetros de consulta:**
- `skip`: Número de registros a saltar (default: 0)
- `limit`: Límite de registros (default: 10)

### `GET /transactions/{transaction_id}` 🔐 🔍
Obtiene una transacción específica por ID. **Requiere API Key**.

### `GET /transactions/odoo/{id_odoo}` 🔐 🏢
Obtiene todas las transacciones de un cliente específico de Odoo. **Requiere API Key**.

### `POST /webhook/securepayment`
Procesa pagos seguros descifrando los datos de tarjetas cifrados.

**Formatos soportados:**
- **CryptoJS**: Detecta automáticamente el formato de CryptoJS con salt
- **Estándar**: Formato tradicional con IV proporcionado separadamente

**Cuerpo de la petición:**
```json
{
  "encryptedData": "datos_cifrados_en_base64",
  "iv": "vector_inicializacion_en_hex",
  "timestamp": "2024-01-01T12:00:00Z",
  "algorithm": "AES-256-CBC"
}
```

**Respuesta exitosa:**
```json
{
  "status": "success",
  "message": "Pago procesado correctamente",
  "transaction_id": "txn_2024-01-01T12:00:00Z",
  "card_data": {
    "cardNumber": "1234 5678 9012 3456",
    "expiryDate": "12/25",
    "cardHolder": "JUAN PÉREZ",
    "cvv": "123"
  },
  "processing_info": {
    "timestamp": "2024-01-01T12:00:00Z",
    "algorithm": "AES-256-CBC"
  }
}
```

### `POST /debug/decrypt`
Endpoint de debug para diagnosticar problemas de descifrado. Proporciona información detallada sobre cada paso del proceso sin exponer datos sensibles.

### `GET /health`
Endpoint de verificación de salud del servicio.

## Seguridad

- **Clave secreta**: La clave de descifrado debe coincidir con la usada en el frontend
- **Vector de inicialización**: Se requiere IV único para cada operación de cifrado
- **No almacenamiento**: Los datos sensibles no se almacenan sin cifrar
- **Validación**: Todos los inputs son validados automáticamente

## Variables de entorno

La aplicación utiliza una clave secreta codificada. En producción, considera usar variables de entorno:

```bash
export SECRET_KEY="tu_clave_secreta_aqui"
```

## Despliegue con Docker y Coolify

### 🐳 **Docker**

El proyecto incluye configuración completa para Docker:

```bash
# Construir imagen
docker build -t payment-decoder .

# Ejecutar localmente
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar contenedor
docker-compose down
```

### ☁️ **Coolify**

Para desplegar en Coolify:

1. **Crear nuevo proyecto** en Coolify
2. **Conectar repositorio** Git
3. **Configurar variables de entorno**:
   ```
   DATABASE_URL=postgresql://postgres:PASSWORD@HOST:PORT/contable
   SECRET_KEY=VaultGuardPay2024SecurePayments!@#$%^&*()
   API_KEY_1=vault-api-key-2024-secure
   API_KEY_2=dev-api-key-12345
   API_KEY_3=prod-api-key-67890
   PORT=8000
   ```

4. **Configurar health check**:
   - URL: `/health`
   - Puerto: `8000`
   - Intervalo: `30s`

5. **Recursos recomendados**:
   - CPU: 1 core
   - RAM: 512MB
   - Almacenamiento: 1GB

6. **Deploy** - Coolify detectará automáticamente el Dockerfile

### 📊 **Monitoreo**

- **Health check**: `http://tu-dominio.com/health`
- **API Docs**: `http://tu-dominio.com/docs`
- **Logs**: Disponibles en Coolify dashboard

## Desarrollo

Para desarrollo con recarga automática:
```bash
uvicorn main:app --reload
```

## Estructura del proyecto

```
decoder/
├── main.py                    # Aplicación principal FastAPI
├── database.py                # Modelos y configuración de base de datos
├── requirements.txt           # Dependencias de Python
├── test_database.py          # Script de prueba de base de datos
├── .env                      # Variables de entorno (no incluir en git)
├── .env.example              # Ejemplo de variables de entorno
├── README.md                 # Este archivo
├── Dockerfile                # Configuración Docker
├── .dockerignore             # Archivos excluidos de Docker
├── docker-compose.yml        # Configuración Docker Compose
├── start.sh                  # Script de inicio del contenedor
├── coolify.conf              # Configuración para Coolify
└── .github/
    └── copilot-instructions.md
```

## Dependencias

- `fastapi`: Framework web
- `uvicorn`: Servidor ASGI
- `cryptography`: Biblioteca de criptografía
- `pydantic`: Validación de datos
- `python-multipart`: Para formularios multipart
- `sqlalchemy`: ORM para base de datos
- `psycopg2-binary`: Driver PostgreSQL
- `python-dotenv`: Manejo de variables de entorno

## Estructura de la base de datos

### Tabla: `cardholder_transactions`
```sql
CREATE TABLE cardholder_transactions (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(255) UNIQUE NOT NULL,
    id_odoo INTEGER,
    cardholder_name VARCHAR(255) NOT NULL,
    card_last_four VARCHAR(4) NOT NULL,
    card_expiry VARCHAR(7) NOT NULL,
    algorithm_used VARCHAR(50) NOT NULL,
    client_authorized VARCHAR(255) NOT NULL,
    transaction_timestamp VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'processed',
    notes TEXT
);
```

## Notas de seguridad

⚠️ **Importante**: 
- Esta implementación es para fines educativos/demostrativos
- **Los datos de tarjeta se devuelven en texto plano en la respuesta**
- En producción, implementa medidas adicionales de seguridad
- No almacenes datos sensibles sin cifrar
- Usa HTTPS en producción
- Implementa autenticación y autorización adecuadas
- **Considera enmascarar datos sensibles** (ej: mostrar solo los últimos 4 dígitos)
- **Log de seguridad**: No registres datos sensibles en logs de servidor

### ⚠️ Advertencia de seguridad adicional
La respuesta actual incluye todos los datos de la tarjeta en texto plano. En un entorno de producción:
1. Procesa el pago inmediatamente
2. No devuelvas datos sensibles completos
3. Usa tokens o referencias en lugar de datos reales
4. Implementa auditoría y monitoreo
