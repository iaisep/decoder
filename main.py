from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session
from datetime import datetime
import base64
import json
import hashlib
import os
from dotenv import load_dotenv

# Importar modelos y configuración de base de datos
from database import create_tables, get_database, CardholderTransaction

# Cargar variables de entorno
load_dotenv()

class EncryptedPayment(BaseModel):
    encryptedData: str
    iv: str
    timestamp: str
    algorithm: str

class CardholderData(BaseModel):
    """Modelo para datos adicionales del tarjetahabiente"""
    id_odoo: int = None
    notes: str = None

class PaymentWithCardholder(BaseModel):
    """Modelo combinado para pago y datos del tarjetahabiente"""
    payment_data: EncryptedPayment
    cardholder_data: CardholderData = None

app = FastAPI(
    title="Secure Payment Decoder API",
    description="API para descifrar datos de tarjetas de crédito de forma segura con almacenamiento en base de datos",
    version="1.0.0"
)


# Configurar CORS para permitir solicitudes desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://secure-payment.universidadisep.com",
        "https://vault-guard-pay.lovable.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Crear tablas al iniciar la aplicación
create_tables()

# Configuración de seguridad
security = HTTPBearer()

# API Keys válidas (cargadas desde variables de entorno)
VALID_API_KEYS = {
    os.getenv("API_KEY_1", "vault-api-key-2024-secure"): "VaultGuard Payment System",
    os.getenv("API_KEY_2", "dev-api-key-12345"): "Development Access",
    os.getenv("API_KEY_3", "prod-api-key-67890"): "Production Access"
}

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verifica que la API Key proporcionada sea válida
    
    Args:
        credentials: Credenciales de autorización del header
    
    Returns:
        str: Nombre del cliente/sistema autorizado
        
    Raises:
        HTTPException: Si la API Key no es válida
    """
    api_key = credentials.credentials
    
    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=401,
            detail="API Key inválida o faltante",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return VALID_API_KEYS[api_key]

def save_transaction_to_db(
    transaction_id: str,
    card_data: dict,
    payment: EncryptedPayment,
    client_name: str,
    id_odoo: int = None,
    notes: str = None,
    db: Session = None
) -> CardholderTransaction:
    """
    Guarda la transacción en la base de datos
    
    Args:
        transaction_id: ID único de la transacción
        card_data: Datos descifrados de la tarjeta
        payment: Datos de la petición de pago
        client_name: Nombre del cliente autorizado
        id_odoo: ID del cliente en Odoo (opcional)
        notes: Notas adicionales (opcional)
        db: Sesión de base de datos
        
    Returns:
        CardholderTransaction: Registro creado en la base de datos
    """
    db_transaction = CardholderTransaction(
        transaction_id=transaction_id,
        id_odoo=id_odoo,
        cardholder_name=card_data.get("cardHolder", ""),
        card_number=card_data.get("cardNumber", ""),
        card_expiry=card_data.get("expiryDate", ""),
        cvv=card_data.get("cvv", ""),
        algorithm_used=payment.algorithm,
        client_authorized=client_name,
        transaction_timestamp=payment.timestamp,
        status="processed",
        notes=notes
    )
    
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    
    return db_transaction

def decrypt_card_data(encrypted_data: str, iv_str: str) -> dict:
    """
    Descifra los datos de la tarjeta enviados desde el frontend
    Soporta tanto formato CryptoJS como formato estándar
    
    Args:
        encrypted_data: Datos cifrados en base64
        iv_str: Vector de inicialización en hexadecimal
    
    Returns:
        dict: Datos descifrados de la tarjeta
    """
    # Clave secreta (desde variables de entorno)
    SECRET_KEY = os.getenv("SECRET_KEY", "VaultGuardPay2024SecurePayments!@#$%^&*()")
    
    try:
        # Validar que los parámetros no estén vacíos
        if not encrypted_data or not iv_str:
            raise ValueError("Los datos cifrados y el IV no pueden estar vacíos")
        
        # Decodificar datos cifrados desde base64
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
        except Exception:
            raise ValueError("Los datos cifrados deben estar en formato base64 válido")
        
        # Verificar si es formato CryptoJS (comienza con "Salted__")
        if encrypted_bytes[:8] == b'Salted__':
            # Formato CryptoJS - extraer salt y datos cifrados
            salt = encrypted_bytes[8:16]  # 8 bytes de salt
            actual_encrypted_data = encrypted_bytes[16:]  # Resto son los datos cifrados
            
            # Derivar clave e IV usando el salt (método de CryptoJS)
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            # CryptoJS usa MD5 para derivar clave e IV, pero usaremos PBKDF2 por seguridad
            # Si esto no funciona, podemos implementar el método exacto de CryptoJS
            password = SECRET_KEY.encode('utf-8')
            
            # Método compatible con CryptoJS usando MD5 (menos seguro pero compatible)
            import hashlib
            
            def derive_key_iv_cryptojs(password: bytes, salt: bytes):
                """
                Deriva clave e IV usando el método exacto de CryptoJS (MD5)
                Implementación que replica exactamente el comportamiento de CryptoJS.enc.OpenSSL
                """
                d = d_i = b''
                while len(d) < 48:  # 32 bytes para clave + 16 bytes para IV
                    d_i = hashlib.md5(d_i + password + salt).digest()
                    d += d_i
                return d[:32], d[32:48]  # key (32 bytes), iv (16 bytes)
            
            key, iv = derive_key_iv_cryptojs(password, salt)
            
        else:
            # Formato estándar - usar clave e IV proporcionados
            key = SECRET_KEY.encode('utf-8')[:32]
            
            # Decodificar IV desde hexadecimal
            try:
                iv = bytes.fromhex(iv_str)
            except ValueError:
                raise ValueError("El IV debe estar en formato hexadecimal válido")
            
            # Validar que el IV tenga 16 bytes para AES
            if len(iv) != 16:
                raise ValueError("El IV debe tener exactamente 16 bytes (32 caracteres hex)")
            
            actual_encrypted_data = encrypted_bytes
        
        # Validar que los datos cifrados no estén vacíos
        if len(actual_encrypted_data) == 0:
            raise ValueError("Los datos cifrados no pueden estar vacíos")
        
        # Crear descifrador
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Descifrar
        decrypted = decryptor.update(actual_encrypted_data) + decryptor.finalize()
        
        # Remover padding PKCS7 de forma segura
        if len(decrypted) == 0:
            raise ValueError("Los datos descifrados están vacíos")
        
        padding_length = decrypted[-1]
        
        # Validar padding PKCS7
        if padding_length == 0 or padding_length > 16:
            raise ValueError(f"Padding PKCS7 inválido: longitud {padding_length}")
        
        # Verificar que todos los bytes de padding sean correctos
        for i in range(padding_length):
            if decrypted[-(i+1)] != padding_length:
                raise ValueError(f"Padding PKCS7 corrupto en posición {i}")
        
        decrypted = decrypted[:-padding_length]
        
        # Convertir a string y luego a JSON
        try:
            decrypted_str = decrypted.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Los datos descifrados no son UTF-8 válidos")
        
        # Limpiar posibles caracteres de control o espacios
        decrypted_str = decrypted_str.strip()
        
        if not decrypted_str:
            raise ValueError("Los datos descifrados están vacíos después de la limpieza")
        
        # Convertir a JSON
        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError as je:
            raise ValueError(f"Los datos descifrados no son JSON válidos: {str(je)}. Datos: '{decrypted_str[:100]}...'")
        
    except ValueError:
        # Re-lanzar ValueError tal como está
        raise
    except Exception as e:
        raise ValueError(f"Error inesperado al descifrar los datos: {str(e)}")

@app.get("/")
async def root():
    """Endpoint de bienvenida"""
    return {
        "message": "Secure Payment Decoder API",
        "version": "1.0.0",
        "status": "active"
    }

@app.post("/webhook/securepayment")
async def process_secure_payment(payment: EncryptedPayment, client_name: str = Depends(verify_api_key)):
    """
    Procesa un pago seguro descifrando los datos de la tarjeta
    Requiere API Key válida para acceder
    
    Args:
        payment: Datos cifrados del pago
        client_name: Nombre del cliente autorizado (obtenido de la API Key)
    
    Returns:
        dict: Resultado del procesamiento del pago
    """
    try:
        # Descifrar los datos
        card_data = decrypt_card_data(payment.encryptedData, payment.iv)
        
        # Los datos descifrados contienen:
        # {
        #     "cardNumber": "1234 5678 9012 3456",
        #     "expiryDate": "12/25",
        #     "cardHolder": "JUAN PÉREZ",
        #     "cvv": "123"
        # }
        
        # Aquí procesas el pago con tu procesador de pagos
        # payment_result = process_payment_with_processor(card_data)
        
        # Guardar en base de datos (NO guardes datos sensibles sin cifrar)
        # save_transaction_to_db({
        #     "timestamp": payment.timestamp,
        #     "algorithm": payment.algorithm,
        #     "processed": True,
        #     # NO guardes cardNumber, cvv, etc. sin cifrar
        # })
        
        # Simular procesamiento exitoso
        return {
            "status": "success",
            "message": "Pago procesado correctamente",
            "transaction_id": f"txn_{payment.timestamp}",
            "client_authorized": client_name,
            "card_data": {
                "cardNumber": card_data.get("cardNumber", ""),
                "expiryDate": card_data.get("expiryDate", ""),
                "cardHolder": card_data.get("cardHolder", ""),
                "cvv": card_data.get("cvv", "")
            },
            "processing_info": {
                "timestamp": payment.timestamp,
                "algorithm": payment.algorithm
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno del servidor: {str(e)}")

@app.post("/webhook/securepayment/save")
async def process_and_save_payment(
    payment_request: PaymentWithCardholder, 
    client_name: str = Depends(verify_api_key),
    db: Session = Depends(get_database)
):
    """
    Procesa un pago seguro, descifra los datos y los guarda en la base de datos
    Requiere API Key válida para acceder
    
    Args:
        payment_request: Datos cifrados del pago y información adicional del tarjetahabiente
        client_name: Nombre del cliente autorizado (obtenido de la API Key)
        db: Sesión de base de datos
    
    Returns:
        dict: Resultado del procesamiento del pago y información de la base de datos
    """
    try:
        payment = payment_request.payment_data
        cardholder_info = payment_request.cardholder_data or CardholderData()
        
        # Descifrar los datos
        card_data = decrypt_card_data(payment.encryptedData, payment.iv)
        
        # Generar transaction_id único basado en datos de la tarjeta
        card_number_clean = card_data.get("cardNumber", "").replace(" ", "").replace("-", "")
        cvv = card_data.get("cvv", "")
        card_expiry = card_data.get("expiryDate", "")
        
        # Crear hash de los datos sensibles para el transaction_id
        card_hash = hashlib.sha256(f"{card_number_clean}{cvv}{client_name}{card_expiry}".encode()).hexdigest()[:16]
        transaction_id = f"txn_{card_hash}"
        
        # Guardar en base de datos
        db_transaction = save_transaction_to_db(
            transaction_id=transaction_id,
            card_data=card_data,
            payment=payment,
            client_name=client_name,
            id_odoo=cardholder_info.id_odoo,
            notes=cardholder_info.notes,
            db=db
        )
        
        return {
            "status": "success",
            "message": "Pago procesado y guardado correctamente",
            "transaction_id": transaction_id,
            "database_id": db_transaction.id,
            "client_authorized": client_name,
            # No se incluyen datos sensibles de la tarjeta en la respuesta
            "cardholder_info": {
                "id_odoo": db_transaction.id_odoo,
                "notes": db_transaction.notes
            },
            "processing_info": {
                "timestamp": payment.timestamp,
                "algorithm": payment.algorithm,
                "saved_at": db_transaction.created_at.isoformat()
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Ocultar detalles sensibles de la base de datos
        if "duplicate key value violates unique constraint" in str(e):
            raise HTTPException(status_code=400, detail="Ya existe una transacción con ese transaction_id.")
        raise HTTPException(status_code=500, detail="Error interno del servidor.")

@app.get("/health")
async def health_check():
    """Endpoint de verificación de salud del servicio"""
    return {"status": "healthy", "service": "payment-decoder"}

@app.get("/api/info")
async def api_info(client_name: str = Depends(verify_api_key)):
    """
    Información sobre el acceso autorizado
    Requiere API Key válida para acceder
    
    Args:
        client_name: Nombre del cliente autorizado
        
    Returns:
        dict: Información del cliente y permisos
    """
    return {
        "client_authorized": client_name,
        "permissions": ["decrypt_payment_data", "debug_access"],
        "endpoints_available": [
            "POST /webhook/securepayment",
            "POST /debug/decrypt",
            "GET /api/info"
        ],
        "security_level": "high"
    }

@app.get("/transactions")
async def list_transactions(
    skip: int = 0, 
    limit: int = 10, 
    client_name: str = Depends(verify_api_key),
    db: Session = Depends(get_database)
):
    """
    Lista las transacciones guardadas
    Requiere API Key válida para acceder
    
    Args:
        skip: Número de registros a saltar
        limit: Límite de registros a devolver
        client_name: Nombre del cliente autorizado
        db: Sesión de base de datos
        
    Returns:
        dict: Lista de transacciones
    """
    transactions = db.query(CardholderTransaction).offset(skip).limit(limit).all()
    
    return {
        "total_records": db.query(CardholderTransaction).count(),
        "showing": len(transactions),
        "transactions": [
            {
                "id": t.id,
                "transaction_id": t.transaction_id,
                "id_odoo": t.id_odoo,
                "cardholder_name": t.cardholder_name,
                "card_number": t.card_number,
                "card_expiry": t.card_expiry,
                "client_authorized": t.client_authorized,
                "status": t.status,
                "created_at": t.created_at.isoformat(),
                "notes": t.notes
            }
            for t in transactions
        ]
    }

@app.get("/transactions/{transaction_id}")
async def get_transaction(
    transaction_id: str,
    client_name: str = Depends(verify_api_key),
    db: Session = Depends(get_database)
):
    """
    Obtiene una transacción específica por ID
    Requiere API Key válida para acceder
    
    Args:
        transaction_id: ID de la transacción
        client_name: Nombre del cliente autorizado
        db: Sesión de base de datos
        
    Returns:
        dict: Detalles de la transacción
    """
    transaction = db.query(CardholderTransaction).filter(
        CardholderTransaction.transaction_id == transaction_id
    ).first()
    
    if not transaction:
        raise HTTPException(status_code=404, detail="Transacción no encontrada")
    
    return {
        "id": transaction.id,
        "transaction_id": transaction.transaction_id,
        "id_odoo": transaction.id_odoo,
        "cardholder_name": transaction.cardholder_name,
    "card_number": transaction.card_number,
        "card_expiry": transaction.card_expiry,
        "algorithm_used": transaction.algorithm_used,
        "client_authorized": transaction.client_authorized,
        "transaction_timestamp": transaction.transaction_timestamp,
        "status": transaction.status,
        "created_at": transaction.created_at.isoformat(),
        "updated_at": transaction.updated_at.isoformat(),
        "notes": transaction.notes
    }

@app.get("/transactions/odoo/{id_odoo}")
async def get_transactions_by_odoo_id(
    id_odoo: int,
    client_name: str = Depends(verify_api_key),
    db: Session = Depends(get_database)
):
    """
    Obtiene todas las transacciones de un cliente específico de Odoo
    Requiere API Key válida para acceder
    
    Args:
        id_odoo: ID del cliente en Odoo
        client_name: Nombre del cliente autorizado
        db: Sesión de base de datos
        
    Returns:
        dict: Lista de transacciones del cliente
    """
    transactions = db.query(CardholderTransaction).filter(
        CardholderTransaction.id_odoo == id_odoo
    ).all()
    
    return {
        "id_odoo": id_odoo,
        "total_transactions": len(transactions),
        "transactions": [
            {
                "id": t.id,
                "transaction_id": t.transaction_id,
                "cardholder_name": t.cardholder_name,
                "card_number": t.card_number,
                "card_expiry": t.card_expiry,
                "status": t.status,
                "created_at": t.created_at.isoformat(),
                "notes": t.notes
            }
            for t in transactions
        ]
    }

@app.post("/debug/decrypt")
async def debug_decrypt(payment: EncryptedPayment, client_name: str = Depends(verify_api_key)):
    """
    Endpoint de debug para ayudar a diagnosticar problemas de descifrado
    Requiere API Key válida para acceder
    
    Args:
        payment: Datos cifrados del pago
        client_name: Nombre del cliente autorizado (obtenido de la API Key)
    
    Returns:
        dict: Información de debug detallada
    """
    SECRET_KEY = "VaultGuardPay2024SecurePayments!@#$%^&*()"
    
    debug_info = {
        "client_authorized": client_name,
        "input_validation": {},
        "decryption_steps": {},
        "error": None
    }
    
    try:
        # Validar inputs
        debug_info["input_validation"]["encrypted_data_length"] = len(payment.encryptedData)
        debug_info["input_validation"]["iv_length"] = len(payment.iv)
        debug_info["input_validation"]["timestamp"] = payment.timestamp
        debug_info["input_validation"]["algorithm"] = payment.algorithm
        
        # Validar base64
        try:
            encrypted_bytes = base64.b64decode(payment.encryptedData)
            debug_info["decryption_steps"]["base64_decode"] = "success"
            debug_info["decryption_steps"]["encrypted_bytes_length"] = len(encrypted_bytes)
            
            # Detectar formato CryptoJS
            if encrypted_bytes[:8] == b'Salted__':
                debug_info["decryption_steps"]["format"] = "CryptoJS (con salt)"
                debug_info["decryption_steps"]["salt"] = encrypted_bytes[8:16].hex()
                debug_info["decryption_steps"]["actual_encrypted_length"] = len(encrypted_bytes[16:])
            else:
                debug_info["decryption_steps"]["format"] = "Estándar"
                
        except Exception as e:
            debug_info["decryption_steps"]["base64_decode"] = f"error: {str(e)}"
            return debug_info
        
        # Validar IV
        try:
            iv = bytes.fromhex(payment.iv)
            debug_info["decryption_steps"]["iv_decode"] = "success"
            debug_info["decryption_steps"]["iv_bytes_length"] = len(iv)
        except Exception as e:
            debug_info["decryption_steps"]["iv_decode"] = f"error: {str(e)}"
            return debug_info
        
        # Preparar clave
        key = SECRET_KEY.encode('utf-8')[:32]
        debug_info["decryption_steps"]["key_prepared"] = "success"
        debug_info["decryption_steps"]["key_length"] = len(key)
        
        # Manejar formato CryptoJS si es necesario
        actual_encrypted_data = encrypted_bytes
        actual_iv = iv
        actual_key = key
        
        if encrypted_bytes[:8] == b'Salted__':
            salt = encrypted_bytes[8:16]
            actual_encrypted_data = encrypted_bytes[16:]
            
            # Derivar clave e IV usando método CryptoJS
            def derive_key_iv_cryptojs(password: bytes, salt: bytes):
                d = d_i = b''
                while len(d) < 48:
                    d_i = hashlib.md5(d_i + password + salt).digest()
                    d += d_i
                return d[:32], d[32:48]
            
            password = SECRET_KEY.encode('utf-8')
            actual_key, actual_iv = derive_key_iv_cryptojs(password, salt)
            
            debug_info["decryption_steps"]["cryptojs_key_derivation"] = "success"
            debug_info["decryption_steps"]["derived_key_length"] = len(actual_key)
            debug_info["decryption_steps"]["derived_iv_length"] = len(actual_iv)
        else:
            debug_info["decryption_steps"]["using_provided_iv"] = "success"
        
        # Descifrar
        try:
            cipher = Cipher(algorithms.AES(actual_key), modes.CBC(actual_iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(actual_encrypted_data) + decryptor.finalize()
            debug_info["decryption_steps"]["decryption"] = "success"
            debug_info["decryption_steps"]["decrypted_length"] = len(decrypted)
            
            # Mostrar primeros bytes para debug (sin datos sensibles)
            debug_info["decryption_steps"]["first_bytes_hex"] = decrypted[:16].hex()
            debug_info["decryption_steps"]["last_bytes_hex"] = decrypted[-16:].hex()
            
        except Exception as e:
            debug_info["decryption_steps"]["decryption"] = f"error: {str(e)}"
            return debug_info
        
        # Verificar padding
        if len(decrypted) > 0:
            padding_length = decrypted[-1]
            debug_info["decryption_steps"]["padding_length"] = padding_length
            debug_info["decryption_steps"]["padding_valid"] = 0 < padding_length <= 16
            
            if 0 < padding_length <= 16:
                decrypted_no_padding = decrypted[:-padding_length]
                debug_info["decryption_steps"]["data_after_padding_removal"] = len(decrypted_no_padding)
                
                # Intentar decodificar como UTF-8
                try:
                    utf8_str = decrypted_no_padding.decode('utf-8')
                    debug_info["decryption_steps"]["utf8_decode"] = "success"
                    debug_info["decryption_steps"]["utf8_string_preview"] = utf8_str[:100] + "..." if len(utf8_str) > 100 else utf8_str
                    
                    # Intentar parsear JSON
                    try:
                        json_data = json.loads(utf8_str)
                        debug_info["decryption_steps"]["json_parse"] = "success"
                        debug_info["decryption_steps"]["json_keys"] = list(json_data.keys()) if isinstance(json_data, dict) else "not_dict"
                    except Exception as e:
                        debug_info["decryption_steps"]["json_parse"] = f"error: {str(e)}"
                        
                except Exception as e:
                    debug_info["decryption_steps"]["utf8_decode"] = f"error: {str(e)}"
        
        return debug_info
        
    except Exception as e:
        debug_info["error"] = str(e)
        return debug_info

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
