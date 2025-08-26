"""
Ejemplo de cliente Python para probar los endpoints de la API
"""
import requests
import json
from datetime import datetime

# Configuración
API_BASE_URL = "http://localhost:8000"
API_KEY = "vault-api-key-2024-secure"

def test_save_encrypted_payment():
    """
    Ejemplo principal: Enviar datos encriptados y guardar en base de datos
    """
    
    # Headers con autenticación
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Datos encriptados que vendrían del frontend
    payload = {
        "payment_data": {
            "encryptedData": "U2FsdGVkX197zrTIecjbXanMoKH4Bv61NOkeY4MiHnkBJQnFtaaRa0DQoL/oRYfeOuaoQIweNGgTRN44M87wjaXMwazlbHbfRpE3M8cqc0HLg3iYMClJ+XkvhhlB4xkCX2NhIiogCg6WoVChzj/Oeg==",
            "iv": "e5416849ff87b15d3802bf1b35012ee5",
            "timestamp": datetime.now().isoformat() + "Z",
            "algorithm": "AES-256-CBC"
        },
        "cardholder_data": {
            "id_odoo": 12345,
            "notes": "Cliente VIP - Pago desde Python"
        }
    }
    
    print("🚀 Enviando datos encriptados a la API...")
    print(f"📡 URL: {API_BASE_URL}/webhook/securepayment/save")
    
    try:
        # Enviar request
        response = requests.post(
            f"{API_BASE_URL}/webhook/securepayment/save",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        # Procesar respuesta
        if response.status_code == 200:
            result = response.json()
            print("✅ ÉXITO - Pago procesado y guardado:")
            print(f"   Transaction ID: {result['transaction_id']}")
            print(f"   Database ID: {result['database_id']}")
            print(f"   Tarjetahabiente: {result['card_data']['cardHolder']}")
            print(f"   Últimos 4 dígitos: ****{result['card_data']['cardNumber'][-4:]}")
            print(f"   ID Odoo: {result['cardholder_info']['id_odoo']}")
            print(f"   Guardado en: {result['processing_info']['saved_at']}")
            
            return result
        else:
            print(f"❌ ERROR {response.status_code}: {response.text}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")
        return None

def test_list_transactions():
    """
    Ejemplo: Listar transacciones guardadas
    """
    headers = {
        "Authorization": f"Bearer {API_KEY}",
    }
    
    print("\n📊 Obteniendo lista de transacciones...")
    
    try:
        response = requests.get(
            f"{API_BASE_URL}/transactions",
            headers=headers,
            params={"skip": 0, "limit": 5}
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ {result['showing']} transacciones de {result['total_records']} totales:")
            
            for txn in result['transactions']:
                print(f"   🆔 ID: {txn['id']}")
                print(f"   📋 Transaction: {txn['transaction_id']}")
                print(f"   👤 Cliente: {txn['cardholder_name']}")
                print(f"   🏢 Odoo ID: {txn['id_odoo']}")
                print(f"   📅 Creado: {txn['created_at']}")
                print("   " + "-" * 40)
                
            return result
        else:
            print(f"❌ ERROR {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")

def test_get_by_odoo_id(odoo_id: int):
    """
    Ejemplo: Obtener transacciones por ID de Odoo
    """
    headers = {
        "Authorization": f"Bearer {API_KEY}",
    }
    
    print(f"\n🏢 Obteniendo transacciones para Odoo ID: {odoo_id}")
    
    try:
        response = requests.get(
            f"{API_BASE_URL}/transactions/odoo/{odoo_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ {result['total_transactions']} transacciones para Odoo ID {odoo_id}:")
            
            for txn in result['transactions']:
                print(f"   📋 {txn['transaction_id']}")
                print(f"   👤 {txn['cardholder_name']}")
                print(f"   💳 ****{txn['card_last_four']}")
                print(f"   📅 {txn['created_at']}")
                print("   " + "-" * 30)
                
            return result
        else:
            print(f"❌ ERROR {response.status_code}: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión: {e}")

def test_health_check():
    """
    Ejemplo: Verificar que la API esté funcionando
    """
    print("\n💚 Verificando salud de la API...")
    
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ API funcionando: {result['status']} - {result['service']}")
            return True
        else:
            print(f"❌ API con problemas: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ API no disponible: {e}")
        return False

if __name__ == "__main__":
    print("🧪 PROBANDO API SECURE PAYMENT DECODER")
    print("=" * 50)
    
    # 1. Verificar que la API esté funcionando
    if not test_health_check():
        print("❌ API no disponible. Verifica que esté ejecutándose.")
        exit(1)
    
    # 2. Procesar pago encriptado (FUNCIÓN PRINCIPAL)
    result = test_save_encrypted_payment()
    
    if result:
        # 3. Listar transacciones
        test_list_transactions()
        
        # 4. Buscar por Odoo ID
        test_get_by_odoo_id(12345)
    
    print("\n🎉 ¡Pruebas completadas!")
