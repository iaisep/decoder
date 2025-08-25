"""
Script de prueba para verificar la conexión a la base de datos
"""
from database import create_tables, engine, SessionLocal, CardholderTransaction
from sqlalchemy import text
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

def test_database_connection():
    """Prueba la conexión a la base de datos 'contable'"""
    try:
        print("🔗 Probando conexión a la base de datos 'contable'...")
        
        # Probar conexión básica
        with engine.connect() as connection:
            result = connection.execute(text("SELECT current_database(), version()"))
            db_info = result.fetchone()
            print(f"✅ Conectado a base de datos: {db_info[0]}")
            print(f"📊 Versión PostgreSQL: {db_info[1]}")
        
        # Crear tablas
        print("📋 Creando tablas en base de datos 'contable'...")
        create_tables()
        print("✅ Tablas creadas exitosamente")
        
        # Probar inserción de datos de prueba
        print("💾 Probando inserción de datos...")
        db = SessionLocal()
        try:
            test_transaction = CardholderTransaction(
                transaction_id="test_001",
                id_odoo=999,
                cardholder_name="Test User",
                card_last_four="1234",
                card_expiry="12/25",
                algorithm_used="AES-256-CBC",
                client_authorized="Test Client",
                transaction_timestamp="2024-08-25T10:00:00Z",
                status="test",
                notes="Datos de prueba"
            )
            
            db.add(test_transaction)
            db.commit()
            print(f"✅ Datos insertados con ID: {test_transaction.id}")
            
            # Limpiar datos de prueba
            db.delete(test_transaction)
            db.commit()
            print("🧹 Datos de prueba eliminados")
            
        finally:
            db.close()
        
        print("\n🎉 ¡Todas las pruebas de base de datos 'contable' pasaron exitosamente!")
        return True
        
    except Exception as e:
        print(f"❌ Error en la prueba de base de datos 'contable': {str(e)}")
        return False

if __name__ == "__main__":
    # Mostrar configuración (sin contraseña)
    db_url = os.getenv("DATABASE_URL", "No configurada")
    print(f"🔧 URL de base de datos 'contable': {db_url[:50]}...")
    
    # Ejecutar pruebas
    success = test_database_connection()
    
    if success:
        print("\n✨ El servidor está listo para usar con base de datos 'contable'!")
    else:
        print("\n⚠️  Revisa la configuración de la base de datos 'contable' antes de usar el servidor")
