"""
Modelos de base de datos para la API Secure Payment Decoder
"""
from sqlalchemy import Column, Integer, String, DateTime, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de base de datos
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/postgres")

# Configuración de SQLAlchemy
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class CardholderTransaction(Base):
    """
    Tabla para almacenar las transacciones de tarjetahabientes
    """
    __tablename__ = "cardholder_transactions"
    
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String(255), unique=True, index=True, nullable=False)
    id_odoo = Column(Integer, index=True, nullable=True)  # ID del cliente en Odoo
    
    # Información del tarjetahabiente (cifrada en producción)
    cardholder_name = Column(String(255), nullable=False)
    card_last_four = Column(String(4), nullable=False)  # Solo últimos 4 dígitos
    card_expiry = Column(String(7), nullable=False)  # MM/YY
    
    # Información de la transacción
    algorithm_used = Column(String(50), nullable=False)
    client_authorized = Column(String(255), nullable=False)
    
    # Timestamps
    transaction_timestamp = Column(String(50), nullable=False)  # Timestamp del frontend
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Información adicional
    status = Column(String(50), default="processed")
    notes = Column(Text, nullable=True)

def create_tables():
    """Crear todas las tablas en la base de datos"""
    Base.metadata.create_all(bind=engine)

def get_database():
    """
    Dependency para obtener sesión de base de datos
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
