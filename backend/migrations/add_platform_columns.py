import sys
import os

# Agrega la carpeta raíz del proyecto al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy import Column, Boolean, text
from backend.models import Base, engine

def add_platform_columns():
    print("[-] Agregando columnas de plataformas...")
    
    # Crear todas las tablas (esto es seguro, no afecta las existentes)
    Base.metadata.create_all(bind=engine)
    
    # Agregar columnas si no existen
    with engine.connect() as conn:
        # Verificar y agregar created_from_intigriti
        try:
            conn.execute(text('SELECT created_from_intigriti FROM projects LIMIT 1'))
        except Exception:
            conn.execute(text('ALTER TABLE projects ADD COLUMN created_from_intigriti BOOLEAN DEFAULT 0'))
            print("[+] Agregada columna created_from_intigriti")
            
        # Verificar y agregar created_from_yeswehack
        try:
            conn.execute(text('SELECT created_from_yeswehack FROM projects LIMIT 1'))
        except Exception:
            conn.execute(text('ALTER TABLE projects ADD COLUMN created_from_yeswehack BOOLEAN DEFAULT 0'))
            print("[+] Agregada columna created_from_yeswehack")
            
        # Verificar y agregar created_from_bugcrowd
        try:
            conn.execute(text('SELECT created_from_bugcrowd FROM projects LIMIT 1'))
        except Exception:
            conn.execute(text('ALTER TABLE projects ADD COLUMN created_from_bugcrowd BOOLEAN DEFAULT 0'))
            print("[+] Agregada columna created_from_bugcrowd")
            
        conn.commit()
    
    print("[✓] ¡Columnas agregadas exitosamente!")

if __name__ == "__main__":
    add_platform_columns()