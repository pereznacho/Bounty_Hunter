import sys
import os

# Agrega la carpeta raíz del proyecto al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.models import Base, engine

def init_db():
    print("[-] Creando tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    print("[✓] ¡Tablas creadas exitosamente!")

if __name__ == "__main__":
    init_db()
