import sys
import os

# Agrega la carpeta raíz del proyecto al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Misma URL que en runtime (Docker puede inyectar SQLALCHEMY_DATABASE_URL)
os.environ.setdefault("SQLALCHEMY_DATABASE_URL", "sqlite:///./db.sqlite3")

from backend.models import Base, engine
from sqlalchemy import text

def init_db():
    print("[-] Creando tablas en la base de datos...")
    Base.metadata.create_all(bind=engine)
    # Migration: add theme column to users if missing (e.g. existing SQLite DB)
    try:
        with engine.connect() as conn:
            if "sqlite" in str(engine.url):
                r = conn.execute(text("PRAGMA table_info(users)"))
                cols = [row[1] for row in r]
                if "theme" not in cols:
                    conn.execute(text("ALTER TABLE users ADD COLUMN theme VARCHAR DEFAULT 'default'"))
                    conn.commit()
                    print("[✓] Columna 'theme' añadida a users")
            # Migration: users with theme=tech or theme=jarvis get default (themes removed)
            upd = conn.execute(text("UPDATE users SET theme = 'default' WHERE theme IN ('tech', 'jarvis')"))
            conn.commit()
            if getattr(upd, "rowcount", 0) and upd.rowcount > 0:
                print(f"[✓] Migración: {upd.rowcount} usuario(s) con theme obsoleto actualizado(s) a default")
    except Exception as e:
        print(f"[!] Migración theme (ignorable): {e}")
    print("[✓] ¡Tablas creadas exitosamente!")

if __name__ == "__main__":
    init_db()
