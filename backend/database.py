"""
Una sola get_db para toda la app: usa SessionLocal de models (misma BD, misma sesión).
"""
from backend.models import SessionLocal  # re-export para db_utils y otros

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
