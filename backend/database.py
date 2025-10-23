from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./db.sqlite3"

# 🔧 Configuración optimizada para concurrencia
engine = create_engine(
    DATABASE_URL, 
    connect_args={
        "check_same_thread": False,
        "timeout": 30,  # Timeout más largo para locks
        "isolation_level": None  # Autocommit mode para SQLite
    },
    pool_size=10,           # Más conexiones en pool
    max_overflow=20,        # Más overflow
    pool_timeout=30,        # Timeout para obtener conexión
    pool_recycle=3600,      # Reciclar conexiones cada hora
    echo=False              # No loggear SQL queries (reduce overhead)
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()