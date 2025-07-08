from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# Base de datos en raíz del proyecto
DATABASE_URL = "sqlite:///./db.sqlite3"

Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Archivos esperados en el output
MODULE_FILES = [
    "subdomains.txt", "httpx.txt", "gau.txt", "waybackurls.txt", "katana.txt",
    "arjun.txt", "dalfox.txt", "ffuf.txt", "tplmap.txt", "sqlmap.txt", "waf.txt", "xsstrike.txt"
]

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    target = Column(String)
    mode = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    result_markdown = Column(Text, nullable=True)
    result_csv = Column(Text, nullable=True)
    result_pdf_path = Column(String, nullable=True)
    results_dir = Column(String, nullable=True)  # <-- campo para guardar nombre real del directorio
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="projects")
    scan_state = relationship("ScanState", uselist=False, back_populates="project")


class ScanState(Base):
    __tablename__ = "scan_states"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    current_stage = Column(String, default="Recon")
    status = Column(String, default="idle")  # idle, running, completed, cancelled
    pid = Column(Integer, nullable=True)
    progress = Column(Integer, default=0)
    current_step = Column(String, default="")
    last_module_index = Column(Integer, default=0)  # ✅ Campo requerido para salto de etapa
    current_module = Column(String, default="")      # ✅ Módulo actual ejecutándose

    project = relationship("Project", back_populates="scan_state")

    def update_progress(self):
        if not self.project or not self.project.results_dir:
            self.progress = 0
            return

        results_dir = os.path.abspath(os.path.join("results", self.project.results_dir))
        if not os.path.isdir(results_dir):
            self.progress = 0
        else:
            total = len(MODULE_FILES)
            found = sum(os.path.isfile(os.path.join(results_dir, f)) for f in MODULE_FILES)
            self.progress = int((found / total) * 100)