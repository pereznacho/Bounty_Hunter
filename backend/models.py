from backend.constants import VULN_RESULT_FILES, SEVERITY_KEYWORDS, NO_FINDINGS_HINTS, MIN_VALID_FILE_SIZE
# backend/models.py

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, ForeignKey, DateTime,
    Boolean, Text, create_engine
)
from sqlalchemy.orm import relationship, sessionmaker, declarative_base

# Configuración de la base de datos
SQLALCHEMY_DATABASE_URL = "sqlite:///./db.sqlite3"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    pool_size=20,
    max_overflow=30,
    pool_timeout=60,
    pool_recycle=3600
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -------------------------------
# Constantes generales
# -------------------------------
MODULE_FILES = [
    "subdomains.txt", "httpx.txt", "gau.txt", "waybackurls.txt", "katana.txt",
    "arjun.txt", "dalfox.txt", "ffuf.txt", "tplmap.txt", "sqlmap.txt", "waf.txt", "xsstrike.txt"
]

# -------------------------------
# Modelo de Usuario
# -------------------------------
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    email = Column(String, nullable=True)

    projects = relationship("Project", back_populates="owner")

# -------------------------------
# Proyecto
# -------------------------------
class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    program = Column(String, nullable=True, default="Manual")
    target = Column(String, nullable=True)
    mode = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    result_markdown = Column(Text, nullable=True)
    result_csv = Column(Text, nullable=True)
    result_pdf_path = Column(String, nullable=True)
    results_dir = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="projects")
    scan_state = relationship("ScanState", back_populates="project", uselist=False)

    # ✅ Bounty Platform support
    platform = Column(String, nullable=True)  # Ej: 'HackerOne', 'BugCrowd', etc. NULL para Manual
    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    
    # Platform flags
    created_from_hackerone = Column(Boolean, default=False)
    created_from_intigriti = Column(Boolean, default=False)
    created_from_yeswehack = Column(Boolean, default=False)
    created_from_bugcrowd = Column(Boolean, default=False)

    @property
    def domain_targets(self):
        return [t for t in self.targets if t.type == "domain"]

    @property
    def url_targets(self):
        return [t for t in self.targets if t.type == "url"]

    @property
    def total_targets(self):
        return len(self.targets)

    @property
    def completed_targets(self):
        return len([t for t in self.targets if t.status == "completed"])

    @property
    def is_hackerone(self):
        """True si el proyecto proviene de HackerOne."""
        return bool(self.created_from_hackerone)

    @property
    def has_vulnerabilities(self):
        """Detecta si el proyecto tiene vulnerabilidades. Busca en results_dir del proyecto O en targets individuales."""
        
        # Método 1: Buscar en results_dir del proyecto (para proyectos de plataformas)
        if self.results_dir:
            import os
            
            # Archivos que indican vulnerabilidades reales 
            # EXCLUIDOS (solo información/recon): recon.py, waf.py, nuclei_scan.py, gf_qsreplace.py, prepare_url_scan.py
            vuln_files = [
                "dalfox_results.txt",      # XSS findings (Dalfox)
                "xss_vulnerables.txt",     # XSS findings (XSS module)
                "sql_vulnerables.txt",     # SQLi findings (SQLi module)  
                "tplmap_results.txt",      # Template injection (Tplmap)
                "ffuf_results.txt",        # Directory/file findings (FFUF)
                "wfuzz_results.txt",       # Fuzzing results (Wfuzz)
                "arjun_results.txt"        # Parameter findings (Arjun)
            ]
            
            for vuln_file in vuln_files:
                file_path = os.path.join(self.results_dir, vuln_file)
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read().strip()
                            # Si el archivo tiene contenido y no es solo headers/empty
                            if content and len(content) > 50:  # Mínimo de contenido significativo
                                # Verificar que no sean solo mensajes de "no findings"
                                no_findings_indicators = [
                                    "no vulnerabilities found",
                                    "no issues found", 
                                    "scan completed with 0 results",
                                    "no findings",
                                    "nothing found"
                                ]
                                content_lower = content.lower()
                                has_no_findings = any(indicator in content_lower for indicator in no_findings_indicators)
                                
                                if not has_no_findings:
                                    return True
                    except Exception:
                        continue
        
        # Método 2: Buscar en targets individuales (para proyectos manuales)
        if hasattr(self, 'targets') and self.targets:
            for target in self.targets:
                if target.has_vulnerabilities:
                    return True
        
        return False

    @property
    def vulnerability_level(self):
        """Retorna el nivel de criticidad más alto entre el proyecto y sus targets."""
        if not self.has_vulnerabilities:
            return "none"
        
        import os
        
        highest_level = "none"
        level_priority = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        
        # Método 1: Buscar en results_dir del proyecto (para proyectos de plataformas)
        if self.results_dir:
            # Solo buscar en archivos de vulnerabilidades reales
            # EXCLUIDOS: recon.py, waf.py, nuclei_scan.py, gf_qsreplace.py, prepare_url_scan.py
            vuln_files = [
                "dalfox_results.txt", "xss_vulnerables.txt", "sql_vulnerables.txt", 
                "tplmap_results.txt", "ffuf_results.txt", "wfuzz_results.txt", "arjun_results.txt"
            ]
            
            # Buscar keywords de criticidad solo en archivos de vulnerabilidades
            critical_keywords = ["critical", "high risk", "severe", "rce", "sqli", "sql injection"]
            high_keywords = ["high", "dangerous", "xss", "csrf", "lfi", "rfi"] 
            medium_keywords = ["medium", "warning", "potential", "directory traversal"]
            
            try:
                for vuln_file in vuln_files:
                    file_path = os.path.join(self.results_dir, vuln_file)
                    if os.path.exists(file_path):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()
                                
                                if any(keyword in content for keyword in critical_keywords):
                                    highest_level = "critical"
                                    break  # Critical es el máximo, no seguir buscando
                                elif any(keyword in content for keyword in high_keywords) and level_priority[highest_level] < 3:
                                    highest_level = "high"
                                elif any(keyword in content for keyword in medium_keywords) and level_priority[highest_level] < 2:
                                    highest_level = "medium"
                                elif highest_level == "none":
                                    highest_level = "low"
                        except Exception:
                            continue
            except Exception:
                pass
        
        # Método 2: Buscar en targets individuales (para proyectos manuales)
        if hasattr(self, 'targets') and self.targets:
            for target in self.targets:
                target_level = target.vulnerability_level
                if level_priority[target_level] > level_priority[highest_level]:
                    highest_level = target_level
                    if highest_level == "critical":
                        break  # Critical es el máximo
        
        return highest_level if highest_level != "none" else "low"

# -------------------------------
# Target (dominio o URL)
# -------------------------------
class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    project = relationship("Project", back_populates="targets")
    
    target = Column(String, nullable=False)
    type = Column(String, nullable=False)  # "domain" o "url"
    status = Column(String, default="pending")
    findings = Column(Text, nullable=True)
    
    # Sistema de alertas de vulnerabilidades
    vulnerability_alert_viewed = Column(Boolean, default=False)
    vulnerability_alert_viewed_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @property
    def results_dir(self):
        """Retorna el directorio de resultados para este target específico."""
        import os
        import glob
        from utils.path_utils import get_safe_name_from_target
        
        safe_target_name = get_safe_name_from_target(self.target)
        
        # 🔍 Buscar directorios existentes que coincidan con el target
        # Patrón: safe_target_name_YYYYMMDD_HHMMSS
        pattern = os.path.join("results", f"{safe_target_name}_*")
        matching_dirs = glob.glob(pattern)
        
        if matching_dirs:
            # Retornar el más reciente (último en orden alfabético = timestamp más reciente)
            return max(matching_dirs)
        
        # Fallback: calcular basado en timestamp del proyecto
        if self.project and self.project.created_at:
            timestamp = self.project.created_at.strftime("%Y%m%d_%H%M%S")
            return os.path.join("results", f"{safe_target_name}_{timestamp}")
        
        return None
    
    @property
    def has_vulnerabilities(self):
        """Verifica si este target específico tiene vulnerabilidades detectadas."""
        import os
        
        if not self.results_dir:
            return False
            
        # Solo buscar en archivos de vulnerabilidades reales (excluir informacionales)
        vuln_files = [
            "dalfox_results.txt",      # XSS findings (Dalfox)
            "sqlmap_results.txt",      # SQLi findings (SQLMap)  
            "xsstrike_results.txt",    # XSS findings (XSStrike)
            "tplmap_results.txt",      # Template injection (Tplmap)
            "ffuf_results.txt",        # Directory/file findings (FFUF)
            "wfuzz_results.txt",       # Fuzzing results (Wfuzz)
            "arjun_results.txt",       # Parameter findings (Arjun)
            "xss_vulnerables.txt",     # XSS findings (actual module output)
            "sql_vulnerables.txt"      # SQL findings (actual module output)
        ]
        
        for vuln_file in vuln_files:
            file_path = os.path.join(self.results_dir, vuln_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().strip()
                        # Si el archivo tiene contenido y no es solo headers/empty
                        if content and len(content) > 50:  # Mínimo de contenido significativo
                            # Verificar que no sean solo mensajes de "no findings"
                            no_findings_indicators = [
                                "no vulnerabilities found",
                                "no issues found", 
                                "scan completed with 0 results",
                                "no findings",
                                "nothing found"
                            ]
                            content_lower = content.lower()
                            has_no_findings = any(indicator in content_lower for indicator in no_findings_indicators)
                            
                            if not has_no_findings:
                                return True
                except Exception:
                    continue
        
        return False

    @property
    def vulnerability_level(self):
        """Retorna el nivel de criticidad basado en keywords en los archivos de vulnerabilidades reales."""
        if not self.has_vulnerabilities:
            return "none"
        
        import os
        
        if not self.results_dir:
            return "none"
            
        # Solo buscar en archivos de vulnerabilidades reales
        vuln_files = [
            "dalfox_results.txt", "sqlmap_results.txt", "xsstrike_results.txt", 
            "tplmap_results.txt", "ffuf_results.txt", "wfuzz_results.txt", "arjun_results.txt",
            "xss_vulnerables.txt", "sql_vulnerables.txt"  # Nombres reales generados por módulos
        ]
        
        highest_level = "none"
        
        for vuln_file in vuln_files:
            file_path = os.path.join(self.results_dir, vuln_file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        
                        # Palabras clave por nivel de criticidad
                        if any(word in content for word in ["critical", "rce", "remote code execution", "sql injection", "sqli"]):
                            return "critical"  # Devolver inmediatamente si es crítico
                        elif any(word in content for word in ["high", "xss", "cross-site scripting", "template injection"]):
                            highest_level = "high"
                        elif highest_level not in ["high", "critical"] and any(word in content for word in ["medium", "directory traversal", "lfi"]):
                            highest_level = "medium"
                        elif highest_level == "none" and any(word in content for word in ["low", "info", "information disclosure"]):
                            highest_level = "low"
                            
                except Exception:
                    continue
        
        return highest_level

    @property 
    def has_unviewed_vulnerabilities(self):
        """Retorna True si tiene vulnerabilidades y no han sido vistas."""
        return self.has_vulnerabilities and not self.vulnerability_alert_viewed

# -------------------------------
# Estado del escaneo (ScanState)
# -------------------------------
class ScanState(Base):
    __tablename__ = "scan_states"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    project = relationship("Project", back_populates="scan_state")

    current_stage = Column(String, default="Recon")
    status = Column(String, default="idle")
    pid = Column(Integer, nullable=True)
    progress = Column(Integer, default=0)
    current_step = Column(String, default="")
    last_module_index = Column(Integer, default=0)
    current_module = Column(String, default="")

    # Flags por módulo
    recon = Column(Boolean, default=False)
    xss = Column(Boolean, default=False)
    sqli = Column(Boolean, default=False)
    tplmap = Column(Boolean, default=False)
    wfuzz = Column(Boolean, default=False)
    reported = Column(Boolean, default=False)

    def update_progress(self):
        total_modules = 6
        completed = sum([
            bool(self.recon),
            bool(self.xss),
            bool(self.sqli),
            bool(self.tplmap),
            bool(self.wfuzz),
            bool(self.reported)
        ])
        self.progress = int((completed / total_modules) * 100)

# -------------------------------
# API Key de HackerOne
# -------------------------------
class HackerOneCredentials(Base):
    __tablename__ = "hackerone_credentials"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    api_key = Column(String, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# -------------------------------
# Plataforma de Bug Bounty (H1, BugCrowd...)
# -------------------------------
class Platform(Base):
    __tablename__ = "platforms"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # Ej: HackerOne
    icon = Column(String, default="🐞")

    programs = relationship("BountyProgram", back_populates="platform")

# -------------------------------
# Programa dentro de la plataforma
# -------------------------------
class BountyProgram(Base):
    __tablename__ = "bounty_programs"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # Ej: "Alshaya"
    platform_id = Column(Integer, ForeignKey("platforms.id"))

    platform = relationship("Platform", back_populates="programs")
    scans = relationship("Scan", back_populates="program")

# -------------------------------
# Escaneo lanzado (puede ser a dominio o URL)
# -------------------------------
class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)  # "domain" o "url"
    target = Column(String)
    date = Column(DateTime)
    status = Column(String)
    progress = Column(Integer)

    program_id = Column(Integer, ForeignKey("bounty_programs.id"))
    program = relationship("BountyProgram", back_populates="scans")