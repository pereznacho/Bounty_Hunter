# utils/realtime_results.py

import os
from datetime import datetime

def write_vulnerability_immediately(results_dir, module_name, vulnerability_data):
    """Escribe una vulnerabilidad inmediatamente a su archivo de resultados"""
    
    # Crear archivo específico del módulo si no existe
    results_file = os.path.join(results_dir, f"{module_name.lower()}_results.txt")
    
    # Escribir inmediatamente
    with open(results_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] VULNERABILIDAD DETECTADA\n")
        f.write(f"Módulo: {module_name}\n")
        
        if isinstance(vulnerability_data, dict):
            for key, value in vulnerability_data.items():
                f.write(f"{key}: {value}\n")
        else:
            f.write(f"Detalles: {vulnerability_data}\n")
        
        f.write("-" * 60 + "\n")
        f.flush()  # Forzar escritura inmediata
    
    print(f"[✓] Vulnerabilidad {module_name} escrita en tiempo real: {results_file}")

def update_vulnerability_status(project_id, target_id=None):
    """Actualiza el estado de vulnerabilidades en la BD"""
    
    try:
        from backend.models import SessionLocal, Project, Target
        
        db = SessionLocal()
        
        # Actualizar timestamp de última actualización
        if target_id:
            target = db.query(Target).filter(Target.id == target_id).first()
            if target:
                target.last_vulnerability_check = datetime.now()
        
        project = db.query(Project).filter(Project.id == project_id).first() 
        if project:
            project.last_vulnerability_check = datetime.now()
        
        db.commit()
        db.close()
        
        print(f"[✓] Estado de vulnerabilidades actualizado para proyecto {project_id}")
        
    except Exception as e:
        print(f"[⚠️] Error actualizando estado de vulnerabilidades: {e}")

def create_live_vulnerability_file(results_dir):
    """Crea archivo de vulnerabilidades en vivo para mostrar en frontend"""
    
    live_file = os.path.join(results_dir, "vulnerabilities_live.json")
    
    # Crear archivo JSON inicial
    initial_data = {
        "scan_started": datetime.now().isoformat(),
        "vulnerabilities": [],
        "last_updated": datetime.now().isoformat()
    }
    
    import json
    with open(live_file, "w", encoding="utf-8") as f:
        json.dump(initial_data, f, indent=2)
        f.flush()
    
    return live_file

def add_vulnerability_to_live_feed(results_dir, module_name, vulnerability):
    """Agrega vulnerabilidad al feed en vivo JSON"""
    
    live_file = os.path.join(results_dir, "vulnerabilities_live.json")
    
    try:
        import json
        
        # Leer archivo existente
        if os.path.exists(live_file):
            with open(live_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {"scan_started": datetime.now().isoformat(), "vulnerabilities": []}
        
        # Agregar nueva vulnerabilidad
        vuln_entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "severity": vulnerability.get("severity", "medium"),
            "url": vulnerability.get("url", ""),
            "description": vulnerability.get("description", ""),
            "details": vulnerability
        }
        
        data["vulnerabilities"].append(vuln_entry)
        data["last_updated"] = datetime.now().isoformat()
        data["total_count"] = len(data["vulnerabilities"])
        
        # Escribir archivo actualizado
        with open(live_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
        
        print(f"[✓] Vulnerabilidad agregada al feed en vivo: {len(data['vulnerabilities'])} total")
        
    except Exception as e:
        print(f"[⚠️] Error actualizando feed en vivo: {e}")