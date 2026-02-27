#!/usr/bin/env python3
"""
Utilidad para manejar operaciones de base de datos concurrentes de manera segura
"""

import time
import functools
import os
from sqlalchemy.exc import OperationalError, IntegrityError
from backend.database import SessionLocal

def retry_db_operation(max_retries=3, delay=0.1):
    """Decorador para reintentar operaciones de BD con backoff exponencial"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (OperationalError, IntegrityError) as e:
                    if attempt == max_retries - 1:
                        raise e
                    
                    wait_time = delay * (2 ** attempt)
                    print(f"[⚠️] BD ocupada, reintentando en {wait_time}s (intento {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
            return None
        return wrapper
    return decorator

def safe_db_execute(operation_func, *args, **kwargs):
    """Ejecuta operación de BD de forma segura con manejo de errores"""
    db = SessionLocal()
    try:
        result = operation_func(db, *args, **kwargs)
        db.commit()
        return result
    except Exception as e:
        db.rollback()
        print(f"[⚠️] Error en operación BD: {e}")
        raise e
    finally:
        db.close()

@retry_db_operation(max_retries=3)
def safe_update_scan_state(db, project_id, step_name):
    """Actualiza estado de scan de forma segura"""
    from backend.models import ScanState
    
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan:
        scan.current_step = step_name
        return True
    return False

@retry_db_operation(max_retries=3) 
def safe_update_target_alerts(db, target_id, vulnerability_alert_viewed=None, last_scan_completed=None):
    """Actualiza alertas de target de forma segura"""
    from backend.models import Target
    from datetime import datetime
    
    target = db.query(Target).filter(Target.id == target_id).first()
    if target:
        if vulnerability_alert_viewed is not None:
            target.vulnerability_alert_viewed = vulnerability_alert_viewed
        if last_scan_completed is not None:
            target.last_scan_completed = datetime.now()
        return True
    return False

def delete_target_and_results(target_id):
    """Elimina un target y sus directorios de resultados de forma segura"""
    def _delete_operation(db, target_id):
        from backend.models import Target
        import shutil
        
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            return False
        
        target_name = target.target
        result_dir = target.results_dir
        
        # Eliminar target de la BD
        db.delete(target)
        
        # Eliminar directorios de resultados si existen
        if result_dir and os.path.exists(result_dir):
            try:
                shutil.rmtree(result_dir)
                print(f"[✓] Directorio {result_dir} eliminado")
            except Exception as e:
                print(f"[!] Error eliminando directorio {result_dir}: {e}")
        
        print(f"[✓] Target {target_name} eliminado completamente")
        return True
    
    try:
        return safe_db_execute(_delete_operation, target_id)
    except Exception as e:
        print(f"[!] Error eliminando target {target_id}: {e}")
        return False