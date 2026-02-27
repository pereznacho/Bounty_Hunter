import subprocess
import os
import signal
from backend.models import SessionLocal, ScanState

STAGES = ["Recon", "Nuclei", "WAF", "XSS", "SQLi", "FFUF"]

STAGE_CMDS = {
    "Recon": ["python3", "cli/etapas/recon.py"],
    "Nuclei": ["python3", "cli/etapas/nuclei.py"],
    "WAF": ["python3", "cli/etapas/waf.py"],
    "XSS": ["python3", "cli/etapas/xss.py"],
    "SQLi": ["python3", "cli/etapas/sqli.py"],
    "FFUF": ["python3", "cli/etapas/ffuf.py"]
}

def run_stage(project_id):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if not state:
        return "Estado no encontrado"

    stage = state.current_stage
    if stage not in STAGE_CMDS:
        state.status = "completed"
        db.commit()
        return "Etapa no reconocida o completada"

    cmd = STAGE_CMDS[stage] + [str(project_id)]
    process = subprocess.Popen(cmd)
    state.pid = process.pid
    state.status = "running"
    db.commit()
    return f"Etapa {stage} iniciada con PID {process.pid}"

def next_stage(project_id):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if not state:
        return "No encontrado"

    try:
        os.kill(state.pid, signal.SIGINT)
    except Exception:
        pass

    current_index = STAGES.index(state.current_stage)
    if current_index + 1 < len(STAGES):
        state.current_stage = STAGES[current_index + 1]
        state.status = "idle"
        db.commit()
        return run_stage(project_id)
    else:
        state.status = "completed"
        db.commit()
        return "Escaneo finalizado"

def repeat_stage(project_id):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    try:
        os.kill(state.pid, signal.SIGINT)
    except Exception:
        pass
    state.status = "idle"
    db.commit()
    return run_stage(project_id)

def cancel_scan(project_id):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    try:
        os.kill(state.pid, signal.SIGTERM)
    except Exception:
        pass
    state.status = "cancelled"
    db.commit()
    return "Escaneo cancelado"
