# backend/scan_worker.py

import time
import sys
import os
import re
from datetime import datetime

from utils.path_utils import get_safe_name_from_target
from modules.arjun import run_arjun
from modules.dalfox_scan import run_dalfox
from modules.ffuf import run_ffuf
from modules.gf_qsreplace import run_gf_qsreplace
from modules.lfi import run_lfi
from modules.sqli import run_sqli_scan
from modules.tplmap import run_tplmap_scan
from modules.waf import run_waf
from modules.wfuzz_fuzz import run_wfuzz_scan
from modules.xss import run_xss_scan
from modules.nuclei_scan import run_nuclei_scan
from modules.recon import run_recon
from utils import reporter

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.constants import MODULES
from backend.models import SessionLocal, Project, ScanState


def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)


def run_scan(project_id, skip=False, repeat=False, forced_index=None):
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()

    if not project:
        db.close()
        print(f"[✘] Proyecto con ID {project_id} no encontrado.")
        return

    if not scan:
        scan = ScanState(
            project_id=project_id,
            current_step="Inicializando",
            status="running",
            progress=0,
            last_module_index=-1
        )
        db.add(scan)
        db.commit()

    safe_target = get_safe_name_from_target(project.target)
    if not project.results_dir:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        folder_name = f"{safe_target}_{timestamp}"
        project.results_dir = folder_name
        db.query(Project).filter(Project.id == project_id).update({"results_dir": folder_name})
        db.commit()

    db.close()

    result_dir = os.path.join("results", project.results_dir)
    os.makedirs(result_dir, exist_ok=True)

    # REPEAT → volver a correr solo ese módulo
    if repeat and forced_index is not None:
        execute_single_module(project, forced_index, result_dir, project_id)
        return

    # SKIP → avanzar al siguiente módulo
    if skip:
        next_index = scan.last_module_index + 1
        if next_index >= len(MODULES):
            complete_scan(project_id, project, result_dir)
            return
        execute_single_module(project, next_index, result_dir, project_id)
        return

    # ✅ CASO NORMAL: correr TODOS los módulos (incluido Recon)
    start_idx = 0

    for idx in range(start_idx, len(MODULES)):
        execute_single_module(project, idx, result_dir, project_id)

        db = SessionLocal()
        scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
        db.close()

        if scan.status != "running":
            print(f"[!] Scan detenido por estado: {scan.status}")
            break

    complete_scan(project_id, project, result_dir)


def execute_single_module(project, module_index, result_dir, project_id):
    module_name = MODULES[module_index]
    print(f"[REPEAT/SKIP] Ejecutando módulo: {module_name}")

    # Actualizar el módulo en ejecución en la base
    db = SessionLocal()
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan:
        scan.current_step = module_name
        db.commit()
    db.close()

    param_urls_file = os.path.join(result_dir, "param_urls.txt")
    log_file = os.path.join(result_dir, "log.txt")
    live_file = os.path.join(result_dir, "live.txt")

    if module_name == "Recon":
        subs_file = os.path.join(result_dir, "subdomains.txt")
        urls_file = os.path.join(result_dir, "urls.txt")
        run_recon(
            project.mode,
            project.target,
            project.target,
            result_dir,
            subs_file,
            live_file,
            urls_file,
            param_urls_file
        )

    elif module_name == "Nuclei Scan":
        run_nuclei_scan(project.mode, project.target, result_dir, log_file)

    elif module_name == "Arjun":
        run_arjun(param_urls_file, result_dir, log_file)

    elif module_name == "Dalfox":
        run_dalfox(param_urls_file, result_dir, log_file)

    elif module_name == "FFUF":
        run_ffuf(param_urls_file, result_dir, log_file)

    elif module_name == "GF + qsreplace":
        run_gf_qsreplace(param_urls_file, result_dir, log_file)

    elif module_name == "LFI":
        run_lfi(param_urls_file, result_dir, log_file)

    elif module_name == "SQLMap (SQLi)":
        run_sqli_scan(param_urls_file, result_dir, log_file)

    elif module_name == "Tplmap":
        run_tplmap_scan(param_urls_file, result_dir, log_file)

    elif module_name == "WAF Detection":
        run_waf(live_file, result_dir, log_file)

    elif module_name == "WFUZZ":
        run_wfuzz_scan(param_urls_file, result_dir, log_file)

    elif module_name == "XSStrike (XSS)":
        run_xss_scan(param_urls_file, result_dir, log_file)

    else:
        print(f"[REPEAT/SKIP] Módulo {module_name} aún no implementado.")
        time.sleep(2)

    # Al finalizar, guardar progreso
    db = SessionLocal()
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan:
        scan.current_step = f"Finalizado módulo {module_name}"
        scan.status = "running"
        scan.progress = min(scan.progress + 10, 100)
        scan.last_module_index = module_index
        db.commit()
    db.close()


def complete_scan(project_id, project, result_dir):
    db = SessionLocal()
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if scan:
        scan.status = "completed"
        scan.current_step = "Finalizado"
        scan.progress = 100
        db.commit()
    db.close()

    print(f"[✓] Proyecto {project_id} finalizado completamente.")

    # Generar reporte Markdown
    safe_target = get_safe_name_from_target(project.target)
    stats = {}
    md_path = reporter.generate_markdown_report(safe_target, stats, result_dir)
    print(f"[✓] Reporte Markdown generado en: {md_path}")