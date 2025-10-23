# backend/scan_worker.py

import os
import threading
import time
import subprocess
from datetime import datetime
import logging
import sqlite3
from urllib.parse import urlparse, parse_qs, unquote
import signal
import json
from typing import Tuple

from backend.models import SessionLocal, Project, Target, ScanState
from utils.realtime_results import create_live_vulnerability_file, add_vulnerability_to_live_feed
from collections import defaultdict

# Imports de módulos
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


# --- Fallback seguro para aliases de módulos ---
try:
    from backend.constants import MODULE_ALIASES as ALIASES
except Exception:
    ALIASES = {
        "SQL Injection Testing": "SQLMap (SQLi)",
        "Template Injection Testing": "Tplmap",
        "Directory Discovery": "FFUF",
        "Parameter Discovery": "GF + qsreplace",
        "XSS Testing": "XSStrike (XSS)",
        "Port Scanning": "Nuclei Scan",
        "Web Crawling": "Arjun"
    }


# Skip flags y procesos por (project_id, target)
TARGET_SKIP_FLAGS = defaultdict(lambda: False)
CURRENT_MODULE_POPEN = defaultdict(lambda: None)  # key: (project_id, target) -> Popen

def _key(project_id: int, target: str) -> Tuple[int, str]:
    return (int(project_id), str(target))

def request_skip(project_id: int, target: str = None):
    """
    Marca skip y mata procesos del módulo EN CURSO.
    - Si se provee `target`, aplica SOLO a (project_id, target) y mata el process group
      asociado a ese target (si está en ejecución en modo aislado).
    - Si no se provee `target`, mantiene el comportamiento anterior (por proyecto).
    """
    import os, time, signal

    # 1) Señalizar skip en flags si existen
    try:
        if target is not None and 'TARGET_SKIP_FLAGS' in globals() and callable(globals().get('_key')):
            k = globals()['_key'](project_id, target)
            globals()['TARGET_SKIP_FLAGS'][k] = True
        elif 'PROJECT_SKIP_FLAGS' in globals():
            globals()['PROJECT_SKIP_FLAGS'][project_id] = True
    except Exception:
        pass

    # 2) Intentar matar SOLO el proceso del target si tenemos tracking por-target
    try:
        if target is not None and 'CURRENT_MODULE_POPEN' in globals() and callable(globals().get('_key')):
            k = globals()['_key'](project_id, target)
            proc = globals()['CURRENT_MODULE_POPEN'].get(k)
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    pass
                time.sleep(0.5)
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
                return  # Hecho: no tocar otros procesos
    except Exception:
        # Si algo falla, cae al fallback de proyecto
        pass

    # 3) Fallback (comportamiento previo): matar procesos conocidos por proyecto
    try:
        kill_running_module_processes(project_id)
    except Exception:
        # Como último recurso no hacemos nada
        pass

def kill_running_module_processes(project_id: int):
    """
    Deshabilitado para evitar matar procesos de otros targets.
    El kill fino se hace por process group en request_skip(project_id, target).
    """
    return
def _build_driver_code():
    return r'''
import sys, json
from backend.scan_worker import clean_param_urls
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

data = json.loads(sys.argv[1])
module = data["module"]; scan_mode = data["scan_mode"]; target = data["target"]
result_dir = data["result_dir"]; log_file = data.get("log_file")
live_file = data.get("live_file"); param_urls_file = data.get("param_urls_file")

def driver():
    if module == "Recon":
        subs_file = result_dir + "/subdomains.txt"; urls_file = result_dir + "/urls.txt"
        project_id = data.get("project_id")
        run_recon(scan_mode, target, target, result_dir, subs_file, live_file, urls_file, param_urls_file, project_id=project_id)
        try:
            clean_param_urls(param_urls_file, max_lines=2000)
        except Exception as e:
            print(f"[⚠️] child-clean_param_urls error: {e}")
        return
    if module == "Nuclei Scan": return run_nuclei_scan(scan_mode, target, result_dir, log_file)
    if module == "Arjun": return run_arjun(param_urls_file, result_dir, log_file)
    if module == "Dalfox": return run_dalfox(param_urls_file, result_dir, log_file)
    if module == "FFUF": return run_ffuf(param_urls_file, result_dir, log_file)
    if module == "GF + qsreplace": return run_gf_qsreplace(param_urls_file, result_dir, log_file)
    if module == "LFI": return run_lfi(param_urls_file, result_dir)
    if module == "SQLMap (SQLi)": return run_sqli_scan(param_urls_file, result_dir, log_file)
    if module == "Tplmap": return run_tplmap_scan(param_urls_file, result_dir, log_file)
    if module == "WAF Detection": return run_waf(live_file, result_dir, log_file)
    if module == "WFUZZ": return run_wfuzz_scan(param_urls_file, result_dir, log_file)
    if module == "XSStrike (XSS)": return run_xss_scan(param_urls_file, result_dir, log_file)
    print(f"[child] módulo desconocido: {module}")

if __name__ == "__main__":
    driver()
'''

def run_module_isolated(project_id, target, module_name, scan_mode, target_url, result_dir, log_file, live_file, param_urls_file, project_platform):
    payload = {
        "module": module_name,
        "scan_mode": scan_mode,
        "target": target_url,
        "result_dir": result_dir,
        "log_file": log_file,
        "live_file": live_file,
        "param_urls_file": param_urls_file,
        "project_platform": project_platform,
        "project_id": project_id,
    }
    code = _build_driver_code()
    cmd = ["python3", "-c", code, json.dumps(payload)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    k = _key(project_id, target)
    CURRENT_MODULE_POPEN[k] = proc

    try:
        while True:
            if proc.poll() is not None:
                break
            if TARGET_SKIP_FLAGS.get(k, False):
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    pass
                time.sleep(0.5)
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
                break
            # drenado básico
            try:
                out = proc.stdout.readline()
                if out:
                    print(out.rstrip())
                err = proc.stderr.readline()
                if err:
                    print(err.rstrip())
            except Exception:
                pass
            time.sleep(0.1)
    finally:
        try:
            rem_out, rem_err = proc.communicate(timeout=0.2)
            if rem_out:
                print(rem_out.rstrip())
            if rem_err:
                print(rem_err.rstrip())
        except Exception:
            pass
        CURRENT_MODULE_POPEN[k] = None

def create_targets_from_recon(project_id, live_file):
    """Crea targets adicionales desde archivo de recon"""
    
    try:
        if not os.path.exists(live_file):
            print(f"[⚠️] Archivo live no encontrado: {live_file}")
            return 0
        
        # Verificar si el archivo tiene contenido
        file_size = os.path.getsize(live_file)
        if file_size == 0:
            print(f"[⚠️] Archivo live está vacío: {live_file}")
            return 0
            
        print(f"[📋] Procesando archivo live: {live_file} ({file_size} bytes)")
        
        db = SessionLocal()
        created_count = 0
        processed_count = 0
        skipped_count = 0
        
        with open(live_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                print(f"[⚠️] Archivo live sin contenido válido: {live_file}")
                db.close()
                return 0
                
            lines = content.split('\n')
            print(f"[📊] Encontradas {len(lines)} líneas en archivo live")
            
            for line in lines:
                subdomain = line.strip()
                processed_count += 1
                
                if not subdomain or subdomain in ["", "localhost"]:
                    skipped_count += 1
                    continue
                    
                print(f"[🔍] Procesando URL: {subdomain}")
                
                # Verificar si ya existe
                existing = db.query(Target).filter(
                    Target.project_id == project_id,
                    Target.target == subdomain
                ).first()
                
                if existing:
                    print(f"[⏭️] Target ya existe: {subdomain}")
                    skipped_count += 1
                    continue
                
                # Crear nuevo target
                target_type = "url" if subdomain.startswith(("http://", "https://")) else "domain"
                new_target = Target(
                    project_id=project_id,
                    target=subdomain,
                    type=target_type,
                    status="pending"
                )
                db.add(new_target)
                created_count += 1
                print(f"[✅] Nuevo target creado: {subdomain} (type: {target_type})")
        
        if created_count > 0:
            db.commit()
            print(f"[💾] Guardados {created_count} nuevos targets en BD")
        else:
            print(f"[ℹ️] No hay targets nuevos para guardar")
            
        db.close()
        
        print(f"[📊] RESUMEN - Procesadas: {processed_count}, Creadas: {created_count}, Saltadas: {skipped_count}")
        print(f"[✅] Creados {created_count} nuevos targets desde recon")
        return created_count
        
    except Exception as e:
        print(f"[❌] Error creando targets desde recon: {e}")
        import traceback
        traceback.print_exc()
        if 'db' in locals():
            db.close()
        return 0

def launch_scans_for_new_targets(project_id):
    """Launches scans for newly created targets in AUTO-EXPANDED mode"""
    
    try:
        db = SessionLocal()
        project = db.query(Project).filter(Project.id == project_id).first()
        
        if not project:
            print(f"[❌] Project {project_id} not found")
            db.close()
            return
        
        # Get all pending URL targets (the new ones created from live_subdomains.txt)
        pending_targets = db.query(Target).filter(
            Target.project_id == project_id,
            Target.status == "pending",
            Target.type == "url"  # Only launch scans for URL targets, not the original domain
        ).all()
        
        project_mode = project.mode
        project_platform = getattr(project, 'platform', None)
        
        db.close()
        
        if pending_targets:
            print(f"[🚀] AUTO-EXPANDED MODE: Launching individual URL scans for {len(pending_targets)} URL targets")
            
            for target_obj in pending_targets:
                target_url = target_obj.target
                print(f"[🎯] AUTO-LAUNCH: Starting individual scan for URL: {target_url}")
                
                # Launch scan in separate thread for each URL target
                threading.Thread(
                    target=run_scan_target,
                    args=(project_id, target_url),
                    kwargs={
                        'project_mode': project_mode,
                        'project_platform': project_platform
                    },
                    daemon=True
                ).start()
                
                time.sleep(3)  # Pause between launches to avoid resource conflicts
            
            print(f"[✅] AUTO-EXPANDED: {len(pending_targets)} individual URL scans launched successfully")
        else:
            print(f"[ℹ️] No pending URL targets found for auto-expansion")
        
    except Exception as e:
        print(f"[❌] Error launching scans for new targets: {e}")
        import traceback
        traceback.print_exc()

def execute_single_module(project_id, project_platform, module_index, result_dir, target):
    """Ejecuta un módulo específico usando mapping robusto.
    Esta versión maneja correctamente la ausencia del identificador ALIASES
    en el scope (problema observado en contenedores/threading) y hace
    un fallback seguro.
    """
    # Asegurarnos de tener MODULES disponible localmente
    try:
        from backend.constants import MODULES
    except Exception as e:
        print(f"[❌] No se pudo importar MODULES desde backend.constants: {e}")
        MODULES = []

    # Garantizar que ALIASES exista: usar variable de módulo si está, luego intentar importar
    try:
        _ = ALIASES  # type: ignore
    except NameError:
        try:
            from backend.constants import MODULE_ALIASES as ALIASES  # type: ignore
            print("[ℹ️] ALIASES cargado desde backend.constants.MODULE_ALIASES")
        except Exception:
            # Fallback local (idéntico al antiguo fallback en el módulo)
            ALIASES = {
                "SQL Injection Testing": "SQLMap (SQLi)",
                "Template Injection Testing": "Tplmap",
                "Directory Discovery": "FFUF",
                "Parameter Discovery": "GF + qsreplace",
                "XSS Testing": "XSStrike (XSS)",
                "Port Scanning": "Nuclei Scan",
                "Web Crawling": "Arjun"
            }
            print("[⚠️] ALIASES no disponible en el scope; usando fallback interno")

    if module_index >= len(MODULES):
        print(f"[!] Índice de módulo inválido: {module_index}")
        return

    original_module_name = MODULES[module_index]
    module_name = ALIASES.get(original_module_name, original_module_name) if isinstance(ALIASES, dict) else original_module_name

    print(f"[*] Ejecutando módulo {module_index + 1}/{len(MODULES)}: {original_module_name} sobre {target}")

    # Determinar modo de escaneo en base al target
    if isinstance(target, str) and target.startswith(("http://", "https://")):
        scan_mode = "url"
        print("[🎯] Target tipo URL - ejecutando en modo URL (scan web directo)")
    else:
        scan_mode = "domain"
        print("[🎯] Target tipo DOMAIN - ejecutando en modo domain")

    # Verificar estado del target antes de continuar (sin devolver ORM)
    try:
        db = SessionLocal()
        status_decision = check_target_status(db, project_id=project_id, target=target)
        db.close()
    except Exception as e:
        print(f"[⚠️] Error checking target status: {e}")
        status_decision = "continue"
    if status_decision == "skip":
        print(f"[⚠️] Target {target} completado previamente, saltando...")
        return

    # Archivos estándar en el directorio de resultados de esta ejecución
    log_file = os.path.join(result_dir, "scan.log")
    live_file = os.path.join(result_dir, "live_subdomains.txt")
    param_urls_file = os.path.join(result_dir, "urls_with_params.txt")

    # Mapping de módulos a funciones ejecutables
    module_runners = {
        "Recon": lambda: execute_recon_module(scan_mode, target, result_dir, live_file, param_urls_file, project_id, project_platform),
        "Nuclei Scan": lambda: run_nuclei_scan(scan_mode, target, result_dir, log_file),
        "Arjun": lambda: run_arjun(param_urls_file, result_dir, log_file),
        "Dalfox": lambda: run_dalfox(param_urls_file, result_dir, log_file),
        "FFUF": lambda: run_ffuf(param_urls_file, result_dir, log_file),
        "GF + qsreplace": lambda: run_gf_qsreplace(param_urls_file, result_dir, log_file),
        "LFI": lambda: run_lfi(param_urls_file, result_dir),
        "SQLMap (SQLi)": lambda: run_sqli_scan(param_urls_file, result_dir, log_file),
        "Tplmap": lambda: run_tplmap_scan(param_urls_file, result_dir, log_file),
        "WAF Detection": lambda: run_waf(live_file, result_dir, log_file),
        "WFUZZ": lambda: run_wfuzz_scan(param_urls_file, result_dir, log_file),
        "XSStrike (XSS)": lambda: run_xss_scan(param_urls_file, result_dir, log_file),
    }

    # Si se ha marcado skip, no ejecutar el módulo
    if TARGET_SKIP_FLAGS.get(_key(project_id, target)):
        print(f"[⏭️] Skip activo; no se ejecuta {module_name} para {target}")
        return

    try:
        if module_name in module_runners:
            print(f"[🚀] Ejecutando {module_name} (aislado)...")
            run_module_isolated(
                project_id=project_id,
                target=target,
                module_name=module_name,
                scan_mode=scan_mode,
                target_url=target,
                result_dir=result_dir,
                log_file=log_file,
                live_file=live_file,
                param_urls_file=param_urls_file,
                project_platform=project_platform,
            )
            if TARGET_SKIP_FLAGS.get(_key(project_id, target)):
                print(f"[⏹️] {module_name} interrumpido por Skip Step para {target}")
                return
            print(f"[✅] {module_name} ejecutado correctamente")
        else:
            available_modules = sorted(module_runners.keys())
            print(f"[⚠️] Módulo '{module_name}' no encontrado en mapping. Disponibles: {', '.join(available_modules)}")
    except Exception as e:
        print(f"[❌] Error ejecutando módulo {module_name}: {e}")

    print(f"[✓] Módulo {original_module_name} completado")

    # Actualizar progreso en BD usando project_id ya obtenido al inicio
    if project_id:
        try:
            db = SessionLocal()
            scan_state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
            if scan_state:
                scan_state.progress = int(((module_index + 1) / len(MODULES)) * 100)
                scan_state.last_module_index = module_index
                db.commit()
                print(f"[📊] Progreso actualizado: {scan_state.progress}% - Módulo {module_index + 1}/{len(MODULES)}")
            db.close()
        except Exception as e:
            print(f"[⚠️] Error actualizando progreso: {e}")
    else:
        print(f"[⚠️] No se pudo obtener project_id para actualizar progreso")


def clean_param_urls(param_urls_file, max_lines=2000):
    """Lee, normaliza y depura urls con parámetros.
    - Extrae el parámetro `r` de wrappers tipo `redir.php?r=` y lo usa como URL real.
    - Decodifica percent-encoding, elimina fragmentos y entradas claramente payload/SQL.
    - Elimina duplicados preservando orden y limita el tamaño final.
    """
    try:
        if not os.path.exists(param_urls_file):
            return 0

        seen = set()
        cleaned = []

        with open(param_urls_file, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue

                # If wrapper like redir.php?r=..., try to extract the r param
                try:
                    p = urlparse(line)
                    extracted = None
                    if p.path and "redir" in os.path.basename(p.path).lower():
                        qs = parse_qs(p.query)
                        if "r" in qs and qs["r"]:
                            extracted = unquote(qs["r"][0])
                    if extracted:
                        url_line = extracted.strip()
                    else:
                        url_line = unquote(line)
                except Exception:
                    url_line = line

                # Remove fragments and surrounding whitespace
                url_line = url_line.split('#')[0].strip()

                # Basic filter: must start with http/https
                if not url_line.lower().startswith(("http://", "https://")):
                    continue

                low = url_line.lower()
                # Filter out obvious injection payloads that bloat the list
                blacklist_tokens = ["union", "select", "sleep(", "--", "/*", "char(", "=1)", "information_schema", "concat("]
                if any(tok in low for tok in blacklist_tokens):
                    continue

                # Keep only unique
                if url_line in seen:
                    continue
                seen.add(url_line)
                cleaned.append(url_line)

                if len(cleaned) >= max_lines:
                    print(f"[⚠️] clean_param_urls: truncated to {max_lines} entries")
                    break

        # Overwrite the file with cleaned content
        with open(param_urls_file, "w", encoding="utf-8") as out:
            out.write("\n".join(cleaned))

        print(f"[ℹ️] clean_param_urls: reduced {param_urls_file} -> {len(cleaned)} entries")
        return len(cleaned)

    except Exception as e:
        print(f"[⚠️] clean_param_urls error: {e}")
        return 0


def execute_recon_module(scan_mode, target, result_dir, live_file, param_urls_file, project_id, project_platform):
    """Ejecuta módulo de reconocimiento con lógica especial de auto-expansión."""
    subs_file = os.path.join(result_dir, "subdomains.txt")
    urls_file = os.path.join(result_dir, "urls.txt")

    # Ejecutar recon - PASS project_id so it creates URL targets like bounty programs
    run_recon(scan_mode, target, target, result_dir, subs_file, live_file, urls_file, param_urls_file, project_id=project_id)

    # Limpiar y depurar el archivo de URLs con parámetros para evitar basura/payloads
    try:
        cleaned = clean_param_urls(param_urls_file, max_lines=2000)
        if cleaned == 0:
            print(f"[ℹ️] execute_recon_module: no se generaron urls con parámetros limpias en {param_urls_file}")
    except Exception as e:
        print(f"[⚠️] execute_recon_module: error limpiando urls: {e}")

    # Auto-expansion logic for domain scanning - ALWAYS for domains
    if scan_mode == "domain":
        platform = project_platform
        print(f"[🔍] AUTO-EXPANSION CHECK - scan_mode: {scan_mode}, platform: {platform}")
        
        # Create additional targets from live_file for ALL domain projects
        print(f"[🎯] DOMAIN PROJECT DETECTED - Creating additional URL targets from {live_file}")
        created_count = create_targets_from_recon(project_id, live_file)
        if created_count > 0:
            print(f"[🚀] AUTO-EXPANDED MODE: Launching individual URL scans for {created_count} new targets")
            # Launch scans immediately for auto-expansion
            try:
                launch_scans_for_new_targets(project_id)
                print(f"[✅] Successfully launched auto-scans for {created_count} URL targets")
            except Exception as e:
                print(f"[❌] Error launching auto-scans: {e}")
        else:
            print(f"[⚠️] No new URL targets created from live_file: {live_file}")
            # Check if file exists and has content
            if os.path.exists(live_file):
                file_size = os.path.getsize(live_file)
                print(f"[📊] live_file size: {file_size} bytes")
                if file_size > 0:
                    with open(live_file, 'r') as f:
                        lines = f.read().strip().split('\n')
                        print(f"[📋] live_file content ({len(lines)} lines): {lines[:5]}...")
            else:
                print(f"[❌] live_file does not exist: {live_file}")

def run_scan_target(project_id, target, project_mode=None, project_platform=None, skip=False, repeat=False, forced_index=None):
    """Ejecuta scan completo en un target
    - Usa project_id (int) y target (str) para evitar objetos ORM desvinculados.
    - Abre su propio directorio de resultados por target+timestamp.
    """
    print(f"[*] Iniciando scan completo: 12 módulos para {target}")

    # Directorio de resultados único por ejecución del target
    safe_name = target.replace("http://", "").replace("https://", "").replace("/", "_").rstrip("_")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    result_dir = f"results/{safe_name}_{timestamp}"
    os.makedirs(result_dir, exist_ok=True)

    # Ejecutar todos los módulos
    from backend.constants import MODULES

    for idx, module_name in enumerate(MODULES):
        try:
            execute_single_module(project_id, project_platform, idx, result_dir, target)
            time.sleep(1)  # Pausa breve entre módulos
        except Exception as e:
            print(f"[❌] Error en módulo {module_name}: {e}")
            continue

    print(f"[✓] Scan completo para target: {target}")

    # Generar reporte final
    try:
        generate_final_report(target, result_dir)
    except Exception as e:
        print(f"[⚠️] Error generando reporte: {e}")

def generate_final_report(target, result_dir):
    """Genera reporte final simple"""
    
    report_content = f"""# Security Scan Report

**Target:** {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Results Directory:** {result_dir}

## Scan Results

"""
    
    # Listar archivos generados
    if os.path.exists(result_dir):
        files = os.listdir(result_dir)
        if files:
            report_content += "### Files Generated:\n\n"
            for file in sorted(files):
                file_path = os.path.join(result_dir, file)
                if os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    report_content += f"- **{file}** ({size} bytes)\n"
        else:
            report_content += "No result files generated.\n"
    
    report_content += "\n## End of Report\n"
    
    # Escribir reporte
    report_path = os.path.join(result_dir, "reporte.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    print(f"[✔] Reporte generado en: {report_path}")

def run_scan(project_id, target=None, mode=None, repeat=False, forced_index=None):
    """Función principal de escaneo"""
    
    print(f"[*] Iniciando scan para proyecto ID: {project_id}")
    
    # Obtener proyecto
    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            print(f"[❌] Proyecto {project_id} no encontrado")
            return
        
        print(f"[*] Proyecto encontrado: {project.name} (modo: {project.mode})")
        
        # Obtener targets
        targets = db.query(Target).filter(Target.project_id == project_id).all()
        
        if not targets:
            print(f"[⚠️] No hay targets para el proyecto {project_id}")
            return
        
        print(f"[*] Encontrados {len(targets)} targets para escanear")
        
        # Escanear cada target
        project_id = project.id
        project_mode = project.mode
        project_platform = getattr(project, 'platform', None)

        for target_obj in targets:
            target = target_obj.target
            print(f"[*] Escaneando target: {target}")
            try:
                run_scan_target(project_id, target, project_mode=project_mode, project_platform=project_platform)
            except Exception as e:
                print(f"[❌] Error escaneando {target}: {e}")
                continue
        
        print(f"[✅] Scan completo para proyecto {project.name}")
        
    except Exception as e:
        print(f"[❌] Error en run_scan: {e}")
    finally:
        db.close()

def continue_scan_from_module(project_id, module_index):
    """Continúa el escaneo desde un módulo específico (usado por Skip Step)"""
    
    print(f"[⏭️] CONTINUACIÓN DE SKIP STEP - Iniciando desde módulo índice {module_index}")
    
    try:
        # Obtener proyecto
        db = SessionLocal()
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            print(f"[❌] Proyecto {project_id} no encontrado")
            return

        # Obtener targets
        targets = db.query(Target).filter(Target.project_id == project_id).all()
        db.close()

        if not targets:
            print(f"[⚠️] No hay targets para continuar escaneo")
            return

        project_id = project.id
        project_platform = getattr(project, 'platform', None)

        from backend.constants import MODULES

        # Validar que el índice sea válido
        if module_index >= len(MODULES):
            print(f"[✅] Skip Step - Ya estamos en el último módulo, marcando como completado")
            db = SessionLocal()
            scan = db.query(ScanState).filter(ScanState.project_id == project_id).order_by(ScanState.id.desc()).first()
            if scan:
                scan.status = "completed"
                scan.current_step = "Completed"
                scan.progress = 100
                db.commit()
            db.close()
            return

        print(f"[📊] Módulos restantes desde {module_index}: {len(MODULES) - module_index}")
        print(f"[🎯] IMPORTANTE: NO es un scan completo, es continuación desde módulo {module_index + 1}")
        # Pequeña espera para liberar recursos de procesos asesinados
        time.sleep(1.0)

        # Ejecutar SOLO los módulos restantes desde el índice especificado
        for idx in range(module_index, len(MODULES)):
            module_name = MODULES[idx]
            print(f"[🔄] SKIP CONTINUATION - Ejecutando módulo {idx + 1}/{len(MODULES)}: {module_name}")

            for target_obj in targets:
                target = target_obj.target
                # limpiar bandera de skip para este target antes de continuar
                TARGET_SKIP_FLAGS[_key(project_id, target_obj.target)] = False

                # Crear directorio de resultados
                if hasattr(project, 'results_dir') and project.results_dir:
                    result_dir = os.path.join("results", str(project.results_dir))
                else:
                    safe_name = str(target).replace("http://", "").replace("https://", "").replace("/", "_")
                    result_dir = f"results/{safe_name}_{project_id}"

                try:
                    execute_single_module(project_id, project_platform, idx, result_dir, target)
                    time.sleep(1)  # Pausa breve entre módulos
                except Exception as e:
                    print(f"[❌] Error en módulo {module_name}: {e}")
                    continue

        # Marcar como completado
        db = SessionLocal()
        scan = db.query(ScanState).filter(ScanState.project_id == project_id).order_by(ScanState.id.desc()).first()
        if scan:
            scan.status = "completed"
            scan.current_step = "Completed"
            scan.progress = 100
            db.commit()
        db.close()

        print(f"[✅] Escaneo continuado completado para proyecto {project_id}")

    except Exception as e:
        print(f"[❌] Error continuando escaneo: {e}")

def delete_target_and_results(target_id, target_url):
    """Elimina target y sus archivos de resultados"""
    
    print(f"[🗑️] Eliminando target {target_id}: {target_url}")
    
    try:
        # Obtener target de BD
        db = SessionLocal()
        target = db.query(Target).filter(Target.id == target_id).first()
        
        if not target:
            print(f"[⚠️] Target {target_id} no encontrado en BD")
            return False
        
        # Limpiar archivos de resultados
        if hasattr(target, 'results_dir') and target.results_dir:
            results_path = os.path.join("results", str(target.results_dir))
            if os.path.exists(results_path):
                import shutil
                shutil.rmtree(results_path)
                print(f"[✔] Eliminado: {results_path}")
        
        # Eliminar de BD
        db.delete(target)
        db.commit()
        db.close()
        
        print(f"[✅] Target {target_id} eliminado exitosamente")
        return True
        
    except Exception as e:
        print(f"[❌] Error eliminando target {target_id}: {e}")
        return False

# Funciones auxiliares para compatibilidad
def check_target_status(db, project_id, target):
    """Verifica estado del target sin devolver ORM."""
    t = db.query(Target).filter(Target.project_id == project_id, Target.target == target).first()
    if not t:
        return "skip"  # si ya no existe, saltar
    if getattr(t, 'status', None) in ("completed", "cancelled"):
        return "skip"
    return "continue"

def clean_param_urls(param_urls_file, max_lines=2000):
    """
    Lee, normaliza y depura urls con parámetros.
    Nueva versión: extrae parámetros únicos y guarda una URL ejemplo por parámetro.
    - Filtra payloads obvios.
    - Normaliza percent-encoding y elimina fragmentos.
    - Produce un archivo con líneas en formato: <param_name> -> <example_url>
    Esto evita listar múltiples URLs con el mismo parámetro y distintos payloads.
    """
    try:
        if not os.path.exists(param_urls_file):
            return 0

        seen_params = {}
        cleaned_params_order = []

        with open(param_urls_file, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue

                # Decodificar y eliminar fragmentos
                try:
                    p = urlparse(line)
                    base = f"{p.scheme}://{p.netloc}{p.path}"
                    qs = parse_qs(p.query, keep_blank_values=True)
                except Exception:
                    continue

                if not qs:
                    continue

                # Blacklist de valores/payloads que no queremos usar como ejemplo
                blacklist_tokens = ["union", "select", "sleep(", "--", "/*", "char(", "=1)", "information_schema", "concat("]

                # Para cada parámetro, si no lo hemos visto, guardamos la URL ejemplo
                for param, values in qs.items():
                    if param in seen_params:
                        continue

                    # Elegir el primer valor que no sea claramente un payload
                    chosen_value = None
                    for v in values:
                        low = (v or "").lower()
                        if any(tok in low for tok in blacklist_tokens):
                            continue
                        chosen_value = v
                        break

                    # Si todos los valores son payloads, usar el primero igualmente
                    if chosen_value is None:
                        chosen_value = values[0]

                    # Reconstruir una URL ejemplo con el parámetro y el valor elegido
                    try:
                        example_qs = f"{param}={chosen_value}"
                        example_url = f"{base}?{example_qs}"
                    except Exception:
                        example_url = line

                    seen_params[param] = example_url
                    cleaned_params_order.append(param)

                    if len(cleaned_params_order) >= max_lines:
                        print(f"[⚠️] clean_param_urls (unique params): truncated to {max_lines} params")
                        break

                if len(cleaned_params_order) >= max_lines:
                    break

        # Escribir solo las URLs ejemplo, una por línea (sin "param ->")
        with open(param_urls_file, "w", encoding="utf-8") as out:
            for param in cleaned_params_order:
                out.write(f"{seen_params[param]}\n")

        print(f"[ℹ️] clean_param_urls: reduced {param_urls_file} -> {len(cleaned_params_order)} unique params")
        return len(cleaned_params_order)

    except Exception as e:
        print(f"[⚠️] clean_param_urls error: {e}")
        return 0