import os
import threading
import subprocess
from datetime import datetime
from backend.models import SessionLocal, ScanState


def start_scan_for_project(project):
    def run():
        folder = f"{project.name.lower()}_{project.created_at.strftime('%Y%m%d')}"
        path = os.path.abspath("cli/bounty_hunter.py")

        cmd = ["python3", path]
        if project.mode == "domain":
            cmd += ["-d", project.target]
        else:
            cmd += ["-u", project.target]

        cmd += ["-n", folder]

        subprocess.Popen(cmd)

    threading.Thread(target=run).start()


def calculate_progress(path):
    expected_files = [
        "subdomains.txt", "live_subdomains.txt", "urls.txt",
        "params.txt", "xss.txt", "sqli.txt"
    ]
    return int(sum(os.path.exists(os.path.join(path, f)) for f in expected_files) / len(expected_files) * 100)


def scan_worker(project_id: int, target: str, mode: str, folder_name: str):
    db = SessionLocal()
    scan = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if not scan:
        db.close()
        return

    scan.status = "running"
    scan.current_step = "Ejecutando reconocimiento"
    db.commit()

    output_dir = os.path.join("results", folder_name)
    os.makedirs(output_dir, exist_ok=True)

    try:
        script_path = "./cli/bounty_hunter.py"
        cmd = ["python3", script_path]

        if mode == "domain":
            cmd += ["-d", target]
        else:
            cmd += ["-u", target]

        cmd += ["-o", output_dir]

        proc = subprocess.Popen(cmd)
        scan.pid = proc.pid
        db.commit()

        proc.wait()
        scan.status = "completed"
        scan.current_step = "Completado"
        scan.progress = 100
        db.commit()

    except Exception as e:
        scan.status = "error"
        scan.current_step = f"Error: {str(e)}"
        db.commit()

    db.close()
