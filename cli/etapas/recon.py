import sys
import os
import subprocess
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from backend.models import SessionLocal, ScanState

def update_progress(project_id, percent, status="running", stage="Recon"):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if state:
        state.progress = percent
        state.status = status
        state.current_stage = stage
        db.commit()
    db.close()

def run_command(command, output_file):
    with open(output_file, "w") as f:
        process = subprocess.run(command, stdout=f, stderr=subprocess.DEVNULL)
    return process.returncode == 0

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 recon.py <project_id>")
        sys.exit(1)

    project_id = int(sys.argv[1])
    update_progress(project_id, 0, status="running")

    db = SessionLocal()
    project = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    db.close()

    output_dir = f"output/project_{project_id}"
    os.makedirs(output_dir, exist_ok=True)

    target_file = os.path.join(output_dir, "target.txt")
    live_file = os.path.join(output_dir, "live.txt")

    # 1. Subfinder
    update_progress(project_id, 10)
    subfinder_cmd = ["subfinder", "-d", project.target, "-silent"]
    run_command(subfinder_cmd, target_file)

    # 2. httpx
    update_progress(project_id, 50)
    httpx_cmd = ["httpx", "-l", target_file, "-silent"]
    run_command(httpx_cmd, live_file)

    # 3. Gau
    update_progress(project_id, 80)
    gau_cmd = ["gau", project.target]
    gau_out = os.path.join(output_dir, "gau.txt")
    run_command(gau_cmd, gau_out)

    # Finaliza
    update_progress(project_id, 100, status="completed")

if __name__ == "__main__":
    main()
