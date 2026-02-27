import sys
from backend.models import SessionLocal, ScanState, Project
import os
from modules.waf import run_waf_detection
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

def update_progress(project_id, percent, status="running"):
    db = SessionLocal()
    state = db.query(ScanState).filter(ScanState.project_id == project_id).first()
    if state:
        state.progress = percent
        state.status = status
        db.commit()
    db.close()

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 waf.py <project_id>")
        sys.exit(1)

    project_id = int(sys.argv[1])
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    result_dir = f"results/{project.target}_{project.created_at.strftime('%Y%m%d_%H%M%S')}"
    live_file = os.path.join(result_dir, "live.txt")
    log_file = os.path.join(result_dir, "log.txt")

    update_progress(project_id, 10)
    run_waf_detection(live_file, result_dir, log_file)
    update_progress(project_id, 100, status="completed")

if __name__ == "__main__":
    main()
