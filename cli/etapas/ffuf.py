import sys
from backend.models import SessionLocal, ScanState, Project
import os
from modules.ffuf import run_ffuf
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
        print("Uso: python3 ffuf.py <project_id>")
        sys.exit(1)

    project_id = int(sys.argv[1])
    db = SessionLocal()
    project = db.query(Project).filter(Project.id == project_id).first()
    db.close()

    result_dir = f"results/{project.target}_{project.created_at.strftime('%Y%m%d_%H%M%S')}"
    param_urls_file = os.path.join(result_dir, "param_urls.txt")

    update_progress(project_id, 10)
    run_ffuf(param_urls_file, result_dir)
    update_progress(project_id, 100, status="completed")

if __name__ == "__main__":
    main()
