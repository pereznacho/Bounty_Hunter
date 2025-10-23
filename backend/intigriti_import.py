import requests
from backend.models import SessionLocal, Project, Target
from datetime import datetime
from typing import Optional
import sys
import os

# Asegurar que podemos importar backend.* aunque se ejecute como script suelto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INTIGRITI_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/intigriti_data.json"

def import_intigriti_programs(owner_id: Optional[int] = None):
    """
    Import Intigriti programs from arkadiyt/bounty-targets-data JSON format.
    Crea Project con platform='Intigriti' y Target por cada elemento en in_scope.
    """
    response = requests.get(INTIGRITI_URL)
    if response.status_code != 200:
        raise Exception("Failed to fetch Intigriti JSON.")

    data = response.json()
    db = SessionLocal()

    for program in data:
        # Intigriti JSON: cada entry tiene program_name, policy_url, targets:{in_scope:[...]}
        name = program.get("program_name")
        if not name:
            continue

        existing = db.query(Project).filter(Project.name == name, Project.platform == "Intigriti").first()
        if existing:
            continue

        new_project = Project(
            name=name,
            created_at=datetime.utcnow(),
            status="NOT_STARTED",
            source="Intigriti",
            platform="Intigriti",
            owner_id=owner_id
        )
        db.add(new_project)
        db.commit()
        db.refresh(new_project)

        # Intigriti JSON tiene targets.in_scope como lista de dicts
        targets_list = []
        targets_block = program.get("targets")
        if isinstance(targets_block, dict):
            targets_list = targets_block.get("in_scope", [])
        elif isinstance(targets_block, list):
            # fallback si targets es lista
            targets_list = targets_block

        for target in targets_list:
            endpoint = target.get("endpoint") or target.get("target") or target.get("url")
            if not endpoint:
                continue

            new_target = Target(
                project_id=new_project.id,
                type=target.get("type", "unknown"),
                target=endpoint,
                in_scope=target.get("in_scope", True)
            )
            db.add(new_target)

        db.commit()  # commit de los targets

    db.close()

# Permite correrlo como script suelto
if __name__ == "__main__":
    import_intigriti_programs()