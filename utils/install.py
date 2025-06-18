#!/usr/bin/env python3
"""
Instalador/Verificador de dependencias para Bounty_Hunter
Autor: Nacho Pérez
"""

import subprocess
import shutil
import json
import os
from pathlib import Path

# ── Rutas base ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[1]          # …/Bounty_Hunter
CONFIG_PATH  = PROJECT_ROOT / "config" / "tools.json"
STATUS_PATH  = PROJECT_ROOT / "config" / "installed.json"
INSTALL_DIR  = PROJECT_ROOT / "tools"
BIN_DIR      = PROJECT_ROOT / "bin"

INSTALL_DIR.mkdir(exist_ok=True)
BIN_DIR.mkdir(exist_ok=True)

# Asegura que BIN_DIR esté en PATH para sub-procesos y futuras sesiones
if str(BIN_DIR) not in os.environ["PATH"].split(os.pathsep):
    os.environ["PATH"] += os.pathsep + str(BIN_DIR)

# ── Utilidades de estado ──────────────────────────────────────────────────────
def load_status():
    return json.loads(STATUS_PATH.read_text()) if STATUS_PATH.exists() else {}

def save_status(status: dict):
    STATUS_PATH.write_text(json.dumps(status, indent=2))

# ── Instalación de Go (solo si falta) ─────────────────────────────────────────
def ensure_go_installed() -> Path | None:
    go_path = shutil.which("go")
    if go_path:
        return Path(go_path)

    print("[+] Go no encontrado. Instalando Go 1.21.0 (linux-amd64)…")
    url = "https://go.dev/dl/go1.21.0.linux-amd64.tar.gz"
    tar = "/tmp/go.tar.gz"
    try:
        subprocess.run(f"wget -qO {tar} {url}", shell=True, check=True)
        subprocess.run("sudo rm -rf /usr/local/go", shell=True, check=True)
        subprocess.run(f"sudo tar -C /usr/local -xzf {tar}", shell=True, check=True)
        go_path = Path("/usr/local/go/bin/go")
        if not go_path.exists():
            raise RuntimeError("Go no quedó instalado correctamente.")
        os.environ["PATH"] += os.pathsep + "/usr/local/go/bin"
        print("[✓] Go instalado en /usr/local/go")
        return go_path
    except Exception as e:
        print(f"[✘] Falló la instalación de Go: {e}")
        return None

GO_BIN = ensure_go_installed()  # Ruta absoluta (o None si falló)

# ── Helpers de comprobación/instalación ───────────────────────────────────────
def already_installed_binary(name: str) -> bool:
    return any([
        shutil.which(name),
        (BIN_DIR / name).is_file(),
        (INSTALL_DIR / name).exists()
    ])

def safe_run(cmd: str, name: str) -> bool:
    """Ejecución shell con manejo de errores y timeout."""
    cmd = cmd.replace("/opt", str(INSTALL_DIR)).replace("/usr/local/bin", str(BIN_DIR))

    # Evitar git clone duplicado
    if cmd.startswith("git clone"):
        dest = Path(cmd.split()[-1])
        if dest.exists():
            print(f"[~] {name}: repositorio ya clonado, omitiendo.")
            return True

    # pip fix
    if cmd.startswith("pip3 install") and "--break-system-packages" not in cmd:
        cmd += " --break-system-packages"

    # ln -s seguro
    if cmd.startswith("ln -s"):
        parts = cmd.split()
        link = Path(parts[-1])
        target = Path(parts[2])
        # Crea el symlink solo si no existe o es incorrecto
        try:
            if link.is_symlink() or link.exists():
                link.unlink(missing_ok=True)
            link.symlink_to(target.resolve())
            print(f"[✓] Symlink creado: {link} → {target}")
            return True
        except Exception as e:
            print(f"[✘] No se pudo crear symlink para {name}: {e}")
            return False

    try:
        subprocess.run(cmd, shell=True, check=True, timeout=300)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[✘] Error ejecutando '{cmd}': {e}")
        return False

def install_tool(tool: dict, status: dict):
    name = tool["name"]

    if status.get(name):
        print(f"[✔] {name}: ya instalada previamente.")
        return

    if already_installed_binary(name):
        print(f"[✔] {name}: binario encontrado en sistema.")
        status[name] = True
        return

    if "check" in tool and Path(tool["check"]).exists():
        print(f"[✔] {name}: recurso presente ({tool['check']}).")
        status[name] = True
        return

    print(f"[+] {name}: instalando…")
    ok = False

    if "repo" in tool:
        if not GO_BIN:
            print(f"[✘] {name}: Go es requerido y no se instaló.")
        else:
            ok = safe_run(f"{GO_BIN} install {tool['repo']}@latest", name)

    elif "install" in tool:
        ok = True
        for part in tool["install"].split("&&"):
            if not safe_run(part.strip(), name):
                ok = False
                break
    else:
        print(f"[✘] {name}: no tiene 'repo' ni 'install' en tools.json")

    status[name] = ok

# ── Ejecución principal ───────────────────────────────────────────────────────
def main():
    if not CONFIG_PATH.exists():
        print(f"[✘] No se encontró {CONFIG_PATH}")
        return

    status = load_status()
    tools = json.loads(CONFIG_PATH.read_text())

    for tool in tools:
        if tool["name"] == "lfi-autopwn":
            continue  # Eliminada
        install_tool(tool, status)

    save_status(status)
    print("[✓] Verificación/instalación finalizada.")

if __name__ == "__main__":
    main()
