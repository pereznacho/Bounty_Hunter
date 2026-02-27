import os
import subprocess
from termcolor import cprint

def run_command(cmd, silent=False):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL if silent else None).decode()
    except subprocess.CalledProcessError as e:
        cprint(f"[ERROR] {cmd} => {e}", "red")
        return ""
    except KeyboardInterrupt:
        raise
    except Exception as e:
        cprint(f"[ERROR] {cmd} => {e}", "red")
        return ""

def get_httpx_binary():
    go_httpx = os.path.expanduser("~/go/bin/httpx")
    return go_httpx if os.path.exists(go_httpx) else "httpx"
