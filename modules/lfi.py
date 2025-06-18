# modules/ffuf_fuzz.py

import os
import subprocess
from termcolor import cprint

SECLISTS_BASE = "/usr/share/seclists"
PARAM_FILE = "param_urls.txt"

FUZZ_CATEGORIES = {
    "LFI": f"{SECLISTS_BASE}/Fuzzing/LFI/LFI-Jhaddix.txt",
    "RFI": f"{SECLISTS_BASE}/Fuzzing/RFI/rfi-payloads.txt",
    "RCE": f"{SECLISTS_BASE}/Fuzzing/RCE/RCE-Os-Commands.txt",
    "XSS": f"{SECLISTS_BASE}/Fuzzing/XSS/XSS-RSNA.txt",
    "SQLi": f"{SECLISTS_BASE}/Fuzzing/SQLi/Generic-SQLi.txt",
    "SSTI": f"{SECLISTS_BASE}/Fuzzing/SSTI/SSTI-payloads.txt",
    "Path Traversal": f"{SECLISTS_BASE}/Fuzzing/LFI/Fuzzing-path-traversal.txt"
}

def validate_files():
    if not os.path.exists(PARAM_FILE):
        cprint(f"[!] Archivo requerido no encontrado: {PARAM_FILE}", "red")
        return False
    missing = [k for k, v in FUZZ_CATEGORIES.items() if not os.path.isfile(v)]
    if missing:
        cprint("[!] Faltan wordlists para: " + ", ".join(missing), "red")
        return False
    return True

def run_ffuf_fuzz():
    if not validate_files():
        return

    with open(PARAM_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        cprint("[!] No hay URLs válidas en param_urls.txt", "red")
        return

    for category, wordlist in FUZZ_CATEGORIES.items():
        cprint(f"\n[+] Step: Fuzzing {category}", "blue", attrs=["bold", "underline"])
        for url in urls:
            cprint(f"  -> URL: {url}", "cyan")
            cmd = f"ffuf -u \"{url}FUZZ\" -w \"{wordlist}\" -mc 200,500 -t 50"
            try:
                subprocess.call(cmd, shell=True)
            except KeyboardInterrupt:
                cprint("\n[!] Interrumpido por el usuario. ¿Continuar con el siguiente payload? (y/n): ", "yellow", end="")
                if input().strip().lower() != "y":
                    return

if __name__ == "__main__":
    run_ffuf_fuzz()
