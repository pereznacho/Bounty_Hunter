# modules/lfi.py

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
        cprint(f"[✘] Archivo requerido no encontrado: {PARAM_FILE}", "red")
        return False
    missing = [k for k, v in FUZZ_CATEGORIES.items() if not os.path.isfile(v)]
    if missing:
        cprint("[✘] Faltan wordlists para: " + ", ".join(missing), "red")
        return False
    return True

def run_lfi(result_dir, log_file):
    if not validate_files():
        return

    with open(PARAM_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        cprint("[!] No hay URLs válidas en param_urls.txt", "red")
        return

    for category, wordlist in FUZZ_CATEGORIES.items():
        result_file = os.path.join(result_dir, f"{category.lower().replace(' ', '_')}_results.txt")

        cprint(f"\n🚀 Fuzzing: {category}", "blue", attrs=["bold", "underline"])
        with open(result_file, "w") as rf, open(log_file, "a") as log:
            for i, url in enumerate(urls, start=1):
                cprint(f"[{category} {i}] 🔗 {url}", "cyan")
                cmd = f'ffuf -u "{url}FUZZ" -w "{wordlist}" -mc 200,500 -t 25 -s'
                try:
                    result = subprocess.check_output(cmd, shell=True, text=True)
                    if result.strip():
                        rf.write(f"🔗 URL: {url}\n")
                        rf.write(f"🧩 Payloads desde: {wordlist}\n")
                        rf.write("📄 Evidencia:\n")
                        rf.write(result + "\n")
                        rf.write("--------------------------------------------------\n")
                        log.write(f"[FFUF][{category}] {url}\n{result}\n\n")
                        cprint("[✓] Resultados encontrados.", "green")
                    else:
                        cprint("[-] Sin hallazgos.", "yellow")
                except KeyboardInterrupt:
                    cprint("\n[!] Interrumpido por el usuario.", "yellow")
                    return
                except subprocess.CalledProcessError:
                    continue


if __name__ == "__main__":
    import sys
    result_dir = sys.argv[1]
    log_file = sys.argv[2]
    run_lfi(result_dir, log_file)