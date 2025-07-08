# modules/nuclei_scan.py

import os
import subprocess
from termcolor import cprint

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def run_nuclei_scan(mode, domain, result_dir, log_file):
    cprint("[*] Ejecutando Nuclei sobre HTTP y HTTPS...", "blue")
    output_file = os.path.join(result_dir, "nuclei_results.txt")

    # Definir correctamente los targets
    if mode == "domain":
        targets = [f"http://{domain}", f"https://{domain}"]
    else:
        # Modo URL: no tocar el protocolo
        targets = [domain]

    with open(output_file, "w") as out, open(log_file, "a") as log:
        for url in targets:
            cprint(f"[-] Analizando: {url}", "yellow")
            try:
                process = subprocess.Popen(
                    ["nuclei", "-u", url, "-silent"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                has_output = False
                out.write(f"# Resultados para {url}:\n")
                for line in process.stdout:
                    print(line, end="")
                    out.write(line)
                    log.write(line)
                    has_output = True
                process.wait()
                if has_output:
                    cprint(f"[✔] Vulnerabilidades encontradas en {url}", "red")
                    out.write("\n")
                else:
                    cprint(f"[✓] Sin hallazgos para {url}", "green")
            except PermissionError:
                cprint(f"[✘] Permission denied al intentar ejecutar nuclei. Verifica permisos o PATH.", "red")
                return
            except Exception as e:
                cprint(f"[✘] Error al ejecutar Nuclei en {url}: {e}", "red")

    if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
        os.remove(output_file)
        cprint("[✓] Nuclei no encontró vulnerabilidades.", "green")
    else:
        cprint(f"[✔] Resultados guardados en {output_file}", "green")