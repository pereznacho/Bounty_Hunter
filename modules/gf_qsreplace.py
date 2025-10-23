# modules/gf_qsreplace.py

import os
import subprocess
from termcolor import cprint

GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RESET = "\033[0m"

def run_gf_qsreplace(param_urls_file, result_dir, log_file):
    output_file = os.path.join(result_dir, "gf_qsreplace_results.txt")

    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[!] No se encontraron URLs con parámetros para analizar con GF + qsreplace.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return

    payload = "PAYLOAD"
    technique = "ssti"  # Puedes cambiarlo o hacer que sea parametrizable

    with open(param_urls_file) as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        cprint("[!] No se encontraron URLs para analizar.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return

    with open(output_file, "w") as out, open(log_file, "a") as log:
        for i, url in enumerate(urls, start=1):
            cprint(f"[GF + qsreplace {i}] 🔗 {url}", "cyan")
            try:
                cmd = f'echo "{url}" | qsreplace "{payload}" | gf {technique}'
                result = subprocess.check_output(cmd, shell=True, text=True).strip()

                if result:
                    out.write(f"🔗 URL: {url}\n")
                    out.write(f"🧩 Payload: {payload}\n")
                    out.write(f"🧪 Técnica detectada: {technique}\n")
                    out.write("📄 Evidencia:\n")
                    out.write(result + "\n")
                    out.write("--------------------------------------------------\n")

                    log.write(f"[GF+qsreplace] {url}\n{result}\n\n")
                    cprint("[✓] Coincidencia detectada.", "green")
                else:
                    cprint("[-] Sin detecciones.", "yellow")

            except subprocess.CalledProcessError:
                continue
            except Exception as e:
                cprint(f"[✘] GF error for {url}: {e}", "red")

    cprint(f"{GREEN}[✔] GF analysis completed. Results in {output_file}{RESET}")
    return output_file

if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_gf_qsreplace(param_urls_file, result_dir, log_file)