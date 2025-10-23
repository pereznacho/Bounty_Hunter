# modules/dalfox_scan.py

import os
import re
from termcolor import cprint
from utils.helpers import run_command

GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"

def extract_param(url):
    match = re.search(r"[?&]([^=]+)=", url)
    return match.group(1) if match else "desconocido"

def run_dalfox(param_urls_file, result_dir, log_file):
    output_file = os.path.join(result_dir, "dalfox_results.txt")

    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[!] No se encontraron URLs con parámetros para analizar con Dalfox.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return

    cprint("[*] Running Dalfox... 🔍", "blue")

    with open(param_urls_file) as f, open(output_file, "w") as out, open(log_file, "a") as log:
        urls = [line.strip() for line in f if "=" in line]

        for i, url in enumerate(urls, start=1):
            cprint(f"[Dalfox {i}] {url}", "cyan")
            param = extract_param(url)

            cmd = f"dalfox url \"{url}\" --silence"
            result = run_command(cmd, silent=True)

            if result and "VULN" in result.upper():
                out.write(f"🔗 URL: {url}\n")
                out.write(f"🧩 Parámetro afectado: {param}\n")

                payloads = re.findall(r"(?:payload|injection):\s*([^\s]+)", result, re.IGNORECASE)
                if payloads:
                    out.write(f"💥 Payload: {payloads[0]}\n")

                out.write("📄 Evidencia:\n")
                out.write(result.strip() + "\n")
                out.write("--------------------------------------------------\n")

                log.write(f"[DALFOX] {url}\n{result}\n\n")

                cprint("[✓] Vulnerabilidad registrada.", "green")
            else:
                cprint("[-] No vulnerable.", "yellow")

    cprint(f"{GREEN}[✔] Dalfox scan completed. Results in {output_file}{RESET}")
    return output_file


if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_dalfox(param_urls_file, result_dir, log_file)