# modules/ffuf_fuzz.py

import os
import subprocess
from urllib.parse import urlparse
from termcolor import cprint

GREEN = "\033[32m"
RED = "\033[31m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"

def run_ffuf(param_urls_file, result_dir, log_file):
    wordlist = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    output_file = os.path.join(result_dir, "ffuf_results.txt")

    if not os.path.exists(wordlist):
        cprint(f"[✘] Wordlist no encontrada: {wordlist}", "red")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return
    
    # Verificar si el archivo param_urls.txt existe y no está vacío
    if not os.path.exists(param_urls_file) or os.path.getsize(param_urls_file) == 0:
        cprint("[!] No se encontraron URLs con parámetros para analizar con FFUF.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return

    urls = [line.strip() for line in open(param_urls_file) if "FUZZ" not in line and line.strip()]
    if not urls:
        cprint("[!] No hay URLs válidas para escanear.", "yellow")
        # Crear archivo vacío para mantener consistencia
        with open(output_file, "w") as out:
            out.write("")
        return

    with open(output_file, "w") as out, open(log_file, "a") as log:
        for i, url in enumerate(urls, start=1):
            base = url + "FUZZ"
            cprint(f"[FFUF {i}] 🔗 {base}", "cyan")
            try:
                result = subprocess.check_output(
                    f'ffuf -u "{base}" -w {wordlist} -mc 200 -t 20 -s',
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                lines = [line for line in result.strip().splitlines() if "/200" in line]
                if lines:
                    out.write(f"🔗 URL: {url}\n")
                    out.write(f"📂 Wordlist: {os.path.basename(wordlist)}\n")
                    out.write(f"📄 Evidencia:\n")
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 1:
                            payload = parts[0]
                            out.write(f"🧩 Payload: {payload}\n")
                        out.write(line + "\n")
                    out.write("--------------------------------------------------\n")

                    log.write(f"[FFUF] {url}\n{result}\n\n")
                    cprint("[✓] Fuzzing exitoso.", "green")
                else:
                    cprint("[-] Sin resultados relevantes.", "yellow")

            except subprocess.CalledProcessError:
                cprint(f"[✘] FFUF error for: {url}", "red")
            except Exception as e:
                cprint(f"[✘] Excepción: {e}", "red")

    cprint(f"{GREEN}[✔] FFUF fuzzing completed. Results in {output_file}{RESET}")
    return output_file

if __name__ == "__main__":
    import sys
    param_urls_file = sys.argv[1]
    result_dir = sys.argv[2]
    log_file = sys.argv[3]
    run_ffuf(param_urls_file, result_dir, log_file)