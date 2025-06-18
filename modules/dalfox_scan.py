# modules/dalfox_scan.py

import os
from termcolor import cprint
from utils.helpers import run_command

def run_dalfox(param_urls_file, result_dir):
    output_file = os.path.join(result_dir, "dalfox_results.txt")

    if not os.path.exists(param_urls_file):
        cprint(f"[!] Archivo no encontrado: {param_urls_file}", "red")
        return

    cprint("[*] Ejecutando Dalfox...", "blue")

    with open(param_urls_file) as f, open(output_file, "w") as out:
        for i, url in enumerate(f, start=1):
            url = url.strip()
            if "=" in url:
                cprint(f"[Dalfox {i}] {url}", "cyan")
                cmd = f"dalfox url '{url}' --silence"
                result = run_command(cmd, silent=True)
                if result:
                    out.write(f"[+] {url}\n{result}\n\n")
                    cprint("[✓] Resultado guardado.", "green")
