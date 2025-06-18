# modules/tplmap.py

import os
import subprocess

def run_tplmap(param_urls_file, result_dir):
    output_file = os.path.join(result_dir, "tplmap_results.txt")
    
    if not os.path.exists(param_urls_file):
        print(f"[!] El archivo {param_urls_file} no existe.")
        return

    with open(param_urls_file) as f, open(output_file, "w") as out:
        for i, url in enumerate(f):
            url = url.strip()
            if not url:
                continue
            print(f"[Tplmap {i+1}] {url}")
            try:
                subprocess.run(
                    ["tplmap", "-u", url, "--silent"],
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=30
                )
            except subprocess.TimeoutExpired:
                out.write(f"[!] Timeout: {url}\n")
            except Exception as e:
                out.write(f"[!] Error en {url}: {e}\n")
