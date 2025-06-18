# modules/gf_qsreplace.py

import os
import subprocess

def run_gf_qsreplace(param_urls_file, result_dir):
    output_file = os.path.join(result_dir, "gf_qsreplace_results.txt")

    if not os.path.exists(param_urls_file):
        print(f"[!] El archivo {param_urls_file} no existe.")
        return

    with open(param_urls_file) as f:
        urls = f.read().splitlines()

    with open(output_file, "w") as out:
        for i, url in enumerate(urls):
            print(f"[GF + qsreplace {i+1}] {url}")
            try:
                # Sustituye el parámetro por PAYLOAD y analiza con gf
                cmd = f'echo "{url}" | qsreplace "PAYLOAD" | gf ssti'
                result = subprocess.check_output(cmd, shell=True, text=True)
                if result.strip():
                    out.write(f"[+] {url} => {result}")
            except subprocess.CalledProcessError:
                continue
