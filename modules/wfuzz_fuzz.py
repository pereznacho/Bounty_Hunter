# modules/wfuzz_fuzz.py

import os
from termcolor import cprint
from utils.helpers import run_command

def run_wfuzz(param_urls_file, result_dir):
    wordlist = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    output_file = os.path.join(result_dir, "wfuzz_results.txt")

    if not os.path.exists(wordlist):
        cprint(f"[!] Wordlist no encontrada: {wordlist}", "red")
        return

    if not os.path.exists(param_urls_file):
        cprint(f"[!] Archivo no encontrado: {param_urls_file}", "red")
        return

    cprint("[*] Ejecutando WFUZZ...", "blue")

    with open(param_urls_file) as f, open(output_file, "w") as out:
        for i, url in enumerate(f, start=1):
            url = url.strip()
            if "=" in url:
                target = url.replace("=", "=FUZZ")
                cmd = f"wfuzz -z file,{wordlist} --sc 200 -o json '{target}'"
                cprint(f"[WFUZZ {i}] {target}", "cyan")
                result = run_command(cmd, silent=True)
                if result and '"results": [' in result:
                    out.write(f"[+] {target}\n{result}\n\n")
                    cprint("[✓] Posible resultado guardado.", "green")
