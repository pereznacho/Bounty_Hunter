# modules/arjun.py

import subprocess

def run_arjun():
    target_file = "urls.txt"
    if not os.path.exists(target_file):
        print("[!] urls.txt no encontrado.")
        return
    with open(target_file) as f:
        for url in f:
            url = url.strip()
            if url:
                subprocess.call(f"arjun -u {url} -oT arjun_output.txt", shell=True)

if __name__ == "__main__":
    import os
    run_arjun()
