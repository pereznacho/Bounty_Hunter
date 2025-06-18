import os
import subprocess

def run_ffuf(param_urls_file, result_dir):
    wordlist = "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    output_file = os.path.join(result_dir, "ffuf_results.txt")

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist no encontrada: {wordlist}")
        return
    if not os.path.exists(param_urls_file):
        print(f"[!] {param_urls_file} no encontrado.")
        return

    with open(param_urls_file) as f, open(output_file, "w") as out:
        for i, url in enumerate(f):
            url = url.strip()
            if not url:
                continue
            print(f"[FFUF {i+1}] {url}")
            try:
                result = subprocess.check_output(
                    f'ffuf -u "{url}FUZZ" -w {wordlist} -mc 200 -t 20 -s',
                    shell=True,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
                if result.strip():
                    out.write(f"[*] Resultados para {url}:\n")
                    out.write(result + "\n")
            except subprocess.CalledProcessError:
                continue
