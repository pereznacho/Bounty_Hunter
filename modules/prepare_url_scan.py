# modules/prepare_url_scan.py

import os
from urllib.parse import urlparse, urlunparse, parse_qs

def prepare_url_scan(input_url, result_dir):
    parsed = urlparse(input_url)
    
    # Construir la ruta base (sin query)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))

    urls = [base_url]

    if parsed.query:
        urls.append(input_url)

    urls_path = os.path.join(result_dir, "urls.txt")
    param_urls_path = os.path.join(result_dir, "param_urls.txt")

    with open(urls_path, "w") as f:
        for u in urls:
            f.write(u + "\n")

    if parsed.query:
        with open(param_urls_path, "w") as f:
            f.write(input_url + "\n")

    print(f"[✓] urls.txt generado: {urls_path}")
    if parsed.query:
        print(f"[✓] param_urls.txt generado: {param_urls_path}")
    else:
        print(f"[!] La URL no contenía parámetros. param_urls.txt vacío.")