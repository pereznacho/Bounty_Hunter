import os
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import base64

def create_burp_item(url, method="GET", body=""):
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    request_line = f"{method} {path} HTTP/1.1\r\n"
    headers = f"Host: {parsed.netloc}\r\nUser-Agent: BountyHunter\r\n\r\n"
    full_request = (request_line + headers + body).encode("latin1")

    encoded_request = base64.b64encode(full_request).decode("utf-8")

    item = ET.Element("item")
    ET.SubElement(item, "request", base64="true").text = encoded_request
    ET.SubElement(item, "response", base64="true").text = ""
    return item

def export_to_burp(project_name, result_dir):
    root = ET.Element("items")

    for fname in os.listdir(result_dir):
        if not fname.endswith(".txt"):
            continue

        path = os.path.join(result_dir, fname)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("http") and " " not in line:
                    try:
                        item = create_burp_item(line)
                        root.append(item)
                    except Exception as e:
                        print(f"[!] Error procesando línea en {fname}: {line} - {e}")

    xml_tree = ET.ElementTree(root)
    out_path = f"/tmp/burp_export_{uuid.uuid4().hex}.xml"
    xml_tree.write(out_path, encoding="utf-8", xml_declaration=True)
    print(f"[✔] Exportación a Burp generada: {out_path}")
    return out_path