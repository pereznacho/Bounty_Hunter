# utils/path_utils.py

from urllib.parse import urlparse

def get_safe_name_from_target(target):
    # Asegura que siempre tenga un esquema válido
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    parsed = urlparse(target)
    hostname = parsed.hostname or 'invalid_target'

    # Sanitiza cualquier carácter extraño
    safe_name = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in hostname)

    return safe_name
