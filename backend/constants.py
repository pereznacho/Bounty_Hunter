# backend/constants.py

# Archivos de resultados de vulnerabilidades estandarizados
VULN_RESULT_FILES = {
    'xss': 'xss_vulnerables.txt',
    'sql': 'sql_vulnerables.txt', 
    'dalfox': 'dalfox_results.txt',
    'nuclei': 'nuclei_results.txt',
    'sqlmap': 'sqlmap_results.txt',
    'tplmap': 'tplmap_results.txt',
    'ffuf': 'ffuf_results.txt',
    'wfuzz': 'wfuzz_results.txt',
    'arjun': 'arjun_results.txt'
}

# Palabras clave para clasificar severidad por contenido
SEVERITY_KEYWORDS = {
    'critical': [
        'remote code execution', 'rce', 'command injection', 'sql injection',
        'authentication bypass', 'arbitrary file upload', 'privilege escalation',
        'deserialization', 'xxe', 'ldap injection'
    ],
    'high': [
        'stored xss', 'reflected xss', 'dom xss', 'csrf', 'ssrf', 
        'path traversal', 'directory traversal', 'file inclusion',
        'open redirect', 'host header injection'
    ],
    'medium': [
        'information disclosure', 'weak ssl', 'missing security headers',
        'clickjacking', 'cors misconfiguration', 'weak authentication',
        'session fixation', 'insecure direct object reference'
    ],
    'low': [
        'fingerprinting', 'banner disclosure', 'directory listing',
        'configuration disclosure', 'verbose error messages',
        'missing httponly', 'missing secure flag'
    ]
}

# Indicadores de "sin hallazgos" para filtrar falsos positivos
NO_FINDINGS_HINTS = [
    'no vulnerabilities found',
    'no issues detected', 
    'scan completed with no findings',
    'no sql injection found',
    'no xss vulnerabilities detected',
    'target appears to be secure',
    'no exploitable vulnerabilities',
    'clean scan results',
    'all tests passed',
    'no security issues identified',
    'target is not vulnerable',
    'no injectable parameters found',
    'no reflected parameters',
    '0 vulnerabilities found',
    'nothing found',
    'no results',
    'empty response',
    'connection refused',
    'timeout',
    'error connecting'
]

# Tamaño mínimo de archivo para considerar válido (en bytes)
MIN_VALID_FILE_SIZE = 10

# Aliases para nombres legacy -> nombre actual usado por los runners
MODULE_ALIASES = {
    "SQL Injection Testing": "SQLMap (SQLi)",
    "Template Injection Testing": "Tplmap",
    "Directory Discovery": "FFUF",
    "Parameter Discovery": "GF + qsreplace",
    "XSS Testing": "XSStrike (XSS)",
    "Port Scanning": "Nuclei Scan",
    "Web Crawling": "Arjun",
    "Reconnaissance": "Recon",
}
# Módulos de escaneo disponibles
MODULES = [
    "Recon",
    "Nuclei Scan",
    "Arjun",
    "Dalfox",
    "FFUF",
    "GF + qsreplace",
    "LFI",
    "SQLMap (SQLi)",
    "Tplmap",
    "WAF Detection",
    "WFUZZ",
    "XSStrike (XSS)"
]