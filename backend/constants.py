"""Shared constants: theme names, vulnerability result files, severity keywords, etc."""
VALID_THEMES = {"default", "cyberpunk", "neon", "matrix", "tron", "purple", "military", "hackthebox", "parrot"}

# App version for /api/version and update checks
APP_VERSION = "1.0.0"

# Vulnerability result filenames (used to detect if project/target has findings)
VULN_RESULT_FILES = [
    "dalfox_results.txt",
    "xss_vulnerables.txt",
    "sql_vulnerables.txt",
    "tplmap_results.txt",
    "ffuf_results.txt",
    "wfuzz_results.txt",
    "arjun_results.txt",
    "sqlmap_results.txt",
    "xsstrike_results.txt",
]

# Phrases that indicate a result file has no real findings
NO_FINDINGS_HINTS = [
    "no vulnerabilities found",
    "no issues found",
    "scan completed with 0 results",
    "no findings",
    "nothing found",
]

# Minimum content length (bytes) to consider a result file as having meaningful content
MIN_VALID_FILE_SIZE = 50

# Keywords per severity level (for vulnerability_level detection)
SEVERITY_KEYWORDS = {
    "critical": ["critical", "high risk", "severe", "rce", "sqli", "sql injection", "remote code execution"],
    "high": ["high", "dangerous", "xss", "csrf", "lfi", "rfi", "cross-site scripting", "template injection"],
    "medium": ["medium", "warning", "potential", "directory traversal", "lfi"],
    "low": ["low", "info", "information disclosure"],
}

# Scan pipeline: ordered list of module display names (project_routes, scan_worker)
MODULES = [
    "Recon",
    "Directory & Files",
    "Arjun",
    "Nuclei Scan",
    "WAF Detection",
    "LFI",
    "XSStrike (XSS)",
    "SQLMap (SQLi)",
    "FFUF",
    "WFUZZ",
    "Dalfox",
    "Tplmap",
    "GF + qsreplace",
]

# Alias display name -> canonical name for module runner lookup (scan_worker)
MODULE_ALIASES = {
    "SQL Injection Testing": "SQLMap (SQLi)",
    "Template Injection Testing": "Tplmap",
    "Directory Discovery": "FFUF",
    "Parameter Discovery": "GF + qsreplace",
    "XSS Testing": "XSStrike (XSS)",
    "Port Scanning": "Nuclei Scan",
    "Web Crawling": "Arjun",
}
