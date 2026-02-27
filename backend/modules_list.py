# backend/modules_list.py

MODULES = [
    "Recon",
    "Nuclei Scan",
    "WAF Detection",
    "XSStrike (XSS)",
    "SQLMap (SQLi)",
    "FFUF",
    "WFUZZ",
    "Dalfox",
    "Tplmap",
    "GF + qsreplace"
]

MODULE_SCRIPT_MAP = {
    "Recon": "recon.py",
    "Nuclei Scan": "nuclei_scan.py",
    "WAF Detection": "waf_detect.py",
    "XSStrike (XSS)": "xsstrike_scan.py",
    "SQLMap (SQLi)": "sqlmap_scan.py",
    "FFUF": "ffuf_scan.py",
    "WFUZZ": "wfuzz_scan.py",
    "Dalfox": "dalfox_scan.py",
    "Tplmap": "tplmap_scan.py",
    "GF + qsreplace": "gf_qsreplace_scan.py",
}