# 🕵️‍♂️ Bounty\_Hunter

Bounty\_Hunter is a modular and automated reconnaissance and vulnerability scanning framework for bug bounty hunting and penetration testing.
It integrates multiple tools to streamline domain recon, parameter fuzzing, and vulnerability detection, storing all outputs in organized result folders.

## 📦 Features

* ✅ Fully automated reconnaissance (Subdomains, URLs, parameters)
* 🔎 Integrated vulnerability scanners: XSStrike, SQLMap, Dalfox, FFUF, Wfuzz, Tplmap, Nuclei, etc.
* 📄 Markdown report generation with statistics
* ⚡ Resumable flow using Ctrl+C between stages
* 📁 Modular structure — easy to extend with new scanners or tools

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/Bounty_Hunter.git
cd Bounty_Hunter
chmod +x bounty_hunter.py
```

### 🧰 Requirements

Make sure you have the following tools installed and in your `$PATH`:

* Python 3.8+
* Go (for installing some tools like `nuclei`)
* Tools used:

  * `subfinder`, `assetfinder`, `httpx`, `gau`, `waybackurls`, `katana`
  * `xsstrike`, `sqlmap`, `dalfox`, `ffuf`, `wfuzz`, `tplmap`, `gf`, `qsreplace`, `nuclei`
  * `Seclists` wordlists

Run the tool once — it will check and auto-install required tools if needed:

```bash
./bounty_hunter.py -d example.com
```

---

## 💠 Usage

You can run the tool in two modes:

### Domain Mode:

```bash
./bounty_hunter.py -d example.com
```

This mode will enumerate subdomains, verify which ones are live, gather URLs, parameters, and perform fuzzing and vulnerability scans.

### URL Mode:

```bash
./bounty_hunter.py -u https://target.com/page.php?id=FUZZ
```

This mode skips subdomain discovery and focuses on the provided target URL for parameter fuzzing and vulnerability analysis.

---

## 📝 Reports

After execution, a Markdown report is generated with all findings:

```
results/example.com_YYYYMMDD_HHMMSS/
├── log.txt
├── urls.txt
├── param_urls.txt
├── waf_detected.txt
├── nuclei_results.txt
├── xsstrike_results.txt
├── sqli_results.txt
└── reporte.md ← 🧠 Full summary here
```

---

## 🔌 Adding New Modules

To create a new module:

1. Add a new Python file inside the `modules/` folder, for example: `new_tool.py`
2. Define a function like:

```python
def run_new_tool(param_urls_file):
    # run your tool here
```

3. Then, register it in `bounty_hunter.py`:

```python
from modules.new_tool import run_new_tool

def etapa_new_tool(param_urls_file):
    run_new_tool(param_urls_file)
```

4. Add the stage:

```python
("New Tool", lambda: etapa_new_tool(param_urls_file)),
```

---

## 🧐 Ctrl+C Interruption Support

At any stage, you can press `Ctrl+C` and you'll be prompted:

* `1`: Continue to the next step
* `2`: Exit and save results so far

This allows flexibility during long scans.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized testing** and educational purposes.
**Do not use on systems without explicit permission.**

---

## 👨‍💼 Author

**Ignacio Pérez** – [LinkedIn](https://www.linkedin.com/in/ignacio-perez)
Community: [ThreatX Security](https://www.threatxsecurity.com) 🇦🇷

---

## 📃 License

MIT License. See `LICENSE` file for details.
