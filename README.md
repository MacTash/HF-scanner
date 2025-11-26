A comprehensive security scanner for Hugging Face models that detects malicious files, unsafe code, license violations, misleading metadata, and security vulnerabilities — before a model ever touches your machine.

🔥 Why This Tool Matters

Modern open-source AI models can contain:

Hidden executable code

Malicious payloads

Unsafe pickle artifacts

Incorrect or missing licenses

Suspicious metadata

Outdated or vulnerable dependencies

This tool gives developers, researchers, and practitioners a pre-execution security audit using static analysis and heuristics.
No downloads, no execution, no risk.
# ✨ Features
1. 🧪 Model Scanning

2. ✅ Scan any public HuggingFace model

3. ✅ Bulk-scan multiple models concurrently

4. ✅ No downloads needed (API-only scanning)

5. ✅ Detect suspicious files, patterns, metadata, and code

6. 🔐 Security Analysis

7. 🔍 License compliance detection

8. 🚨 Malicious file + executable detection

9. 🧾 Metadata completeness & integrity checks

10. 🧬 Vulnerability scanning (unsafe code, CVEs)

11. 📊 Risk scoring (0–10 scale)

12. 📄 Reporting

13. 📝 Text reports

14. 📑 JSON export

15. 🌐 Beautiful HTML reports

16. 📌 Detailed issues, severity levels, recommendations

# 🚀 Installation
**Requirements**

1. Python 3.8+

2. pip or pipx

3. (Optional) HF API token for private models & higher rate limits

### Clone the repository
git clone https://github.com/mactash/hfscanner

cd hfscanner

### Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

### Install dependencies
pip install -r requirements.txt

### Install package in editable mode (enables hf-scan)
pip install -e .
### Start scanning models
hf-scan scan (model name)
**This installs the CLI tool hf-scan globally inside your venv.**
'''
# 🧭 Usage
## ✅ Run a Scan (CLI)
## Single model scan
hf-scan scan gpt2
## Save HTML report
hf-scan scan gpt2 --format html --output gpt2_report.html
## JSON output
hf-scan scan bert-base-uncased --format json --output report.json

# 📦 Batch Scanning
hf-scan batch gpt2 bert-base-uncased distilbert-base-uncased

# 🔐 Optional: HuggingFace API Token

**You currently do not need a token for public models, but support will be added for:**

1. Private model access

2. Faster API calls

3. Higher rate limits

**For now, scanning works out of the box.**

# 🔍 What Gets Scanned?
## 🗂️ File Analysis

1. Executables (exe, dll, sh, bat)

2. Suspicious binaries

3. Pickle-based PyTorch weights

5. Path traversal attempts

6. Embedded scripts

## 🧾 License Analysis

1. Missing license

2. Non-commercial restrictions

3. Copyleft obligations

4. License mismatches

## 🧱 Metadata Analysis

1. Missing or incomplete model card

2. No license specified

3. Suspicious or misleading tags

4. Low metadata completeness scores

## 🛑 Vulnerability Analysis

1. Unsafe loading patterns

2. Embedded Python code

3. Outdated or vulnerable Python packages

4. Static heuristics for possible exploits

📊 Risk Scoring
Score	Severity	Meaning
0.0 – 2.9	🟢 Low	Likely safe
3.0 – 5.9	🟡 Medium	Review recommended
6.0 – 7.9	🔴 High	Use with caution
8.0 – 10.0	🚨 Critical	Avoid entirely

# 🧪 Examples

a) scan_example.py — Basic demo

b) batch_scan.py — Multi-model scanning

c) custom_rules.py — Extend with your own rules

# 🛡️ Security Patterns

## Detection includes:

1. Executables & scripts

2. Embedded code (eval, exec, import os, etc.)

3. Pickle loaders

4. API keys, secrets

5. Copyleft / NC licenses

6. Known CVEs (database included)

# ⚠️ Limitations

1. Static analysis only (no execution)

2. Cannot detect deeply obfuscated payloads

3. Rate-limited by the HF API

# 🤝 Contributing

1. Pull requests welcome!

2. Fork the repo

3. Create a feature branch

4. Add tests

5. Submit PR

## 📝 License

MIT License — free to use, modify, and distribute.

## 🙏 Acknowledgments

1. HuggingFace Hub API

2. Community security researchers

3. Open-source contributors everywhere

## ⚠️ Disclaimer

This tool provides best-effort security analysis.
Always review and sandbox unknown models before execution.




