# sha256-to-sha1-vt-exporter
vt-hash-analyzer analyzes your SHA256 hash values on VirusTotal, retrieves the corresponding SHA1 hash, VT score (e.g., 48/72), and "Popular Threat Label", and exports the data into an .xlsx table. The main purpose is to convert SHA256 to SHA1, as some security solutions (e.g., SentinelOne) only work with SHA1 for bulk blocking.

## ✨ Features:

🔄 SHA256 → SHA1 conversion

🔍 VirusTotal hash analysis

⚠️ Malicious / Total score output (e.g., 12/70)

🛡️ Popular Threat Label information (e.g., Trojan, Backdoor)

📊 Export to Excel table

## Requirements

🐍 Python 3.x

📑 openpyxl
