#  Malware YARA Rule Generator

An automated system to extract features and generate **custom YARA rules** from malware binaries


— using a modular JSON-RPC server-client model.

---

##  Features

-  Analyze malware samples for strings, PE imports, sections, and hashes
-  Generate YARA rules 
- Supports both single-file and batch analysis
-  Output:
- Raw feature JSON
- YARA rules 
- Auto-detects PE files 

---

## Quickstart

###  1. Install Dependencies

Ensure the following are available:

- Python 3.8+
- Linux/macOS with `strings` in PATH
- Custom `peanalyzer` binary in `/usr/local/bin/`

Optional: Create a virtual environment

```bash
python3 -m venv venv && source venv/bin/activate
