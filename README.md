# Malware Detection Enhancement with YARA + ClamAV

## Project Overview

This project demonstrates how to enhance ClamAV's malware detection capabilities by automatically generating YARA rules from malware samples using a custom Model context Protocol (MCP) server.

We scan a malware sample dataset before and after YARA rule injection, showing significant detection improvements.

---

## Table of Contents

* [Goal](#goal)
* [Setup Instructions](#setup-instructions)
* [Running the Rule Generator](#running-the-rule-generator)
* [Integrating Generated Rules with ClamAV](#integrating-generated-rules-with-clamav)
* [Performing Malware Scan](#performing-malware-scan)
* [Results](#results)

---

## Goal

* Use AI-driven feature extraction + rule generation to improve traditional AV tools
* Integrate YARA rules into ClamAV to catch more samples

---

## Setup Instructions

### Dependencies

Install the following tools and libraries:

```bash
sudo apt update && sudo apt install -y \
    clamav \
    clamav-daemon \
    python3 \
    python3-pip \
    git \
    build-essential

pip install -r requirements.txt
```

### Clone the Project

```bash
git clone https://github.com/abdmusleh/mcp-for-clamav.git
cd mcp-for-clamav
```

---

## Running the Rule Generator

This project uses an MCP server (`app/mcp.py`) to analyze malware samples and extract features used to generate YARA rules.

### Step-by-step:

1. Run the script:

```bash
python3 generate_rules/generate_rules.py --batch data/sample_paths.txt --output generate_rules/custom_generated2_part1.yara --output-type rules
```

This will:

* Analyze malware samples
* Generate YARA rules
* Save the rules into `.yara` files in the `generate_rules/` directory


---

## Integrating Generated Rules with ClamAV

You can add the newly generated `.yara` rules to ClamAV to boost detection.

### 1. Copy rules

```bash
sudo cp generate_rules/custom_generated2_part1.yara /usr/local/share/clamav/
sudo cp generate_rules/custom_generated2_part2.yara /usr/local/share/clamav/
sudo cp generate_rules/custom_generated2_part3.yara /usr/local/share/clamav/
```

### 2. Enable ClamAV Daemon

```bash
sudo systemctl enable clamav-daemon.service
sudo systemctl start clamav-daemon.service
```

### 3. Reload Database (optional)

```bash
sudo freshclam
```

---

## Performing Malware Scan

To run a scan with ClamAV:

```bash
clamscan /path/to/scan_target
```

Or for a whole directory:

```bash
clamscan -r /path/to/directory
```

---

## Results

Located in the `scan_result/` directory:

* `scan_before.txt` — Scan results using ClamAV only
* `scan_after.txt` — Scan results after injecting custom YARA rules

These results show enhanced detection with rule-based scanning.

---

## Summary

This project bridges the gap between machine learning–assisted malware feature extraction and traditional antivirus tools like ClamAV.

It provides a full pipeline from sample to signature to detection — helping security researchers, malware analysts, and defenders improve coverage with open-source tools.

---

## License

MIT License. See `LICENSE` file.
