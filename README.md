# 🛡️ DMZBox: A Secure Sandboxed Environment for File Analysis

DMZBox is a **local, sandboxed malware analysis utility** built for secure, offline or controlled investigation of potentially malicious files. It combines modern static analysis techniques, threat intelligence enrichment, and security best practices into a single, easy-to-use toolkit — ideal for **incident responders, forensic analysts, and cybersecurity students**.

---

## 🎯 Key Features

- ✅ **Firejail Sandboxed Environment**  
  Runs critical operations (downloads, file analysis, tool execution) inside an isolated Firejail sandbox, limiting system exposure.

- ✅ **Modular Static Analysis Suite**
  - **Strings Extraction** with suspicious indicator matching
  - **Hexdump Visualization**
  - **File Entropy Analysis** (packing/encryption detection)
  - **Binwalk Deep Inspection** with hidden file extraction
  - **ExifTool Metadata Analysis**
  - **YARA Signature Scanning** with CTI (CVE & MITRE ATT&CK) enrichment
  - **VirusTotal Hash Reputation Lookup** or direct file submission

- ✅ **Risk Scoring Engine**
  - Weighted risk calculation across all scans
  - Visual risk meter with color-coded output (green/orange/red)

- ✅ **Secure File Fetching**
  - Built-in URL file retrieval with automatic sandbox containment

- ✅ **Profile-Based API & Preferences Handling**
  - Per-user configuration for VirusTotal API key management
  - Local profile database for seamless operation

---

## 🏗️ Technical Architecture

DMZBox is implemented entirely in **Python 3**, with clean modular separation:

```bash
dmzBox/
├── gui.py              # Tkinter-based secure dashboard
├── utils.py            # File utilities, hashing, entropy, VT logic
├── analysis_tools.py   # Binwalk & ExifTool integration
├── yara_cti.py         # YARA scanning with CVE/ATT&CK enrichment
├── virustotal.py       # Direct VT file submission module
├── risk_engine.py      # Risk scoring logic
├── config.py           # Config paths & defaults
├── risk_meter.py       # UI-friendly risk calculations
└── reports/            # Auto-generated analysis reports

```

### External Tools & Dependencies

- **Firejail** (sandboxing)
- **Binwalk** (binary inspection)
- **ExifTool** (metadata extraction)
- **YARA** (signature-based detection)
- **VirusTotal Public API**
- **Python Libraries:**
  - `tkinter` (GUI)
  - `requests` (API communication)
  - `yara-python` (YARA integration)
  - `PyPDF2` (PDF text extraction)
  - `pandas` (CTI enrichment datasets)
  - `subprocess`, `tempfile`, `hashlib`, `math`, `re`

---

## 🔒 Sandbox Security Model

DMZBox leverages **Firejail** to contain untrusted operations:

- File Downloads
- File Scanning
- Tool Execution

When sandbox mode is enabled, all subprocesses run within the Firejail profile, minimizing risks from malicious files or exploitation attempts.

---

## 🌐 Threat Intelligence & Enrichment

- YARA rule matches are enriched with:
  - Mapped CVEs
  - MITRE ATT&CK Techniques
  - Kill Chain Phases
  - Data Sources & Detection Guidance

- VirusTotal results incorporate:
  - Hash Reputation Checks
  - Direct File Upload & Polling *(optional)*
  - API key security via profile isolation

---

## 📦 Installation & Requirements

### Prerequisites

- Python 3.8+
- Linux System (Firejail required)
- Tools:
  - `firejail`, `binwalk`, `exiftool`, `yara`

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

## 🚀 Usage
python3 gui.py
Use "Browse" to select files for analysis
Toggle Sandbox Mode as needed
Run selected scans or full analysis
View risk score and detailed output
Dispose of files securely after review

## 📊 Risk Scoring Model
DMZBox applies weighted risk calculation:
Scan Type	Risk Weight
Strings	10
Binwalk	15
ExifTool	10
Hexdump	10
YARA + CTI	20
VirusTotal	25

## Final score maps to:
🟢 Low Risk: 0-20
🟠 Moderate Risk: 21-50
🔴 High Risk: 51-100

## 📂 Example Report Artifacts
Reports are saved to the reports/ directory, containing:
  - Raw scan results
  - Extracted hidden files (Binwalk)
  - Risk assessments

## 👨‍💻 Key Takeaways from this Project
 - **Gained deep hands-on experience** with **sandbox technologies (Firejail)** to contain potentially malicious code.
 - Developed a **complete modular Python application**, with separation of logic, configuration, and GUI layers.
 - Integrated real-world static analysis tools such as Binwalk, ExifTool, YARA, and VirusTotal for comprehensive file assessment.
 - Applied **threat intelligence enrichment**, connecting YARA rules to CVEs and MITRE ATT&CK, enhancing detection context.
 - Implemented **secure API handling with per-profile API key management**, improving security and usability.
 - Designed a **weighted risk scoring engine**, offering immediate risk visualisation for rapid decision-making.
 - Reinforced secure coding practices with **file isolation, safe temporary file handling, and error control.**
 - Strengthened understanding of **malware analysis workflows** and safe tool-chain orchestration in Linux environments.

## 🛡️ Why DMZBox is Unique
Built with security-first principles
Full sandbox isolation of high-risk operations
Offline-capable for air-gapped environments
Transparent, user-friendly GUI
Integrated CTI enrichment beyond basic YARA matches
Modular design for easy extension
Designed for real-world SOC, IR, and forensic workflows

## ✅ Disclaimer
DMZBox is intended for controlled, legal use only. It does not replace enterprise-grade sandboxes or malware detonation platforms but serves as a safe, local analysis environment for educational or investigative purposes.

## ⭐ Future Roadmap (Planned)
- Integration with Docker-based isolation (Phase 2)
- Report export to PDF/JSON
- Automated IOC generation
- Enhanced YARA rule management
- GUI visual refinements
