# === Risk Engine for DMZBox ===

# Risk Weights for each scan
RISK_WEIGHTS = {
    "Strings": 10,
    "Binwalk": 15,
    "ExifTool": 10,
    "Hexdump": 10,
    "YARA + CTI": 20,
    "VirusTotal": 25
}

# Color thresholds for risk meter
RISK_COLORS = {
    "low": (0, 20),
    "moderate": (21, 50),
    "high": (51, 100)
}

# Suspicious Indicators
STRING_SIGNATURES = [
    "cmd.exe", "powershell", "wget", "curl", "base64", "eval", "<script>",
    "/bin/sh", "nc -e", "whoami", "net user", "schtasks", "vbs", "mshta", "0x4d5a"
]

METADATA_SIGNATURES = [
    "Microsoft Word", "Adobe Photoshop", "Hacker", "Anonymous", "Visual Basic", "AutoIt",
    "Metasploit", "Exploit", "Cobalt Strike", "Empire", "Mimikatz", "Pwsh", "Powersploit",
    "Offsec", "Kali", "Remcos", "NjRat", "Quasar", "Backdoor", "Malware Generator",
    "Nullsoft Installer", "Inno Setup", "PyInstaller", "UPX", "DarkComet", "Poison Ivy"
]

BINWALK_SIGNATURES = [
    "ELF", "PE32", "executable", "firmware", "bootloader", "compressed", "archive",
    "JFFS2", "Squashfs", "CRAMFS", "LZMA", "gzip", "bzip2", "XZ"
]

HEX_SIGNATURES = [
    "4d5a", "25504446", "89504e47", "ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "504b0304", "377abcaf"
]

YARA_SIGNATURES = [
    "MALWARE", "TROJAN", "EXPLOIT", "BACKDOOR", "C2", "ROOTKIT", "RANSOMWARE", "SPYWARE"
]

RISKY_FILE_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".apk", ".jar"
]

VT_DETECTION_THRESHOLD = 5
ENTROPY_THRESHOLD = 7.5


# --- Detection Functions ---

def contains_suspicious_string(text):
    return any(indicator.lower() in text.lower() for indicator in STRING_SIGNATURES)

def contains_suspicious_metadata(metadata):
    return any(indicator.lower() in metadata.lower() for indicator in METADATA_SIGNATURES)

def contains_binwalk_signature(text):
    return any(indicator.lower() in text.lower() for indicator in BINWALK_SIGNATURES)

def contains_hex_signature(text):
    return any(indicator.lower() in text.lower() for indicator in HEX_SIGNATURES)

def contains_yara_signature(text):
    return any(indicator.lower() in text.lower() for indicator in YARA_SIGNATURES)

def is_risky_filetype(filename):
    return any(filename.lower().endswith(ext) for ext in RISKY_FILE_EXTENSIONS)

def vt_detection_risky(detection_count):
    return detection_count >= VT_DETECTION_THRESHOLD

def entropy_risky(entropy_value):
    return entropy_value >= ENTROPY_THRESHOLD


# --- Risk Meter Logic ---

def calculate_risk(scan_results):
    """
    scan_results: dict like {'Strings': True, 'Binwalk': False, ...}
    True indicates a risky finding.
    """
    score = sum(weight for scan, risky in scan_results.items() if risky for scan_name, weight in RISK_WEIGHTS.items() if scan == scan_name)
    return min(score, 100)

def get_risk_color(score):
    if RISK_COLORS['low'][0] <= score <= RISK_COLORS['low'][1]:
        return "green"
    elif RISK_COLORS['moderate'][0] <= score <= RISK_COLORS['moderate'][1]:
        return "orange"
    else:
        return "red"
