import hashlib
import subprocess
import requests
import os
import yara
import json
import config

def get_file_hash(filepath):
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_strings(content):
    import re
    strings = re.findall(rb"[ -~]{4,}", content)
    return "\n".join(s.decode(errors="ignore") for s in strings)

def hexdump(content, length=16):
    result = []
    for i in range(0, len(content), length):
        chunk = content[i:i+length]
        hex_chunk = ' '.join(f"{b:02x}" for b in chunk)
        ascii_chunk = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f"{i:08x}  {hex_chunk:<48}  {ascii_chunk}")
    return "\n".join(result)

def run_yara_cti(filepath):
    try:
        rules = yara.compile(filepath=config.YARA_RULES_FILE)
        cmd = ["yara", config.YARA_RULES_FILE, filepath]
        if config.SANDBOX_ENABLED:
            cmd = ["firejail", "--quiet"] + cmd
        result = subprocess.check_output(cmd, text=True)
        risky = bool(result.strip())
        return result or "No YARA matches.", risky
    except Exception as e:
        return f"YARA Scan Error: {str(e)}", False

def check_virustotal(filepath):
    api_key = config.VT_API_KEY
    if not api_key:
        return "[!] VirusTotal API key not set.", False

    file_hash = get_file_hash(filepath)
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            output = f"VT Detections: {malicious}/{total}"
            risky = malicious > 3
            return output, risky
        elif response.status_code == 404:
            return "[+] File not found on VirusTotal.", False
        else:
            return f"[!] VT Error: {response.status_code}", False
    except Exception as e:
        return f"[!] VT Exception: {str(e)}", False

def get_file_entropy(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0
    import math
    from collections import Counter
    counter = Counter(data)
    entropy = -sum((count/len(data)) * math.log2(count/len(data)) for count in counter.values())
    return round(entropy, 2)
