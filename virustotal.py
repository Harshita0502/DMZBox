import requests
import config
import tempfile
import os
import subprocess

def scan_with_virustotal(file_content):
    """
    Submits the provided file content to VirusTotal and returns a summary.
    """
    if not config.VT_API_KEY:
        return "[VirusTotal] API Key not configured."

    try:
        # Save content to a temporary file
        tmp_fd, tmp_path = tempfile.mkstemp()
        with os.fdopen(tmp_fd, "wb") as tmp_file:
            tmp_file.write(file_content.encode())

        result = submit_file(tmp_path)

        os.remove(tmp_path)
        return result

    except Exception as e:
        return f"[VirusTotal] Error: {str(e)}"


def submit_file(filepath):
    """
    Submits a file at 'filepath' to VirusTotal.
    Runs within Firejail if sandbox is enabled.
    """
    headers = {"x-apikey": config.VT_API_KEY}
    try:
        cmd = ["curl", "-s", "-X", "POST", "-H", f"x-apikey: {config.VT_API_KEY}", 
               "-F", f"file=@{filepath}", "https://www.virustotal.com/api/v3/files"]

        if config.SANDBOX_ENABLED:
            cmd.insert(0, "firejail")
            cmd.insert(1, "--quiet")

        output = subprocess.check_output(cmd, text=True)
        response = parse_response(output)
        return response

    except Exception as e:
        return f"[VirusTotal] Submission Error: {str(e)}"


def parse_response(output):
    """
    Parses VT submission response and optionally polls for results.
    """
    try:
        import json
        data = json.loads(output)
        analysis_id = data["data"]["id"]

        # Poll for result
        headers = {"x-apikey": config.VT_API_KEY}
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        for _ in range(10):
            poll = requests.get(analysis_url, headers=headers)
            if poll.status_code == 200:
                result_data = poll.json()
                if result_data["data"]["attributes"]["status"] == "completed":
                    stats = result_data["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    return f"[VirusTotal] Malicious: {malicious} | Suspicious: {suspicious}"
        return "[VirusTotal] Scan result unavailable or still processing."

    except Exception as e:
        return f"[VirusTotal] Parsing Error: {str(e)}"
