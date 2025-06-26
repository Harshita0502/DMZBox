import yara
import os
import config
import pandas as pd

# Paths to CTI datasets
YARA_CVE_FILE = "YaraRulesWithCVEs.csv"
CVE_ATTACK_FILE = "cve-10.21.2021_attack-9.0-enterprise.csv"
ENTERPRISE_ATTACK_FILE = "enterprise-attack.csv"


# --- YARA Rule Loader ---

def load_rules():
    """
    Load compiled YARA rules from configured path.
    """
    try:
        return yara.compile(filepath=config.YARA_RULES_FILE), None
    except Exception as e:
        return None, f"[YARA] Error loading rules: {str(e)}"


# --- CTI Enrichment Logic ---

def enrich_with_cti(rule_name):
    """
    Enrich a triggered YARA rule with CVE and MITRE ATT&CK mappings.
    """
    if not all(os.path.isfile(f) for f in [YARA_CVE_FILE, CVE_ATTACK_FILE, ENTERPRISE_ATTACK_FILE]):
        return "[CTI] Required CTI dataset files missing."

    try:
        yara_df = pd.read_csv(YARA_CVE_FILE)
        cve_df = pd.read_csv(CVE_ATTACK_FILE)
        attack_df = pd.read_csv(ENTERPRISE_ATTACK_FILE)

        matched_cves = yara_df[yara_df['Rule'] == rule_name]
        if matched_cves.empty:
            return f"[CTI] No CVE mapping found for rule '{rule_name}'."

        cves = matched_cves['CVE'].dropna().tolist()
        attack_rows = cve_df[cve_df['capability_id'].isin(cves)]

        output = "\n--- CTI Enrichment ---\n"

        if not attack_rows.empty:
            attack_ids = attack_rows['attack_object_id'].dropna().tolist()
            enterprise_rows = attack_df[attack_df['id'].isin(attack_ids)]

            if not enterprise_rows.empty:
                for _, row in enterprise_rows.iterrows():
                    output += (
                        f"[ATT&CK] Name: {row['name']}\n"
                        f"[ATT&CK] ID: {row['id']}\n"
                        f"[ATT&CK] Platforms: {row['platforms']}\n"
                        f"[ATT&CK] Kill Chain Phases: {row['kill chain phases']}\n"
                        f"[ATT&CK] Description: {row['description']}\n"
                        f"[ATT&CK] Data Sources: {row['data sources']}\n"
                        f"[ATT&CK] Detection: {row['detection']}\n"
                        "---\n"
                    )
            else:
                output += "[CTI] No detailed ATT&CK info found for matched attack IDs.\n"

            output += "\n--- Additional Mappings ---\n"
            for _, row in attack_rows.iterrows():
                output += (
                    f"[CVE] Capability ID: {row['capability_id']}\n"
                    f"[CVE] Description: {row['capability_description']}\n"
                    f"[CVE] Mapping Type: {row['mapping_type']}\n"
                    "---\n"
                )
        else:
            output += "[CTI] No ATT&CK mappings found for associated CVEs.\n"

        return output

    except Exception as e:
        return f"[CTI] Error during enrichment: {str(e)}"


# --- Full YARA + CTI Execution ---

def run_yara_cti(content):
    """
    Runs YARA rules on provided content and enriches hits with CTI data.
    """
    rules, error = load_rules()
    if not rules:
        return error or "[YARA] Failed to load rules."

    try:
        matches = rules.match(data=content.encode() if isinstance(content, str) else content)
        if matches:
            output = ""
            for match in matches:
                output += f"[YARA] Rule Triggered: {match.rule}\n"
                output += enrich_with_cti(match.rule) + "\n"
            return output
        else:
            return "[YARA/CTI] No threats or indicators found."
    except Exception as e:
        return f"[YARA] Error during scan: {str(e)}"
