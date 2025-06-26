import os

REPORTS_DIR = os.path.join(os.getcwd(), "reports")
IOC_FEED = os.path.join(os.getcwd(), "ioc_feed.txt")
YARA_RULES_FILE = os.path.join(os.getcwd(), "rules.yar")
VT_API_KEY = "YOUR_API_KEY_HERE"

SANDBOX_ENABLED = False  # Default, controlled via GUI checkbox
