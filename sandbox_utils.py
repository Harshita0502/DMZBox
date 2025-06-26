import subprocess
import config

# Global flag, controlled by GUI toggle or config
SANDBOX_ENABLED = False

def set_sandbox(state: bool):
    """Enable or disable sandbox globally."""
    global SANDBOX_ENABLED
    SANDBOX_ENABLED = state

def sandbox_command(cmd_list):
    """
    Wraps a command list with Firejail if sandbox is enabled.
    """
    if SANDBOX_ENABLED:
        return ["firejail", "--net=none", "--private"] + cmd_list
    return cmd_list

def run_command(cmd_list, capture_output=True, text=True):
    """
    Runs a system command, respecting sandbox state.
    """
    try:
        cmd = sandbox_command(cmd_list)
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=text)
        return result
    except Exception as e:
        return f"[!] Command Error: {str(e)}"

def run_command_no_output(cmd_list):
    """
    Runs a system command with no output, respecting sandbox state.
    """
    try:
        cmd = sandbox_command(cmd_list)
        subprocess.check_call(cmd)
        return True
    except Exception:
        return False

