import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog
import os
import utils
import analysis_tools
import risk_engine
import subprocess
import config
from tkinter import ttk
import json

# Global variables
file_content = None
current_file_path = None
sandbox_enabled = False

def run_in_sandbox(command_list):
    """Wrapper to execute commands inside Firejail if sandbox is enabled."""
    if sandbox_enabled:
        return ["firejail"] + command_list
    return command_list

def browse_file(file_viewer):
    global file_content, current_file_path
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    current_file_path = file_path

    for widget in file_viewer.winfo_children():
        widget.destroy()

    is_pdf = False
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_content = file_data
            if file_data.startswith(b'%PDF'):
                is_pdf = True
    except:
        messagebox.showerror("Error", "Could not read file.")
        file_content = None
        return

    text_area = scrolledtext.ScrolledText(file_viewer, width=65, height=35)
    text_area.pack()

    if is_pdf:
        try:
            import PyPDF2
            reader = PyPDF2.PdfReader(file_path)
            pdf_text = ""
            for page in reader.pages:
                pdf_text += page.extract_text() or ""
            if pdf_text.strip():
                text_area.insert(tk.END, pdf_text)
                file_content = pdf_text.encode()
            else:
                text_area.insert(tk.END, "[!] PDF contains no extractable text.")
                file_content = None
        except:
            text_area.insert(tk.END, "[!] Failed to extract text from PDF.")
            file_content = None
    else:
        try:
            content = file_data.decode(errors="ignore")
            text_area.insert(tk.END, content)
        except:
            hex_data = file_data.hex()
            text_area.insert(tk.END, f"[Binary File Detected]\n\n{hex_data[:500]} ...")

def fetch_link(file_viewer):
    global file_content, current_file_path
    url = simpledialog.askstring("Fetch from Link", "Enter file URL:")
    if not url:
        return

    try:
        filename = os.path.basename(url) or "fetched_file"
        tmp_path = os.path.join(config.REPORTS_DIR, filename)
        cmd = run_in_sandbox(["wget", "-O", tmp_path, url])
        subprocess.check_output(cmd)
        current_file_path = tmp_path
    except:
        messagebox.showerror("Error", "Failed to fetch file from URL.")
        return

    for widget in file_viewer.winfo_children():
        widget.destroy()

    browse_file(file_viewer)

def toggle_sandbox(state_label):
    global sandbox_enabled
    sandbox_enabled = not sandbox_enabled
    state_label.config(text=f"Sandbox: {'Enabled' if sandbox_enabled else 'Disabled'}")

if not os.path.exists(config.REPORTS_DIR):
    os.makedirs(config.REPORTS_DIR)

window = tk.Tk()
window.title("DMZBox - Secure File Analysis Dashboard")
window.geometry("1500x900")
window.configure(bg="#ECEFF1")

previous_profiles = []
if os.path.exists("profile_db.json"):
    try:
        with open("profile_db.json") as f:
            previous_profiles = json.load(f)
    except:
        previous_profiles = []

profile = {}
sandbox_enabled = tk.BooleanVar(value=True)

def login_prompt():
    login_win = tk.Frame(window, bg="#263238")
    login_win.pack(fill="both", expand=True)

    tk.Label(login_win, text="DMZBox - User Login", bg="#263238", fg="white", font=("Helvetica", 18, "bold")).pack(pady=20)

    form_frame = tk.Frame(login_win, bg="#263238")
    form_frame.pack(pady=10)

    tk.Label(form_frame, text="Select User:", bg="#263238", fg="white").grid(row=0, column=0, sticky="e", padx=5, pady=5)
    name_var = tk.StringVar()
    name_menu = ttk.Combobox(form_frame, textvariable=name_var, values=[p['name'] for p in previous_profiles], state="readonly")
    name_menu.grid(row=0, column=1, pady=5)

    tk.Label(form_frame, text="Password:", bg="#263238", fg="white").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    pwd_entry = tk.Entry(form_frame, show="*")
    pwd_entry.grid(row=1, column=1, pady=5)

    def validate_login():
        selected = name_var.get()
        pwd = pwd_entry.get().strip()

        for p in previous_profiles:
            if p['name'] == selected and p.get('password') == pwd:
                global profile
                profile = p.copy()
                login_win.destroy()
                build_gui()
                return

        messagebox.showerror("Login Failed", "Invalid username or password.")

    btn_frame = tk.Frame(login_win, bg="#263238")
    btn_frame.pack(pady=15)

    tk.Button(btn_frame, text="Login", bg="#4CAF50", fg="white", width=15, command=validate_login).pack(pady=5)
    tk.Button(btn_frame, text="Create New User", width=15, command=lambda: [login_win.destroy(), profile_setup()]).pack(pady=5)

def profile_setup():
    setup_win = tk.Frame(window, bg="#263238")
    setup_win.pack(fill="both", expand=True)

    tk.Label(setup_win, text="DMZBox - Create New Profile", bg="#263238", fg="white",
             font=("Helvetica", 18, "bold")).pack(pady=20)

    form_frame = tk.Frame(setup_win, bg="#263238")
    form_frame.pack(pady=10)

    # Full Name
    tk.Label(form_frame, text="Full Name:", bg="#263238", fg="white").grid(row=0, column=0, sticky="e", padx=5, pady=5)
    name_entry = tk.Entry(form_frame)
    name_entry.grid(row=0, column=1, pady=5)

    # Department
    tk.Label(form_frame, text="Department:", bg="#263238", fg="white").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    dept_entry = tk.Entry(form_frame)
    dept_entry.grid(row=1, column=1, pady=5)

    # Role
    tk.Label(form_frame, text="Role:", bg="#263238", fg="white").grid(row=2, column=0, sticky="e", padx=5, pady=5)
    role_var = tk.StringVar()
    role_menu = ttk.Combobox(form_frame, textvariable=role_var,
                             values=["Analyst", "Threat Hunter", "Researcher", "Malware Analyst", "Other"])
    role_menu.grid(row=2, column=1, pady=5)

    # Password
    tk.Label(form_frame, text="Password:", bg="#263238", fg="white").grid(row=3, column=0, sticky="e", padx=5, pady=5)
    pwd_var = tk.StringVar()
    pwd_entry = tk.Entry(form_frame, textvariable=pwd_var, show="*")
    pwd_entry.grid(row=3, column=1, pady=5)

    show_pwd_var = tk.BooleanVar(value=False)

    def toggle_pwd_visibility():
        pwd_entry.config(show="" if show_pwd_var.get() else "*")

    tk.Checkbutton(form_frame, text="Show Password", variable=show_pwd_var, command=toggle_pwd_visibility,
                   bg="#263238", fg="white").grid(row=3, column=2, padx=5)
                   
def toggle_run_all(run_all_var, scan_checkboxes):
    """Disable individual scan checkboxes when Run All is selected."""
    state = tk.DISABLED if run_all_var.get() else tk.NORMAL
    for checkbox in scan_checkboxes:
        checkbox.config(state=state)

    # VirusTotal API
    tk.Label(form_frame, text="VirusTotal API Key:", bg="#263238", fg="white").grid(row=4, column=0, sticky="e", padx=5, pady=5)
    vt_api_var = tk.StringVar()
    vt_api_entry = tk.Entry(form_frame, textvariable=vt_api_var, show="*")
    vt_api_entry.grid(row=4, column=1, pady=5)

    show_vt_var = tk.BooleanVar(value=False)

    def toggle_vt_visibility():
        vt_api_entry.config(show="" if show_vt_var.get() else "*")

    tk.Checkbutton(form_frame, text="Show API Key", variable=show_vt_var, command=toggle_vt_visibility,
                   bg="#263238", fg="white").grid(row=4, column=2, padx=5)

    # Notes
    tk.Label(form_frame, text="Notes:", bg="#263238", fg="white").grid(row=5, column=0, sticky="ne", padx=5, pady=5)
    notes_text = scrolledtext.ScrolledText(form_frame, height=4, width=25)
    notes_text.grid(row=5, column=1, pady=5)

    # Save Profile Function
    def save_profile():
        name = name_entry.get().strip()
        dept = dept_entry.get().strip()
        role = role_var.get().strip()
        pwd = pwd_var.get().strip()
        vt_api = vt_api_var.get().strip()
        notes = notes_text.get("1.0", tk.END).strip()

        if not name or not pwd:
            messagebox.showerror("Error", "Full Name and Password are required.")
            return

        profile_obj = {
            "name": name,
            "department": dept,
            "role": role,
            "password": pwd,
            "virustotal_api": vt_api,
            "notes": notes
        }

        previous_profiles.append(profile_obj)

        with open("profile_db.json", "w") as f:
            json.dump(previous_profiles, f)

        setup_win.destroy()
        login_prompt()

    tk.Button(setup_win, text="Create Profile", bg="#4CAF50", fg="white", command=save_profile).pack(pady=20)

def view_reports():
    win = tk.Toplevel(window)
    win.title("Reports")
    win.geometry("700x500")

    tk.Label(win, text="Structured Reports", font=("Helvetica", 14, "bold")).pack(pady=10)
    report_box = scrolledtext.ScrolledText(win, width=80, height=25, bg="white", fg="black", font=("Courier", 10))
    report_box.pack(padx=10, pady=10)

    try:
        with open(f"{config.REPORTS_DIR}/{profile['name']}_reports.log") as f:
            report_box.insert(tk.END, f.read())
    except:
        report_box.insert(tk.END, "No reports available.")

def view_profile():
    win = tk.Toplevel(window)
    win.title("Profile Info")
    win.geometry("300x200")
    tk.Label(win, text=f"Name: {profile['name']}\nDepartment: {profile['department']}\nRole: {profile['role']}\nNotes: {profile['notes']}", justify="left", font=("Helvetica", 11)).pack(padx=20, pady=20)

def open_analytics():
    win = tk.Toplevel(window)
    win.title("Analytics")
    win.geometry("400x300")
    tk.Label(win, text="Analytics Graphs Coming Soon", font=("Helvetica", 12)).pack(pady=20)

def open_settings():
    win = tk.Toplevel(window)
    win.title("Settings")
    form_frame = tk.Frame(win)
    form_frame.pack(padx=20, pady=20)

    tk.Label(form_frame, text="Department:").grid(row=0, column=0, sticky="e", pady=5)
    dept_entry = tk.Entry(form_frame)
    dept_entry.insert(0, profile.get("department", ""))
    dept_entry.grid(row=0, column=1, pady=5)

    tk.Label(form_frame, text="Role:").grid(row=1, column=0, sticky="e", pady=5)
    role_var = tk.StringVar(value=profile.get("role", ""))
    role_menu = ttk.Combobox(form_frame, textvariable=role_var, values=["Analyst", "Threat Hunter", "Researcher", "Malware Analyst", "Other"])
    role_menu.grid(row=1, column=1, pady=5)

    tk.Label(form_frame, text="Notes:").grid(row=2, column=0, sticky="ne", pady=5)
    notes_text = scrolledtext.ScrolledText(form_frame, height=4, width=25)
    notes_text.insert(tk.END, profile.get("notes", ""))
    notes_text.grid(row=2, column=1, pady=5)

    tk.Label(form_frame, text="VirusTotal API Key:").grid(row=3, column=0, sticky="e", pady=5)
    api_entry = tk.Entry(form_frame, show="*")
    api_entry.insert(0, profile.get("virustotal_api", ""))
    api_entry.grid(row=3, column=1, pady=5)

    show_api_var = tk.BooleanVar(value=False)
    def toggle_api_visibility():
        api_entry.config(show="" if show_api_var.get() else "*")

    tk.Checkbutton(form_frame, text="Show API Key", variable=show_api_var, command=toggle_api_visibility).grid(row=4, column=1, sticky="w")

    tk.Label(form_frame, text="Current Password:").grid(row=5, column=0, sticky="e", pady=5)
    current_pwd = tk.Entry(form_frame, show="*")
    current_pwd.grid(row=5, column=1, pady=5)

    tk.Label(form_frame, text="New Password:").grid(row=6, column=0, sticky="e", pady=5)
    new_pwd = tk.Entry(form_frame, show="*")
    new_pwd.grid(row=6, column=1, pady=5)

    tk.Label(form_frame, text="Retype New Password:").grid(row=7, column=0, sticky="e", pady=5)
    confirm_pwd = tk.Entry(form_frame, show="*")
    confirm_pwd.grid(row=7, column=1, pady=5)

    def save_settings():
        if current_pwd.get() != profile.get("password"):
            messagebox.showerror("Error", "Incorrect current password.")
            return
        if new_pwd.get() and new_pwd.get() != confirm_pwd.get():
            messagebox.showerror("Error", "New passwords do not match.")
            return

        profile["department"] = dept_entry.get()
        profile["role"] = role_var.get()
        profile["notes"] = notes_text.get("1.0", tk.END).strip()
        profile["virustotal_api"] = api_entry.get().strip()

        if new_pwd.get():
            profile["password"] = new_pwd.get()

        for p in previous_profiles:
            if p["name"] == profile["name"]:
                p.update(profile)

        with open("profile_db.json", "w") as f:
            json.dump(previous_profiles, f)

        messagebox.showinfo("Settings Saved", "Profile updated successfully.")
        win.destroy()

    def delete_account():
        pwd = simpledialog.askstring("Confirm", "Enter current password to confirm:", show="*")
        if pwd != profile.get("password"):
            messagebox.showerror("Error", "Incorrect password.")
            return
        global previous_profiles
        previous_profiles = [p for p in previous_profiles if p["name"] != profile["name"]]
        with open("profile_db.json", "w") as f:
            json.dump(previous_profiles, f)
        win.destroy()
        window.destroy()
        os.execl(sys.executable, sys.executable, *sys.argv)

    btn_frame = tk.Frame(win)
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Save", bg="#4CAF50", fg="white", command=save_settings).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Delete Account", bg="#D32F2F", fg="white", command=delete_account).pack(side="left", padx=5)

def toggle_sandbox(btn):
    current = sandbox_enabled.get()
    sandbox_enabled.set(not current)

    if sandbox_enabled.get():
        btn.config(text="Sandbox Enabled", bg="#4CAF50")
        messagebox.showinfo("Sandbox", "Sandbox mode enabled. All scans will run isolated.")
    else:
        btn.config(text="Sandbox Disabled", bg="#D32F2F")
        messagebox.showwarning("Sandbox", "Sandbox mode disabled. Scans will run without isolation.")

def build_gui():
    sidebar = tk.Frame(window, width=220, bg="#263238")
    sidebar.pack(side="left", fill="y")

    tk.Label(sidebar, text="DMZBox", bg="#263238", fg="white", font=("Helvetica", 16, "bold")).pack(pady=10)
    tk.Label(sidebar, text=f"User: {profile['name']}", bg="#263238", fg="white", font=("Helvetica", 11)).pack(pady=5)

    sandbox_btn_var = tk.BooleanVar(value=sandbox_enabled.get())

    def update_sandbox():
        sandbox_enabled.set(sandbox_btn_var.get())
        if sandbox_btn_var.get():
            sandbox_btn.config(text="Sandbox Enabled", bg="#4CAF50")
        else:
            sandbox_btn.config(text="Sandbox Disabled", bg="#D32F2F")

    sandbox_btn = tk.Checkbutton(sidebar, text="Sandbox Disabled", variable=sandbox_btn_var, command=update_sandbox, bg="#D32F2F", fg="white", width=20)
    sandbox_btn.pack(pady=5)

    tk.Button(sidebar, text="Reports", bg="#37474F", fg="white", command=view_reports, width=20).pack(pady=5)
    tk.Button(sidebar, text="Analytics", bg="#37474F", fg="white", command=open_analytics, width=20).pack(pady=5)
    tk.Button(sidebar, text="Profile Info", bg="#546E7A", fg="white", command=view_profile, width=20).pack(pady=5)
    tk.Button(sidebar, text="Settings", bg="#546E7A", fg="white", command=open_settings, width=20).pack(pady=5)
    tk.Button(sidebar, text="Exit", bg="#D32F2F", fg="white", command=window.quit, width=20).pack(side="bottom", pady=10)

    main_frame = tk.Frame(window, bg="#ECEFF1")
    main_frame.pack(side="right", fill="both", expand=True)

    header = tk.Frame(main_frame, bg="#455A64", height=50)
    header.pack(fill="x")
    tk.Label(header, text="Secure File Analysis Dashboard", bg="#455A64", fg="white", font=("Helvetica", 14)).pack(pady=10)

    content = tk.Frame(main_frame, bg="#ECEFF1")
    content.pack(fill="both", expand=True, padx=15, pady=15)

    left_pane = tk.Frame(content, bg="#ECEFF1", width=600)
    left_pane.pack(side="left", fill="y", padx=10)

    file_btn_frame = tk.Frame(left_pane, bg="#ECEFF1")
    file_btn_frame.pack(pady=5)
    tk.Button(file_btn_frame, text="Browse File", bg="#4CAF50", fg="white", command=lambda: browse_file(file_viewer)).pack(side="left", padx=5)
    tk.Button(file_btn_frame, text="Fetch from Link", bg="#2196F3", fg="white", command=lambda: fetch_link(file_viewer)).pack(side="left", padx=5)

    tk.Label(left_pane, text="File Viewer", bg="#ECEFF1", font=("Helvetica", 12, "bold")).pack(pady=5)
    file_viewer = scrolledtext.ScrolledText(left_pane, width=65, height=35)
    file_viewer.pack()

    btn_frame = tk.Frame(left_pane, bg="#ECEFF1")
    btn_frame.pack(pady=5)

    dispose_btn = tk.Button(btn_frame, text="Dispose File", bg="#D32F2F", fg="white", state="disabled")
    dispose_btn.pack(side="left", padx=5)

    download_btn = tk.Button(btn_frame, text="Download File", bg="#4CAF50", fg="white", state="disabled")
    download_btn.pack(side="left", padx=5)

    right_pane = tk.Frame(content, bg="#ECEFF1")
    right_pane.pack(side="right", fill="both", expand=True)

    risk_frame = tk.Frame(right_pane, bg="#ECEFF1")
    risk_frame.pack(pady=10)

    tk.Label(risk_frame, text="Risk Meter:", bg="#ECEFF1", font=("Helvetica", 11, "bold")).pack(side="left", padx=5)

    risk_progress = ttk.Progressbar(risk_frame, length=200, maximum=100)
    risk_progress.pack(side="left", padx=5)

    risk_value_label = tk.Label(risk_frame, text="N/A", bg="#ECEFF1", font=("Helvetica", 11, "bold"))
    risk_value_label.pack(side="left", padx=5)

    scan_frame = tk.LabelFrame(right_pane, text="Select Scans to Perform", bg="#ECEFF1")
    scan_frame.pack(fill="x", pady=10)

    scans = {
        "Strings": tk.IntVar(),
        "Binwalk": tk.IntVar(),
        "ExifTool": tk.IntVar(),
        "Hexdump": tk.IntVar(),
        "YARA + CTI": tk.IntVar(),
        "VirusTotal": tk.IntVar()
    }

    scan_descriptions = {
        "Strings": "Extract readable strings from file",
        "Binwalk": "Analyze embedded files & firmware",
        "ExifTool": "View metadata of the file",
        "Hexdump": "Hexadecimal representation of file",
        "YARA + CTI": "Threat rule matching with enrichment",
        "VirusTotal": "Scan with VirusTotal API"
    }

    tk.Label(scan_frame, text="Select Scans to Perform:", bg="#ECEFF1", font=("Helvetica", 11, "bold")).pack(anchor="w", pady=(0, 5))

    for scan, var in scans.items():
        row_frame = tk.Frame(scan_frame, bg="#ECEFF1")
        row_frame.pack(anchor="w", pady=2, fill="x")

        tk.Checkbutton(row_frame, text=scan, variable=var, bg="#ECEFF1").pack(side="left")
        tk.Label(row_frame, text=f" - {scan_descriptions.get(scan, '')}", bg="#ECEFF1", fg="#555555", anchor="w").pack(side="left")

    run_all_var = tk.IntVar()
    tk.Checkbutton(scan_frame, text="Run All", variable=run_all_var, bg="#ECEFF1").pack(anchor="w", pady=5)

    start_btn = tk.Button(right_pane, text="Start Scan", bg="#FF9800", fg="white")
    start_btn.pack(pady=10)

    progress_label = tk.Label(right_pane, text="", bg="#ECEFF1")
    progress_label.pack()

    tk.Label(right_pane, text="Scan Results", bg="#ECEFF1", font=("Helvetica", 12, "bold")).pack(pady=5)
    result_text = scrolledtext.ScrolledText(right_pane, width=60, height=10)
    result_text.pack()

# CORRECT: Pass file_content, NOT file_viewer
    start_btn.config(command=lambda: run_scans(
    scans, run_all_var, current_file_path, result_text, risk_progress, 
    risk_value_label, dispose_btn, download_btn, file_content))
    
    dispose_btn.config(command=lambda: dispose_file(file_viewer, dispose_btn, download_btn))
    download_btn.config(command=lambda: download_file())

def run_scans(scans, run_all_var, file_path, result_text, risk_progress, risk_value_label, dispose_btn, download_btn, file_content):
    if not file_path or not file_content:
        messagebox.showerror("Error", "No file loaded.")
        return

    result_text.delete("1.0", tk.END)
    scan_results = {}

    # Strings Scan
    if run_all_var.get() or scans["Strings"].get():
        strings_output = utils.get_strings(file_content)
        result_text.insert(tk.END, "\n=== Strings Scan ===\n" + strings_output + "\n")
        scan_results["Strings"] = risk_engine.contains_suspicious_string(strings_output)

    # Binwalk Scan
    if run_all_var.get() or scans["Binwalk"].get():
        binwalk_output = analysis_tools.run_binwalk(file_path)
        result_text.insert(tk.END, "\n=== Binwalk Scan ===\n" + binwalk_output + "\n")
        scan_results["Binwalk"] = risk_engine.contains_binwalk_signature(binwalk_output)

    # ExifTool Scan
    if run_all_var.get() or scans["ExifTool"].get():
        exif_output = analysis_tools.run_exiftool(file_content)
        result_text.insert(tk.END, "\n=== ExifTool Scan ===\n" + exif_output + "\n")
        scan_results["ExifTool"] = risk_engine.contains_suspicious_metadata(exif_output)

    # Hexdump Scan
    if run_all_var.get() or scans["Hexdump"].get():
        hex_output = utils.hexdump(file_content)
        result_text.insert(tk.END, "\n=== Hexdump ===\n" + hex_output + "\n")
        scan_results["Hexdump"] = risk_engine.contains_hex_signature(hex_output)

    # YARA + CTI Scan
    if run_all_var.get() or scans["YARA + CTI"].get():
        yara_output = utils.run_yara_cti(file_path)
        result_text.insert(tk.END, "\n=== YARA + CTI Scan ===\n" + yara_output + "\n")
        scan_results["YARA + CTI"] = risk_engine.contains_yara_signature(yara_output)

    # VirusTotal Scan
    if run_all_var.get() or scans["VirusTotal"].get():
        vt_output, risky = utils.check_virustotal(file_path)
        result_text.insert(tk.END, "\n=== VirusTotal ===\n" + vt_output + "\n")
        scan_results["VirusTotal"] = risky

    # Risk Calculation
    score = risk_engine.calculate_risk(scan_results)
    risk_progress["value"] = score
    risk_value_label.config(text=f"Risk Score: {score}%")

    color = risk_engine.get_risk_color(score)
    risk_progress.config(style=f"{color}.Horizontal.TProgressbar")

    if score >= 50:
        dispose_btn.config(state="normal")
    else:
        dispose_btn.config(state="disabled")

    download_btn.config(state="normal")

    def task():
        """ Executes scans in a background-safe way when Start Scan is clicked."""
    file_path = file_viewer.get()
    if not file_path:
        result_text.insert("end", "[!] No file selected.\n")
        return

    with open(file_path, "rb") as f:
        file_content = f.read()

    content_str = file_content.decode(errors="ignore")

    scan_results = {}
    result_text.delete("1.0", "end")
    result_text.insert("end", f"[+] Scanning file: {file_path}\n\n")

    # STRINGS SCAN
    result_text.insert("end", "[+] Running Strings scan...\n")
    output = utils.get_strings(content_str)
    result_text.insert("end", output + "\n\n")
    risky = risk_engine.contains_suspicious_string(output)
    scan_results["Strings"] = risky
    if risky:
        result_text.insert("end", "[!] Suspicious strings detected.\n", "risky")

    # BINWALK SCAN
    result_text.insert("end", "[+] Running Binwalk scan...\n")
    output = analysis_tools.run_binwalk(content_str)
    result_text.insert("end", output + "\n\n")
    risky = risk_engine.contains_binwalk_signature(output)
    scan_results["Binwalk"] = risky
    if risky:
        result_text.insert("end", "[!] Suspicious binwalk findings detected.\n", "risky")

    # EXIFTOOL SCAN
    result_text.insert("end", "[+] Running ExifTool scan...\n")
    output = analysis_tools.run_exiftool(file_content)
    result_text.insert("end", output + "\n\n")
    risky = risk_engine.contains_suspicious_metadata(output)
    scan_results["ExifTool"] = risky
    if risky:
        result_text.insert("end", "[!] Suspicious metadata detected.\n", "risky")

    # HEXDUMP SCAN
    result_text.insert("end", "[+] Running Hexdump scan...\n")
    output = utils.hexdump(file_content)
    result_text.insert("end", output + "\n\n")
    risky = risk_engine.contains_hex_signature(output)
    scan_results["Hexdump"] = risky
    if risky:
        result_text.insert("end", "[!] Suspicious hexdump patterns detected.\n", "risky")

    # YARA + CTI SCAN
    result_text.insert("end", "[+] Running YARA + CTI scan...\n")
    yara_output, yara_hits = utils.run_yara(file_path)
    result_text.insert("end", yara_output + "\n\n")
    risky = any(risk_engine.contains_yara_signature(hit) for hit in yara_hits)
    scan_results["YARA + CTI"] = risky
    if risky:
        result_text.insert("end", "[!] YARA rule triggered with CTI match.\n", "risky")

    # VIRUSTOTAL SCAN
    result_text.insert("end", "[+] Running VirusTotal scan...\n")
    vt_output, detection_count = utils.virustotal_scan(file_path)
    result_text.insert("end", vt_output + "\n\n")
    risky = risk_engine.vt_detection_risky(detection_count)
    scan_results["VirusTotal"] = risky
    if risky:
        result_text.insert("end", "[!] High VirusTotal detection count.\n", "risky")

    # FINAL RISK METER CALCULATION
    risk_score = risk_engine.calculate_risk(scan_results)
    risk_color = risk_engine.get_risk_color(risk_score)
    risk_progress["value"] = risk_score
    risk_value_label.config(text=f"Risk Meter: {risk_score}%", fg=risk_color)

    dispose_btn.pack(side="left", padx=5)
    download_btn.pack(side="left", padx=5)

def dispose_file(file_viewer, dispose_btn, download_btn):
    for widget in file_viewer.winfo_children():
        widget.destroy()
    dispose_btn.config(state="disabled")
    download_btn.config(state="disabled")
    messagebox.showinfo("Disposed", "File has been disposed from the viewer.")

def download_file():
    save_path = filedialog.asksaveasfilename(title="Save File As")
    tmp_path = os.path.join(config.REPORTS_DIR, "fetched_file")
    if save_path and os.path.exists(tmp_path):
        os.rename(tmp_path, save_path)
        messagebox.showinfo("Saved", "File saved successfully.")
    else:
        messagebox.showerror("Error", "Temporary file not found.")

login_prompt()
window.mainloop()
