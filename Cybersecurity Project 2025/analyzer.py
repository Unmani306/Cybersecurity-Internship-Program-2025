import re
from collections import defaultdict
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# Dark mode colors
BG_COLOR = "#1e1e1e"
FG_COLOR = "#f5f5f5"
ALERT_COLOR = "#ff4c4c"
SUCCESS_COLOR = "#4caf50"
INFO_COLOR = "#4fc3f7"
BUTTON_BG = "#333333"
BUTTON_FG = "#f5f5f5"
HIGHLIGHT_COLOR = "#555555"

def analyze_log(file_path, output_area, status_label, progress_var, filter_var):
    """Analyzes the log file and updates GUI output area."""
    output_area.config(state='normal')
    output_area.delete('1.0', tk.END)
    status_label.config(text="🔍 Analyzing logs...")
    progress_var.set(0)

    if not file_path:
        messagebox.showwarning("Warning", "Please select a log file to analyze.")
        status_label.config(text="⚠️ No file selected.")
        return

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        messagebox.showerror("Error", f"The file '{file_path}' was not found.")
        status_label.config(text="❌ File not found.")
        return

    failed_login_attempts = defaultdict(int)
    suspicious_activities = []
    total_log_entries = len(lines)

    # Patterns
    failed_login_pattern = re.compile(r"failed login from IP:\s*(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
    unauthorized_access_pattern = re.compile(r"accessed unauthorized file:\s*(.+)", re.IGNORECASE)
    permission_change_pattern = re.compile(r"chmod\s+\d+\s+(/.+)", re.IGNORECASE)
    failed_command_pattern = re.compile(r"ran '.*malware.*'", re.IGNORECASE)

    for idx, line in enumerate(lines, start=1):
        line = line.strip()

        failed_match = failed_login_pattern.search(line)
        if failed_match:
            ip = failed_match.group(1)
            failed_login_attempts[ip] += 1
            if failed_login_attempts[ip] == 3:
                alert_msg = f"Brute-force attack from IP: {ip} (3+ failed logins)."
                suspicious_activities.append(alert_msg)
                if filter_var.get() in ["All", "Alerts"]:
                    output_area.insert(tk.END, f"🚨 [ALERT] {alert_msg}\n", 'alert')

        unauthorized_match = unauthorized_access_pattern.search(line)
        if unauthorized_match:
            filepath = unauthorized_match.group(1)
            alert_msg = f"Unauthorized file access detected: {filepath}"
            suspicious_activities.append(alert_msg)
            if filter_var.get() in ["All", "Alerts"]:
                output_area.insert(tk.END, f"🚨 [ALERT] {alert_msg}\n", 'alert')

        permission_match = permission_change_pattern.search(line)
        if permission_match:
            filepath = permission_match.group(1)
            alert_msg = f"Sensitive file permission change: {filepath}"
            suspicious_activities.append(alert_msg)
            if filter_var.get() in ["All", "Alerts"]:
                output_area.insert(tk.END, f"🚨 [ALERT] {alert_msg}\n", 'alert')

        failed_command_match = failed_command_pattern.search(line)
        if failed_command_match:
            alert_msg = f"Suspicious malware execution detected."
            suspicious_activities.append(alert_msg)
            if filter_var.get() in ["All", "Alerts"]:
                output_area.insert(tk.END, f"🚨 [ALERT] {alert_msg}\n", 'alert')

        if filter_var.get() in ["All", "Logs"]:
            output_area.insert(tk.END, f"[LOG] {line}\n", 'log')

        progress_var.set((idx / total_log_entries) * 100)
        output_area.update_idletasks()

    output_area.insert(tk.END, "\n" + "="*50 + "\n")
    output_area.insert(tk.END, "      ✅ Log Analysis Report\n", 'heading')
    output_area.insert(tk.END, "="*50 + "\n")
    output_area.insert(tk.END, f"Total log entries processed: {total_log_entries}\n")
    output_area.insert(tk.END, "-"*50 + "\n")

    if suspicious_activities:
        output_area.insert(tk.END, "🚨 Summary of Suspicious Activities:\n", 'alert-summary')
        for activity in suspicious_activities:
            output_area.insert(tk.END, f"  - {activity}\n", 'alert-summary')
    else:
        output_area.insert(tk.END, "✅ No suspicious activities detected.\n", 'success')

    output_area.insert(tk.END, "="*50 + "\n")
    status_label.config(text="✅ Analysis completed successfully.")
    output_area.config(state='disabled')

def browse_file(entry_field):
    file_path = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Log files", "*.log"), ("All files", "*.*")]
    )
    if file_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)

def save_analysis(output_area):
    content = output_area.get('1.0', tk.END)
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(content)
        messagebox.showinfo("Saved", f"Analysis saved to {file_path}")

def create_gui():
    window = tk.Tk()
    window.title("🔎 Dark Log Analyzer & Suspicious Activity Detector")
    window.geometry("1000x700")
    window.configure(bg=BG_COLOR)

    heading_label = tk.Label(window, text="📁 Log File Analyzer & Suspicious Activity Detector",
                             font=("Arial", 18, "bold"), bg=BG_COLOR, fg=FG_COLOR)
    heading_label.pack(pady=10)

    file_frame = tk.Frame(window, bg=BG_COLOR)
    file_frame.pack(pady=5)

    file_entry = tk.Entry(file_frame, width=70, font=("Arial", 12), bg="#2b2b2b", fg=FG_COLOR, insertbackground=FG_COLOR)
    file_entry.pack(side=tk.LEFT, padx=5)

    browse_btn = tk.Button(file_frame, text="Browse", bg=BUTTON_BG, fg=BUTTON_FG, font=("Arial", 11, "bold"),
                           command=lambda: browse_file(file_entry))
    browse_btn.pack(side=tk.LEFT, padx=5)

    filter_var = tk.StringVar(value="All")
    filter_dropdown = ttk.Combobox(window, textvariable=filter_var, values=["All", "Logs", "Alerts"], width=15)
    filter_dropdown.pack(pady=5)

    btn_frame = tk.Frame(window, bg=BG_COLOR)
    btn_frame.pack(pady=5)

    analyze_btn = tk.Button(btn_frame, text="Start Analysis", font=("Arial", 13, "bold"), bg="#28a745", fg=BUTTON_FG,
                            command=lambda: analyze_log(file_entry.get(), output_area, status_label, progress_var, filter_var))
    analyze_btn.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)

    save_btn = tk.Button(btn_frame, text="Save Report", font=("Arial", 12, "bold"), bg="#17a2b8", fg=BUTTON_FG,
                         command=lambda: save_analysis(output_area))
    save_btn.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=5)

    status_label = tk.Label(window, text="Select a log file to start analysis.", bg=BG_COLOR, fg=FG_COLOR, font=("Arial", 11))
    status_label.pack(pady=5)

    progress_var = tk.DoubleVar()
    progress_bar = ttk.Progressbar(window, variable=progress_var, maximum=100, length=900)
    progress_bar.pack(pady=5)

    output_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=120, height=30, font=("Courier", 10),
                                            bg="#2b2b2b", fg=FG_COLOR)
    output_area.pack(pady=10, fill=tk.BOTH, expand=True)

    output_area.tag_configure('alert', foreground=ALERT_COLOR, font=("Courier", 10, 'bold'))
    output_area.tag_configure('alert-summary', foreground=ALERT_COLOR, font=("Courier", 10, 'italic'))
    output_area.tag_configure('heading', font=("Courier", 11, 'bold'))
    output_area.tag_configure('success', foreground=SUCCESS_COLOR)
    output_area.tag_configure('info', foreground=INFO_COLOR)
    output_area.tag_configure('log', foreground=FG_COLOR)

    window.mainloop()

if __name__ == "__main__":
    create_gui()
