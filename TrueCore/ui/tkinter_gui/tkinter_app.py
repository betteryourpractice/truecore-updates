import os
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from tkinter import *
from tkinter import filedialog, ttk, simpledialog, messagebox

from tkinterdnd2 import TkinterDnD
from PIL import Image, ImageTk

# Engine modules
from TrueCore.core.packet_processor import process_packet
from TrueCore.medical.icd_lookup import load_icd_codes
from TrueCore.export.workbook_export import export_patient
from TrueCore.core.packet_triage import triage_packet

# Runtime helpers
from TrueCore.utils.runtime_info import (
    resource_path,
    ensure_runtime_environment,
    get_version,
    get_build_info,
    get_latest_update_title,

)

# App constants + dev utilities
from TrueCore.ui.truecore_app import (
    SUPPORTED_EXTENSIONS,
    LOGO_WIDTH,
    LOGO_HEIGHT,
    ADMIN_PASSWORD,
    MAX_WORKERS,
    load_changelog,
    load_activity_log,
    detect_development_cycle
)

# -------------------------------------------------
# MAIN APPLICATION
# -------------------------------------------------

class TrueCoreApp:

    def __init__(self, root):

        ensure_runtime_environment()
        load_icd_codes()

        self.root = root
        self.version = get_version()
        _, self.build_timestamp = get_build_info()

        self.verify_ui_methods()

        if not self.root.winfo_exists():
            return
        
        self.root.title(f"TrueCore Packet Auditor v{self.version}")
        self.root.state("zoomed")

        self.files = []
        self.results = {}

        self.approved_count = 0
        self.review_count = 0
        self.rejected_count = 0

        main = Frame(root)
        main.pack(fill=BOTH, expand=True)

        header = Frame(main)
        header.pack(fill=X, pady=10)

        title = Frame(header)
        title.pack()

        Label(title, text="TrueBrain™, LLC", font=("Arial", 18, "bold")).pack()
        Label(title, text="TrueValour Packet Auditor", font=("Arial", 14)).pack()
        Label(title, text=f"TrueCore Engine v{self.version}", font=("Arial", 10)).pack()

        if self.build_timestamp:
            
            update_title = get_latest_update_title()

            display_time = self.build_timestamp

            try:
                dt = datetime.strptime(self.build_timestamp, "%H:%M:%S")
                display_time = dt.strftime("%b %d, %Y %H:%M")

            except Exception:
                pass

            version_only = self.version.split(".")[0]
            text = f"Build TC{self.version}"
        
            if update_title:
                text += f" - Latest Update: {update_title} "

            text += f" • {display_time}"
        
            Label(
                title,
                text=text,
                font=("Arial", 9)
            ).pack()

        try:

            logo = Image.open(resource_path("assets/truebrain_logo.png"))
            logo = logo.resize((LOGO_WIDTH, LOGO_HEIGHT))

            self.logo_img = ImageTk.PhotoImage(logo)

            Label(header, image=self.logo_img).place(relx=0.98, rely=0.5, anchor="e")

        except Exception:
            pass

        buttons = Frame(main)
        buttons.pack(fill=X, pady=6)

        Button(buttons, text="Select Files", width=18, command=self.select_files).pack(side=LEFT, padx=6)
        Button(buttons, text="Analyze Packets", width=18, command=self.analyze).pack(side=LEFT, padx=6)
        Button(buttons, text="Analyze Folder", width=18, command=self.analyze_folder).pack(side=LEFT, padx=6)
        Button(buttons, text="Export Report", width=18, command=self.export_report).pack(side=LEFT, padx=6)
        Button(buttons, text="Clear Results", width=18, command=self.clear).pack(side=LEFT, padx=6)
        Button(buttons, text="Admin Panel", width=14, command=self.open_admin_panel).pack(side=RIGHT, padx=10)

        self.dashboard_label = Label(
            main,
            text="Approved: 0 | Needs Review: 0 | Rejected: 0",
            font=("Arial", 10, "bold")
        )
        self.dashboard_label.pack(pady=4)

        table_frame = Frame(main)
        table_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

        columns = ("file", "score", "issues")

        self.table = ttk.Treeview(table_frame, columns=columns, show="headings")

        self.table.heading("file", text="File")
        self.table.heading("score", text="Score")
        self.table.heading("issues", text="Issues")

        self.table.column("file", width=400)
        self.table.column("score", width=80, anchor=CENTER)
        self.table.column("issues", width=80, anchor=CENTER)

        self.table.pack(fill=BOTH, expand=True)
        # Packet score highlighting
        self.table.tag_configure("good", background="#d8f5d0")
        self.table.tag_configure("warning", background="#fff4c2")
        self.table.tag_configure("bad", background="#ffd6d6")  

        self.table.bind("<<TreeviewSelect>>", self.open_packet)

        output_frame = Frame(main)
        output_frame.pack(fill=BOTH, expand=True, padx=10, pady=6)

        scrollbar = Scrollbar(output_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.output = Text(
            output_frame,
            bg="#1e1e1e",
            fg="#d4d4d4",
            font=("Consolas", 11),
            wrap=WORD,
            yscrollcommand=scrollbar.set
        )

        self.output.pack(side=LEFT, fill=BOTH, expand=True)

        scrollbar.config(command=self.output.yview)

        # -------------------------------------------------
        # COLOR TAGS (RESTORED FROM v1.3)
        # -------------------------------------------------

        self.output.tag_config("header", foreground="#4ea3ff", font=("Consolas", 14, "bold"))
        self.output.tag_config("score", foreground="#44d17a")
        self.output.tag_config("missing", foreground="#ff4c4c")
        self.output.tag_config("issue", foreground="#ff4c4c")
        self.output.tag_config("fix", foreground="#ffcc00")

    def update_dashboard(self):

        text = (
            f"Approved: {self.approved_count} | "
            f"Needs Review: {self.review_count} | "
            f"Rejected: {self.rejected_count}"
        )

        self.dashboard_label.config(text=text)

    # -------------------------------------------------
    # UI METHOD GUARD
    # -------------------------------------------------

    def verify_ui_methods(self):

        required = [
            "select_files",
            "analyze",
            "analyze_folder",
            "export_report",
            "clear",
            "open_admin_panel"
        ]

        missing = [m for m in required if not hasattr(self, m)]

        if missing:

            messagebox.showerror(
                "Startup Error",
                f"Missing UI methods:\n{', '.join(missing)}"
            )

            self.root.destroy()

    # -------------------------------------------------
    # FILE SELECTION
    # -------------------------------------------------

    def select_files(self):

        files = filedialog.askopenfilenames()

        for f in files:

            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                self.files.append(f)

        self.output.insert(END, f"Loaded {len(self.files)} files\n")

    # -------------------------------------------------
    # ANALYSIS
    # -------------------------------------------------

    def analyze(self):

        self.table.delete(*self.table.get_children())

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

            futures = {executor.submit(process_packet, file): file for file in self.files}

            for future in as_completed(futures):

                file = futures[future]
                result = future.result()

                score = result.get("score", 0)
                issues = len(result.get("issues", []))

                self.results[file] = result

                tag = None
                if score >= 90:
                    tag = "good"
                    self.approved_count += 1
                    export_patient(result.get("fields", {}), file)
                elif score >= 70:
                    tag = "warning"
                    self.review_count += 1
                else:
                    tag = "bad"
                    self.rejected_count += 1
                self.update_dashboard()

                # Packet triage
                triage_packet(file, score)
                
                self.table.insert(
                    "",
                    END,
                    values=(os.path.basename(file), score, issues),
                    iid=file,
                    tags=(tag,)
                )

    def analyze_folder(self):

        folder = filedialog.askdirectory()

        if not folder:
            return

        files = []

        for r, dirs, fs in os.walk(folder):

            for f in fs:

                if f.lower().endswith(SUPPORTED_EXTENSIONS):
                    files.append(os.path.join(r, f))

        self.files = files
        self.analyze()

    # -------------------------------------------------
    # PACKET DETAIL VIEW
    # -------------------------------------------------

    def open_packet(self, event):

        item = self.table.focus()

        if not item:
            return

        result = self.results.get(item)

        if not result:
            return

        self.output.delete(1.0, END)

        fields = result.get("fields", {})
        forms = result.get("forms", [])
        issues = result.get("issues", [])
        fixes = result.get("fixes", [])
        score = result.get("score", 0)

        self.output.insert(END, f"PACKET: {os.path.basename(item)}\n\n", "header")
        self.output.insert(END, f"Score: {score}%\n\n", "score")

        self.output.insert(END, "Forms\n")

        for f in forms:
            self.output.insert(END, f"✓ {f}\n")

        self.output.insert(END, "\nFields\n")

        for k, v in fields.items():

            if isinstance(v, list):
                v = ", ".join(v)

            tag = "missing" if not v else None

            if tag:
                self.output.insert(END, f"{k}: {v}\n", tag)
            else:
                self.output.insert(END, f"{k}: {v}\n")

        if issues:

            self.output.insert(END, "\nIssues\n")

            for i in issues:
                self.output.insert(END, f"{i}\n", "issue")

        if fixes:

            self.output.insert(END, "\nSuggested Fixes\n")

            for f in fixes:
                self.output.insert(END, f"{f}\n", "fix")

    # -------------------------------------------------
    # EXPORT
    # -------------------------------------------------

    def export_report(self):

        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return

        filename = f"TrueCore_Audit_Report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

        path = filedialog.asksaveasfilename(
            initialfile=filename,
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )

        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as csvfile:

            writer = csv.writer(csvfile)

            writer.writerow(["File", "Score", "Issues", "Forms Detected"])

            for file, result in self.results.items():

                forms = "; ".join(result.get("forms", []))
                issues = len(result.get("issues", []))
                score = result.get("score", 0)

                writer.writerow([
                    os.path.basename(file),
                    score,
                    issues,
                    forms
                ])

        messagebox.showinfo("Export Complete", "Audit report exported successfully.")

    # -------------------------------------------------
    # CLEAR RESULTS
    # -------------------------------------------------

    def clear(self):

        self.files.clear()
        self.results.clear()

        self.table.delete(*self.table.get_children())
        self.output.delete(1.0, END)

        self.approved_count = 0
        self.review_count = 0
        self.rejected_count = 0
        self.update_dashboard()

    # -------------------------------------------------
    # ADMIN PANEL
    # -------------------------------------------------

    def open_admin_panel(self):

        password = simpledialog.askstring("Admin Access", "Enter admin password:", show="*")

        if password != ADMIN_PASSWORD:
            return

        admin = Toplevel(self.root)
        admin.title("TrueCore Admin Panel")
        admin.geometry("1000x700")

        topbar = Frame(admin)
        topbar.pack(fill=X)

        text = Text(admin, font=("Consolas", 11), wrap=WORD)
        text.pack(fill=BOTH, expand=True)

        Button(
            topbar,
            text="Refresh",
            command=lambda: self.populate_admin(text)
        ).pack(side=RIGHT, padx=10, pady=5)

        self.populate_admin(text)


    def populate_admin(self, text):

        text.config(state=NORMAL)
        text.delete(1.0, END)


        changelog = load_changelog()
        activity = load_activity_log()

        text.insert(END, "TRUECORE SYSTEM OVERVIEW\n\n")

        cycle = detect_development_cycle(changelog)

        text.insert(END, "Recent Updates\n\n")
        
        # -------------------------------------------------
        # FORMAT CHANGELOG BY VERSION BLOCKS
        # -------------------------------------------------

        blocks = changelog.split("VERSION:")
        blocks = [b.strip() for b in blocks if b.strip()]
        blocks.reverse()
        blocks = blocks[:10]

        for block in blocks:
            text.insert(END, "VERSION: " + block + "\n\n")

        text.insert(END, "\n\nActivity Log\n\n")
        text.insert(END, activity)

        text.config(state=DISABLED)

# -------------------------------------------------
# GUI LAUNCHER
# -------------------------------------------------

def launch_gui():

    root = TkinterDnD.Tk()

    app = TrueCoreApp(root)

    root.mainloop()