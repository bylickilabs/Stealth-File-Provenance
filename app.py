import os
import hashlib
import mimetypes
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
import platform
import binascii
import webbrowser

try:
    import piexif
except ImportError:
    piexif = None
    
try:
    import PyPDF2
except ImportError:
    PyPDF2 = None
    
try:
    import docx
except ImportError:
    docx = None

LANG = {
    'de': {
        'app_title': 'Stealth File Provenance Inspector | ©Thorsten Bylicki | ©BYLICKILABS',
        'select_file': 'Datei auswählen',
        'analyze': 'Analysieren',
        'export': 'Exportieren',
        'report': 'Ergebnisbericht',
        'file_info': 'Dateiinformationen',
        'hashes': 'Hashwerte',
        'metadata': 'Metadaten',
        'anomalies': 'Anomalien',
        'timestamp': 'Zeitstempel',
        'filetype': 'Dateityp',
        'magic': 'Magic Number',
        'no_file': 'Keine Datei gewählt!',
        'success_export': 'Bericht erfolgreich exportiert.',
        'err_export': 'Fehler beim Export.',
        'choose_lang': 'Sprache',
        'mode': 'Modus',
        'dark': 'Dunkel',
        'light': 'Hell',
        'info': 'Info',
        'info_title': 'Über die Anwendung',
        'info_text': (
            'Der Stealth File Provenance Inspector ermöglicht forensische Analysen beliebiger Dateien.\n\n'
            'Die Anwendung erkennt Manipulationen, prüft Dateityp, Magic Number, Hashwerte und Metadaten (EXIF, PDF, DOCX).\n\n'
            'Sie unterstützt Dark/Light Mode, Sprachumschaltung, Exportfunktion und ist vollständig offline nutzbar.\n\n'
            'Ideal für IT-Forensik, Datenschutz, Compliance und Security-Audits.'
        ),
        'github': 'GitHub'
    },
    'en': {
        'app_title': 'Stealth File Provenance Inspector | ©Thorsten Bylicki | ©BYLICKILABS',
        'select_file': 'Select file',
        'analyze': 'Analyze',
        'export': 'Export',
        'report': 'Report',
        'file_info': 'File Info',
        'hashes': 'Hashes',
        'metadata': 'Metadata',
        'anomalies': 'Anomalies',
        'timestamp': 'Timestamps',
        'filetype': 'Filetype',
        'magic': 'Magic Number',
        'no_file': 'No file selected!',
        'success_export': 'Report exported successfully.',
        'err_export': 'Export failed.',
        'choose_lang': 'Language',
        'mode': 'Mode',
        'dark': 'Dark',
        'light': 'Light',
        'info': 'Info',
        'info_title': 'About This Application',
        'info_text': (
            'The Stealth File Provenance Inspector enables forensic analysis of any file.\n\n'
            'The app detects manipulation, checks file type, magic number, hash values, and metadata (EXIF, PDF, DOCX).\n\n'
            'Features include dark/light mode, language switching, export, and full offline operation.\n\n'
            'Ideal for IT forensics, data privacy, compliance, and security audits.'
        ),
        'github': 'GitHub'
    }
}

GITHUB_URL = "https://github.com/bylickilabs"

class ProvenanceInspectorApp:
    def __init__(self, root):
        self.root = root
        self.lang = 'de'
        self.darkmode = False
        self.selected_file = None
        self.analysis_result = ""
        self.build_gui()
        self.set_theme()

    def build_gui(self):
        self.root.title(LANG[self.lang]['app_title'])
        self.root.geometry('950x740')
        self.root.minsize(870, 600)

        self.style = ttk.Style(self.root)
        self.style.theme_use('default')

        self.top = ttk.Frame(self.root)
        self.top.pack(fill='x', padx=12, pady=7)

        self.btn_select = ttk.Button(self.top, text=LANG[self.lang]['select_file'], command=self.select_file, width=16)
        self.btn_select.pack(side='left', padx=4)

        self.btn_analyze = ttk.Button(self.top, text=LANG[self.lang]['analyze'], command=self.analyze_file, width=16)
        self.btn_analyze.pack(side='left', padx=4)

        self.btn_export = ttk.Button(self.top, text=LANG[self.lang]['export'], command=self.export_report, state='disabled', width=16)
        self.btn_export.pack(side='left', padx=4)

        self.btn_github = ttk.Button(self.top, text=LANG[self.lang]['github'], command=self.open_github, width=12)
        self.btn_github.pack(side='right', padx=4)

        self.btn_info = ttk.Button(self.top, text=LANG[self.lang]['info'], command=self.show_info, width=12)
        self.btn_info.pack(side='right', padx=4)

        self.mode_var = tk.StringVar(value=LANG[self.lang]['light'])
        mode_label = ttk.Label(self.top, text=LANG[self.lang]['mode'] + ":")
        mode_label.pack(side='right', padx=2)
        self.mode_switch = ttk.Combobox(self.top, values=[LANG[self.lang]['light'], LANG[self.lang]['dark']],
                                        width=8, state='readonly', textvariable=self.mode_var)
        self.mode_switch.pack(side='right')
        self.mode_switch.bind("<<ComboboxSelected>>", self.toggle_mode)

        self.lang_var = tk.StringVar(value=self.lang)
        lang_label = ttk.Label(self.top, text=LANG[self.lang]['choose_lang'] + ":")
        lang_label.pack(side='right', padx=(10, 2))
        self.lang_switch = ttk.Combobox(self.top, values=['de', 'en'], width=3, state='readonly', textvariable=self.lang_var)
        self.lang_switch.pack(side='right')
        self.lang_switch.bind("<<ComboboxSelected>>", self.switch_language)

        main = ttk.Frame(self.root)
        main.pack(fill='both', expand=True, padx=12, pady=7)

        self.report = scrolledtext.ScrolledText(main, font=('Consolas', 11), wrap='word')
        self.report.pack(fill='both', expand=True)
        self.report.config(state='disabled')

    def set_theme(self):
        bg = '#232323' if self.darkmode else '#f4f4f4'
        fg = '#fff' if self.darkmode else '#111'
        txt_bg = '#181818' if self.darkmode else '#fff'
        txt_fg = '#f8f8f8' if self.darkmode else '#111'
        entry_bg = '#2a2a2a' if self.darkmode else '#fff'
        entry_fg = '#fff' if self.darkmode else '#111'
        hilite_bg = '#444' if self.darkmode else "#cce6ff"

        self.root.configure(bg=bg)
        self.top.configure(style='TFrame')
        self.style.configure('TFrame', background=bg)
        self.style.configure('TLabel', background=bg, foreground=fg)
        self.style.configure('TButton', background=bg, foreground=fg)
        self.style.configure('TCombobox',
                             fieldbackground=entry_bg,
                             background=entry_bg,
                             foreground=entry_fg)
        self.report.config(bg=txt_bg, fg=txt_fg, insertbackground=txt_fg, selectbackground=hilite_bg)
        try:
            self.lang_switch.configure(background=entry_bg, foreground=entry_fg)
            self.mode_switch.configure(background=entry_bg, foreground=entry_fg)
        except Exception:
            pass

    def switch_language(self, event=None):
        self.lang = self.lang_var.get()
        self.root.title(LANG[self.lang]['app_title'])
        self.btn_select.config(text=LANG[self.lang]['select_file'])
        self.btn_analyze.config(text=LANG[self.lang]['analyze'])
        self.btn_export.config(text=LANG[self.lang]['export'])
        self.btn_info.config(text=LANG[self.lang]['info'])
        self.btn_github.config(text=LANG[self.lang]['github'])
        for child in self.top.winfo_children():
            if isinstance(child, ttk.Label):
                txt = child.cget("text").split(":")[0].lower()
                for k, v in LANG[self.lang].items():
                    if v.split(":")[0].lower() == txt:
                        child.config(text=LANG[self.lang][k] + ":")
                        break
        self.mode_switch['values'] = [LANG[self.lang]['light'], LANG[self.lang]['dark']]
        self.mode_var.set(LANG[self.lang]['dark'] if self.darkmode else LANG[self.lang]['light'])
        self.set_theme()

    def toggle_mode(self, event=None):
        sel = self.mode_var.get()
        if sel.lower().startswith("d"):
            self.darkmode = True
        else:
            self.darkmode = False
        self.set_theme()

    def select_file(self):
        path = filedialog.askopenfilename(title=LANG[self.lang]['select_file'], filetypes=[("Alle Dateien", "*.*")])
        if path:
            self.selected_file = path
            messagebox.showinfo(LANG[self.lang]['file_info'], f"{LANG[self.lang]['file_info']}: {os.path.basename(path)}")

    def analyze_file(self):
        if not self.selected_file:
            messagebox.showwarning("Warnung", LANG[self.lang]['no_file'])
            return

        info = self.collect_file_info(self.selected_file)
        hashes = self.compute_hashes(self.selected_file)
        magic = self.get_magic(self.selected_file)
        anomalies = self.check_anomalies(info, magic)
        metadata = self.read_metadata(self.selected_file)

        report = []
        report.append(f"=== {LANG[self.lang]['file_info']} ===\n")
        for k, v in info.items():
            report.append(f"{k}: {v}")
        report.append(f"\n=== {LANG[self.lang]['hashes']} ===\n")
        for k, v in hashes.items():
            report.append(f"{k}: {v}")
        report.append(f"\n=== {LANG[self.lang]['filetype']} / {LANG[self.lang]['magic']} ===\n")
        report.append(f"Extension: {magic['extension']}")
        report.append(f"MIME: {magic['mime']}")
        report.append(f"Magic Number: {magic['magic']}")
        report.append(f"\n=== {LANG[self.lang]['metadata']} ===\n")
        for k, v in metadata.items():
            report.append(f"{k}: {v}")
        report.append(f"\n=== {LANG[self.lang]['anomalies']} ===\n")
        for k, v in anomalies.items():
            report.append(f"{k}: {v}")
        self.analysis_result = "\n".join(report)

        self.report.config(state='normal')
        self.report.delete(1.0, 'end')
        self.report.insert('end', self.analysis_result)
        self.report.config(state='disabled')
        self.btn_export.config(state='normal')

    def export_report(self):
        if not self.analysis_result:
            return
        try:
            fname = filedialog.asksaveasfilename(title=LANG[self.lang]['export'], defaultextension=".txt", filetypes=[("Textdatei", "*.txt")])
            if fname:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(self.analysis_result)
                messagebox.showinfo("Info", LANG[self.lang]['success_export'])
        except Exception as e:
            messagebox.showerror("Fehler", LANG[self.lang]['err_export'] + f"\n{e}")

    def collect_file_info(self, filepath):
        stat = os.stat(filepath)
        creation = self.fmt_time(stat.st_ctime)
        modified = self.fmt_time(stat.st_mtime)
        accessed = self.fmt_time(stat.st_atime)
        size = f"{stat.st_size} Bytes"
        info = {
            LANG[self.lang]['file_info']: os.path.basename(filepath),
            LANG[self.lang]['timestamp']+' (created)': creation,
            LANG[self.lang]['timestamp']+' (modified)': modified,
            LANG[self.lang]['timestamp']+' (accessed)': accessed,
            "Pfad / Path": filepath,
            "Größe / Size": size,
            "OS": platform.system()
        }
        return info

    def fmt_time(self, t):
        return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")

    def compute_hashes(self, filepath):
        hashes = {}
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            try:
                h = hashlib.new(algo)
                with open(filepath, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''):
                        h.update(chunk)
                hashes[algo.upper()] = h.hexdigest()
            except Exception as e:
                hashes[algo.upper()] = f"Error: {e}"
        return hashes

    def get_magic(self, filepath):
        mime, _ = mimetypes.guess_type(filepath)
        ext = os.path.splitext(filepath)[1]
        try:
            with open(filepath, 'rb') as f:
                magic_bytes = f.read(12)
            magic = binascii.hexlify(magic_bytes).decode()
        except Exception as e:
            magic = f"Error: {e}"
        return {
            'extension': ext,
            'mime': mime,
            'magic': magic
        }

    def check_anomalies(self, info, magic):
        anomalies = {}
        ext = magic['extension'].lower()
        mime = magic['mime']
        magicstr = magic['magic']
        if mime and ext:
            if not mime.endswith(ext.replace('.', '')):
                anomalies['MIME-Extension Mismatch'] = f"{mime} vs. {ext}"
        if not magicstr or magicstr.startswith("Error"):
            anomalies['Magic Number Problem'] = f"{magicstr}"
        try:
            created = datetime.strptime(info[LANG[self.lang]['timestamp']+' (created)'], "%Y-%m-%d %H:%M:%S")
            modified = datetime.strptime(info[LANG[self.lang]['timestamp']+' (modified)'], "%Y-%m-%d %H:%M:%S")
            if created > modified:
                anomalies['Timestamps Anomaly'] = f"Creation ({created}) > Modified ({modified})"
        except Exception as e:
            anomalies['Timestamp Error'] = f"{e}"
        return anomalies

    def read_metadata(self, filepath):
        meta = {}
        ext = os.path.splitext(filepath)[1].lower()
        try:
            if ext in ['.jpg', '.jpeg', '.tiff', '.png'] and piexif:
                exif = piexif.load(filepath)
                meta['EXIF'] = {k: str(v)[:120] for k, v in exif.items()}
            elif ext == '.pdf' and PyPDF2:
                with open(filepath, 'rb') as f:
                    pdf = PyPDF2.PdfReader(f)
                    meta['PDF-Info'] = str(pdf.metadata)
            elif ext == '.docx' and docx:
                doc = docx.Document(filepath)
                cp = doc.core_properties
                meta['DOCX-Meta'] = {a: str(getattr(cp, a)) for a in dir(cp) if not a.startswith("_")}
            else:
                meta['Standard'] = "No specialized metadata handler"
        except Exception as e:
            meta['Error'] = str(e)
        return meta

    def show_info(self):
        info_window = tk.Toplevel(self.root)
        info_window.title(LANG[self.lang]['info_title'])
        info_window.geometry("500x270")
        info_window.resizable(False, False)
        bg = '#232323' if self.darkmode else '#f4f4f4'
        fg = '#fff' if self.darkmode else '#111'
        info_window.configure(bg=bg)

        content = tk.Frame(info_window, bg=bg)
        content.pack(fill="both", expand=True, padx=18, pady=18)

        lbl = tk.Label(
            content,
            text=LANG[self.lang]['info_text'],
            wraplength=450,
            justify="left",
            anchor="w",
            bg=bg,
            fg=fg,
            font=("Segoe UI", 11)
        )
        lbl.pack(fill="both", expand=True, padx=8, pady=8)

        btn = ttk.Button(content, text="OK", command=info_window.destroy)
        btn.pack(pady=(10, 2), anchor="e")

    def open_github(self):
        webbrowser.open_new_tab(GITHUB_URL)

if __name__ == "__main__":
    root = tk.Tk()
    app = ProvenanceInspectorApp(root)
    root.mainloop()