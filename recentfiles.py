"""
Windows MRU / Recently Used Registry Extractor (Educational)

- Reads common MRU keys from HKCU (Current User).
- Displays results in a simple Tkinter GUI.
- Exports results to CSV.
- Heavily commented for students learning:
    * Windows Registry structure
    * winreg usage
    * basic decoding of MRU binary data
    * GUI + table rendering

SAFETY / ETHICS NOTE:
This is intended for authorized, educational, or forensic-lab use on systems
where you have explicit permission. Reading MRU history can reveal sensitive
user activity.

Tested conceptually for Windows 10/11 with Python 3.9+.
"""

import sys
import os
import csv
import binascii
import datetime
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# winreg is only available on Windows
try:
    import winreg
except ImportError:
    winreg = None


# -----------------------------
# Utility functions (decoding, formatting)
# -----------------------------

def now_iso():
    """Return current time in ISO-ish format for logs/exports."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_str(x):
    """Convert anything to a safe string for GUI/CSV."""
    try:
        return "" if x is None else str(x)
    except Exception:
        return "<unprintable>"


def bytes_to_hex_preview(b: bytes, max_len: int = 64) -> str:
    """
    Return a short hex preview of bytes for display when decoding isn't clear.
    Example: '01 02 0A ...'
    """
    if not b:
        return ""
    preview = b[:max_len]
    hex_str = " ".join(f"{byte:02X}" for byte in preview)
    if len(b) > max_len:
        hex_str += " ..."
    return hex_str


def try_decode_mru_bytes(b: bytes) -> str:
    """
    Attempt to decode MRU bytes into a human-readable string.

    Many MRU values are:
      - UTF-16LE null-terminated strings
      - ASCII strings
      - binary PIDL structures containing strings embedded inside

    Strategy:
      1) Try UTF-16LE decode and strip nulls if it looks plausible.
      2) Try UTF-8/ASCII with replacement.
      3) As a fallback, search for readable substrings inside the bytes.
      4) If still unclear, return a hex preview.
    """
    if not b:
        return ""

    # 1) UTF-16LE attempt
    try:
        s = b.decode("utf-16le", errors="ignore")
        # Remove null characters and whitespace noise
        s_clean = s.replace("\x00", "").strip()
        # Heuristic: if it contains reasonable printable chars and isn't empty
        if s_clean and any(ch.isalnum() for ch in s_clean):
            return s_clean
    except Exception:
        pass

    # 2) UTF-8 attempt (rare, but sometimes helpful)
    try:
        s = b.decode("utf-8", errors="ignore").strip()
        if s and any(ch.isalnum() for ch in s):
            return s
    except Exception:
        pass

    # 3) ASCII attempt
    try:
        s = b.decode("ascii", errors="ignore").strip()
        if s and any(ch.isalnum() for ch in s):
            return s
    except Exception:
        pass

    # 4) Substring extraction: keep only "printable-ish" sequences
    # This is a simplistic approach: it can pull out embedded paths.
    printable = []
    current = []
    for byte in b:
        # printable ASCII range
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= 6:  # only keep meaningful chunks
                printable.append("".join(current))
            current = []
    if len(current) >= 6:
        printable.append("".join(current))

    if printable:
        # Join chunks with separator; often reveals a file path
        return " | ".join(printable[:5])

    # 5) Final fallback
    return bytes_to_hex_preview(b)


def reg_type_to_name(t):
    """Map winreg type integer to a friendly name."""
    mapping = {
        winreg.REG_SZ: "REG_SZ",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_QWORD: "REG_QWORD",
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_NONE: "REG_NONE",
    }
    return mapping.get(t, f"REG_TYPE_{t}")


# -----------------------------
# Registry reading helpers
# -----------------------------

def open_key(root, path):
    """
    Open a registry key read-only.
    Returns handle or raises FileNotFoundError / OSError.
    """
    return winreg.OpenKey(root, path, 0, winreg.KEY_READ)


def enum_values(key_handle):
    """
    Enumerate all values under a key.
    Returns a list of tuples: (value_name, value_data, value_type)
    """
    results = []
    i = 0
    while True:
        try:
            name, data, vtype = winreg.EnumValue(key_handle, i)
            results.append((name, data, vtype))
            i += 1
        except OSError:
            # No more values
            break
    return results


def enum_subkeys(key_handle):
    """
    Enumerate subkeys under a key.
    Returns list of subkey names.
    """
    results = []
    i = 0
    while True:
        try:
            sub = winreg.EnumKey(key_handle, i)
            results.append(sub)
            i += 1
        except OSError:
            break
    return results


# -----------------------------
# MRU extractors (each returns list of "rows")
# Row schema: dict with keys:
#   source, reg_path, value_name, value_type, decoded_value
# -----------------------------

def extract_recentdocs():
    """
    Extract MRU entries from RecentDocs.

    Path:
      HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

    Notes:
      - Values include numbers like "0", "1", etc plus "MRUListEx".
      - Subkeys per file extension (e.g., .txt, .docx) also contain MRUs.
      - Many are UTF-16LE strings or binary with embedded strings.
    """
    rows = []
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

    try:
        with open_key(winreg.HKEY_CURRENT_USER, base) as k:
            # Extract values at the root
            for name, data, vtype in enum_values(k):
                rows.append({
                    "source": "RecentDocs (root)",
                    "reg_path": base,
                    "value_name": name,
                    "value_type": reg_type_to_name(vtype),
                    "decoded_value": decode_reg_data(data, vtype),
                })

            # Extract subkeys (by extension)
            for sub in enum_subkeys(k):
                sub_path = base + "\\" + sub
                try:
                    with open_key(winreg.HKEY_CURRENT_USER, sub_path) as sk:
                        for name, data, vtype in enum_values(sk):
                            rows.append({
                                "source": f"RecentDocs ({sub})",
                                "reg_path": sub_path,
                                "value_name": name,
                                "value_type": reg_type_to_name(vtype),
                                "decoded_value": decode_reg_data(data, vtype),
                            })
                except OSError:
                    # subkey might disappear or be unreadable; skip
                    continue

    except FileNotFoundError:
        # Not all systems/users have this populated
        pass

    return rows


def extract_runmru():
    """
    Extract Run dialog history.

    Path:
      HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
    """
    rows = []
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    try:
        with open_key(winreg.HKEY_CURRENT_USER, path) as k:
            for name, data, vtype in enum_values(k):
                rows.append({
                    "source": "RunMRU",
                    "reg_path": path,
                    "value_name": name,
                    "value_type": reg_type_to_name(vtype),
                    "decoded_value": decode_reg_data(data, vtype),
                })
    except FileNotFoundError:
        pass
    return rows


def extract_wordwheelquery():
    """
    Extract Explorer search box history (WordWheelQuery).

    Path:
      HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
    """
    rows = []
    path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
    try:
        with open_key(winreg.HKEY_CURRENT_USER, path) as k:
            for name, data, vtype in enum_values(k):
                rows.append({
                    "source": "WordWheelQuery",
                    "reg_path": path,
                    "value_name": name,
                    "value_type": reg_type_to_name(vtype),
                    "decoded_value": decode_reg_data(data, vtype),
                })
    except FileNotFoundError:
        pass
    return rows


def extract_comdlg32_mrus():
    """
    Extract common-file-dialog MRUs from ComDlg32.

    Base path:
      HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32

    Common subkeys:
      - OpenSavePidlMRU (binary PIDL structures, but often contains paths/filenames)
      - OpenSaveMRU (sometimes friendlier strings)
      - LastVisitedPidlMRU (recent folders/apps used in open/save dialogs)
    """
    rows = []
    base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
    subkeys = ["OpenSavePidlMRU", "OpenSaveMRU", "LastVisitedPidlMRU"]

    for sub in subkeys:
        path = base + "\\" + sub
        try:
            with open_key(winreg.HKEY_CURRENT_USER, path) as k:
                # values at this subkey
                for name, data, vtype in enum_values(k):
                    rows.append({
                        "source": f"ComDlg32\\{sub} (root)",
                        "reg_path": path,
                        "value_name": name,
                        "value_type": reg_type_to_name(vtype),
                        "decoded_value": decode_reg_data(data, vtype),
                    })

                # Some of these keys have subkeys (e.g. file extensions under OpenSaveMRU)
                for child in enum_subkeys(k):
                    child_path = path + "\\" + child
                    try:
                        with open_key(winreg.HKEY_CURRENT_USER, child_path) as ck:
                            for name, data, vtype in enum_values(ck):
                                rows.append({
                                    "source": f"ComDlg32\\{sub} ({child})",
                                    "reg_path": child_path,
                                    "value_name": name,
                                    "value_type": reg_type_to_name(vtype),
                                    "decoded_value": decode_reg_data(data, vtype),
                                })
                    except OSError:
                        continue
        except FileNotFoundError:
            continue

    return rows


def decode_reg_data(data, vtype) -> str:
    """
    Convert registry data to a readable string, based on registry type.

    Important:
    - REG_SZ / REG_EXPAND_SZ: already string
    - REG_DWORD / REG_QWORD: integers
    - REG_MULTI_SZ: list of strings
    - REG_BINARY: bytes -> try decode
    """
    try:
        if vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            return safe_str(data)
        if vtype == winreg.REG_MULTI_SZ:
            return "; ".join(data) if isinstance(data, list) else safe_str(data)
        if vtype in (winreg.REG_DWORD, winreg.REG_QWORD):
            return str(int(data))
        if vtype == winreg.REG_BINARY:
            if isinstance(data, (bytes, bytearray)):
                decoded = try_decode_mru_bytes(bytes(data))
                # Show both decoded and a short hex preview if decoding is "thin"
                # (This helps students understand the underlying bytes.)
                if decoded and decoded != bytes_to_hex_preview(bytes(data)):
                    return f"{decoded}   [hex: {bytes_to_hex_preview(bytes(data))}]"
                return decoded or bytes_to_hex_preview(bytes(data))
            return safe_str(data)
        # Catch-all
        return safe_str(data)
    except Exception:
        return "<decode error>"


def collect_all_mrus():
    """
    Run all extractors and return a single combined list of rows.
    """
    rows = []
    rows.extend(extract_recentdocs())
    rows.extend(extract_runmru())
    rows.extend(extract_wordwheelquery())
    rows.extend(extract_comdlg32_mrus())

    # Add a timestamp column so exports show when collection happened
    stamp = now_iso()
    for r in rows:
        r["collected_at"] = stamp
    return rows


# -----------------------------
# GUI application
# -----------------------------

class MRUApp(tk.Tk):
    """
    Tkinter main window.

    Features:
    - "Scan" button to read registry
    - Search filter box (simple substring filter)
    - Treeview table for results
    - Export to CSV
    - Status bar with counts
    """

    def __init__(self):
        super().__init__()

        self.title("Windows MRU / Recently Used Registry Extractor (Educational)")
        self.geometry("1200x650")

        # Keep raw results in memory for filtering/export
        self.all_rows = []

        # Top controls frame
        controls = ttk.Frame(self, padding=10)
        controls.pack(side=tk.TOP, fill=tk.X)

        self.scan_btn = ttk.Button(controls, text="Scan MRU Registry Keys", command=self.scan)
        self.scan_btn.pack(side=tk.LEFT)

        ttk.Label(controls, text="   Filter:").pack(side=tk.LEFT)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(controls, textvariable=self.filter_var, width=40)
        self.filter_entry.pack(side=tk.LEFT, padx=(5, 5))
        self.filter_entry.bind("<KeyRelease>", lambda e: self.apply_filter())

        self.export_btn = ttk.Button(controls, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.clear_btn = ttk.Button(controls, text="Clear", command=self.clear)
        self.clear_btn.pack(side=tk.LEFT, padx=(10, 0))

        # Table frame
        table_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Define columns for Treeview
        self.columns = ("collected_at", "source", "reg_path", "value_name", "value_type", "decoded_value")
        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings")

        # Human-friendly headers
        self.tree.heading("collected_at", text="Collected At")
        self.tree.heading("source", text="Source")
        self.tree.heading("reg_path", text="Registry Path")
        self.tree.heading("value_name", text="Value Name")
        self.tree.heading("value_type", text="Type")
        self.tree.heading("decoded_value", text="Decoded Value")

        # Reasonable column widths
        self.tree.column("collected_at", width=140, anchor=tk.W)
        self.tree.column("source", width=180, anchor=tk.W)
        self.tree.column("reg_path", width=380, anchor=tk.W)
        self.tree.column("value_name", width=120, anchor=tk.W)
        self.tree.column("value_type", width=90, anchor=tk.W)
        self.tree.column("decoded_value", width=900, anchor=tk.W)

        # Scrollbars
        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        status = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status.pack(side=tk.BOTTOM, fill=tk.X)

        # If not Windows, disable scan
        if winreg is None:
            self.scan_btn.configure(state=tk.DISABLED)
            self.status_var.set("winreg not available. This script must be run on Windows with Python.")

    def set_status(self, text):
        """Update status bar."""
        self.status_var.set(text)
        self.update_idletasks()

    def clear(self):
        """Clear results from table and reset state."""
        self.tree.delete(*self.tree.get_children())
        self.all_rows = []
        self.export_btn.configure(state=tk.DISABLED)
        self.set_status("Cleared.")

    def scan(self):
        """
        Scan registry and populate table.
        """
        try:
            self.set_status("Scanning MRU registry keys...")
            self.tree.delete(*self.tree.get_children())
            self.all_rows = collect_all_mrus()

            self.populate_table(self.all_rows)
            self.export_btn.configure(state=tk.NORMAL if self.all_rows else tk.DISABLED)

            self.set_status(f"Scan complete. Items found: {len(self.all_rows)}")
        except PermissionError:
            messagebox.showerror("Permission Error", "Access denied reading a registry key. Try running with appropriate permissions.")
            self.set_status("Permission error during scan.")
        except Exception as e:
            # For teaching: show a friendly error plus optional details
            messagebox.showerror("Error", f"Unexpected error:\n{e}\n\nDetails (for debugging):\n{traceback.format_exc()}")
            self.set_status("Error during scan.")

    def populate_table(self, rows):
        """
        Insert rows into the Treeview.
        """
        for r in rows:
            values = tuple(r.get(c, "") for c in self.columns)
            self.tree.insert("", tk.END, values=values)

    def apply_filter(self):
        """
        Simple substring filter applied over a few fields.
        This is intentionally straightforward for student readability.
        """
        q = (self.filter_var.get() or "").strip().lower()

        if not q:
            # No filter -> show everything
            self.tree.delete(*self.tree.get_children())
            self.populate_table(self.all_rows)
            self.set_status(f"Showing all items: {len(self.all_rows)}")
            return

        # Filter over selected fields
        filtered = []
        for r in self.all_rows:
            haystack = " ".join([
                safe_str(r.get("source")),
                safe_str(r.get("reg_path")),
                safe_str(r.get("value_name")),
                safe_str(r.get("decoded_value")),
            ]).lower()
            if q in haystack:
                filtered.append(r)

        self.tree.delete(*self.tree.get_children())
        self.populate_table(filtered)
        self.set_status(f"Filter '{q}' -> showing {len(filtered)} / {len(self.all_rows)} items")

    def export_csv(self):
        """
        Export current *displayed* rows to CSV.

        Note:
        - We export what’s currently in the table view (which may be filtered),
          not necessarily all rows.
        """
        if not self.tree.get_children():
            messagebox.showinfo("Nothing to export", "There are no rows to export.")
            return

        # Ask user where to save
        default_name = f"mru_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=default_name,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Header row
                writer.writerow(self.columns)

                # Export currently visible rows
                for item_id in self.tree.get_children():
                    row = self.tree.item(item_id, "values")
                    writer.writerow(row)

            messagebox.showinfo("Export complete", f"Exported to:\n{path}")
            self.set_status(f"Exported CSV: {path}")
        except Exception as e:
            messagebox.showerror("Export error", f"Failed to export CSV:\n{e}")
            self.set_status("Export failed.")


def main():
    """
    Entry point.
    """
    if os.name != "nt":
        print("This script is Windows-only (requires winreg).")
        sys.exit(1)

    app = MRUApp()
    app.mainloop()


if __name__ == "__main__":
    main()
