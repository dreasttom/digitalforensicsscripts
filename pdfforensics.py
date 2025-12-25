#!/usr/bin/env python3
"""
PDF Forensic Examiner -> Screen + JSON + CSV (Student-Friendly)
===============================================================

What this script does (high-level):
- Computes cryptographic hashes (MD5/SHA1/SHA256) for chain-of-custody
- Extracts basic PDF metadata (producer/creator, dates, etc.)
- Counts objects/pages and looks for suspicious indicators
- Extracts:
    - All text (best-effort, not OCR)
    - URLs found in text and in PDF actions/annotations
    - JavaScript actions (if present)
    - Embedded files (attachments), and hashes them
- Outputs:
    - A readable screen report
    - JSON file with full structured results
    - CSV files (URLs, embedded files, and suspicious findings)

IMPORTANT NOTES (for students):
- This is a *forensic triage* script, not a full PDF reverse engineering suite.
- PDF internals are complex. This script focuses on common, teachable artifacts.
- Text extraction is best-effort (scanned PDFs may have little/no extractable text).
- No internet access is used; everything is local to the PDF.

Dependencies (install as needed):
- pikepdf (recommended): pip install pikepdf
- PyPDF2 (fallback for basic parsing): pip install pypdf2

Usage:
  python pdf_forensic_examiner.py --pdf suspicious.pdf --outdir results/

Example:
  python pdf_forensic_examiner.py --pdf report.pdf --outdir pdf_report

"""

import argparse
import csv
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Try to import pikepdf (best for forensic-ish PDF structure access)
HAVE_PIKEPDF = False
try:
    import pikepdf  # type: ignore
    HAVE_PIKEPDF = True
except Exception:
    HAVE_PIKEPDF = False

# Fallback: PyPDF2 for metadata/pages/text extraction
HAVE_PYPDF2 = False
try:
    import PyPDF2  # type: ignore
    HAVE_PYPDF2 = True
except Exception:
    HAVE_PYPDF2 = False


# -----------------------------------------------------------------------------
# Data models (structured output)
# -----------------------------------------------------------------------------

@dataclass
class FileHashes:
    md5: str
    sha1: str
    sha256: str


@dataclass
class SuspiciousFinding:
    category: str
    indicator: str
    details: str


@dataclass
class EmbeddedFileInfo:
    name: str
    size_bytes: int
    hashes: FileHashes
    extracted_path: str


@dataclass
class PdfForensicReport:
    input_pdf: str
    analyzed_utc: str
    tool: str = "pdf_forensic_examiner.py"
    parser_used: str = ""
    file_size_bytes: int = 0
    file_hashes: FileHashes = None  # type: ignore

    # Basic document info
    metadata: Dict[str, Any] = field(default_factory=dict)
    page_count: int = 0

    # Structural/behavioral artifacts
    object_count: Optional[int] = None  # best effort (pikepdf)
    has_encryption: Optional[bool] = None
    has_acroform: Optional[bool] = None
    has_xfa: Optional[bool] = None
    javascript_snippets: List[str] = field(default_factory=list)
    actions: List[Dict[str, Any]] = field(default_factory=list)

    # Content-derived artifacts
    extracted_text_chars: int = 0
    urls: List[str] = field(default_factory=list)

    # Attachments / embedded files
    embedded_files: List[EmbeddedFileInfo] = field(default_factory=list)

    # Triaged suspicious indicators
    suspicious_findings: List[SuspiciousFinding] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Utility helpers (hashing, safe IO, etc.)
# -----------------------------------------------------------------------------

URL_RE = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"'()]+)"""
)

PDF_DATE_RE = re.compile(r"^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?.*")


def compute_hashes(path: Path) -> FileHashes:
    """
    Compute MD5/SHA1/SHA256 for the file.
    In forensics, hashes help prove integrity and chain-of-custody.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(md5=md5.hexdigest(), sha1=sha1.hexdigest(), sha256=sha256.hexdigest())


def ensure_outdir(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def normalize_url(u: str) -> str:
    """Normalize URLs so students don't get duplicates like 'www.' vs http://www."""
    u = u.strip()
    if u.lower().startswith("www."):
        u = "http://" + u
    # Strip trailing punctuation common in text
    u = u.rstrip(").,;:\"'")
    return u


def parse_pdf_date(pdf_date: str) -> Optional[str]:
    """
    PDF dates often look like: D:20240101123000-05'00'
    We'll convert to a readable ISO-ish string when possible.
    """
    if not isinstance(pdf_date, str):
        return None
    m = PDF_DATE_RE.match(pdf_date)
    if not m:
        return None

    y = int(m.group(1))
    mo = int(m.group(2) or 1)
    d = int(m.group(3) or 1)
    hh = int(m.group(4) or 0)
    mm = int(m.group(5) or 0)
    ss = int(m.group(6) or 0)
    try:
        return datetime(y, mo, d, hh, mm, ss).isoformat()
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Suspicious indicator checks (simple triage rules)
# -----------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/URI",
    "/EmbeddedFile", "/RichMedia", "/XFA", "/AcroForm"
]

EXECUTABLE_EXTS = {".exe", ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".jar", ".hta"}


def add_finding(findings: List[SuspiciousFinding], category: str, indicator: str, details: str) -> None:
    findings.append(SuspiciousFinding(category=category, indicator=indicator, details=details))


# -----------------------------------------------------------------------------
# Extraction using pikepdf (preferred)
# -----------------------------------------------------------------------------

def analyze_with_pikepdf(pdf_path: Path, outdir: Path) -> Tuple[Dict[str, Any], PdfForensicReport]:
    """
    Use pikepdf to extract richer structural details.
    """
    report = PdfForensicReport(
        input_pdf=str(pdf_path),
        analyzed_utc=datetime.utcnow().isoformat() + "Z",
        parser_used="pikepdf",
        file_size_bytes=pdf_path.stat().st_size,
        file_hashes=compute_hashes(pdf_path),
    )

    # pikepdf can open encrypted PDFs but may require a password; we do best-effort.
    try:
        pdf = pikepdf.open(str(pdf_path))
        report.has_encryption = False
    except pikepdf._qpdf.PasswordError:
        report.has_encryption = True
        add_finding(report.suspicious_findings, "encryption", "Encrypted PDF", "PDF is encrypted; cannot fully parse without password.")
        # Stop early because we can't extract structure without the password
        return {}, report
    except Exception as e:
        add_finding(report.suspicious_findings, "parse_error", "Failed to parse PDF", f"pikepdf error: {e}")
        return {}, report

    # Page count
    report.page_count = len(pdf.pages)

    # Object count (approx: number of indirect objects)
    try:
        report.object_count = len(list(pdf.objects))
    except Exception:
        report.object_count = None

    # Metadata (document info dictionary)
    meta: Dict[str, Any] = {}
    try:
        docinfo = pdf.docinfo  # may contain keys like /Author /Creator /Producer /CreationDate
        for k, v in docinfo.items():
            # Keys may be pikepdf.Name like '/Author'
            key_str = str(k).lstrip("/")
            val_str = str(v)
            meta[key_str] = val_str

        # Normalize a couple of common date fields if present
        for date_key in ("CreationDate", "ModDate"):
            if date_key in meta:
                iso = parse_pdf_date(meta[date_key])
                if iso:
                    meta[date_key + "_ISO"] = iso

    except Exception:
        pass
    report.metadata = meta

    # Check for AcroForm / XFA (interactive forms)
    try:
        root = pdf.Root
        if "/AcroForm" in root:
            report.has_acroform = True
            add_finding(report.suspicious_findings, "forms", "AcroForm present", "Interactive forms can contain actions and scripts.")
            acro = root["/AcroForm"]
            # XFA is often embedded under AcroForm
            if isinstance(acro, pikepdf.Dictionary) and "/XFA" in acro:
                report.has_xfa = True
                add_finding(report.suspicious_findings, "forms", "XFA present", "XFA forms are higher-risk and sometimes abused.")
        else:
            report.has_acroform = False
    except Exception:
        pass

    # Extract JavaScript snippets and common actions by walking the PDF objects
    # This is a best-effort "greedy" scan: we look for dictionaries with /S /JavaScript or /JS.
    js_snips: List[str] = []
    actions: List[Dict[str, Any]] = []

    def safe_to_str(x: Any) -> str:
        try:
            return str(x)
        except Exception:
            return repr(x)

    # Walk all objects (can be many; but good for teaching triage)
    try:
        for obj in pdf.objects:
            try:
                resolved = obj
                # We want dictionaries that might represent actions
                if isinstance(resolved, pikepdf.Dictionary):
                    # Look for action type: /S
                    s_val = resolved.get("/S", None)
                    if s_val and safe_to_str(s_val) in ("/JavaScript", "/URI", "/Launch", "/GoTo", "/GoToR", "/SubmitForm"):
                        act = {
                            "S": safe_to_str(s_val),
                            "URI": safe_to_str(resolved.get("/URI", "")) if "/URI" in resolved else None,
                            "F": safe_to_str(resolved.get("/F", "")) if "/F" in resolved else None,
                            "D": safe_to_str(resolved.get("/D", "")) if "/D" in resolved else None,
                            "raw_keys": [safe_to_str(k) for k in resolved.keys()],
                        }
                        actions.append(act)

                    # JavaScript code usually appears in /JS
                    if "/JS" in resolved:
                        js_obj = resolved["/JS"]
                        js_text = safe_to_str(js_obj)
                        js_snips.append(js_text)

            except Exception:
                continue
    except Exception:
        pass

    # Deduplicate JS snippets (keep order)
    seen = set()
    for s in js_snips:
        if s not in seen:
            seen.add(s)
            report.javascript_snippets.append(s)

    report.actions = actions

    if report.javascript_snippets:
        add_finding(report.suspicious_findings, "active_content", "JavaScript present", f"Found {len(report.javascript_snippets)} JS snippet(s).")

    # Embedded files (attachments):
    # Many PDFs store attachments under:
    #   Root -> /Names -> /EmbeddedFiles -> /Names (an array of name/object pairs)
    embedded: List[EmbeddedFileInfo] = []
    try:
        root = pdf.Root
        if "/Names" in root and "/EmbeddedFiles" in root["/Names"]:
            add_finding(report.suspicious_findings, "attachments", "Embedded files present", "PDF contains embedded file attachments.")
            ef_tree = root["/Names"]["/EmbeddedFiles"]

            # The simplest case uses /Names array [name1, dict1, name2, dict2, ...]
            names_arr = ef_tree.get("/Names", None)
            if names_arr and isinstance(names_arr, pikepdf.Array):
                attachments_dir = outdir / "embedded_files"
                attachments_dir.mkdir(parents=True, exist_ok=True)

                # Iterate pairs
                for i in range(0, len(names_arr), 2):
                    try:
                        fname = str(names_arr[i])
                        file_spec = names_arr[i + 1]
                        # Filespec dictionary usually has /EF -> /F -> stream
                        ef = file_spec.get("/EF", None)
                        if ef and "/F" in ef:
                            stream = ef["/F"]
                            data = bytes(stream.read_bytes())

                            safe_name = fname.replace("/", "_").replace("\\", "_")
                            out_path = attachments_dir / safe_name
                            out_path.write_bytes(data)

                            h = compute_hashes(out_path)
                            embedded.append(
                                EmbeddedFileInfo(
                                    name=fname,
                                    size_bytes=len(data),
                                    hashes=h,
                                    extracted_path=str(out_path),
                                )
                            )

                            # Flag executable-ish attachments
                            ext = out_path.suffix.lower()
                            if ext in EXECUTABLE_EXTS:
                                add_finding(
                                    report.suspicious_findings,
                                    "attachments",
                                    "Potentially executable attachment",
                                    f"Embedded file '{fname}' has extension '{ext}'.",
                                )
                    except Exception:
                        continue

    except Exception:
        pass

    report.embedded_files = embedded

    # Extract text (best-effort):
    # pikepdf is not a text-extraction library; we will do a simple fallback:
    # - If PyPDF2 is available, use it for text extraction even when we parse with pikepdf.
    extracted_text = ""
    if HAVE_PYPDF2:
        extracted_text = extract_text_with_pypdf2(pdf_path)
    report.extracted_text_chars = len(extracted_text)

    # URL extraction from text + from actions
    urls = set()

    for m in URL_RE.finditer(extracted_text):
        urls.add(normalize_url(m.group(1)))

    for act in report.actions:
        if act.get("S") == "/URI" and act.get("URI"):
            urls.add(normalize_url(str(act["URI"])))

    report.urls = sorted(urls)

    # Keyword-based quick scan for suspicious strings (basic triage)
    # We scan a subset of serialized structures and metadata (not the full binary)
    try:
        serialized = json.dumps(report.metadata, ensure_ascii=False)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.strip("/") in serialized:
                add_finding(report.suspicious_findings, "keyword", kw, "Keyword found in metadata/structure summary.")
    except Exception:
        pass

    return {"extracted_text": extracted_text}, report


# -----------------------------------------------------------------------------
# Extraction using PyPDF2 (fallback)
# -----------------------------------------------------------------------------

def extract_text_with_pypdf2(pdf_path: Path) -> str:
    """
    Extract text using PyPDF2 (best-effort).
    Note: If the PDF is scanned images, there may be little/no extractable text.
    """
    text_parts: List[str] = []
    try:
        with pdf_path.open("rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                try:
                    t = page.extract_text() or ""
                    text_parts.append(t)
                except Exception:
                    continue
    except Exception:
        return ""
    return "\n".join(text_parts)


def analyze_with_pypdf2_only(pdf_path: Path) -> Tuple[Dict[str, Any], PdfForensicReport]:
    """
    PyPDF2-only analysis: limited structural insight, but still useful for:
    - metadata
    - page count
    - text extraction
    - URLs in text
    """
    report = PdfForensicReport(
        input_pdf=str(pdf_path),
        analyzed_utc=datetime.utcnow().isoformat() + "Z",
        parser_used="PyPDF2",
        file_size_bytes=pdf_path.stat().st_size,
        file_hashes=compute_hashes(pdf_path),
    )

    extracted_text = ""

    try:
        with pdf_path.open("rb") as f:
            reader = PyPDF2.PdfReader(f)
            report.page_count = len(reader.pages)

            # Encryption?
            try:
                report.has_encryption = bool(reader.is_encrypted)
                if report.has_encryption:
                    add_finding(report.suspicious_findings, "encryption", "Encrypted PDF", "PDF is encrypted; content may be inaccessible.")
            except Exception:
                report.has_encryption = None

            # Metadata (may be None)
            meta = {}
            try:
                if reader.metadata:
                    for k, v in reader.metadata.items():
                        key_str = str(k).lstrip("/")
                        meta[key_str] = str(v)
                # Date normalization if present
                for date_key in ("CreationDate", "ModDate"):
                    if date_key in meta:
                        iso = parse_pdf_date(meta[date_key])
                        if iso:
                            meta[date_key + "_ISO"] = iso
            except Exception:
                pass
            report.metadata = meta

            # Text extraction
            extracted_text = extract_text_with_pypdf2(pdf_path)
            report.extracted_text_chars = len(extracted_text)

    except Exception as e:
        add_finding(report.suspicious_findings, "parse_error", "Failed to parse PDF", f"PyPDF2 error: {e}")

    # URLs from text
    urls = set()
    for m in URL_RE.finditer(extracted_text):
        urls.add(normalize_url(m.group(1)))
    report.urls = sorted(urls)

    return {"extracted_text": extracted_text}, report


# -----------------------------------------------------------------------------
# Output routines
# -----------------------------------------------------------------------------

def print_screen_report(report: PdfForensicReport) -> None:
    """Human-readable report for students."""
    print("\n" + "=" * 80)
    print("PDF FORENSIC EXAMINATION REPORT")
    print("=" * 80)
    print(f"Input PDF:       {report.input_pdf}")
    print(f"Analyzed (UTC):  {report.analyzed_utc}")
    print(f"Parser Used:     {report.parser_used}")
    print(f"File Size:       {report.file_size_bytes} bytes")
    print(f"MD5:             {report.file_hashes.md5}")
    print(f"SHA1:            {report.file_hashes.sha1}")
    print(f"SHA256:          {report.file_hashes.sha256}")
    print(f"Pages:           {report.page_count}")
    if report.object_count is not None:
        print(f"Object Count:    {report.object_count}")

    if report.has_encryption is not None:
        print(f"Encrypted:       {report.has_encryption}")

    if report.has_acroform is not None:
        print(f"AcroForm:        {report.has_acroform}")
    if report.has_xfa is not None:
        print(f"XFA:             {report.has_xfa}")

    print("\n--- Metadata ---")
    if report.metadata:
        for k in sorted(report.metadata.keys()):
            print(f"{k}: {report.metadata[k]}")
    else:
        print("(No metadata found or could not parse)")

    print("\n--- Active Content / Actions ---")
    if report.javascript_snippets:
        print(f"JavaScript snippets found: {len(report.javascript_snippets)}")
        # Print only the first 2 snippets (students can read the JSON for full detail)
        for i, js in enumerate(report.javascript_snippets[:2], start=1):
            snippet = js[:300] + (" ...[truncated]..." if len(js) > 300 else "")
            print(f"[JS {i}] {snippet}")
    else:
        print("No JavaScript snippets found (or not detectable).")

    if report.actions:
        print(f"Actions found: {len(report.actions)}")
        for a in report.actions[:8]:
            print(a)
        if len(report.actions) > 8:
            print("... (more actions in JSON)")
    else:
        print("No actions found (or not detectable).")

    print("\n--- URLs ---")
    if report.urls:
        for u in report.urls:
            print(u)
    else:
        print("No URLs found.")

    print("\n--- Embedded Files ---")
    if report.embedded_files:
        for ef in report.embedded_files:
            print(f"Name: {ef.name}")
            print(f"  Size:   {ef.size_bytes} bytes")
            print(f"  MD5:    {ef.hashes.md5}")
            print(f"  SHA256: {ef.hashes.sha256}")
            print(f"  Saved:  {ef.extracted_path}")
    else:
        print("No embedded files extracted.")

    print("\n--- Suspicious Findings (triage) ---")
    if report.suspicious_findings:
        for f in report.suspicious_findings:
            print(f"[{f.category}] {f.indicator} -> {f.details}")
    else:
        print("No suspicious indicators flagged by this script.")


def save_outputs(outdir: Path, report: PdfForensicReport, extracted_text: str) -> None:
    """
    Write JSON and CSV outputs to disk.
    """
    ensure_outdir(outdir)

    # 1) Save full JSON report (best for later analysis)
    json_path = outdir / "pdf_forensic_report.json"
    write_json(json_path, asdict(report))

    # 2) Save extracted text to a file (so students can search it)
    text_path = outdir / "extracted_text.txt"
    text_path.write_text(extracted_text, encoding="utf-8", errors="replace")

    # 3) Save URLs to CSV
    url_rows = [{"url": u} for u in report.urls]
    write_csv(outdir / "urls.csv", url_rows, fieldnames=["url"])

    # 4) Save embedded files list to CSV
    ef_rows = []
    for ef in report.embedded_files:
        ef_rows.append({
            "name": ef.name,
            "size_bytes": ef.size_bytes,
            "md5": ef.hashes.md5,
            "sha1": ef.hashes.sha1,
            "sha256": ef.hashes.sha256,
            "extracted_path": ef.extracted_path,
        })
    write_csv(outdir / "embedded_files.csv", ef_rows,
              fieldnames=["name", "size_bytes", "md5", "sha1", "sha256", "extracted_path"])

    # 5) Save suspicious findings to CSV
    sf_rows = []
    for s in report.suspicious_findings:
        sf_rows.append({
            "category": s.category,
            "indicator": s.indicator,
            "details": s.details,
        })
    write_csv(outdir / "suspicious_findings.csv", sf_rows,
              fieldnames=["category", "indicator", "details"])

    # Also save a small "summary" JSON for quick viewing
    summary = {
        "input_pdf": report.input_pdf,
        "analyzed_utc": report.analyzed_utc,
        "parser_used": report.parser_used,
        "file_size_bytes": report.file_size_bytes,
        "hashes": asdict(report.file_hashes),
        "page_count": report.page_count,
        "object_count": report.object_count,
        "encrypted": report.has_encryption,
        "acroform": report.has_acroform,
        "xfa": report.has_xfa,
        "urls_found": len(report.urls),
        "embedded_files_found": len(report.embedded_files),
        "javascript_snippets_found": len(report.javascript_snippets),
        "actions_found": len(report.actions),
        "suspicious_findings_count": len(report.suspicious_findings),
    }
    write_json(outdir / "summary.json", summary)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Forensically examine a PDF and produce artifacts (screen + JSON/CSV)."
    )
    parser.add_argument("--pdf", required=True, help="Path to the PDF to analyze")
    parser.add_argument("--outdir", default="pdf_forensic_output", help="Directory for output artifacts")
    args = parser.parse_args()

    pdf_path = Path(args.pdf)
    outdir = Path(args.outdir)

    if not pdf_path.exists():
        print(f"[!] PDF not found: {pdf_path}")
        return

    if not HAVE_PIKEPDF and not HAVE_PYPDF2:
        print("[!] No PDF parser libraries available.")
        print("    Install one of:")
        print("      pip install pikepdf")
        print("      pip install PyPDF2")
        return

    extracted_text = ""
    report: PdfForensicReport

    if HAVE_PIKEPDF:
        extra, report = analyze_with_pikepdf(pdf_path, outdir)
        extracted_text = extra.get("extracted_text", "")
    else:
        extra, report = analyze_with_pypdf2_only(pdf_path)
        extracted_text = extra.get("extracted_text", "")

    # Print to screen (for students doing lab work)
    print_screen_report(report)

    # Save artifacts to disk (for reports / grading / further analysis)
    save_outputs(outdir, report, extracted_text)

    print("\nOutputs written to:")
    print(f"  {outdir / 'summary.json'}")
    print(f"  {outdir / 'pdf_forensic_report.json'}")
    print(f"  {outdir / 'urls.csv'}")
    print(f"  {outdir / 'embedded_files.csv'}")
    print(f"  {outdir / 'suspicious_findings.csv'}")
    print(f"  {outdir / 'extracted_text.txt'}")


if __name__ == "__main__":
    main()
