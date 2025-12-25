#!/usr/bin/env python3
"""
Web Server Log -> CSV Extractor (Student-Friendly)

This script finds common web server log files (Apache / Nginx),
parses them (Common Log Format / Combined Log Format), and writes
the results to a CSV file for easy analysis in Excel or a SIEM.

It is designed for students:
- Heavily commented
- Safe defaults
- Works even if some lines don't match (they get flagged)

NOTE:
- This script is for *legitimate* log analysis on systems you own or are authorized to examine.
"""

import csv
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Iterable, Tuple

# -----------------------------
# 1) REGEX PATTERNS FOR LOGS
# -----------------------------
# Most Apache/Nginx logs use one of these formats:
#
# Common Log Format (CLF):
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
#
# Combined Log Format:
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
#   "http://example.com/start.html" "Mozilla/5.0 ..."
#
# We'll parse both with one regex where referrer and user-agent are optional.

LOG_LINE_RE = re.compile(
    r'^'
    r'(?P<ip>\S+)\s+'                          # IP address
    r'(?P<ident>\S+)\s+'                       # ident (often '-')
    r'(?P<user>\S+)\s+'                        # authenticated user (often '-')
    r'\[(?P<time>[^\]]+)\]\s+'                 # timestamp in [ ... ]
    r'"(?P<request>[^"]*)"\s+'                 # "METHOD path HTTP/x.y"
    r'(?P<status>\d{3})\s+'                    # status code
    r'(?P<size>\S+)'                           # response size (or '-')
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'  # optional "referrer" "user-agent"
    r'\s*$'
)

# The time format in Apache/Nginx logs often looks like:
#   10/Oct/2000:13:55:36 -0700
APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# -----------------------------
# 2) COMMON LOG LOCATIONS
# -----------------------------
# Students often run Linux VMs where logs are in these folders:
DEFAULT_LOG_DIRS = [
    "/var/log/apache2",   # Debian/Ubuntu Apache
    "/var/log/httpd",     # RHEL/CentOS/Fedora Apache
    "/var/log/nginx",     # Nginx
]

# Common log filename patterns
DEFAULT_GLOBS = [
    "*.log",          # access.log, error.log, other.log
    "*.log.*",        # rotated logs like access.log.1
    "*.gz",           # compressed rotated logs like access.log.2.gz
]

# -----------------------------
# 3) HELPERS
# -----------------------------
def parse_request_field(request: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Split the "request" field into method, path, protocol.

    Example request field:
      "GET /index.html HTTP/1.1"

    Sometimes it may be empty or malformed, so we handle that safely.
    """
    if not request or request == "-":
        return None, None, None

    parts = request.split()
    if len(parts) == 3:
        method, path, protocol = parts
        return method, path, protocol
    elif len(parts) == 2:
        method, path = parts
        return method, path, None
    else:
        # Something unexpected (e.g., a weird quoted string)
        return None, request, None


def parse_apache_time(timestr: str) -> Optional[str]:
    """
    Convert Apache/Nginx log time to ISO 8601 string for easier sorting.

    Input example:
      10/Oct/2000:13:55:36 -0700

    Output example:
      2000-10-10T13:55:36-07:00
    """
    try:
        dt = datetime.strptime(timestr, APACHE_TIME_FORMAT)
        return dt.isoformat()
    except Exception:
        # If parsing fails, return the original string so we don't lose it.
        return None


def parse_log_line(line: str) -> Dict[str, Optional[str]]:
    """
    Parse a single log line into a dictionary.

    If the line doesn't match expected patterns, we return a record that
    stores the raw line and marks it as 'unparsed'.
    """
    m = LOG_LINE_RE.match(line)
    if not m:
        return {
            "parsed": "no",
            "ip": None,
            "ident": None,
            "user": None,
            "timestamp_raw": None,
            "timestamp_iso": None,
            "method": None,
            "path": None,
            "protocol": None,
            "status": None,
            "size": None,
            "referrer": None,
            "user_agent": None,
            "raw_line": line.strip(),
        }

    data = m.groupdict()

    method, path, protocol = parse_request_field(data.get("request", ""))

    timestamp_raw = data.get("time")
    timestamp_iso = parse_apache_time(timestamp_raw) if timestamp_raw else None

    # Size can be '-' (unknown). Normalize it to None for CSV cleanliness.
    size = data.get("size")
    if size == "-" or size is None:
        size = None

    return {
        "parsed": "yes",
        "ip": data.get("ip"),
        "ident": data.get("ident"),
        "user": data.get("user"),
        "timestamp_raw": timestamp_raw,
        "timestamp_iso": timestamp_iso,
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": data.get("status"),
        "size": size,
        "referrer": data.get("referrer"),
        "user_agent": data.get("agent"),
        "raw_line": None,  # parsed OK, so raw_line not needed
    }


def find_log_files(log_dirs: Iterable[str], globs: Iterable[str]) -> Iterable[Path]:
    """
    Search for log files under the given directories using filename patterns.

    Yields Path objects.

    NOTE:
    - This does NOT recurse deeply by default; it scans the given directories.
    - You can extend it to recurse if you want.
    """
    for d in log_dirs:
        base = Path(d)
        if not base.exists():
            continue
        for g in globs:
            for p in base.glob(g):
                # Only include real files
                if p.is_file():
                    yield p


def open_maybe_gzip(path: Path):
    """
    Open a file normally, or as gzip if it ends in .gz.

    Rotated logs often end with .gz, so this lets students handle both types.
    """
    if path.suffix == ".gz":
        import gzip
        # 'rt' means read-text mode. errors='replace' prevents crashes on odd bytes.
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        return open(path, "r", encoding="utf-8", errors="replace")


# -----------------------------
# 4) MAIN PROGRAM
# -----------------------------
def main():
    # argparse lets students run:
    #   python3 log_to_csv.py --out logs.csv --dirs /var/log/nginx /var/log/apache2
    parser = argparse.ArgumentParser(
        description="Extract Apache/Nginx web server logs and export them to a CSV."
    )
    parser.add_argument(
        "--out",
        default="web_logs.csv",
        help="Output CSV filename (default: web_logs.csv)"
    )
    parser.add_argument(
        "--dirs",
        nargs="*",
        default=DEFAULT_LOG_DIRS,
        help="Directories to search for logs (default: common Apache/Nginx log dirs)"
    )
    parser.add_argument(
        "--include-globs",
        nargs="*",
        default=DEFAULT_GLOBS,
        help="File patterns to include (default: *.log *.log.* *.gz)"
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=0,
        help="Limit total lines processed (0 means no limit). Useful for testing."
    )

    args = parser.parse_args()

    # CSV columns (fieldnames) we will write in this exact order.
    fieldnames = [
        "source_file",
        "parsed",
        "ip",
        "ident",
        "user",
        "timestamp_raw",
        "timestamp_iso",
        "method",
        "path",
        "protocol",
        "status",
        "size",
        "referrer",
        "user_agent",
        "raw_line",
    ]

    log_files = list(find_log_files(args.dirs, args.include_globs))

    if not log_files:
        print("No log files found. Try specifying --dirs with your log folder(s).")
        print("Example: --dirs /var/log/nginx /var/log/apache2")
        return

    print(f"Found {len(log_files)} log file(s). Writing output to: {args.out}")

    total_lines = 0
    parsed_ok = 0
    parsed_fail = 0

    # newline="" is important for CSV on Windows (prevents blank lines).
    with open(args.out, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for logfile in log_files:
            try:
                with open_maybe_gzip(logfile) as f_in:
                    for line in f_in:
                        # Stop if user asked for max lines
                        if args.max_lines and total_lines >= args.max_lines:
                            break

                        total_lines += 1

                        record = parse_log_line(line)
                        record["source_file"] = str(logfile)

                        if record["parsed"] == "yes":
                            parsed_ok += 1
                        else:
                            parsed_fail += 1

                        writer.writerow(record)

            except PermissionError:
                print(f"[Permission denied] Could not read: {logfile}")
            except FileNotFoundError:
                print(f"[Missing] File vanished while reading: {logfile}")
            except Exception as e:
                print(f"[Error] {logfile}: {e}")

            if args.max_lines and total_lines >= args.max_lines:
                break

    print("Done.")
    print(f"Total lines processed: {total_lines}")
    print(f"Parsed successfully:   {parsed_ok}")
    print(f"Unparsed lines:        {parsed_fail}")
    print(f"CSV saved as:          {args.out}")
    print("\nTip: Unparsed lines are kept in the 'raw_line' column for investigation.")


if __name__ == "__main__":
    main()
