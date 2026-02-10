# logsleuth.py  (Python 3.8+ compatible)
# LogSleuth - simple log analyzer + report generator (CSV + HTML)

import argparse
import csv
import random
import re
from collections import Counter
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any


# -------------------------
# Patterns (extendable)
# -------------------------
FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"login failed.*user=(?P<user>\S+).*ip=(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
]
SUCCESS_LOGIN_PATTERNS = [
    re.compile(r"accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"login success.*user=(?P<user>\S+).*ip=(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
]
ERROR_PATTERNS = [
    re.compile(r"\berror\b", re.IGNORECASE),
    re.compile(r"\bexception\b", re.IGNORECASE),
    re.compile(r"\bfatal\b", re.IGNORECASE),
]
TIMESTAMP_PATTERNS = [
    # 2026-02-09 21:14:33 OR 2026-02-09T21:14:33
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    # Feb 09 21:14:33 (assume current year)
    re.compile(r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
          "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def parse_timestamp(line: str, assumed_year: int) -> Optional[datetime]:
    for pat in TIMESTAMP_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        raw = m.group("ts")
        try:
            if raw[0].isdigit():
                return datetime.strptime(raw.replace("T", " "), "%Y-%m-%d %H:%M:%S")
            # "Feb  9 21:14:33"
            parts = raw.split()
            mon = MONTHS.get(parts[0], 1)
            day = int(parts[1])
            hh, mm, ss = map(int, parts[2].split(":"))
            return datetime(assumed_year, mon, day, hh, mm, ss)
        except Exception:
            return None
    return None


def classify_line(line: str) -> str:
    for p in FAILED_LOGIN_PATTERNS:
        if p.search(line):
            return "failed_login"
    for p in SUCCESS_LOGIN_PATTERNS:
        if p.search(line):
            return "success_login"
    for p in ERROR_PATTERNS:
        if p.search(line):
            return "error"
    return "other"


def extract_user_ip(line: str, kind: str) -> Tuple[Optional[str], Optional[str]]:
    patterns = FAILED_LOGIN_PATTERNS if kind == "failed_login" else SUCCESS_LOGIN_PATTERNS
    for p in patterns:
        m = p.search(line)
        if m:
            return m.group("user"), m.group("ip")
    return None, None


def read_lines_from_path(path: Path) -> List[str]:
    if path.is_file():
        return path.read_text(errors="ignore").splitlines()

    lines: List[str] = []
    for fp in path.rglob("*"):
        if fp.is_file() and fp.suffix.lower() in {".log", ".txt", ".csv"}:
            try:
                lines.extend(fp.read_text(errors="ignore").splitlines())
            except Exception:
                pass
    return lines


def detect_bursts(events: List[datetime], window_seconds: int = 60, threshold: int = 8) -> int:
    """Count bursts (>= threshold fails within window)."""
    if len(events) < threshold:
        return 0
    events = sorted(events)
    bursts = 0
    i = 0
    for j in range(len(events)):
        while (events[j] - events[i]).total_seconds() > window_seconds:
            i += 1
        if (j - i + 1) == threshold:
            bursts += 1
    return bursts


def write_csv_report(out_csv: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        out_csv.write_text("no data\n", encoding="utf-8")
        return
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_html_report(
    out_html: Path,
    summary: Dict[str, Any],
    top_ips: List[Tuple[str, int]],
    top_users: List[Tuple[str, int]],
    timeline: List[Tuple[str, int]],
) -> None:
    def tr(cells):
        return "<tr>" + "".join("<td>{}</td>".format(escape(str(x))) for x in cells) + "</tr>"

    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'/>")
    html.append("<meta name='viewport' content='width=device-width,initial-scale=1'/>")
    html.append("<title>LogSleuth Report</title>")
    html.append("<style>"
                "body{font-family:system-ui,Segoe UI,Arial;margin:24px}"
                ".card{border:1px solid #ddd;border-radius:14px;padding:14px;margin:10px 0}"
                "table{width:100%;border-collapse:collapse}"
                "th,td{border-bottom:1px solid #eee;padding:8px;text-align:left;vertical-align:top}"
                "th{background:#fafafa}"
                "</style>")
    html.append("</head><body>")
    html.append("<h1>LogSleuth Report</h1>")

    html.append("<div class='card'><h2>Summary</h2><table>")
    for k, v in summary.items():
        html.append(tr([k, v]))
    html.append("</table></div>")

    html.append("<div class='card'><h2>Top IPs (failed logins)</h2><table><tr><th>IP</th><th>Count</th></tr>")
    for ip, c in top_ips:
        html.append(tr([ip, c]))
    html.append("</table></div>")

    html.append("<div class='card'><h2>Top Users (failed logins)</h2><table><tr><th>User</th><th>Count</th></tr>")
    for u, c in top_users:
        html.append(tr([u, c]))
    html.append("</table></div>")

    html.append("<div class='card'><h2>Hourly timeline (events)</h2><table><tr><th>Hour</th><th>Count</th></tr>")
    for hour, c in timeline:
        html.append(tr([hour, c]))
    html.append("</table></div>")

    html.append("</body></html>")
    out_html.write_text("\n".join(html), encoding="utf-8")


def generate_sample_logs(out_dir: Path, lines: int = 500) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    fp = out_dir / "sample_auth.log"

    users = ["alex", "cassidy", "admin", "svc_backup", "bob", "charlie"]
    ips = [f"192.168.1.{i}" for i in range(2, 40)] + [f"45.33.12.{i}" for i in range(10, 60)]
    now = datetime.now()

    data: List[str] = []
    t = now - timedelta(hours=12)

    for _ in range(lines):
        t += timedelta(seconds=random.randint(5, 80))
        u = random.choice(users)
        ip = random.choice(ips)

        roll = random.random()
        if roll < 0.18:
            msg = f"{t:%Y-%m-%d %H:%M:%S} sshd[123]: Failed password for {u} from {ip} port 51122 ssh2"
        elif roll < 0.24:
            msg = f"{t:%Y-%m-%d %H:%M:%S} sshd[123]: Accepted password for {u} from {ip} port 51122 ssh2"
        elif roll < 0.30:
            msg = f"{t:%Y-%m-%d %H:%M:%S} app: ERROR Something bad happened - exception=Timeout"
        else:
            msg = f"{t:%Y-%m-%d %H:%M:%S} system: info heartbeat ok"
        data.append(msg)

    # Add a brute-force burst
    burst_ip = "45.33.12.34"
    burst_user = "admin"
    burst_start = now - timedelta(minutes=15)
    for i in range(18):
        t2 = burst_start + timedelta(seconds=i * 3)
        data.append(f"{t2:%Y-%m-%d %H:%M:%S} sshd[777]: Failed password for {burst_user} from {burst_ip} port 50000 ssh2")

    fp.write_text("\n".join(data), encoding="utf-8")
    return fp


def main():
    ap = argparse.ArgumentParser(description="LogSleuth - log analyzer + report generator")
    ap.add_argument("--path", type=str, default=".", help="file or folder containing logs (.log/.txt/.csv)")
    ap.add_argument("--out", type=str, default="./out", help="output folder for reports")
    ap.add_argument("--make-sample", action="store_true", help="generate sample logs into ./sample_logs and analyze them")
    ap.add_argument("--burst-window", type=int, default=60, help="seconds window for burst detection")
    ap.add_argument("--burst-threshold", type=int, default=8, help="fails within window to count a burst")
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    path = Path(args.path)
    if args.make_sample:
        path = Path("./sample_logs")
        sample = generate_sample_logs(path, lines=600)
        print(f"Generated sample log: {sample}")

    lines = read_lines_from_path(path)
    if not lines:
        print("No log lines found. Use --make-sample or point --path to a folder with .log/.txt/.csv")
        return

    assumed_year = datetime.now().year

    counts = Counter()
    failed_by_ip = Counter()
    failed_by_user = Counter()
    hourly = Counter()
    failed_times: List[datetime] = []

    parsed_rows: List[Dict[str, Any]] = []
    for line in lines:
        kind = classify_line(line)
        counts[kind] += 1
        ts = parse_timestamp(line, assumed_year)

        if ts:
            hourly[f"{ts:%Y-%m-%d %H}:00"] += 1

        user = ip = None
        if kind in ("failed_login", "success_login"):
            user, ip = extract_user_ip(line, kind)

        if kind == "failed_login":
            if ip:
                failed_by_ip[ip] += 1
            if user:
                failed_by_user[user] += 1
            if ts:
                failed_times.append(ts)

        parsed_rows.append({
            "timestamp": ts.isoformat(sep=" ") if ts else "",
            "kind": kind,
            "user": user or "",
            "ip": ip or "",
            "line": line[:500],
        })

    bursts = detect_bursts(failed_times, window_seconds=args.burst_window, threshold=args.burst_threshold)

    summary: Dict[str, Any] = {
        "total_lines": len(lines),
        "failed_logins": counts["failed_login"],
        "successful_logins": counts["success_login"],
        "errors": counts["error"],
        "other": counts["other"],
        "bruteforce_bursts_detected": bursts,
        "analysis_path": str(path.resolve()),
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
    }

    top_ips = failed_by_ip.most_common(10)
    top_users = failed_by_user.most_common(10)
    timeline = sorted(hourly.items())[-24:]

    out_csv = out_dir / "logsleuth_report.csv"
    out_html = out_dir / "logsleuth_report.html"

    write_csv_report(out_csv, parsed_rows)
    write_html_report(out_html, summary, top_ips, top_users, timeline)

    print("\nLogSleuth Summary")
    for k, v in summary.items():
        print(f"- {k}: {v}")

    print("\nTop IPs (failed logins):")
    for ip, c in top_ips[:5]:
        print(f"  {ip:15}  {c}")

    print("\nOutputs:")
    print(f"- CSV : {out_csv}")
    print(f"- HTML: {out_html}")
    print("\nTip: open the HTML report in your browser.")


if __name__ == "__main__":
    main()
