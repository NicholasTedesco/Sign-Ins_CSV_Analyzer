"""
Detects IOCs from Microsoft Entra ID sign-in CSV exports.

prompt:
    python3 analyze_signins.py <path_to_csv> <output.txt> 

Detections:
    1. Foreign / unexpected country sign-ins
    2. Impossible travel (same user, multiple locations, implausible time delta)
    3. VPN / Tor / anonymous / bad-reputation ASN sign-ins
    4. Suspicious user agents (legacy browsers, scripting tools, attack tooling)
    5. Suspicious client applications (PowerShell, Graph Explorer, ROPC flows, etc.)
    6. Stolen / shared Session ID reused across different UA / OS / Location / IP
    7. Microsoft-flagged risky users ("Flagged for review")
    8. Suspicious sign-in error codes (50199, 500119, 90014, and others)
    9. Single-factor auth on sensitive resources (MFA gaps)
"""

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_TRUSTED_COUNTRIES = {"US"}

IMPOSSIBLE_TRAVEL_SPEED_KMH = 900


IMPOSSIBLE_TRAVEL_MIN_KM = 200

SEVERITY_WEIGHTS = {
    "CRITICAL": 30,
    "HIGH":     10,
    "MEDIUM":   5,
    "LOW":      1,  
    "INFO":     0,
}

COMPROMISE_SCORE_THRESHOLD = 8 

ALERT_CATEGORIES = {
    "Foreign Sign-In",
    "Impossible Travel",
    "Suspicious ASN / Hosting IP",
    "Suspicious User Agent",
    "Outdated Browser",
    "Suspicious Client Application",
    "MFA Gap — Sensitive Resource",
    "Risky User (MS-Flagged)",
    "Suspicious Error Code",
    "Session ID Reuse / Token Replay",
}

# ASNs associated with known VPN providers, Tor exit nodes, hosting/proxy ranges. Feel free to extend this list
SUSPICIOUS_ASNS = {
    "AS60729", "AS208323", "AS396507",
    "AS9009",   # M247 (heavily abused)
    "AS174",    # Cogent (often seen in spray attacks)
    "AS20473",  # Vultr
    "AS14061",  # DigitalOcean
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS13335",  # Cloudflare (Workers/WARP)
    "AS212238", # Datacamp / residential proxy
}

# Partial ISP/org name substrings that suggest VPN/proxy/hosting infrastructure.
SUSPICIOUS_ISP_SUBSTRINGS = [
    "vpn", "proxy", "tor exit", "anonymous", "hosting", "datacenter",
    "data center", "linode", "vultr", "digitalocean", "hetzner", "ovh",
    "m247", "leaseweb", "choopa", "packetflip", "mullvad", "nord",
    "expressvpn", "private internet", "ipvanish", "windscribe", "surfshark",
]

# User-agent substrings that indicate scripting / automation / attack tooling.
SUSPICIOUS_UA_PATTERNS = [
    r"python-requests",
    r"curl/",
    r"wget/",
    r"powershell",
    r"invoke-webrequest",
    r"go-http-client",
    r"okhttp",
    r"axios",
    r"java/",
    r"ruby",
    r"perl",
    r"libwww",
    r"scrapy",
    r"masscan",
    r"nmap",
    r"nuclei",
    r"spray",               
    r"teamfiltration",
    r"trevorspray",
    r"o365spray",
    r"burpsuite",
    r"postman",
    r"httpie",
    r"aiohttp",
    r"httpx",
    r"msoidcli",          
    r"office 16\.0\.",      # very old Office builds — may indicate cred-stuffing
]

# Browser version thresholds — flag if major version is below these.
OUTDATED_BROWSER_THRESHOLDS = {
    "chrome":  143,
    "firefox": 145,
    "edge":    143,
    "safari":  16,
    "msie":    1,      # Any IE is ancient
    "trident": 1,      # IE engine
}

# Client apps that are commonly used by attackers
SUSPICIOUS_APP_NAMES = [
    "microsoft graph",
    "graph explorer",
    "azure active directory powershell",
    "azure powershell",
    "azure cli",
    "office home",          # historically abused in BEC
    "microsoft office",     # legacy thick-client auth
    "exchange online powershell",
    "teams powershell",
    "security & compliance center",
    "substrate context service",  # internal MS; sometimes seen in token replay
]

# resources where single-factor auth should be checked if location is suspicious
SENSITIVE_RESOURCES = [
    "microsoft graph",
    "office 365 exchange online",
    "sharepoint",
    "azure key vault",
    "azure management",
    "windows azure service management api",
]                


# Error codes that indicate suspicious conditions.
# Change this as needed. Some logs will just be swimming with this /s
SUSPICIOUS_ERROR_CODES = {
    "50199": "User prompted for additional verification (often post-compromise MFA disruption)",
    "500119": "Strong auth required by resource — possible step-up bypass attempt",
    "90014": "Missing required field — seen in some token-replay / automated attacks",
    "50097": "Device compliance required — potential policy bypass probe",
    "70011": "Scope invalid — common in OAuth phishing / illicit consent grant flows",
    "65001":  "App not consented — possible OAuth phishing setup",
    "50076": "MFA required but not satisfied (enumeration/spray indicator)",
    "50158": "External security challenge not satisfied",
    "50053": "Account locked (smart lockout triggered)",
}


# COLUMN MAP  — adjust if your CSV export uses different header names

# THIS IS CONFIGURED FOR "Entra" sign in logs. If you are pulling from that DO NOT CHANGE


COL = {
    "date":           "Date (UTC)",
    "request_id":     "Request ID",
    "user_agent":     "User agent",
    "user_id":        "User ID",
    "user":           "User",
    "username":       "Username",
    "app":            "Application",
    "resource":       "Resource",
    "ip":             "IP address",
    "location":       "Location",
    "status":         "Status",
    "error_code":     "Sign-in error code",
    "client_app":     "Client app",
    "browser":        "Browser",
    "os":             "Operating System",
    "mfa_result":     "Multifactor authentication result",
    "mfa_method":     "Multifactor authentication auth method",
    "auth_req":       "Authentication requirement",
    "session_id":     "Session ID",
    "asn":            "Autonomous system  number",   # note double-space in header
    "flagged":        "Flagged for review",
    "token_id":       "Unique token identifier",
    "device_id":      "Device ID",
    "compliant":      "Compliant",
    "managed":        "Managed",
}

# helpers 

def parse_date(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def extract_country(location: str) -> str:
    """Return 2-letter country code from 'City, State, CC' or 'City, CC'."""
    parts = [p.strip() for p in location.split(",")]
    if parts:
        return parts[-1].upper()
    return ""


def extract_state(location: str) -> str:
    """
    Return the state/region segment from 'City, State, CC'.
    Format from Entra logs is typically: 'City, State, CC' (3 parts) or
    'City, CC' (2 parts — no state info).  Returns '' if unavailable.
    """
    parts = [p.strip() for p in location.split(",")]
    if len(parts) >= 3:
        return parts[-2].upper()   # middle segment = state/region
    return ""


def haversine_km(loc1: str, loc2: str, coord_cache: dict) -> float | None:
    """
    Very rough distance estimate by caching approximate coordinates per
    'City, State/Region, Country' string.  For precise results replace with
    a geo-IP database lookup.  Returns None if either location is unknown.
    """
    # We do a naive lookup; real deployments should use MaxMind GeoLite2 etc.
    # Here we return None (skip the check) unless the same cache is populated
    # externally.  The function signature is ready for a real implementation.
    return None


def browser_version(browser_field: str) -> tuple[str, int] | None:
    """Extract (name_lower, major_version) from the Browser column."""
    if not browser_field:
        return None
    m = re.match(r"([A-Za-z]+)\s+([\d]+)", browser_field.strip())
    if m:
        return m.group(1).lower(), int(m.group(2))
    return None


def is_suspicious_ua(ua: str) -> list[str]:
    ua_lower = ua.lower()
    hits = []
    for pat in SUSPICIOUS_UA_PATTERNS:
        if re.search(pat, ua_lower):
            hits.append(pat)
    return hits


def is_outdated_browser(browser_field: str, max_seen: dict, gap: int = 2) -> str | None:
    """
    Flag a browser only when its major version is more than `gap` versions behind
    the highest version seen for that browser across the entire log.

    gap=2 means: if the log's max Chrome is 149, then 148 and 149 are fine,
    but 147 and below are flagged.  This absorbs the normal 1-version rollout
    lag (Chrome 148 -> 149) without generating noise.

    Falls back to the absolute OUTDATED_BROWSER_THRESHOLDS config value when
    that browser appears in only one version across the whole log.
    """
    bv = browser_version(browser_field)
    if not bv:
        return None
    name, ver = bv
    observed_max = max_seen.get(name)
    if observed_max is not None:
        if ver < (observed_max - gap):
            return (f"{name.title()} {ver} "
                    f"(latest seen in log: {observed_max}, flagging gap > {gap})")
    else:
        threshold = OUTDATED_BROWSER_THRESHOLDS.get(name)
        if threshold and ver < threshold:
            return f"{name.title()} {ver} (absolute floor: {threshold})"
    return None


def normalize_asn(asn_field: str) -> str:
    """Normalize ASN field to 'AS12345' format."""
    s = asn_field.strip()
    if not s:
        return ""
    if not s.upper().startswith("AS"):
        s = "AS" + s
    return s.upper()


# plain dict for simplicity

def finding(category: str, severity: str, row: dict, detail: str) -> dict:
    return {
        "category":  category,
        "severity":  severity,   # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "date":      row.get(COL["date"], ""),
        "user":      row.get(COL["user"], ""),
        "username":  row.get(COL["username"], ""),
        "ip":        row.get(COL["ip"], ""),
        "location":  row.get(COL["location"], ""),
        "app":       row.get(COL["app"], ""),
        "resource":  row.get(COL["resource"], ""),
        "detail":    detail,
        "request_id": row.get(COL["request_id"], ""),
    }



# main analysis functions 
# if you find an unusual amount of false positives this is probably where your edits are needed 

def analyze(csv_path: str, trusted_countries: set[str]) -> list[dict]:
    findings: list[dict] = []

    # tracking for impossible travel & SID reuse
    user_sessions: dict[str, list[dict]] = defaultdict(list)   
    session_map:   dict[str, list[dict]] = defaultdict(list)  

    rows: list[dict] = []

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    # find newest version of each browser in the log
    # used to exlude some browsers from flagging as "old" 
    browser_max_seen: dict[str, int] = {}
    for _row in rows:
        _bv = browser_version(_row.get(COL["browser"], "").strip())
        if _bv:
            _name, _ver = _bv
            if _ver > browser_max_seen.get(_name, 0):
                browser_max_seen[_name] = _ver

    for row in rows:
        status    = row.get(COL["status"], "").strip()
        username  = row.get(COL["username"], "").strip()
        user_id   = row.get(COL["user_id"], "").strip()
        location  = row.get(COL["location"], "").strip()
        ip        = row.get(COL["ip"], "").strip()
        ua        = row.get(COL["user_agent"], "").strip()
        browser   = row.get(COL["browser"], "").strip()
        app       = row.get(COL["app"], "").strip()
        resource  = row.get(COL["resource"], "").strip()
        error_code = str(row.get(COL["error_code"], "")).strip()
        asn_raw   = row.get(COL["asn"], "").strip()
        session_id = row.get(COL["session_id"], "").strip()
        flagged   = row.get(COL["flagged"], "").strip().lower()
        auth_req  = row.get(COL["auth_req"], "").strip().lower()
        mfa_result = row.get(COL["mfa_result"], "").strip().lower()
        dt        = parse_date(row.get(COL["date"], ""))

        is_success = status.lower() == "success"

        # Foreign sign-ins
        if is_success and location:
            country = extract_country(location)
            if country and country not in trusted_countries:
                findings.append(finding(
                    "Foreign Sign-In", "HIGH", row,
                    f"Successful sign-in from {country} ({location}). "
                    f"Trusted countries: {', '.join(sorted(trusted_countries))}."
                ))

        # flagges for review in the logs 
        if flagged in ("true", "yes", "1"):
            findings.append(finding(
                "Risky User (MS-Flagged)", "CRITICAL", row,
                f"Microsoft Entra marked this sign-in as 'Flagged for review'."
            ))

        # suspicious error codes (really might need to edit error codes this might produce a LOT of FPs)
        if error_code in SUSPICIOUS_ERROR_CODES:
            findings.append(finding(
                "Suspicious Error Code", "MEDIUM", row,
                f"Error code {error_code}: {SUSPICIOUS_ERROR_CODES[error_code]}."
            ))

        # This is useful for catching brute force attempts on one account. If there is like 1 attempt per account on this it's just noise
        asn = normalize_asn(asn_raw)
        if asn and asn in SUSPICIOUS_ASNS:
            findings.append(finding(
                "Suspicious ASN / Hosting IP", "HIGH", row,
                f"Sign-in from ASN {asn} — known VPN/hosting/proxy range."
            ))

        # sus ua's like powershell, curl, python-requests, etc.
        if ua:
            ua_hits = is_suspicious_ua(ua)
            if ua_hits:
                findings.append(finding(
                    "Suspicious User Agent", "HIGH", row,
                    f"UA matched suspicious pattern(s): {ua_hits}. UA: {ua[:200]}"
                ))

        # outdated browser check
        if browser:
            old = is_outdated_browser(browser, browser_max_seen)
            if old:
                findings.append(finding(
                    "Outdated Browser", "LOW", row,
                    f"Browser version is outdated: {old}. Full field: '{browser}'."
                ))

        # suspicious applications like microsoft graph, etc
        app_lower = app.lower()
        for sus_app in SUSPICIOUS_APP_NAMES:
            if sus_app in app_lower:
                findings.append(finding(
                    "Suspicious Client Application", "MEDIUM", row,
                    f"Application '{app}' matches suspicious app pattern '{sus_app}'."
                ))
            break

        # check for repeated access to sensitive resource without 2FA from outside home state
        # implementation for changing home state through terminal is coming... probably (remind me)
        if is_success and "single-factor" in auth_req:
            res_lower = resource.lower()
            for sens in SENSITIVE_RESOURCES:
                if sens in res_lower and extract_state(location) !="TEXAS":
                    findings.append(finding(
                        "MFA Gap — Sensitive Resource", "HIGH", row,
                        f"Single-factor auth used to access '{resource}'. "
                        f"MFA result: '{mfa_result}'."
                    ))
                    break

        # store rows on success for checking impossible travel and other things
        if status.lower() in ("success", "interrupted") and dt:
            user_sessions[user_id].append({
                "dt": dt, "location": location, "ip": ip,
                "ua": ua, "os": row.get(COL["os"], ""),
                "row": row,
            })
        # store rows on session_id being given or used. Catches session IDs on "failed" sign-ins
        if session_id:
            session_map[session_id].append({
                "ua": ua, "ip": ip, "location": location,
                "os": row.get(COL["os"], ""),
                "device_id": row.get(COL["device_id"], ""),
                "row": row,
            })

    # second pass, comparing rows 

    # impossible travel
    for user_id, events in user_sessions.items():
        events_sorted = sorted(events, key=lambda e: e["dt"])

        for i in range(len(events_sorted) - 1):
            a, b = events_sorted[i], events_sorted[i + 1]
            ## debug
            
            ## debug
            if (a["location"] == b["location"]) or (a['location'] == ", ," or b['location'] == ", ,"):
                continue
            if a.get("session_id") != b.get("session_id") :
                continue
            country_a = extract_country(a["location"])
            country_b = extract_country(b["location"])

            # also skip if state/region matches
            state_a = extract_state(a["location"])
            state_b = extract_state(b["location"])
        
            if (state_a and state_b and state_a == state_b) and (country_a == country_b):
                continue
            delta_h = (b["dt"] - a["dt"]).total_seconds() / 3600

            if delta_h < 0.5:  # less than 30 minutes between different locations
                findings.append(finding(
                    "Impossible Travel", "CRITICAL", b["row"],
                    f"User signed in from '{a['location']}' at {a['dt'].isoformat()} "
                    f"then '{b['location']}' at {b['dt'].isoformat()} "
                    f"— only {delta_h:.1f}h apart across different locations."
                ))

            

    # SID reuse
    for session_id, events in session_map.items():
        if not session_id or len(events) < 2:
            continue

        def _ua_family(ua: str) -> str:
            """
            Collapse a UA string to 'browser_name/major_version' so that a
            browser auto-update within the same session (e.g. Chrome/148 ->
            Chrome/149) does not look like a different user agent.
            Only flag when the browser name or major version changes by more
            than 1.
            """
            if not ua:
                return ""
            # Extract the primary browser token: look for Chrome/X, Firefox/X, etc.
            m = re.search(r'(Chrome|Firefox|Edg(?:e|)|Safari|OPR|MSIE)[/ ](\d+)', ua, re.I)
            if m:
                return f"{m.group(1).lower()}/{int(m.group(2))}"
            return ua  # fall back to full string if unparseable

        ua_families = [_ua_family(e["ua"]) for e in events if e["ua"]]

        def _ua_bucket(fam: str) -> str:
            """Round major version DOWN to nearest even number so consecutive
            versions (148, 149) land in the same bucket (148)."""
            m = re.match(r'(.+)/(\d+)$', fam)
            if m:
                maj = int(m.group(2))
                return f"{m.group(1)}/{maj - (maj % 2)}"
            return fam

        unique_ua_buckets = {_ua_bucket(f) for f in ua_families if f}
        unique_ips  = {e["ip"]       for e in events if e["ip"]}
        unique_locs = {e["location"] for e in events if e["location"]}
        unique_os   = {e["os"]       for e in events if e["os"]}

        # get rid of duplicates to reduce noise 
        unique_contexts = {
            (_ua_bucket(_ua_family(e["ua"])), e["ip"], e["os"])
            for e in events
        }
        # if everything is basically the same just skip 
        if len(unique_contexts) < 2:
            continue

        if len(unique_locs) <= 1:
            unique_ips = set()

        unique_states = {extract_state(e["location"]) for e in events if e["location"]}
        if len(unique_states) <= 1:
            unique_locs = set()
            unique_ips = set()

        anomalies = []
        if len(unique_ua_buckets) > 1:
            anomalies.append(f"UAs (normalised): {unique_ua_buckets}")
        if len(unique_ips)  > 1: anomalies.append(f"IPs: {unique_ips}")
        if len(unique_locs) > 1: anomalies.append(f"locations: {unique_locs}")
        if len(unique_os)   > 1: anomalies.append(f"OSes: {unique_os}")

        if anomalies:
            findings.append(finding(
                "Session ID Reuse / Token Replay", "CRITICAL", events[0]["row"],
                f"Session ID '{session_id}' seen across different contexts: "
                + "; ".join(anomalies) + "."
            ))

    return findings

def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """
    Group findings by (username, category, key detail signature).
    Keep the first occurrence but append a count if it happened more than once.
    """
    seen: dict[tuple, dict] = {}
    counts: dict[tuple, int] = {}

    for f in findings:
        # Build a signature that captures "same event, same user"
        # For error codes: include the code. For impossible travel: include the location pair.
        # For everything else: category + username is enough.
        detail = f["detail"]

        if f["category"] == "Suspicious Error Code":
            # Extract the error code from the detail string
            m = re.search(r"Error code (\d+)", detail)
            sig_detail = m.group(0) if m else detail[:40]

        elif f["category"] == "Impossible Travel":
            # Extract the two locations
            m = re.search(r"from '(.+?)'.+?'(.+?)'", detail)
            sig_detail = f"{m.group(1)} -> {m.group(2)}" if m else detail[:40]

        elif f["category"] == "Foreign Sign-In":
            m = re.search(r"from (\w+)", detail)
            sig_detail = m.group(0) if m else detail[:40]

        elif f["category"] == "Outdated Browser":
            # Same browser version for same user
            m = re.search(r"([\w]+ \d+)", detail)
            sig_detail = m.group(0) if m else detail[:40]

        elif f["category"] == "Suspicious User Agent":
            sig_detail = detail[:60]

        elif f["category"] == "MFA Gap — Sensitive Resource":
            m = re.search(r"'(.+?)'", detail)
            sig_detail = m.group(0) if m else detail[:40]

        elif f["category"] == "Session ID Reuse / Token Replay":
            m = re.search(r"Session ID '(.+?)'", detail)
            sig_detail = m.group(0) if m else detail[:40]

        else:
            sig_detail = detail[:40]

        key = (f["username"], f["category"], sig_detail)

        if key not in seen:
            seen[key] = f
            counts[key] = 1
        else:
            counts[key] += 1

    # Annotate with count where > 1
    result = []
    for key, f in seen.items():
        if counts[key] > 1:
            f = dict(f)  # don't mutate the original
            f["category"] = f"{f['category']} x{counts[key]}"
        result.append(f)

    return result

# output

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#3498db",
    "INFO":     "#95a5a6",
}

def print_text_summary(findings: list[dict]) -> None:
    from collections import Counter
    counts = Counter(f["severity"] for f in findings)
    cat_counts = Counter(f["category"] for f in findings)

    print("\n" + "=" * 70)
    print("  ENTRA ID SIGN-IN THREAT DETECTION REPORT")
    print("=" * 70)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = counts.get(sev, 0)
        if n:
            print(f"  {sev:<10} {n}")
    print(f"\n  Total findings: {len(findings)}")
    print("=" * 70)

    from collections import defaultdict as _dd
    user_scores  = _dd(int)
    user_cats    = _dd(set)
    for f in findings:
        if f["username"]:
            user_scores[f["username"]] += SEVERITY_WEIGHTS.get(f["severity"], 0)
            user_cats[f["username"]].add(f["category"])

    def _sort_key(item):
        user, score = item
        cats = user_cats[user]
        score = score * (len(cats))^2
        all_cats   = cats >= ALERT_CATEGORIES   # has every category
        single_cat = len(cats) == 1             # all alerts same category
        return (
            0 if all_cats else 1,   # full spread floats to top
            -len(cats),
            -score,                 # then by weighted score descending
        )

    likely_compromised = [
        (u, s) for u, s in user_scores.items()
        if s >= COMPROMISE_SCORE_THRESHOLD and len(user_cats[u]) > 1  # exclude single-category
    ]
    likely_compromised.sort(key=_sort_key)

    for user, score in likely_compromised:
            cats = user_cats[user]
            print(f"  {user:<48} score: {score}  categories: {len(cats)}")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    for f in sorted_findings:
        print(f"\n[{f['severity']}] {f['category']}")
        print(f"  Date:     {f['date']}")
        print(f"  User:     {f['user']} ({f['username']})")
        print(f"  IP:       {f['ip']}  Location: {f['location']}")
        print(f"  App:      {f['app']}  Resource: {f['resource']}")
        print(f"  Detail:   {f['detail']}")
        print(f"  ReqID:    {f['request_id']}")


def print_header(csv_path: str, trusted: set[str]) -> None:
    print("=" * 60)
    print("  ENTRA ID SIGN-IN ANALYZER")
    print("=" * 60)
    print(f"  Source:            {csv_path}")
    print(f"  Trusted countries: {', '.join(sorted(trusted))}")
    print("=" * 60)


def pick(options: list[str], prompt_text: str = "Select an option") -> int:
    """Print a numbered menu and return the 1-based choice as an int. 0 = back/quit."""
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    print(f"  [0] Quit")
    while True:
        try:
            val = int(input(f"\n{prompt_text}: ").strip())
            if 0 <= val <= len(options):
                return val
            print(f"  Enter a number between 0 and {len(options)}.")
        except ValueError:
            print("  Invalid input, enter a number.")


def menu_main(csv_path: str, trusted: set[str]) -> None:
    while True:
        print_header(csv_path, trusted)
        print()
        choice = pick([
            "Full Analysis  — run all detections across all users",
            "Analyze Specific User  — get all detections for this user",
        ])

        if choice == 0:
            print("\nExiting.\n")
            break
        elif choice == 1:
            menu_full_analysis(csv_path, trusted)
        elif choice == 2:
            menu_user_analysis(csv_path, trusted)

def menu_full_analysis(csv_path: str, trusted: set[str]) -> None:
    print_header(csv_path, trusted)
    print("\n  FULL ANALYSIS — Output Format\n")
    choice = pick([
        "Print to terminal",
        "Save as TXT file",
    ], "Select output format")

    if choice == 0:
        return

    print(f"\n[*] Analyzing {csv_path} …")
    findings = analyze(csv_path, trusted)
    findings = deduplicate_findings(findings)
    print(f"[*] {len(findings)} findings.\n")

    if choice == 1:
        print_text_summary(findings)
        input("\nPress Enter to return to the main menu…")

    elif choice == 2:
        out_path = input("  Output file path [report.txt]: ").strip() or "report.txt"
        import io
        buf = io.StringIO()
        _stdout = sys.stdout
        sys.stdout = buf
        print_text_summary(findings)
        sys.stdout = _stdout
        Path(out_path).write_text(buf.getvalue(), encoding="utf-8")
        print(f"[*] Report written to {out_path}")
        input("\nPress Enter to return to the main menu…")

def menu_user_analysis(csv_path: str, trusted: set[str]) -> None:
    print_header(csv_path, trusted)
    print("\n  ANALYZE SPECIFIC USER\n")
    username = input("  Enter username (email): ").strip().lower()
    if not username:
        print("  Username not found.")
        return

    print(f"\n[*] Analyzing {csv_path} …")
    all_findings = analyze(csv_path, trusted)
    all_findings = deduplicate_findings(all_findings)
    findings = [f for f in all_findings if f["username"].lower() == username]

    if not findings:
        print(f"  No findings for '{username}'.")
        input("\n  Press Enter to return to the main menu…")
        return

    print(f"[*] {len(findings)} findings for {username}.\n")

    choice = pick([
        "Print to terminal",
        "Save as TXT file",
    ], "Select output format")

    if choice == 0:
        return

    if choice == 1:
        print_text_summary(findings)
        input("\nPress Enter to return to the main menu…")

    elif choice == 2:
        out_path = input(f"  Output file path [{username}_report.txt]: ").strip() or f"{username}_report.txt"
        import io
        buf = io.StringIO()
        _stdout = sys.stdout
        sys.stdout = buf
        print_text_summary(findings)
        sys.stdout = _stdout
        Path(out_path).write_text(buf.getvalue(), encoding="utf-8")
        print(f"[*] Report written to {out_path}")
        input("\nPress Enter to return to the main menu…")

    input("\nPress Enter to return to the main menu…")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Entra ID interactive sign-in CSV for security threats."
    )
    parser.add_argument("csv", help="Path to the InteractiveSignIns CSV file.")
    parser.add_argument(
        "--trusted-countries", "-t", default=None,
        help="Comma-separated ISO country codes considered trusted "
             f"(default: {','.join(sorted(DEFAULT_TRUSTED_COUNTRIES))})."
    )
    args = parser.parse_args()

    trusted = (
        {c.strip().upper() for c in args.trusted_countries.split(",")}
        if args.trusted_countries
        else DEFAULT_TRUSTED_COUNTRIES
    )

    menu_main(args.csv, trusted)


if __name__ == "__main__":
    main()


