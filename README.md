# Sign-Ins_CSV_Analyzer

This is a CSV analyzer largely designed for Entra Sign-In logs. This is not a comlete replacement for traditional threathunting and CSV parsing but this should reveal obvious true positives immediately for rapid response. 

What it does:
it detects
    1. Foreign / unexpected country sign-ins
    2. Impossible travel (same user, multiple locations, implausible time delta)
    3. VPN / Tor / anonymous / bad-reputation ASN sign-ins
    4. Suspicious user agents (legacy browsers, scripting tools, attack tooling)
    5. Suspicious client applications (PowerShell, Graph Explorer, ROPC flows, etc.)
    6. Stolen / shared Session ID reused across different UA / OS / Location / IP
    7. Microsoft-flagged risky users ("Flagged for review")
    8. Outdated browsers
    9. Suspicious sign-in error codes (50199, 500119, 90014, and others)
This is what it initially looks for. 
#3 is based on a hard coded library, same goes for suspicious user agents and outdated browsers. Feel free to add to this library as you see fit. 

This is a rudementary script (may be obvious by this scuffed README) so use with caution and verify all findings. 
