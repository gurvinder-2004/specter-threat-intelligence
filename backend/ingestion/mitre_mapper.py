"""
MITRE ATT&CK Mapper
Maps text keywords/phrases to ATT&CK technique IDs automatically.
No API call needed — uses a curated keyword lookup table.
"""
import re
from dataclasses import dataclass

@dataclass
class TTPMatch:
    technique_id: str
    technique_name: str
    tactic: str
    matched_keyword: str


# ── Keyword → ATT&CK mapping ──────────────────────────────────────────────────
# Format: (regex_pattern, technique_id, technique_name, tactic)
_TTP_MAP: list[tuple[str, str, str, str]] = [
    # Credential Access
    (r"lsass|credential dump|mimikatz|sekurlsa",         "T1003",     "OS Credential Dumping",           "Credential Access"),
    (r"lsass\.exe memory",                                "T1003.001", "LSASS Memory",                    "Credential Access"),
    (r"ntds\.dit|domain controller dump",                 "T1003.003", "NTDS",                            "Credential Access"),
    (r"kerberoast|spn|service principal",                 "T1558.003", "Kerberoasting",                   "Credential Access"),
    (r"pass.the.hash|pth\b",                              "T1550.002", "Pass the Hash",                   "Lateral Movement"),
    (r"brute.forc|password spray|credential stuff",       "T1110",     "Brute Force",                     "Credential Access"),

    # Execution
    (r"powershell.*encoded|encodedcommand|-enc\b",        "T1059.001", "PowerShell",                      "Execution"),
    (r"cmd\.exe|command.line",                            "T1059.003", "Windows Command Shell",           "Execution"),
    (r"python.*exec|bash.*exec|shell.*exec",              "T1059",     "Command and Scripting Interpreter","Execution"),
    (r"wscript|cscript|vbscript|jscript",                 "T1059.005", "Visual Basic",                    "Execution"),
    (r"mshta|hta.applic",                                 "T1218.005", "Mshta",                           "Defense Evasion"),
    (r"regsvr32|scrobj",                                  "T1218.010", "Regsvr32",                        "Defense Evasion"),

    # Persistence
    (r"registry run key|hklm\\software\\microsoft\\windows\\currentversion\\run", "T1547.001", "Registry Run Keys", "Persistence"),
    (r"scheduled task|schtask|at\.exe",                   "T1053.005", "Scheduled Task",                  "Persistence"),
    (r"startup folder",                                   "T1547.001", "Startup Folder",                  "Persistence"),
    (r"dll.hijack|dll.side.load",                         "T1574.001", "DLL Hijacking",                   "Persistence"),
    (r"web shell|webshell",                               "T1505.003", "Web Shell",                       "Persistence"),

    # Defense Evasion
    (r"obfuscat|base64.encod",                            "T1027",     "Obfuscated Files or Information", "Defense Evasion"),
    (r"process.inject|shellcode.inject",                  "T1055",     "Process Injection",               "Defense Evasion"),
    (r"uac bypass|elevat.*priv",                          "T1548.002", "Bypass UAC",                      "Defense Evasion"),
    (r"disable.*antivirus|tamper.*defender|kill.*av",     "T1562.001", "Disable or Modify Tools",         "Defense Evasion"),
    (r"timestomp|modify.timestamp",                       "T1070.006", "Timestomp",                       "Defense Evasion"),
    (r"living.off.the.land|lolbin",                       "T1218",     "System Binary Proxy Execution",   "Defense Evasion"),

    # Discovery
    (r"nmap|port.scan|network.scan",                      "T1046",     "Network Service Discovery",       "Discovery"),
    (r"whoami|net user|net group",                        "T1033",     "System Owner/User Discovery",     "Discovery"),
    (r"ipconfig|ifconfig|arp",                            "T1016",     "System Network Config Discovery", "Discovery"),
    (r"bloodhound|sharphound|ldap.*enum",                 "T1087",     "Account Discovery",               "Discovery"),

    # Lateral Movement
    (r"psexec|wmi.*exec|wmiexec",                         "T1021.003", "Distributed Component Object Model", "Lateral Movement"),
    (r"rdp|remote desktop|3389",                          "T1021.001", "Remote Desktop Protocol",        "Lateral Movement"),
    (r"smb|445|admin\$",                                  "T1021.002", "SMB/Windows Admin Shares",        "Lateral Movement"),
    (r"ssh.* lateral|ssh.*pivot",                         "T1021.004", "SSH",                             "Lateral Movement"),

    # Collection
    (r"keylog",                                           "T1056.001", "Keylogging",                      "Collection"),
    (r"screenshot|screen.capture",                        "T1113",     "Screen Capture",                  "Collection"),
    (r"clipboard",                                        "T1115",     "Clipboard Data",                  "Collection"),

    # Command & Control
    (r"c2|command.and.control|c&c",                       "T1071",     "Application Layer Protocol",      "Command and Control"),
    (r"cobalt.strike|beacon",                             "T1071.001", "Web Protocols",                   "Command and Control"),
    (r"dns.tunnel|iodine|dnscat",                         "T1071.004", "DNS",                             "Command and Control"),
    (r"domain.front|fronting",                            "T1090.004", "Domain Fronting",                 "Command and Control"),
    (r"tor\b|onion.network|darkweb",                      "T1090.003", "Multi-hop Proxy",                 "Command and Control"),

    # Exfiltration
    (r"exfil|data.theft|steal.*data",                     "T1041",     "Exfiltration Over C2 Channel",    "Exfiltration"),
    (r"dropbox.*exfil|s3.*exfil|cloud.*exfil",            "T1567",     "Exfiltration Over Web Service",   "Exfiltration"),

    # Impact
    (r"ransomware|encrypt.*file|ransom.note",             "T1486",     "Data Encrypted for Impact",       "Impact"),
    (r"wiper|disk.wipe|mbr.*overwrite",                   "T1561",     "Disk Wipe",                       "Impact"),
    (r"ddos|denial.of.service",                           "T1498",     "Network Denial of Service",       "Impact"),

    # Initial Access
    (r"spear.phish|phishing.*email|malicious.*attachment","T1566.001", "Spearphishing Attachment",        "Initial Access"),
    (r"phishing.*link|malicious.*url",                    "T1566.002", "Spearphishing Link",              "Initial Access"),
    (r"watering.hole|strategic.*web",                     "T1189",     "Drive-by Compromise",             "Initial Access"),
    (r"supply.chain|software.*supply",                    "T1195",     "Supply Chain Compromise",         "Initial Access"),
    (r"exploit.*public|cve-20\d{2}",                      "T1190",     "Exploit Public-Facing Application","Initial Access"),
]

_COMPILED: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(pattern, re.IGNORECASE), tid, tname, tactic)
    for pattern, tid, tname, tactic in _TTP_MAP
]


def map_ttps(text: str) -> list[TTPMatch]:
    """
    Scan text and return all matched MITRE ATT&CK techniques.
    Deduplicates by technique_id.
    """
    seen_ids: set[str] = set()
    matches: list[TTPMatch] = []

    for pattern, tid, tname, tactic in _COMPILED:
        m = pattern.search(text)
        if m and tid not in seen_ids:
            seen_ids.add(tid)
            matches.append(TTPMatch(
                technique_id=tid,
                technique_name=tname,
                tactic=tactic,
                matched_keyword=m.group(0),
            ))

    return matches


def ttp_summary(matches: list[TTPMatch]) -> str:
    """Human-readable TTP summary for LLM context."""
    if not matches:
        return "No MITRE ATT&CK techniques detected."
    lines = [f"• {m.technique_id} – {m.technique_name} [{m.tactic}]" for m in matches]
    return "Detected techniques:\n" + "\n".join(lines)
