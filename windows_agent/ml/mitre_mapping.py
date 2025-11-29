"""
MITRE ATT&CK Technique Mapping
Maps detected behaviors to ATT&CK framework techniques.
"""

from typing import List, Dict, Any

MITRE_TECHNIQUES = {
    # Initial Access (TA0001)
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "indicators": ["outlook", "mail", ".doc", ".xls", "macro"]},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access", "indicators": ["browser", "javascript", "flash"]},
    
    # Execution (TA0002)
    "T1059.001": {"name": "PowerShell", "tactic": "Execution", "indicators": ["powershell", "-enc", "invoke-", "iex"]},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution", "indicators": ["cmd.exe", "/c", "cmd /"]},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution", "indicators": ["wscript", "cscript", ".vbs", ".vbe"]},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution", "indicators": ["wscript", "cscript", ".js", ".jse"]},
    "T1047": {"name": "WMI", "tactic": "Execution", "indicators": ["wmic", "wmiprvse", "winmgmt"]},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Execution", "indicators": ["schtasks", "at.exe", "taskschd"]},
    "T1569.002": {"name": "Service Execution", "tactic": "Execution", "indicators": ["sc.exe", "services.exe", "psexec"]},
    
    # Persistence (TA0003)
    "T1547.001": {"name": "Registry Run Keys", "tactic": "Persistence", "indicators": ["reg add", "currentversion\\run", "runonce"]},
    "T1543.003": {"name": "Windows Service", "tactic": "Persistence", "indicators": ["sc create", "new-service", "installutil"]},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "indicators": ["schtasks /create", "at \\\\"]},
    
    # Privilege Escalation (TA0004)
    "T1548.002": {"name": "UAC Bypass", "tactic": "Privilege Escalation", "indicators": ["fodhelper", "eventvwr", "sdclt", "computerdefaults"]},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation", "indicators": ["impersonate", "token", "runas"]},
    
    # Defense Evasion (TA0005)
    "T1562.001": {"name": "Disable Security Tools", "tactic": "Defense Evasion", "indicators": ["stop-service", "sc stop", "taskkill", "defender"]},
    "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion", "indicators": ["del /f", "remove-item", "erase"]},
    "T1027": {"name": "Obfuscated Files", "tactic": "Defense Evasion", "indicators": ["-enc", "base64", "frombase64", "gzipstream"]},
    "T1218": {"name": "Signed Binary Proxy", "tactic": "Defense Evasion", "indicators": ["mshta", "regsvr32", "rundll32", "msiexec"]},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "indicators": ["svchost", "csrss", "lsass"]},
    
    # Credential Access (TA0006)
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access", "indicators": ["lsass", "mimikatz", "sekurlsa", "procdump"]},
    "T1003.002": {"name": "SAM Database", "tactic": "Credential Access", "indicators": ["sam", "system", "security", "ntds"]},
    "T1558.003": {"name": "Kerberoasting", "tactic": "Credential Access", "indicators": ["kerberos", "spn", "ticket", "asreproast"]},
    "T1552.001": {"name": "Credentials in Files", "tactic": "Credential Access", "indicators": ["password", "credential", ".config", "web.config"]},
    
    # Discovery (TA0007)
    "T1082": {"name": "System Information", "tactic": "Discovery", "indicators": ["systeminfo", "hostname", "whoami"]},
    "T1083": {"name": "File Discovery", "tactic": "Discovery", "indicators": ["dir /s", "get-childitem", "find /"]},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery", "indicators": ["tasklist", "get-process", "ps aux"]},
    "T1049": {"name": "Network Connections", "tactic": "Discovery", "indicators": ["netstat", "get-nettcpconnection"]},
    "T1016": {"name": "Network Configuration", "tactic": "Discovery", "indicators": ["ipconfig", "ifconfig", "route print"]},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery", "indicators": ["net view", "ping", "nslookup"]},
    
    # Lateral Movement (TA0008)
    "T1021.001": {"name": "RDP", "tactic": "Lateral Movement", "indicators": ["mstsc", "rdp", "3389"]},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement", "indicators": ["net use", "\\\\", "admin$", "c$"]},
    "T1021.006": {"name": "WinRM", "tactic": "Lateral Movement", "indicators": ["winrm", "invoke-command", "enter-pssession", "5985", "5986"]},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "indicators": ["copy", "xcopy", "robocopy", "scp"]},
    
    # Collection (TA0009)
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection", "indicators": ["compress-archive", "7z", "rar", "zip"]},
    "T1115": {"name": "Clipboard Data", "tactic": "Collection", "indicators": ["clipboard", "get-clipboard", "paste"]},
    "T1113": {"name": "Screen Capture", "tactic": "Collection", "indicators": ["screenshot", "printscreen", "bitblt"]},
    
    # Command and Control (TA0011)
    "T1071.001": {"name": "Web Protocols", "tactic": "Command and Control", "indicators": ["http", "https", "443", "80"]},
    "T1071.004": {"name": "DNS", "tactic": "Command and Control", "indicators": ["dns", "nslookup", "53"]},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control", "indicators": ["tunnel", "proxy", "socks"]},
    
    # Exfiltration (TA0010)
    "T1041": {"name": "Exfil Over C2", "tactic": "Exfiltration", "indicators": ["upload", "exfil", "send-file"]},
    "T1048": {"name": "Exfil Over Alternative Protocol", "tactic": "Exfiltration", "indicators": ["dns", "icmp", "ftp"]},
    "T1567": {"name": "Exfil Over Web Service", "tactic": "Exfiltration", "indicators": ["dropbox", "gdrive", "onedrive", "pastebin"]},
    
    # Impact (TA0040)
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "indicators": ["encrypt", "ransom", ".locked", "bitcoin"]},
    "T1489": {"name": "Service Stop", "tactic": "Impact", "indicators": ["stop-service", "sc stop", "net stop"]},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "indicators": ["vssadmin", "bcdedit", "wbadmin"]},
}


def map_to_mitre(event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Map event data to MITRE ATT&CK techniques.
    
    Args:
        event_data: Dictionary containing event details
        
    Returns:
        List of matched techniques with confidence scores
    """
    matches = []
    
    # Combine all searchable text
    searchable = ' '.join([
        str(event_data.get('name', '')),
        str(event_data.get('exe', '')),
        str(event_data.get('cmdline', '')),
        str(event_data.get('description', '')),
        str(event_data.get('details', '')),
    ]).lower()
    
    for technique_id, technique_info in MITRE_TECHNIQUES.items():
        indicators = technique_info.get('indicators', [])
        matched_indicators = [ind for ind in indicators if ind.lower() in searchable]
        
        if matched_indicators:
            confidence = min(len(matched_indicators) / len(indicators), 1.0)
            matches.append({
                'technique_id': technique_id,
                'technique_name': technique_info['name'],
                'tactic': technique_info['tactic'],
                'confidence': confidence,
                'matched_indicators': matched_indicators,
            })
    
    # Sort by confidence
    matches.sort(key=lambda x: x['confidence'], reverse=True)
    
    return matches


def get_technique_info(technique_id: str) -> Dict[str, Any]:
    """Get information about a specific technique."""
    return MITRE_TECHNIQUES.get(technique_id, {})


def get_techniques_by_tactic(tactic: str) -> List[str]:
    """Get all techniques for a specific tactic."""
    return [
        tid for tid, info in MITRE_TECHNIQUES.items()
        if info.get('tactic', '').lower() == tactic.lower()
    ]
