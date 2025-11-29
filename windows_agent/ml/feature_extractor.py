"""
Advanced Feature Extraction for ML Threat Detection
Extracts 150+ features from security events.
Based on EMBER2024 methodology and endpoint telemetry research.
"""

import os
import math
import re
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime

import logging
logger = logging.getLogger("SentinelAgent.ML")


class AdvancedFeatureExtractor:
    """Extract 150+ features from security events."""
    
    # Feature count per category
    PROCESS_FEATURES = 30
    NETWORK_FEATURES = 25
    FILE_FEATURES = 25
    REGISTRY_FEATURES = 15
    BEHAVIORAL_FEATURES = 20
    CONTEXT_FEATURES = 15
    ANOMALY_FEATURES = 20
    TOTAL_FEATURES = 150
    
    def __init__(self):
        self._entropy_cache = {}
        self.feature_names = self._build_feature_names()
        
    def _build_feature_names(self) -> List[str]:
        """Build list of all feature names."""
        return [
            # Process (30)
            "proc_name_length", "proc_name_entropy", "proc_name_has_numbers",
            "proc_name_has_special", "proc_name_is_random", "proc_exe_length",
            "proc_exe_depth", "proc_exe_in_system32", "proc_exe_in_programfiles",
            "proc_exe_in_temp", "proc_exe_in_appdata", "proc_exe_in_downloads",
            "proc_exe_in_public", "proc_exe_unsigned_location", "proc_cmdline_length",
            "proc_cmdline_entropy", "proc_cmdline_has_encoded", "proc_cmdline_has_hidden",
            "proc_cmdline_has_bypass", "proc_cmdline_has_download", "proc_cmdline_has_invoke",
            "proc_cmdline_has_http", "proc_cmdline_has_base64", "proc_cmdline_has_reflection",
            "proc_cmdline_has_credential", "proc_cmdline_arg_count", "proc_cmdline_max_arg_len",
            "proc_cmdline_suspicious_ratio", "proc_is_script_engine", "proc_is_lolbin",
            # Network (25)
            "net_remote_port", "net_remote_port_is_standard", "net_remote_port_is_suspicious",
            "net_remote_port_is_high", "net_local_port", "net_is_inbound", "net_is_outbound",
            "net_remote_ip_is_private", "net_remote_ip_is_localhost", "net_remote_ip_entropy",
            "net_connection_count", "net_unique_ports", "net_unique_ips", "net_bytes_sent",
            "net_bytes_recv", "net_is_encrypted_port", "net_is_c2_port", "net_is_exfil_port",
            "net_dns_query_length", "net_dns_subdomain_count", "net_dns_entropy",
            "net_dns_is_suspicious_tld", "net_dns_is_dga", "net_dns_has_ip_pattern", "net_dns_query_rate",
            # File (25)
            "file_path_length", "file_path_depth", "file_extension_suspicious",
            "file_extension_executable", "file_extension_script", "file_extension_archive",
            "file_in_temp", "file_in_startup", "file_in_system", "file_name_entropy",
            "file_name_length", "file_name_has_double_ext", "file_name_mimics_system",
            "file_size_bytes", "file_size_suspicious", "file_is_hidden", "file_is_readonly",
            "file_created_recently", "file_modified_recently", "file_has_ads", "file_entropy",
            "file_has_pe_header", "file_has_script_content", "file_hash_known_bad", "file_signature_valid",
            # Registry (15)
            "reg_key_is_run", "reg_key_is_service", "reg_key_is_driver", "reg_key_is_security",
            "reg_key_is_firewall", "reg_key_is_defender", "reg_key_depth", "reg_value_length",
            "reg_value_has_exe", "reg_value_has_script", "reg_value_has_encoded",
            "reg_value_entropy", "reg_operation_create", "reg_operation_modify", "reg_operation_delete",
            # Behavioral (20)
            "behav_event_rate", "behav_unique_processes", "behav_process_spawn_rate",
            "behav_network_rate", "behav_file_create_rate", "behav_file_modify_rate",
            "behav_reg_modify_rate", "behav_has_recon_pattern", "behav_has_lateral_pattern",
            "behav_has_exfil_pattern", "behav_has_persistence_pattern", "behav_has_evasion_pattern",
            "behav_has_credential_pattern", "behav_time_of_day", "behav_is_business_hours",
            "behav_is_weekend", "behav_sequence_length", "behav_sequence_entropy",
            "behav_parent_child_depth", "behav_lateral_hop_count",
            # Context (15)
            "ctx_user_is_admin", "ctx_user_is_system", "ctx_user_is_service",
            "ctx_session_is_interactive", "ctx_session_is_rdp", "ctx_parent_is_explorer",
            "ctx_parent_is_services", "ctx_parent_is_cmd", "ctx_parent_is_powershell",
            "ctx_parent_is_browser", "ctx_parent_is_office", "ctx_parent_suspicious",
            "ctx_integrity_level", "ctx_token_elevated", "ctx_process_age_seconds",
            # Anomaly (20)
            "anom_process_frequency", "anom_process_rarity", "anom_cmdline_rarity",
            "anom_path_rarity", "anom_port_rarity", "anom_connection_rarity",
            "anom_time_deviation", "anom_behavior_deviation", "anom_sequence_deviation",
            "anom_volume_deviation", "anom_parent_child_unusual", "anom_network_unusual",
            "anom_file_access_unusual", "anom_registry_unusual", "anom_overall_score",
            "anom_isolation_score", "anom_local_outlier", "anom_cluster_distance",
            "anom_baseline_deviation", "anom_peer_deviation",
        ]
    
    def calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        if s in self._entropy_cache:
            return self._entropy_cache[s]
        
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        
        length = len(s)
        entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
        
        if len(self._entropy_cache) < 10000:
            self._entropy_cache[s] = entropy
        return entropy
    
    def is_random_string(self, s: str, threshold: float = 3.5) -> bool:
        """Check if string appears randomly generated."""
        if len(s) < 5:
            return False
        entropy = self.calculate_entropy(s.lower())
        unique_ratio = len(set(s.lower())) / len(s)
        return entropy > threshold and unique_ratio > 0.6
    
    def extract_process_features(self, event: Dict) -> List[float]:
        """Extract 30 process-related features."""
        features = []
        name = str(event.get('name', '') or '').lower()
        exe = str(event.get('exe', '') or '').lower()
        cmdline = str(event.get('cmdline', '') or '').lower()
        
        # Name features (5)
        features.append(float(len(name)))
        features.append(self.calculate_entropy(name))
        features.append(1.0 if any(c.isdigit() for c in name) else 0.0)
        features.append(1.0 if any(c in name for c in '_-$@#') else 0.0)
        features.append(1.0 if self.is_random_string(name) else 0.0)
        
        # Exe path features (9)
        features.append(float(len(exe)))
        features.append(float(exe.count('\\') + exe.count('/')))
        features.append(1.0 if 'system32' in exe or 'syswow64' in exe else 0.0)
        features.append(1.0 if 'program files' in exe else 0.0)
        features.append(1.0 if 'temp' in exe or 'tmp' in exe else 0.0)
        features.append(1.0 if 'appdata' in exe else 0.0)
        features.append(1.0 if 'download' in exe else 0.0)
        features.append(1.0 if 'public' in exe or 'users\\public' in exe else 0.0)
        features.append(1.0 if any(p in exe for p in ['temp', 'tmp', 'downloads']) else 0.0)
        
        # Command line features (14)
        features.append(float(len(cmdline)))
        features.append(self.calculate_entropy(cmdline))
        features.append(1.0 if any(p in cmdline for p in ['-enc', '-encoded', 'encodedcommand']) else 0.0)
        features.append(1.0 if any(p in cmdline for p in ['-hidden', '-windowstyle hidden']) else 0.0)
        features.append(1.0 if 'bypass' in cmdline else 0.0)
        features.append(1.0 if any(p in cmdline for p in ['downloadstring', 'downloadfile', 'wget', 'curl']) else 0.0)
        features.append(1.0 if 'invoke-' in cmdline or 'iex' in cmdline else 0.0)
        features.append(1.0 if 'http://' in cmdline or 'https://' in cmdline else 0.0)
        features.append(1.0 if 'base64' in cmdline or 'frombase64' in cmdline else 0.0)
        features.append(1.0 if 'reflection' in cmdline or 'assembly' in cmdline else 0.0)
        features.append(1.0 if any(p in cmdline for p in ['credential', 'password', 'secret']) else 0.0)
        
        args = cmdline.split()
        features.append(float(len(args)))
        features.append(float(max(len(a) for a in args)) if args else 0.0)
        
        suspicious_patterns = ['-enc', 'hidden', 'bypass', 'invoke', 'download', 'http', 'base64']
        features.append(sum(1 for p in suspicious_patterns if p in cmdline) / len(suspicious_patterns))
        
        # Process type (2)
        script_engines = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'python']
        features.append(1.0 if any(s in name for s in script_engines) else 0.0)
        
        lolbins = ['mshta', 'regsvr32', 'rundll32', 'msiexec', 'certutil', 'bitsadmin', 'wmic', 'cmstp']
        features.append(1.0 if any(l in name for l in lolbins) else 0.0)
        
        return features
    
    def extract_network_features(self, event: Dict) -> List[float]:
        """Extract 25 network-related features."""
        features = []
        remote_ip = str(event.get('remote_ip', '') or '')
        remote_port = int(event.get('remote_port', 0) or 0)
        local_port = int(event.get('local_port', 0) or 0)
        direction = str(event.get('direction', 'outbound') or 'outbound').lower()
        domain = str(event.get('domain', '') or '')
        
        # Port features (8)
        features.append(float(remote_port))
        standard_ports = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995}
        features.append(1.0 if remote_port in standard_ports else 0.0)
        suspicious_ports = {4444, 5555, 6666, 1337, 31337, 12345, 54321}
        features.append(1.0 if remote_port in suspicious_ports else 0.0)
        features.append(1.0 if remote_port > 49152 else 0.0)
        features.append(float(local_port))
        features.append(1.0 if direction == 'inbound' else 0.0)
        features.append(1.0 if direction == 'outbound' else 0.0)
        
        # IP features (3)
        features.append(1.0 if remote_ip.startswith(('10.', '192.168.', '172.16.')) else 0.0)
        features.append(1.0 if remote_ip in ['127.0.0.1', '::1', 'localhost'] else 0.0)
        features.append(self.calculate_entropy(remote_ip))
        
        # Connection stats (5)
        features.append(float(event.get('connection_count', 1)))
        features.append(float(event.get('unique_ports', 1)))
        features.append(float(event.get('unique_ips', 1)))
        features.append(float(event.get('bytes_sent', 0)))
        features.append(float(event.get('bytes_recv', 0)))
        
        # Port categories (3)
        features.append(1.0 if remote_port in {443, 993, 995, 465, 587, 22} else 0.0)
        features.append(1.0 if remote_port in {4444, 5555, 8080, 8443, 9001} else 0.0)
        features.append(1.0 if remote_port in {21, 22, 53, 443, 8080} else 0.0)
        
        # DNS features (6)
        features.append(float(len(domain)))
        features.append(float(domain.count('.')))
        features.append(self.calculate_entropy(domain))
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        features.append(1.0 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0.0)
        features.append(1.0 if domain and self.is_random_string(domain.split('.')[0]) else 0.0)
        features.append(1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0.0)
        features.append(float(event.get('dns_query_rate', 0)))
        
        return features
    
    def extract_file_features(self, event: Dict) -> List[float]:
        """Extract 25 file-related features."""
        features = []
        path = str(event.get('path', '') or '').lower()
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        
        # Path features (3)
        features.append(float(len(path)))
        features.append(float(path.count('\\') + path.count('/')))
        
        # Extension categories (4)
        suspicious_exts = ['.exe', '.dll', '.scr', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        features.append(1.0 if ext in suspicious_exts else 0.0)
        features.append(1.0 if ext in ['.exe', '.dll', '.sys', '.drv'] else 0.0)
        features.append(1.0 if ext in ['.ps1', '.bat', '.cmd', '.vbs', '.js'] else 0.0)
        features.append(1.0 if ext in ['.zip', '.rar', '.7z', '.tar', '.gz'] else 0.0)
        
        # Location features (3)
        features.append(1.0 if 'temp' in path or 'tmp' in path else 0.0)
        features.append(1.0 if 'startup' in path or 'start menu' in path else 0.0)
        features.append(1.0 if 'system32' in path or 'syswow64' in path else 0.0)
        
        # Name features (4)
        features.append(self.calculate_entropy(name))
        features.append(float(len(name)))
        features.append(1.0 if name.count('.') > 1 else 0.0)
        system_names = ['svchost', 'csrss', 'lsass', 'services', 'explorer']
        features.append(1.0 if any(s in name and name != f"{s}.exe" for s in system_names) else 0.0)
        
        # File metadata (11)
        features.append(float(event.get('size', 0)))
        size = event.get('size', 0)
        features.append(1.0 if size < 10000 or size > 100000000 else 0.0)
        features.append(1.0 if event.get('hidden', False) else 0.0)
        features.append(1.0 if event.get('readonly', False) else 0.0)
        features.append(1.0 if event.get('created_recently', False) else 0.0)
        features.append(1.0 if event.get('modified_recently', False) else 0.0)
        features.append(1.0 if event.get('has_ads', False) else 0.0)
        features.append(float(event.get('entropy', 0)))
        features.append(1.0 if event.get('has_pe_header', False) else 0.0)
        features.append(1.0 if event.get('has_script_content', False) else 0.0)
        features.append(1.0 if event.get('hash_known_bad', False) else 0.0)
        features.append(1.0 if event.get('signature_valid', True) else 0.0)
        
        return features
    
    def extract_registry_features(self, event: Dict) -> List[float]:
        """Extract 15 registry-related features."""
        features = []
        key = str(event.get('key', '') or '').lower()
        value = str(event.get('value', '') or '').lower()
        operation = str(event.get('operation', '') or '').lower()
        
        # Key categories (6)
        features.append(1.0 if 'currentversion\\run' in key or 'runonce' in key else 0.0)
        features.append(1.0 if 'services\\' in key else 0.0)
        features.append(1.0 if 'enum\\' in key or 'class\\' in key else 0.0)
        features.append(1.0 if 'security\\' in key or 'sam\\' in key else 0.0)
        features.append(1.0 if 'firewall' in key else 0.0)
        features.append(1.0 if 'defender' in key else 0.0)
        
        # Key depth (1)
        features.append(float(key.count('\\')))
        
        # Value features (5)
        features.append(float(len(value)))
        features.append(1.0 if '.exe' in value else 0.0)
        features.append(1.0 if any(s in value for s in ['.ps1', '.vbs', '.bat']) else 0.0)
        features.append(1.0 if any(e in value for e in ['-enc', 'encoded', 'base64']) else 0.0)
        features.append(self.calculate_entropy(value))
        
        # Operation type (3)
        features.append(1.0 if operation in ['create', 'setvalue'] else 0.0)
        features.append(1.0 if operation in ['modify', 'setvalue'] else 0.0)
        features.append(1.0 if operation in ['delete', 'deletevalue'] else 0.0)
        
        return features
    
    def extract_behavioral_features(self, events: List[Any]) -> List[float]:
        """Extract 20 behavioral sequence features."""
        features = [0.0] * 20
        if not events:
            return features
        
        # Event rate
        if len(events) >= 2:
            try:
                time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
                features[0] = len(events) / max(time_span, 1)
            except:
                features[0] = 0.0
        
        # Process diversity
        try:
            features[1] = float(len(set(e.process_name for e in events)))
        except:
            features[1] = 0.0
        
        # Event type rates
        total = len(events)
        try:
            features[2] = sum(1 for e in events if 'process' in e.event_type) / total
            features[3] = sum(1 for e in events if 'network' in e.event_type) / total
            features[4] = sum(1 for e in events if 'file' in e.event_type) / total
            features[5] = features[4]  # file modify
            features[6] = sum(1 for e in events if 'registry' in e.event_type) / total
        except:
            pass
        
        # Attack patterns
        recon = ['systeminfo', 'whoami', 'ipconfig', 'netstat', 'tasklist']
        lateral = ['psexec', 'wmic /node', 'winrm', 'net use']
        exfil = ['compress', 'archive', 'upload', 'ftp']
        persist = ['schtasks', 'reg add', 'sc create']
        evasion = ['del /f', 'remove-item', 'clear-eventlog']
        cred = ['mimikatz', 'sekurlsa', 'lsass', 'sam']
        
        try:
            for e in events:
                details = str(e.details).lower()
                if any(r in details for r in recon): features[7] = 1.0
                if any(l in details for l in lateral): features[8] = 1.0
                if any(x in details for x in exfil): features[9] = 1.0
                if any(p in details for p in persist): features[10] = 1.0
                if any(v in details for v in evasion): features[11] = 1.0
                if any(c in details for c in cred): features[12] = 1.0
        except:
            pass
        
        # Time features
        try:
            hour = events[-1].timestamp.hour
            features[13] = float(hour)
            features[14] = 1.0 if 9 <= hour <= 17 else 0.0
            features[15] = 1.0 if events[-1].timestamp.weekday() >= 5 else 0.0
        except:
            pass
        
        # Sequence features
        features[16] = float(len(events))
        try:
            event_types = ' '.join(e.event_type for e in events)
            features[17] = self.calculate_entropy(event_types)
        except:
            pass
        
        features[18] = min(5.0, features[1])  # parent-child depth
        try:
            features[19] = float(sum(1 for e in events if 'remote' in str(e.details).lower()))
        except:
            pass
        
        return features
    
    def extract_context_features(self, event: Dict) -> List[float]:
        """Extract 15 context-related features."""
        features = []
        user = str(event.get('user', '') or '').lower()
        parent = str(event.get('parent_name', '') or '').lower()
        
        # User context (5)
        features.append(1.0 if 'admin' in user else 0.0)
        features.append(1.0 if user in ['system', 'nt authority\\system'] else 0.0)
        features.append(1.0 if 'service' in user else 0.0)
        features.append(1.0 if event.get('interactive', False) else 0.0)
        features.append(1.0 if event.get('rdp_session', False) else 0.0)
        
        # Parent process (7)
        features.append(1.0 if parent == 'explorer.exe' else 0.0)
        features.append(1.0 if parent == 'services.exe' else 0.0)
        features.append(1.0 if parent == 'cmd.exe' else 0.0)
        features.append(1.0 if parent in ['powershell.exe', 'pwsh.exe'] else 0.0)
        features.append(1.0 if parent in ['chrome.exe', 'firefox.exe', 'msedge.exe'] else 0.0)
        features.append(1.0 if parent in ['winword.exe', 'excel.exe', 'outlook.exe'] else 0.0)
        features.append(1.0 if parent in ['mshta.exe', 'wscript.exe', 'cscript.exe'] else 0.0)
        
        # Integrity and elevation (3)
        features.append(float(event.get('integrity_level', 0)))
        features.append(1.0 if event.get('elevated', False) else 0.0)
        features.append(float(event.get('process_age', 0)))
        
        return features
    
    def extract_anomaly_features(self, event: Dict, baseline: Dict = None) -> List[float]:
        """Extract 20 anomaly-related features."""
        features = []
        baseline = baseline or {}
        
        process_name = str(event.get('name', '')).lower()
        cmdline = str(event.get('cmdline', ''))[:50].lower()
        path = str(event.get('exe', '')).lower()
        port = event.get('remote_port', 0)
        remote_ip = event.get('remote_ip', '')
        
        # Frequency-based (6)
        features.append(float(baseline.get('process_frequency', {}).get(process_name, 0)))
        features.append(1.0 / max(baseline.get('process_frequency', {}).get(process_name, 1), 1))
        features.append(1.0 / max(baseline.get('cmdline_frequency', {}).get(cmdline, 1), 1))
        features.append(1.0 / max(baseline.get('path_frequency', {}).get(path, 1), 1))
        features.append(1.0 / max(baseline.get('port_frequency', {}).get(port, 1), 1))
        features.append(1.0 / max(baseline.get('ip_frequency', {}).get(remote_ip, 1), 1))
        
        # Time deviation (1)
        hour = datetime.now().hour
        avg_hour = baseline.get('avg_activity_hour', 12)
        features.append(abs(hour - avg_hour) / 12.0)
        
        # Behavior deviations (3)
        features.append(float(event.get('behavior_deviation', 0)))
        features.append(float(event.get('sequence_deviation', 0)))
        features.append(float(event.get('volume_deviation', 0)))
        
        # Unusual patterns (4)
        features.append(1.0 if event.get('parent_child_unusual', False) else 0.0)
        features.append(1.0 if event.get('network_unusual', False) else 0.0)
        features.append(1.0 if event.get('file_access_unusual', False) else 0.0)
        features.append(1.0 if event.get('registry_unusual', False) else 0.0)
        
        # Anomaly scores (6)
        features.append(float(event.get('anomaly_score', 0)))
        features.append(float(event.get('isolation_score', 0)))
        features.append(float(event.get('local_outlier_score', 0)))
        features.append(float(event.get('cluster_distance', 0)))
        features.append(float(event.get('baseline_deviation', 0)))
        features.append(float(event.get('peer_deviation', 0)))
        
        return features
    
    def extract_all_features(self, event: Dict, behavioral_events: List = None, 
                            baseline: Dict = None) -> List[float]:
        """Extract all 150 features from an event."""
        features = []
        features.extend(self.extract_process_features(event))      # 30
        features.extend(self.extract_network_features(event))      # 25
        features.extend(self.extract_file_features(event))         # 25
        features.extend(self.extract_registry_features(event))     # 15
        features.extend(self.extract_behavioral_features(behavioral_events or []))  # 20
        features.extend(self.extract_context_features(event))      # 15
        features.extend(self.extract_anomaly_features(event, baseline))  # 20
        return features
