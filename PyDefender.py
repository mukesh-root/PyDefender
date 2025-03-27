#!/usr/bin/env python3
"""
PyDefender - Advanced Malware Detection System
Features:
- Multi-layered detection (signatures, behavior, heuristics)
- Entropy analysis for packed executables
- Comprehensive threat reporting
- Cross-platform support
"""

import os
import sys
import json
import time
import mmap
import math
import stat
import hashlib
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
import argparse

# ASCII Banner
BANNER = r"""
   _____       _____  __________  ___  ____  ___  ____________
  / ____|     |  __ \|___  / __ \|  __ \ \/ /  \/  /\ \ / /  ____/ __ \
 | (___  _   _| |  | |  / / |  | | |  | \  / \  / /  \ V /| |__ | |  | |
  \___ \| | | | |  | | / /| |  | | |  | |\/| |\/ /    > < |  __|| |  | |
  ____) | |_| | |__| |/ /_| |__| | |__| |  | |  /    / . \| |___| |__| |
 |_____/ \__, |_____//_____\____/|_____/|__|_|_/    /_/ \_\______\____/
          __/ |
         |___/"""

# Detection Parameters
DETECTION_PARAMS = {
    'suspicious_patterns': {
        'executable': [b'MZ', b'PE\x00\x00', b'\x7fELF'],
        'script': [b'#!/bin', b'#!/usr/bin', b'<?php'],
        'archive': [b'PK\x03\x04', b'\x1f\x8b\x08']
    },
    'risk_indicators': {
        'names': ['cmd.exe', 'powershell', 'wscript'],
        'extensions': ['.exe', '.dll', '.vbs', '.ps1']
    },
    'thresholds': {
        'high_entropy': 7.0,
        'max_size': 100 * 1024 * 1024  # 100MB
    }
}

@dataclass
class ThreatReport:
    file_path: str
    threat_score: int
    detected_indicators: List[str]
    file_type: str
    entropy: float
    hashes: Dict[str, str]

class PyDefenderEngine:
    def __init__(self):
        self.scan_stats = defaultdict(int)
        self.signatures = self._init_signatures()
        self.scan_stats['start_time'] = time.time()

    def _init_signatures(self) -> Dict:
        """Initialize detection signatures"""
        return {
            "known_threats": [
                "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",  # Sample SHA1
                "5d41402abc4b2a76b9719d911017c592"           # Sample MD5
            ],
            "trusted_hashes": []  # For whitelisting
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Compute file entropy for packed binary detection"""
        if not data:
            return 0.0
            
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
            
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            p = count / total
            entropy -= p * math.log2(p)
            
        return entropy

    def analyze_file(self, file_path: str) -> Optional[ThreatReport]:
        """Core file analysis engine"""
        try:
            path = Path(file_path)
            if not path.is_file():
                return None
                
            # Skip large files
            if path.stat().st_size > DETECTION_PARAMS['thresholds']['max_size']:
                return None
                
            indicators = []
            threat_score = 0
            
            # Name/extension analysis
            filename = path.name.lower()
            if any(risk in filename for risk in DETECTION_PARAMS['risk_indicators']['names']):
                indicators.append("Suspicious filename")
                threat_score += 25
                
            if path.suffix.lower() in DETECTION_PARAMS['risk_indicators']['extensions']:
                indicators.append("Risky extension") 
                threat_score += 20
                
            # Content analysis
            with path.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    sample = mm.read(4096)
                    
                    # Entropy check
                    entropy = self._calculate_entropy(sample)
                    if entropy > DETECTION_PARAMS['thresholds']['high_entropy']:
                        indicators.append(f"High entropy ({entropy:.2f})")
                        threat_score += 35
                        
                    # Pattern matching
                    for ptype, patterns in DETECTION_PARAMS['suspicious_patterns'].items():
                        if any(p in sample for p in patterns):
                            indicators.append(f"{ptype} pattern")
                            threat_score += 40
                            
            # Hash calculation
            hashes = {
                'md5': self._hash_file(path, hashlib.md5()),
                'sha1': self._hash_file(path, hashlib.sha1()),
                'sha256': self._hash_file(path, hashlib.sha256())
            }
            
            # Signature matching
            if hashes['sha1'] in self.signatures['known_threats']:
                indicators.append("Known malware signature")
                threat_score = 100  # Maximum confidence
                
            self.scan_stats['files_processed'] += 1
            
            if threat_score > 0:
                self.scan_stats['threats_detected'] += 1
                return ThreatReport(
                    file_path=str(path),
                    threat_score=threat_score,
                    detected_indicators=indicators,
                    file_type=self._classify_file(sample),
                    entropy=entropy,
                    hashes=hashes
                )
                
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}", file=sys.stderr)
        return None
        
    def _hash_file(self, path: Path, hasher) -> str:
        """Generate file hash"""
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
        
    def _classify_file(self, data: bytes) -> str:
        """Determine file type"""
        if not data:
            return "Unknown"
            
        # Text file check
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
        if all(b in text_chars for b in data[:1024]):
            return "Text"
            
        # Binary patterns
        for ptype, patterns in DETECTION_PARAMS['suspicious_patterns'].items():
            if any(p in data[:1024] for p in patterns):
                return ptype.capitalize()
                
        return "Binary"

class PyDefenderCLI:
    def __init__(self):
        self.engine = PyDefenderEngine()
        self.findings = []
        
    def run_scan(self, targets: List[str], report_file: Optional[str] = None):
        """Execute scanning workflow"""
        print(BANNER)
        print(f"\nPyDefender v1.0 | Threat Detection System\n{'='*50}")
        
        scan_start = time.time()
        
        # Process targets
        for target in targets:
            if os.path.isfile(target):
                self._process_file(target)
            elif os.path.isdir(target):
                self._process_directory(target)
            else:
                print(f"[!] Path not accessible: {target}", file=sys.stderr)
                
        # Output results
        self._show_results()
        
        # Generate report if requested
        if report_file or self.findings:
            output_file = report_file or f"pydefender_report_{int(time.time())}.json"
            self._generate_report(output_file)
            
        # Summary statistics
        print(f"\n{' Scan Summary ':-^50}")
        print(f"Duration: {time.time() - scan_start:.2f} seconds")
        print(f"Files scanned: {self.engine.scan_stats['files_processed']}")
        print(f"Threats detected: {self.engine.scan_stats['threats_detected']}")
        
    def _process_file(self, file_path: str):
        """Analyze single file"""
        if result := self.engine.analyze_file(file_path):
            self.findings.append(result)
            
    def _process_directory(self, directory: str):
        """Recursive directory scan"""
        for root, _, files in os.walk(directory):
            for file in files:
                self._process_file(os.path.join(root, file))
                
    def _show_results(self):
        """Display findings in console"""
        if not self.findings:
            print("\n[+] No threats detected!")
            return
            
        print("\n[!] THREAT DETECTIONS:")
        print("=" * 70)
        for threat in sorted(self.findings, key=lambda x: x.threat_score, reverse=True):
            print(f"\nFile: {threat.file_path}")
            print(f"Type: {threat.file_type} | Confidence: {threat.threat_score}/100")
            print(f"Entropy: {threat.entropy:.2f} | Hashes:")
            print(f"  MD5:    {threat.hashes['md5']}")
            print(f"  SHA1:   {threat.hashes['sha1']}")
            print("Indicators:")
            for indicator in threat.detected_indicators:
                print(f"  - {indicator}")
                
    def _generate_report(self, output_path: str):
        """Create JSON report file"""
        report = {
            "metadata": {
                "scanner": "PyDefender",
                "version": "1.0",
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_sec": time.time() - self.engine.scan_stats['start_time']
            },
            "statistics": dict(self.engine.scan_stats),
            "findings": [
                {
                    "path": f.file_path,
                    "score": f.threat_score,
                    "type": f.file_type,
                    "indicators": f.detected_indicators,
                    "hashes": f.hashes
                } for f in self.findings
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\n[+] Report saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(
        description="PyDefender - Advanced Malware Detection",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Files/directories to scan"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save JSON report to specified file"
    )
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Perform quick scan (system locations only)"
    )
    
    args = parser.parse_args()
    
    # Adjust targets for quick scan
    if args.quick:
        args.targets = [
            "/usr/bin" if platform.system() != "Windows" else "C:\\Windows\\System32"
        ]
    
    scanner = PyDefenderCLI()
    scanner.run_scan(args.targets, args.output)

if __name__ == "__main__":
    main()
