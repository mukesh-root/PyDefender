#!/usr/bin/env python3
"""
PyDefender Engine - Core malware detection logic
Implements:
- Multi-algorithm hash scanning
- Entropy analysis
- File type detection
- Threat scoring system
"""

import os
import mmap
import hashlib
import math
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class ThreatReport:
    """Structured scan results for each file"""
    file_path: str
    threat_score: int          # 0-100 confidence level
    detected_indicators: List[str]  # List of detected threats
    file_type: str            # Detected file type
    entropy: float            # Entropy measurement
    hashes: Dict[str, str]    # Cryptographic hashes

class PyDefenderEngine:
    def __init__(self):
        """Initialize detection engine with default parameters"""
        self.detection_params = {
            # File patterns to flag
            'risk_indicators': {
                'names': ['cmd.exe', 'powershell', 'wscript'],
                'extensions': ['.exe', '.dll', '.vbs', '.ps1', '.js']
            },
            
            # Binary patterns
            'suspicious_patterns': {
                'executable': [b'MZ', b'PE\x00\x00', b'\x7fELF'],
                'script': [b'#!/bin', b'#!/usr/bin', b'<?php'],
                'archive': [b'PK\x03\x04', b'\x1f\x8b\x08']
            },
            
            # Detection thresholds
            'thresholds': {
                'high_entropy': 7.0,    # Entropy >7.0 is suspicious
                'max_size': 100 * 1024 * 1024  # 100MB max file size
            }
        }
        
        # Load threat signatures
        self.signatures = self._load_signatures()
        
        # Scan statistics
        self.stats = {
            'files_processed': 0,
            'threats_detected': 0,
            'start_time': time.time()
        }

    def _load_signatures(self) -> Dict:
        """Load threat signatures with fallback to embedded database"""
        try:
            # In production, load from external source
            return {
                "known_malicious": [
                    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",  # SHA1
                    "5d41402abc4b2a76b9719d911017c592"           # MD5
                ],
                "trusted_hashes": []
            }
        except Exception:
            return {"known_malicious": [], "trusted_hashes": []}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for packed binary detection"""
        if not data:
            return 0.0
            
        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1
            
        entropy = 0.0
        total = len(data)
        for count in frequency.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
            
        return entropy

    def analyze_file(self, file_path: str) -> Optional[ThreatReport]:
        """
        Analyze a file for malicious indicators
        Returns ThreatReport if threats detected, None otherwise
        """
        try:
            path = Path(file_path)
            if not path.is_file():
                return None
                
            # Skip files over size limit
            file_size = path.stat().st_size
            if file_size > self.detection_params['thresholds']['max_size']:
                return None
                
            indicators = []
            threat_score = 0
            
            # Filename analysis
            filename = path.name.lower()
            if any(risk in filename for risk in 
                  self.detection_params['risk_indicators']['names']):
                indicators.append("Suspicious filename")
                threat_score += 25
                
            if path.suffix.lower() in \
               self.detection_params['risk_indicators']['extensions']:
                indicators.append("Risky extension")
                threat_score += 20
                
            # Content analysis
            with path.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    sample = mm.read(4096)  # Analyze first 4KB
                    
                    # Entropy analysis
                    entropy = self._calculate_entropy(sample)
                    if entropy > self.detection_params['thresholds']['high_entropy']:
                        indicators.append(f"High entropy ({entropy:.2f})")
                        threat_score += 35
                        
                    # Pattern matching
                    for ptype, patterns in self.detection_params['suspicious_patterns'].items():
                        if any(p in sample for p in patterns):
                            indicators.append(f"{ptype} pattern detected")
                            threat_score += 40
                            
            # Hash calculation
            hashes = {
                'md5': self._hash_file(path, hashlib.md5()),
                'sha1': self._hash_file(path, hashlib.sha1()),
                'sha256': self._hash_file(path, hashlib.sha256())
            }
            
            # Signature matching
            if hashes['sha1'] in self.signatures['known_malicious']:
                indicators.append("Known malware signature")
                threat_score = 100  # Maximum confidence
                
            self.stats['files_processed'] += 1
            
            if threat_score > 0:
                self.stats['threats_detected'] += 1
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
        """Generate file hash using specified algorithm"""
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
        
    def _classify_file(self, data: bytes) -> str:
        """Determine file type from content"""
        if not data:
            return "Unknown"
            
        # Text file check
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f}
        if all(b in text_chars for b in data[:1024]):
            return "Text"
            
        # Binary patterns
        for ptype, patterns in self.detection_params['suspicious_patterns'].items():
            if any(p in data[:1024] for p in patterns):
                return ptype.capitalize()
                
        return "Binary"
