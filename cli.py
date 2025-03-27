#!/usr/bin/env python3
"""
PyDefender CLI - User interface and scan orchestration
Handles:
- Argument parsing
- Scan execution
- Result display
- Report generation
"""

import os
import sys
import time
import json
import argparse
from typing import List, Optional
from pathlib import Path
from pydefender.engine import PyDefenderEngine, ThreatReport

BANNER = r"""
   _____       _____  __________  ___  ____  ___  ____________
  / ____|     |  __ \|___  / __ \|  __ \ \/ /  \/  /\ \ / /  ____/ __ \
 | (___  _   _| |  | |  / / |  | | |  | \  / \  / /  \ V /| |__ | |  | |
  \___ \| | | | |  | | / /| |  | | |  | |\/| |\/ /    > < |  __|| |  | |
  ____) | |_| | |__| |/ /_| |__| | |__| |  | |  /    / . \| |___| |__| |
 |_____/ \__, |_____//_____\____/|_____/|__|_|_/    /_/ \_\______\____/
          __/ |
         |___/"""

class PyDefenderCLI:
    def __init__(self):
        """Initialize CLI interface"""
        self.engine = PyDefenderEngine()
        self.findings: List[ThreatReport] = []
        
    def run_scan(self, targets: List[str], report_path: Optional[str] = None):
        """
        Execute scan workflow
        Args:
            targets: List of files/directories to scan
            report_path: Optional path to save JSON report
        """
        self._show_banner()
        
        scan_start = time.time()
        
        # Process targets
        for target in targets:
            if os.path.isfile(target):
                self._process_file(target)
            elif os.path.isdir(target):
                self._process_directory(target)
            else:
                print(f"[!] Path not found: {target}", file=sys.stderr)
                
        # Show results
        self._display_results()
        
        # Generate report if threats found or explicitly requested
        if report_path or self.findings:
            output_file = report_path or self._generate_report_path()
            self._generate_json_report(output_file)
            
        # Print summary
        self._print_summary(scan_start)
        
    def _show_banner(self):
        """Display PyDefender banner"""
        print(BANNER)
        print("\nPyDefender Malware Detection System")
        print("=" * 50)
        
    def _process_file(self, file_path: str):
        """Analyze single file"""
        if result := self.engine.analyze_file(file_path):
            self.findings.append(result)
            
    def _process_directory(self, directory: str):
        """Recursively scan directory"""
        for root, _, files in os.walk(directory):
            for file in files:
                self._process_file(os.path.join(root, file))
                
    def _display_results(self):
        """Print findings to console"""
        if not self.findings:
            print("\n[+] No threats detected!")
            return
            
        print("\n[!] THREAT DETECTIONS:")
        print("=" * 70)
        
        # Sort by threat score (descending)
        for threat in sorted(self.findings, key=lambda x: x.threat_score, reverse=True):
            print(f"\nFile: {threat.file_path}")
            print(f"Type: {threat.file_type} | Confidence: {threat.threat_score}/100")
            print(f"Entropy: {threat.entropy:.2f}")
            print("Hashes:")
            print(f"  MD5:    {threat.hashes['md5']}")
            print(f"  SHA1:   {threat.hashes['sha1']}")
            print("Indicators:")
            for indicator in threat.detected_indicators:
                print(f"  - {indicator}")
                
    def _generate_json_report(self, output_path: str):
        """Generate JSON report file"""
        report = {
            "metadata": {
                "scanner": "PyDefender",
                "version": "1.0",
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_sec": time.time() - self.engine.stats['start_time']
            },
            "statistics": dict(self.engine.stats),
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
        
    def _generate_report_path(self) -> str:
        """Generate default report path"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        return f"pydefender_report_{timestamp}.json"
        
    def _print_summary(self, start_time: float):
        """Print scan summary statistics"""
        print(f"\n{' Scan Summary ':-^50}")
        print(f"Duration: {time.time() - start_time:.2f} seconds")
        print(f"Files scanned: {self.engine.stats['files_processed']}")
        print(f"Threats detected: {self.engine.stats['threats_detected']}")

def main():
    """Command line entry point"""
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
        metavar="FILE",
        help="Save JSON report to specified file"
    )
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Scan system locations only"
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
