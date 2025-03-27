def analyze_file(self, file_path: str) -> Optional[ThreatReport]:
    """Perform deep file analysis with comprehensive error handling"""
    try:
        path = Path(file_path)
        
        # Validate file existence and type
        if not path.exists():
            print(f"[!] File not found: {file_path}", file=sys.stderr)
            return None
        if not path.is_file():
            print(f"[!] Path is not a file: {file_path}", file=sys.stderr)
            return None
            
        file_size = path.stat().st_size
        
        # Handle special cases
        if file_size == 0:
            return None  # Silently skip empty files
        if file_size > self.detection_params['thresholds']['max_size']:
            print(f"[!] Skipping large file: {file_path} ({file_size/1024/1024:.2f} MB)")
            return None
            
        indicators = []
        threat_score = 0
        
        # File content analysis
        try:
            with path.open('rb') as f:
                # Use optimal reading strategy based on file size
                if file_size < 4096:
                    sample = f.read()  # Read entire small file
                else:
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            sample = mm.read(4096)  # Read first 4KB of large file
                    except ValueError as ve:
                        print(f"[!] MMAP failed for {file_path}: {str(ve)}")
                        sample = f.read(4096)  # Fallback to regular read
                
                # Filename analysis
                filename = path.name.lower()
                if any(risk in filename for risk in self.detection_params['risk_indicators']['names']):
                    indicators.append("Suspicious filename")
                    threat_score += 25
                    
                if path.suffix.lower() in self.detection_params['risk_indicators']['extensions']:
                    indicators.append("Risky extension")
                    threat_score += 20
                    
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
                        
        except PermissionError:
            print(f"[!] Permission denied: {file_path}", file=sys.stderr)
            return None
            
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
        print(f"[!] Unexpected error scanning {file_path}: {str(e)}", file=sys.stderr)
        return None
