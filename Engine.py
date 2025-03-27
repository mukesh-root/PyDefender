def analyze_file(self, file_path: str) -> Optional[ThreatReport]:
    """Perform deep file analysis with robust error handling"""
    try:
        path = Path(file_path)
        
        # Basic validation
        if not path.exists():
            print(f"[!] File not found: {file_path}", file=sys.stderr)
            return None
        if not path.is_file():
            print(f"[!] Path is not a file: {file_path}", file=sys.stderr)
            return None
            
        file_size = path.stat().st_size
        
        # Skip special cases
        if file_size == 0:
            return None  # Silently skip empty files
        if file_size > self.detection_params['thresholds']['max_size']:
            print(f"[!] Skipping large file: {file_path} ({file_size/1024/1024:.2f} MB)")
            return None
            
        # File analysis
        try:
            with path.open('rb') as f:
                # Use regular read for tiny files, mmap for larger ones
                if file_size < 4096:
                    sample = f.read()
                else:
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            sample = mm.read(4096)
                    except ValueError as ve:
                        print(f"[!] MMAP failed for {file_path}: {str(ve)}")
                        sample = f.read(4096)
                        
                # Rest of your analysis logic...
                
        except PermissionError:
            print(f"[!] Permission denied: {file_path}", file=sys.stderr)
            return None
            
    except Exception as e:
        print(f"[!] Unexpected error scanning {file_path}: {str(e)}", file=sys.stderr)
        return None
