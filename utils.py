import hashlib
from pathlib import Path

def calculate_hashes(file_path: str) -> dict:
    """Calculate multiple hashes for a file"""
    hashers = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with Path(file_path).open('rb') as f:
        while chunk := f.read(8192):
            for h in hashers.values():
                h.update(chunk)
                
    return {name: h.hexdigest() for name, h in hashers.items()}
