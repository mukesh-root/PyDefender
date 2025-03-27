import argparse
from .core import PyDefender

def main():
    defender = PyDefender()
    defender.show_banner()
    
    parser = argparse.ArgumentParser(
        description="PyDefender - Advanced Malware Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("paths", nargs="*", help="Paths to scan")
    parser.add_argument("--quick", action="store_true", help="Quick system scan")
    parser.add_argument("--full", action="store_true", help="Full system scan")
    parser.add_argument("--version", action="store_true", help="Show version")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"PyDefender v{defender.version}")
        return
        
    # Add your scanning logic here...

if __name__ == "__main__":
    main()
