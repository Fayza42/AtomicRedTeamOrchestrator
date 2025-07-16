#!/usr/bin/env python3
"""
VPLE Remote Attack Runner
Run from the root directory to avoid import issues
"""

import sys
import os
from pathlib import Path

# Ensure we're in the right directory
script_dir = Path(__file__).parent.absolute()
os.chdir(script_dir)

# Add current directory to Python path
sys.path.insert(0, str(script_dir))

def main():
    """Main runner function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="VPLE Remote Attack Runner")
    parser.add_argument("--ip", default="192.168.1.100", help="VPLE VM IP address")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run")
    parser.add_argument("--test-connection", action="store_true", help="Test SSH connection only")
    
    args = parser.parse_args()
    
    try:
        # Import after path setup
        from examples.vple_remote_attack import main as remote_main
        
        # Pass arguments to the remote attack script
        sys.argv = [
            "vple_remote_attack.py",
            "--ip", args.ip
        ]
        
        if args.dry_run:
            sys.argv.append("--dry-run")
        if args.test_connection:
            sys.argv.append("--test-connection")
        
        remote_main()
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("\n🔧 Setup Instructions:")
        print("1. Make sure you're in the atomic_orchestrator directory")
        print("2. Run: python fix_imports.py")
        print("3. Install dependencies: pip install paramiko scp")
        print("4. Try again: python run_vple_attack.py --ip YOUR_IP")

if __name__ == "__main__":
    main()
