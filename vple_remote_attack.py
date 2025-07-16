#!/usr/bin/env python3
"""
VPLE Remote Attack Example
Execute attacks remotely via SSH to VPLE VM
"""

import sys
import os
import time
import argparse
sys.path.append('..')
from core.ssh_executor import VPLEConnection
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """Main remote attack demonstration"""
    parser = argparse.ArgumentParser(description="VPLE Remote Attack Orchestrator")
    parser.add_argument("--ip", default="172.20.10.8", help="VPLE VM IP address")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run")
    parser.add_argument("--test-connection", action="store_true", help="Test SSH connection only")
    
    args = parser.parse_args()
    
    print("🎯 VPLE Remote Attack Orchestrator")
    print(f"Target: {args.ip}")
    print(f"SSH: administrator:password")
    
    if args.test_connection:
        print("🔍 Testing SSH connection...")
        try:
            with VPLEConnection(args.ip) as vple:
                info = vple.get_system_info()
                print("✅ SSH connection successful!")
                print(f"Hostname: {info.get('hostname', {}).get('output', 'Unknown')}")
                return
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            return
    
    print("🚀 Starting remote attack orchestration...")
    
    try:
        with VPLEConnection(args.ip) as vple:
            # Phase 1: Reconnaissance
            print("\n🔍 Phase 1: Reconnaissance")
            info = vple.get_system_info()
            print(f"Target system: {info.get('hostname', {}).get('output', 'Unknown')}")
            
            # Phase 2: Web exploitation
            print("\n🌐 Phase 2: Web Exploitation")
            web_result = vple.execute_atomic_technique("T1190", dry_run=args.dry_run)
            if web_result["success"]:
                print("✅ Web exploitation completed")
                if "results" in web_result:
                    for result in web_result["results"]:
                        print(f"   Port {result['port']}: {result['status']}")
            
            # Phase 3: Shell access
            print("\n🐚 Phase 3: Shell Access")
            shell_result = vple.execute_atomic_technique("T1059.004", dry_run=args.dry_run)
            if shell_result["success"]:
                print("✅ Shell access established")
            
            # Phase 4: Privilege escalation
            print("\n⬆️ Phase 4: Privilege Escalation")
            privesc_result = vple.execute_atomic_technique("T1548.001", dry_run=args.dry_run)
            if privesc_result["success"]:
                print(f"✅ Current user: {privesc_result.get('current_user', 'unknown')}")
        
        print("\n🎉 Remote attack orchestration complete!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Attack interrupted")
    except Exception as e:
        print(f"\n❌ Attack failed: {e}")

if __name__ == "__main__":
    main()
