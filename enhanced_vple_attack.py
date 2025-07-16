#!/usr/bin/env python3
"""
Enhanced VPLE Remote Attack with Comprehensive Analysis
Provides detailed attack documentation and impact analysis
"""

import sys
import os
import time
import argparse
import json
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append('..')

from core.enhanced_ssh_executor import EnhancedVPLEConnection
import logging

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'vple_attack_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)

logger = logging.getLogger(__name__)

def display_banner():
    """Display enhanced attack banner"""
    print("""
🎯 ═══════════════════════════════════════════════════════════════
   ENHANCED VPLE REMOTE ATTACK ORCHESTRATOR v2.0
   Advanced Atomic Red Team Framework with Detailed Analysis
═══════════════════════════════════════════════════════════════
""")

def display_target_info(args):
    """Display target information"""
    print(f"""
📡 TARGET CONFIGURATION:
   IP Address: {args.ip}
   SSH Credentials: administrator:password
   Attack Mode: {'DRY RUN' if args.dry_run else 'LIVE EXECUTION'}
   Analysis Level: {'BASIC' if args.basic else 'COMPREHENSIVE'}
""")

def test_connection(ip):
    """Test SSH connection with enhanced diagnostics"""
    print("🔍 TESTING SSH CONNECTION...")
    print("─" * 50)
    
    try:
        with EnhancedVPLEConnection(ip) as vple:
            # Get comprehensive system info
            info = vple.get_system_info()
            baseline = vple.attack_session.get("baseline", {})
            
            print("✅ SSH CONNECTION SUCCESSFUL!")
            print(f"   Hostname: {info.get('hostname', {}).get('output', 'Unknown')}")
            print(f"   Kernel: {info.get('kernel', {}).get('output', 'Unknown')}")
            print(f"   IP Address: {info.get('ip_address', {}).get('output', 'Unknown')}")
            
            # Display web services
            web_services = info.get('web_services', {}).get('output', '')
            if web_services:
                print(f"   Active Web Services: {len(web_services.split('\\n'))} detected")
            
            # Display system baseline summary
            if baseline:
                print("\\n📋 SYSTEM BASELINE CAPTURED:")
                for category in baseline.keys():
                    print(f"   ✓ {category.replace('_', ' ').title()}")
            
            return True
            
    except Exception as e:
        print(f"❌ SSH CONNECTION FAILED: {e}")
        return False

def execute_enhanced_attack(ip, dry_run=False, basic=False):
    """Execute enhanced attack with comprehensive analysis"""
    print("🚀 STARTING ENHANCED ATTACK ORCHESTRATION...")
    print("═" * 60)
    
    attack_start = datetime.now()
    
    try:
        with EnhancedVPLEConnection(ip) as vple:
            
            # Phase 1: Enhanced Reconnaissance
            print("\\n🔍 PHASE 1: COMPREHENSIVE RECONNAISSANCE")
            print("─" * 50)
            
            recon_start = time.time()
            info = vple.get_system_info()
            baseline = vple.attack_session.get("baseline", {})
            
            print(f"✅ Target System: {info.get('hostname', {}).get('output', 'Unknown')}")
            print(f"✅ Operating System: {baseline.get('system_info', {}).get('os_release', {}).get('output', 'Unknown')[:50]}...")
            print(f"✅ System Uptime: {baseline.get('system_info', {}).get('uptime', {}).get('output', 'Unknown')}")
            print(f"✅ Reconnaissance completed in {time.time() - recon_start:.2f}s")
            
            # Display network information
            network_info = baseline.get('network_info', {})
            if network_info:
                listening_ports = network_info.get('listening_ports', {}).get('output', '')
                web_ports = [line for line in listening_ports.split('\\n') if any(port in line for port in ['1335', '1336', '1337', '3000', '8080', '8800', '8899'])]
                print(f"✅ Web Applications Detected: {len(web_ports)} services")
            
            # Phase 2: Enhanced Web Exploitation
            print("\\n🌐 PHASE 2: COMPREHENSIVE WEB EXPLOITATION")
            print("─" * 50)
            
            web_start = time.time()
            web_result = vple.execute_atomic_technique("T1190", dry_run=dry_run)
            
            if web_result["success"]:
                analysis = web_result.get("detailed_analysis", {})
                summary = web_result.get("summary", {})
                
                print(f"✅ Web Exploitation Analysis Completed in {time.time() - web_start:.2f}s")
                print(f"   Total Applications Scanned: {summary.get('total_apps', 0)}")
                print(f"   Accessible Applications: {summary.get('accessible_apps', 0)}")
                print(f"   Successful Exploits: {summary.get('successful_exploits', 0)}")
                
                # Display detailed findings
                if "applications" in analysis:
                    print("\\n   📊 APPLICATION ANALYSIS:")
                    for port, app_data in analysis["applications"].items():
                        status_icon = "🟢" if app_data["accessibility"] == "accessible" else "🔴"
                        print(f"   {status_icon} {app_data['name']} (Port {port}): {app_data['accessibility']}")
                        
                        if app_data["accessibility"] == "accessible" and app_data.get("exploitation_results"):
                            for vuln in app_data["exploitation_results"]:
                                print(f"      ⚠️  {vuln['vulnerability']}")
                
                # Display successful exploits
                if analysis.get("successful_exploits"):
                    print("\\n   🎯 SUCCESSFUL EXPLOITS:")
                    for exploit in analysis["successful_exploits"]:
                        print(f"   ✅ {exploit['app']} (Port {exploit['port']}): {len(exploit['exploits'])} vulnerabilities")
            
            # Phase 3: Enhanced Shell Access Analysis
            print("\\n🐚 PHASE 3: COMPREHENSIVE SHELL ACCESS ANALYSIS")
            print("─" * 50)
            
            shell_start = time.time()
            shell_result = vple.execute_atomic_technique("T1059.004", dry_run=dry_run)
            
            if shell_result["success"]:
                analysis = shell_result.get("detailed_analysis", {})
                summary = shell_result.get("summary", {})
                
                print(f"✅ Shell Analysis Completed in {time.time() - shell_start:.2f}s")
                print(f"   Current User: {summary.get('user', 'unknown')}")
                print(f"   System: {summary.get('system', 'unknown')}")
                print(f"   Privileges: {summary.get('privileges', 'unknown')}")
                
                # Display detailed shell analysis
                if not basic and analysis:
                    print("\\n   📊 DETAILED SHELL ANALYSIS:")
                    for category, data in analysis.items():
                        successful_commands = len([cmd for cmd in data.values() if cmd.get("success", False)])
                        print(f"   ✓ {category.replace('_', ' ').title()}: {successful_commands}/{len(data)} commands successful")
            
            # Phase 4: Enhanced Privilege Escalation Analysis
            print("\\n⬆️ PHASE 4: COMPREHENSIVE PRIVILEGE ESCALATION ANALYSIS")
            print("─" * 50)
            
            privesc_start = time.time()
            privesc_result = vple.execute_atomic_technique("T1548.001", dry_run=dry_run)
            
            if privesc_result["success"]:
                analysis = privesc_result.get("detailed_analysis", {})
                summary = privesc_result.get("summary", {})
                findings = privesc_result.get("findings", {})
                
                print(f"✅ Privilege Escalation Analysis Completed in {time.time() - privesc_start:.2f}s")
                print(f"   Current User: {summary.get('current_user', 'unknown')}")
                print(f"   SUID Binaries Found: {summary.get('suid_binaries_found', 0)}")
                print(f"   Potential Vectors: {summary.get('potential_vectors', 0)}")
                
                # Display findings
                if findings and findings.get("potential_vectors"):
                    print("\\n   🚨 PRIVILEGE ESCALATION VECTORS FOUND:")
                    for vector in findings["potential_vectors"]:
                        print(f"   ⚠️  {vector}")
                
                # Display interesting files if not basic mode
                if not basic and analysis:
                    privilege_vectors = analysis.get("privilege_vectors", {})
                    if privilege_vectors.get("suid_files", {}).get("success"):
                        suid_files = privilege_vectors["suid_files"]["output"].split('\\n')[:5]
                        print(f"\\n   📄 SUID FILES (showing first 5):")
                        for suid_file in suid_files:
                            if suid_file.strip():
                                print(f"   📁 {suid_file.strip()}")
            
            # Phase 5: Impact Analysis
            print("\\n📊 PHASE 5: COMPREHENSIVE IMPACT ANALYSIS")
            print("─" * 50)
            
            impact_start = time.time()
            
            # Analyze overall impact from all phases
            total_changes = 0
            high_impact_phases = 0
            artifacts_created = 0
            
            for phase in vple.attack_session["phases"]:
                if "analysis" in phase:
                    changes = len(phase["analysis"].get("changes_detected", []))
                    total_changes += changes
                    
                    if phase["analysis"].get("system_impact") == "high":
                        high_impact_phases += 1
                
                artifacts_created += len(phase.get("artifacts_created", []))
            
            print(f"✅ Impact Analysis Completed in {time.time() - impact_start:.2f}s")
            print(f"   Total System Changes: {total_changes}")
            print(f"   High Impact Phases: {high_impact_phases}")
            print(f"   Artifacts Created: {artifacts_created}")
            print(f"   Evidence Files Generated: {len([e for e in vple.attack_session['evidence'] if 'evidence' in str(e)])}")
            
            # Phase 6: Generate Comprehensive Report
            print("\\n📋 PHASE 6: GENERATING COMPREHENSIVE REPORT")
            print("─" * 50)
            
            report_start = time.time()
            report = vple.generate_comprehensive_report()
            
            attack_duration = (datetime.now() - attack_start).total_seconds()
            
            print(f"✅ Report Generation Completed in {time.time() - report_start:.2f}s")
            print(f"✅ Total Attack Duration: {attack_duration:.2f}s")
            
            # Display report summary
            if "summary" in report:
                summary = report["summary"]
                overview = summary.get("attack_overview", {})
                
                print("\\n🎊 ATTACK EXECUTION SUMMARY:")
                print("═" * 50)
                print(f"✓ Target: {overview.get('target', 'Unknown')}")
                print(f"✓ Total Duration: {overview.get('duration', 0):.2f} seconds")
                print(f"✓ Techniques Executed: {overview.get('techniques_executed', 0)}")
                print(f"✓ Successful Phases: {overview.get('successful_phases', 0)}")
                print(f"✓ Commands Executed: {overview.get('total_commands', 0)}")
                print(f"✓ Artifacts Created: {overview.get('artifacts_created', 0)}")
                
                # Display key findings
                key_findings = summary.get("key_findings", [])
                if key_findings:
                    print("\\n🔍 KEY SECURITY FINDINGS:")
                    for finding in key_findings:
                        severity_icon = "🚨" if finding.get("severity") == "high" else "⚠️"
                        print(f"{severity_icon} {finding.get('description', 'Unknown finding')}")
                
                print(f"\\n📊 Detailed Report: {report.get('report_file', 'Not generated')}")
                print(f"📁 Evidence Directory: {report.get('evidence_directory', 'Not available')}")
        
        print("\\n🎉 ENHANCED ATTACK ORCHESTRATION COMPLETE!")
        print("=" * 60)
        
        return True
        
    except KeyboardInterrupt:
        print("\\n⚠️ ATTACK INTERRUPTED BY USER")
        return False
    except Exception as e:
        print(f"\\n❌ ATTACK FAILED: {e}")
        logger.error(f"Attack failed with error: {e}", exc_info=True)
        return False

def main():
    """Main enhanced attack orchestrator"""
    parser = argparse.ArgumentParser(
        description="Enhanced VPLE Remote Attack Orchestrator with Comprehensive Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_vple_attack.py --test-connection --ip 192.168.1.100
  python enhanced_vple_attack.py --ip 192.168.1.100 --dry-run
  python enhanced_vple_attack.py --ip 192.168.1.100 --basic
  python enhanced_vple_attack.py --ip 192.168.1.100
        """
    )
    
    parser.add_argument("--ip", default="192.168.1.100", 
                       help="VPLE VM IP address (default: 192.168.1.100)")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Perform dry run without actual exploitation")
    parser.add_argument("--test-connection", action="store_true", 
                       help="Test SSH connection and system info only")
    parser.add_argument("--basic", action="store_true",
                       help="Basic analysis mode (less detailed output)")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help="Set logging level")
    
    args = parser.parse_args()
    
    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Display banner and info
    display_banner()
    display_target_info(args)
    
    # Test connection only
    if args.test_connection:
        success = test_connection(args.ip)
        sys.exit(0 if success else 1)
    
    # Execute enhanced attack
    success = execute_enhanced_attack(args.ip, args.dry_run, args.basic)
    
    if success:
        print("\\n✅ Attack completed successfully. Check log files for detailed information.")
    else:
        print("\\n❌ Attack failed. Check log files for error details.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
