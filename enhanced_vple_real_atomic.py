#!/usr/bin/env python3
"""
Enhanced VPLE Attack Orchestrator with Real Atomic Red Team Integration
Combines intelligent attack chaining with actual Invoke-AtomicTest framework
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

# Import your existing modules
try:
    from core.real_atomic_executor import RealAtomicVPLEConnection
    from categorizer import AttackCategorizer
    from dependency_mapper import DependencyMapper
    from attack_chain_builder import AttackChainBuilder, AttackObjective
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the correct directory and all modules are available")
    sys.exit(1)

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'real_atomic_vple_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)

logger = logging.getLogger(__name__)

class IntelligentRealAtomicOrchestrator:
    """
    Orchestrator that combines intelligent attack chaining with real Atomic Red Team execution
    """
    
    def __init__(self, vple_ip: str):
        self.vple_ip = vple_ip
        self.categorizer = AttackCategorizer()
        self.dependency_mapper = DependencyMapper()
        self.chain_builder = None
        
        # Real MITRE technique mappings for VPLE (Linux platform)
        self.vple_techniques = {
            # Discovery techniques
            "T1082": {
                "name": "System Information Discovery",
                "tactics": ["discovery"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "System info via uname"},
                    {"elevation_required": False, "description": "Hostname discovery"},
                    {"elevation_required": False, "description": "Linux kernel info"}
                ]
            },
            "T1083": {
                "name": "File and Directory Discovery", 
                "tactics": ["discovery"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "File system enumeration"},
                    {"elevation_required": False, "description": "Directory traversal"}
                ]
            },
            "T1018": {
                "name": "Remote System Discovery",
                "tactics": ["discovery"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Network discovery"},
                    {"elevation_required": False, "description": "ARP table enumeration"}
                ]
            },
            "T1057": {
                "name": "Process Discovery",
                "tactics": ["discovery"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Process enumeration"}
                ]
            },
            "T1033": {
                "name": "System Owner/User Discovery",
                "tactics": ["discovery"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "User enumeration"}
                ]
            },
            
            # Execution techniques
            "T1059.004": {
                "name": "Unix Shell",
                "tactics": ["execution"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Bash command execution"},
                    {"elevation_required": False, "description": "Shell script execution"},
                    {"elevation_required": False, "description": "Environment manipulation"}
                ]
            },
            
            # Privilege Escalation
            "T1548.001": {
                "name": "Setuid and Setgid",
                "tactics": ["privilege-escalation"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "SUID binary discovery"},
                    {"elevation_required": True, "description": "SUID exploitation"}
                ]
            },
            "T1068": {
                "name": "Exploitation for Privilege Escalation",
                "tactics": ["privilege-escalation"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Kernel exploit enumeration"}
                ]
            },
            
            # Credential Access
            "T1003.008": {
                "name": "/etc/passwd and /etc/shadow",
                "tactics": ["credential-access"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Password file access"},
                    {"elevation_required": True, "description": "Shadow file access"}
                ]
            },
            "T1552.001": {
                "name": "Credentials In Files",
                "tactics": ["credential-access"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Config file credential search"}
                ]
            },
            
            # Persistence
            "T1543.002": {
                "name": "Systemd Service",
                "tactics": ["persistence"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": True, "description": "Systemd service creation"}
                ]
            },
            "T1547.006": {
                "name": "Kernel Modules and Extensions",
                "tactics": ["persistence"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": True, "description": "Kernel module installation"}
                ]
            },
            
            # Defense Evasion
            "T1070.004": {
                "name": "File Deletion",
                "tactics": ["defense-evasion"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Log file deletion"},
                    {"elevation_required": False, "description": "Secure file deletion"}
                ]
            },
            "T1222.002": {
                "name": "Linux and Mac File and Directory Permissions Modification",
                "tactics": ["defense-evasion"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "File permission modification"}
                ]
            },
            
            # Collection
            "T1005": {
                "name": "Data from Local System",
                "tactics": ["collection"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Local file collection"}
                ]
            },
            
            # Lateral Movement (for network scenarios)
            "T1021.004": {
                "name": "SSH",
                "tactics": ["lateral-movement"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "SSH lateral movement"}
                ]
            },
            
            # Web Application specific (for VPLE web apps)
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "tactics": ["initial-access"],
                "platforms": ["linux"],
                "tests": [
                    {"elevation_required": False, "description": "Web application exploitation"}
                ]
            }
        }
        
    def categorize_real_techniques(self) -> dict:
        """Categorize real MITRE techniques for VPLE"""
        logger.info("🏷️ Categorizing real MITRE techniques for VPLE...")
        
        categorized = self.categorizer.categorize_techniques(self.vple_techniques)
        
        # Filter for Linux platform
        linux_categorized = self.categorizer.filter_by_platform(categorized, "linux")
        
        logger.info(f"✅ Categorized {len(self.vple_techniques)} real techniques")
        
        return linux_categorized
    
    def build_intelligent_attack_chain(self, objective: AttackObjective) -> list:
        """Build intelligent attack chain using real techniques"""
        logger.info(f"🧠 Building intelligent attack chain for objective: {objective.value}")
        
        # Get categorized techniques
        categorized = self.categorize_real_techniques()
        
        # Initialize chain builder
        self.chain_builder = AttackChainBuilder(self.dependency_mapper, self.categorizer)
        
        # Build attack chain
        constraints = {
            "avoid_elevation": False,  # Allow elevation for realistic attack
            "required_platforms": ["linux"],
            "single_test_per_technique": False  # Allow multiple tests per technique
        }
        
        attack_chain = self.chain_builder.build_attack_chain(
            objective=objective,
            target_platform="linux",
            categorized_techniques=categorized,
            constraints=constraints
        )
        
        # Convert to format suitable for real Atomic Red Team execution
        real_chain = self._convert_to_real_atomic_chain(attack_chain)
        
        logger.info(f"✅ Built attack chain with {len(real_chain)} techniques")
        
        return real_chain
    
    def _convert_to_real_atomic_chain(self, attack_chain) -> list:
        """Convert attack chain to real Atomic Red Team execution format"""
        real_chain = []
        
        for step in attack_chain.steps:
            technique_id = step.technique_id
            
            # Get test numbers for this technique
            test_numbers = step.test_numbers if step.test_numbers else [1]
            
            # Determine wait time based on technique category
            wait_time = self._get_wait_time_for_category(step.category)
            
            real_step = {
                "technique_id": technique_id,
                "name": step.technique_name,
                "test_numbers": test_numbers,
                "category": step.category,
                "description": step.description,
                "expected_outcome": step.expected_outcome,
                "risk_level": step.risk_level,
                "detection_likelihood": step.detection_likelihood,
                "wait_time": wait_time,
                "stop_on_failure": self._should_stop_on_failure(step.category, step.risk_level)
            }
            
            real_chain.append(real_step)
        
        return real_chain
    
    def _get_wait_time_for_category(self, category: str) -> int:
        """Get appropriate wait time between techniques based on category"""
        wait_times = {
            "discovery": 3,
            "execution": 5,
            "privilege_escalation": 10,
            "credential_access": 8,
            "persistence": 15,
            "defense_evasion": 5,
            "lateral_movement": 12,
            "collection": 8
        }
        
        return wait_times.get(category, 5)
    
    def _should_stop_on_failure(self, category: str, risk_level: str) -> bool:
        """Determine if attack should stop on failure for this technique"""
        # Stop on failure for critical techniques
        critical_categories = ["privilege_escalation", "persistence"]
        return category in critical_categories and risk_level == "high"
    
    def execute_intelligent_attack(self, objective: AttackObjective, dry_run: bool = False) -> dict:
        """Execute intelligent attack using real Atomic Red Team framework"""
        
        logger.info(f"🚀 Starting intelligent attack with objective: {objective.value}")
        
        attack_start = datetime.now()
        
        try:
            # Build intelligent attack chain
            attack_chain = self.build_intelligent_attack_chain(objective)
            
            # Display attack chain
            print(f"\n🔗 INTELLIGENT ATTACK CHAIN ({objective.value.upper()})")
            print("=" * 70)
            for i, step in enumerate(attack_chain, 1):
                risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(step["risk_level"], "⚪")
                print(f"{i:2d}. {step['technique_id']} - {step['name']}")
                print(f"    Category: {step['category']} | Risk: {risk_icon} {step['risk_level']} | Tests: {step['test_numbers']}")
                print(f"    Expected: {step['expected_outcome']}")
                print()
            
            # Execute via real Atomic Red Team
            with RealAtomicVPLEConnection(self.vple_ip) as vple:
                
                # Verify framework is ready
                if not vple.atomic_framework_ready:
                    return {"success": False, "error": "Atomic Red Team framework not ready"}
                
                print(f"\n🎯 EXECUTING ATTACK CHAIN")
                print("=" * 50)
                
                # Execute the intelligent attack chain
                result = vple.execute_attack_chain(attack_chain, dry_run=dry_run)
                
                # Generate detailed report
                session_report = vple.get_session_report()
                
                # Combine results
                final_result = {
                    "objective": objective.value,
                    "attack_chain": attack_chain,
                    "execution_result": result,
                    "session_report": session_report,
                    "total_duration": (datetime.now() - attack_start).total_seconds(),
                    "success": result.get("overall_success", False)
                }
                
                return final_result
        
        except Exception as e:
            logger.error(f"❌ Intelligent attack failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "duration": (datetime.now() - attack_start).total_seconds()
            }
    
    def display_results(self, result: dict):
        """Display comprehensive attack results"""
        
        print(f"\n🎊 INTELLIGENT ATTACK RESULTS")
        print("=" * 60)
        
        if result.get("success"):
            print("✅ ATTACK COMPLETED SUCCESSFULLY")
        else:
            print("❌ ATTACK FAILED OR PARTIALLY COMPLETED")
        
        print(f"\n📊 EXECUTION SUMMARY:")
        print(f"   Objective: {result.get('objective', 'Unknown')}")
        print(f"   Total Duration: {result.get('total_duration', 0):.2f}s")
        
        execution = result.get("execution_result", {})
        print(f"   Techniques Planned: {execution.get('chain_length', 0)}")
        print(f"   Techniques Executed: {len(execution.get('executed_steps', []))}")
        print(f"   Techniques Failed: {len(execution.get('failed_steps', []))}")
        
        session = result.get("session_report", {}).get("session_overview", {})
        print(f"   Prerequisites Checked: {session.get('prerequisites_checked', 0)}")
        print(f"   Commands Executed: {session.get('commands_executed', 0)}")
        
        # Display executed techniques
        executed_steps = execution.get("executed_steps", [])
        if executed_steps:
            print(f"\n✅ SUCCESSFULLY EXECUTED TECHNIQUES:")
            for step in executed_steps:
                duration = step.get("duration", 0)
                print(f"   ✓ {step['technique_id']} - {step.get('technique_details', {}).get('tests', ['Unknown'])} ({duration:.1f}s)")
        
        # Display failed techniques
        failed_steps = execution.get("failed_steps", [])
        if failed_steps:
            print(f"\n❌ FAILED TECHNIQUES:")
            for step in failed_steps:
                error = step.get("error", "Unknown error")
                print(f"   ✗ {step['technique_id']} - {error}")
        
        # Display framework info
        framework_info = result.get("session_report", {}).get("framework_info", {})
        if framework_info:
            print(f"\n🔧 ATOMIC RED TEAM FRAMEWORK INFO:")
            module_check = framework_info.get("module_check", "")
            if "invoke-atomicredteam" in module_check.lower():
                print("   ✅ Invoke-AtomicRedTeam module verified")
            print(f"   📅 Verification: {framework_info.get('verification_time', 'Unknown')}")


def display_banner():
    """Display enhanced banner"""
    print("""
🎯 ═══════════════════════════════════════════════════════════════════════════════
   INTELLIGENT ATOMIC RED TEAM ORCHESTRATOR v3.0
   Real MITRE ATT&CK Techniques + Intelligent Attack Chaining
   
   🧠 Smart Attack Logic + 🎯 Real Atomic Red Team Framework
═══════════════════════════════════════════════════════════════════════════════
""")


def test_framework_connection(ip: str) -> bool:
    """Test connection to framework"""
    try:
        with RealAtomicVPLEConnection(ip) as vple:
            if vple.atomic_framework_ready:
                print("✅ Atomic Red Team framework connection verified")
                
                # Test technique details retrieval
                details = vple.get_technique_details("T1082")
                if details.get("details_available"):
                    print("✅ Technique details retrieval working")
                    return True
            
            return False
    
    except Exception as e:
        print(f"❌ Framework connection test failed: {e}")
        return False


def main():
    """Main orchestrator"""
    parser = argparse.ArgumentParser(
        description="Intelligent Atomic Red Team Orchestrator with Real Framework Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Objectives:
  web_application      - Target VPLE web applications
  privilege_escalation - Focus on gaining elevated privileges  
  full_compromise      - Complete attack kill chain
  credential_harvesting- Focus on credential collection
  lateral_movement     - Network movement and expansion

Examples:
  python enhanced_vple_real_atomic.py --ip 192.168.1.100 --test-framework
  python enhanced_vple_real_atomic.py --ip 192.168.1.100 --objective web_application --dry-run
  python enhanced_vple_real_atomic.py --ip 192.168.1.100 --objective full_compromise
        """
    )
    
    parser.add_argument("--ip", default="192.168.1.100", 
                       help="VPLE VM IP address")
    parser.add_argument("--objective", 
                       choices=[obj.value for obj in AttackObjective],
                       default="web_application",
                       help="Attack objective")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Perform dry run without actual execution")
    parser.add_argument("--test-framework", action="store_true",
                       help="Test Atomic Red Team framework connection only")
    
    args = parser.parse_args()
    
    display_banner()
    
    print(f"🎯 TARGET: {args.ip}")
    print(f"🎪 OBJECTIVE: {args.objective}")
    print(f"🧪 MODE: {'DRY RUN' if args.dry_run else 'LIVE EXECUTION'}")
    print()
    
    # Test framework connection
    if args.test_framework:
        success = test_framework_connection(args.ip)
        sys.exit(0 if success else 1)
    
    # Execute intelligent attack
    try:
        orchestrator = IntelligentRealAtomicOrchestrator(args.ip)
        objective = AttackObjective(args.objective)
        
        result = orchestrator.execute_intelligent_attack(objective, args.dry_run)
        orchestrator.display_results(result)
        
        success = result.get("success", False)
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error(f"❌ Orchestration failed: {e}")
        print(f"\n❌ Attack orchestration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
