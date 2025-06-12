#!/usr/bin/env python3
"""
Script to create all missing data files for Atomic Red Team Orchestrator
"""

import os
import json
from pathlib import Path

def create_directories():
    """Create necessary directories"""
    directories = [
        "data",
        "examples", 
        "utils",
        "output",
        "logs",
        "config"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")

def create_technique_categories():
    """Create technique_categories.json"""
    content = {
        "technique_mappings": {
            "initial_access": {
                "description": "Techniques for gaining initial foothold",
                "techniques": [
                    "T1190", "T1566.001", "T1566.002", "T1078.001", "T1078.003", 
                    "T1078.004", "T1133", "T1091", "T1195"
                ],
                "priority": 1,
                "color": "red"
            },
            "execution": {
                "description": "Techniques for executing malicious code",
                "techniques": [
                    "T1059", "T1059.001", "T1059.002", "T1059.003", "T1059.004", 
                    "T1059.005", "T1059.006", "T1059.007", "T1047", "T1106", 
                    "T1129", "T1127", "T1127.001"
                ],
                "priority": 2,
                "color": "orange"
            },
            "persistence": {
                "description": "Techniques to maintain access",
                "techniques": [
                    "T1543.001", "T1543.002", "T1543.003", "T1543.004", "T1547.001", 
                    "T1547.002", "T1547.003", "T1547.004", "T1547.006", "T1053.002", 
                    "T1053.003", "T1053.005", "T1053.006", "T1053.007", "T1037.001", 
                    "T1037.002", "T1037.004", "T1037.005"
                ],
                "priority": 3,
                "color": "yellow"
            },
            "privilege_escalation": {
                "description": "Techniques to gain higher privileges",
                "techniques": [
                    "T1548.001", "T1548.002", "T1548.003", "T1055", "T1055.001", 
                    "T1055.002", "T1055.003", "T1055.004", "T1055.011", "T1055.012", 
                    "T1134.001", "T1134.002", "T1134.004", "T1134.005"
                ],
                "priority": 4,
                "color": "purple"
            },
            "defense_evasion": {
                "description": "Techniques to avoid detection",
                "techniques": [
                    "T1027", "T1027.001", "T1027.002", "T1027.004", "T1027.006", 
                    "T1027.007", "T1036", "T1036.003", "T1036.004", "T1036.005", 
                    "T1036.006", "T1036.007", "T1070", "T1070.001", "T1070.002", 
                    "T1070.003", "T1070.004", "T1070.005", "T1070.006", "T1070.008",
                    "T1562.001", "T1562.002", "T1562.003", "T1562.004", "T1562.006",
                    "T1564.001", "T1564.002", "T1564.003", "T1564.004", "T1564.006",
                    "T1564.008"
                ],
                "priority": 5,
                "color": "blue"
            },
            "credential_access": {
                "description": "Techniques to steal credentials",
                "techniques": [
                    "T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", 
                    "T1003.005", "T1003.006", "T1003.007", "T1003.008", "T1110.001", 
                    "T1110.002", "T1110.003", "T1110.004", "T1555", "T1555.001", 
                    "T1555.003", "T1555.004", "T1056.001", "T1056.002", "T1056.004",
                    "T1552.001", "T1552.002", "T1552.003", "T1552.004", "T1552.005",
                    "T1552.006", "T1552.007", "T1558.001", "T1558.002", "T1558.003",
                    "T1558.004"
                ],
                "priority": 6,
                "color": "cyan"
            },
            "discovery": {
                "description": "Techniques for system/network reconnaissance",
                "techniques": [
                    "T1087.001", "T1087.002", "T1083", "T1082", "T1057", "T1018", 
                    "T1135", "T1016", "T1016.001", "T1016.002", "T1033", "T1049", 
                    "T1007", "T1012", "T1069.001", "T1069.002", "T1124", "T1482", 
                    "T1518", "T1518.001"
                ],
                "priority": 7,
                "color": "green"
            },
            "lateral_movement": {
                "description": "Techniques to move through network",
                "techniques": [
                    "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", 
                    "T1021.006", "T1570", "T1563.002", "T1550.001", "T1550.002", 
                    "T1550.003"
                ],
                "priority": 8,
                "color": "magenta"
            },
            "collection": {
                "description": "Techniques to gather data",
                "techniques": [
                    "T1005", "T1039", "T1025", "T1074.001", "T1113", "T1123", 
                    "T1125", "T1115", "T1119", "T1120", "T1114.001", "T1114.002", 
                    "T1114.003", "T1560", "T1560.001", "T1560.002"
                ],
                "priority": 9,
                "color": "bright_blue"
            },
            "exfiltration": {
                "description": "Techniques to steal data",
                "techniques": [
                    "T1041", "T1048", "T1048.002", "T1048.003", "T1020", "T1030", 
                    "T1567.002", "T1567.003"
                ],
                "priority": 10,
                "color": "bright_red"
            },
            "command_control": {
                "description": "Techniques for remote communication",
                "techniques": [
                    "T1071", "T1071.001", "T1071.004", "T1095", "T1105", "T1090.001", 
                    "T1090.003", "T1572", "T1573", "T1571", "T1132.001"
                ],
                "priority": 11,
                "color": "bright_yellow"
            },
            "impact": {
                "description": "Techniques to disrupt operations",
                "techniques": [
                    "T1485", "T1486", "T1489", "T1490", "T1491.001", "T1496", 
                    "T1529", "T1531"
                ],
                "priority": 12,
                "color": "bright_red"
            },
            "web_attacks": {
                "description": "Web application specific attacks",
                "techniques": [
                    "T1190", "T1505.002", "T1505.003", "T1505.004", "T1505.005"
                ],
                "keywords": ["web", "http", "browser", "javascript", "sql", "xss", "application"],
                "priority": 13,
                "color": "bright_cyan"
            },
            "process_injection": {
                "description": "Process injection and manipulation",
                "techniques": [
                    "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004", 
                    "T1055.011", "T1055.012", "T1055.015"
                ],
                "keywords": ["injection", "hollowing", "dll", "process"],
                "priority": 14,
                "color": "bright_magenta"
            },
            "powershell_attacks": {
                "description": "PowerShell-based techniques",
                "techniques": [
                    "T1059.001", "T1070.001"
                ],
                "keywords": ["powershell", "ps1", "invoke"],
                "priority": 15,
                "color": "blue"
            },
            "network_attacks": {
                "description": "Network-based attack techniques",
                "techniques": [
                    "T1018", "T1021.001", "T1021.002", "T1021.003", "T1135", 
                    "T1040", "T1557.001"
                ],
                "keywords": ["network", "smb", "rdp", "ssh", "snmp", "dns"],
                "priority": 16,
                "color": "green"
            }
        },
        "technique_dependencies": {
            "T1190": {
                "enables": ["T1059", "T1059.001", "T1059.003", "T1059.004"],
                "difficulty": "medium",
                "stealth": "medium"
            },
            "T1059.001": {
                "requires": ["T1059"],
                "enables": ["T1055", "T1003", "T1070.001"],
                "difficulty": "low",
                "stealth": "low"
            },
            "T1055": {
                "requires": ["T1059", "T1134"],
                "enables": ["T1003", "T1134.002"],
                "difficulty": "high",
                "stealth": "medium"
            },
            "T1003": {
                "requires": ["T1055", "T1548.002"],
                "enables": ["T1021.001", "T1021.002", "T1550.002"],
                "difficulty": "high",
                "stealth": "low"
            }
        }
    }
    
    with open("data/technique_categories.json", "w") as f:
        json.dump(content, f, indent=2)
    print("✅ Created data/technique_categories.json")

def create_attack_chains():
    """Create attack_chains.json"""
    content = {
        "predefined_chains": {
            "vple_web_compromise": {
                "name": "VPLE Web Application Compromise",
                "description": "Specifically designed for VulnHub VPLE VM exploitation",
                "target_platform": "linux",
                "phases": [
                    {
                        "phase": "reconnaissance",
                        "description": "Gather information about the target",
                        "techniques": ["T1595.003", "T1018", "T1016"],
                        "mandatory": True
                    },
                    {
                        "phase": "initial_access",
                        "description": "Exploit web application vulnerabilities",
                        "techniques": ["T1190", "T1505.003"],
                        "mandatory": True
                    },
                    {
                        "phase": "execution",
                        "description": "Execute code through web shell",
                        "techniques": ["T1059.004", "T1105"],
                        "mandatory": True
                    },
                    {
                        "phase": "privilege_escalation",
                        "description": "Escalate to root privileges",
                        "techniques": ["T1548.001", "T1053.003"],
                        "mandatory": False
                    },
                    {
                        "phase": "persistence",
                        "description": "Maintain access to the system",
                        "techniques": ["T1543.002", "T1053.003"],
                        "mandatory": False
                    }
                ],
                "estimated_duration": "30-45 minutes",
                "difficulty": "medium"
            },
            "windows_domain_compromise": {
                "name": "Windows Domain Compromise Chain",
                "description": "Complete Windows domain takeover simulation",
                "target_platform": "windows",
                "phases": [
                    {
                        "phase": "initial_access",
                        "description": "Gain initial foothold",
                        "techniques": ["T1566.001", "T1059.001"],
                        "mandatory": True
                    },
                    {
                        "phase": "execution",
                        "description": "Execute PowerShell payloads",
                        "techniques": ["T1059.001", "T1047"],
                        "mandatory": True
                    },
                    {
                        "phase": "defense_evasion",
                        "description": "Bypass security controls",
                        "techniques": ["T1027.001", "T1562.001"],
                        "mandatory": True
                    },
                    {
                        "phase": "credential_access",
                        "description": "Dump credentials",
                        "techniques": ["T1003.001", "T1003.002", "T1110.003"],
                        "mandatory": True
                    },
                    {
                        "phase": "discovery",
                        "description": "Enumerate domain",
                        "techniques": ["T1482", "T1087.002", "T1018"],
                        "mandatory": True
                    },
                    {
                        "phase": "lateral_movement",
                        "description": "Move to domain controllers",
                        "techniques": ["T1021.001", "T1021.002"],
                        "mandatory": True
                    },
                    {
                        "phase": "persistence",
                        "description": "Establish domain persistence",
                        "techniques": ["T1098", "T1484.001"],
                        "mandatory": True
                    }
                ],
                "estimated_duration": "2-3 hours",
                "difficulty": "high"
            }
        },
        "chain_templates": {
            "web_application_focused": {
                "categories": ["web_attacks", "execution", "privilege_escalation", "persistence"],
                "platforms": ["linux", "windows"],
                "description": "Focus on web application vulnerabilities"
            },
            "credential_focused": {
                "categories": ["execution", "credential_access", "lateral_movement"],
                "platforms": ["windows"],
                "description": "Focus on credential harvesting and lateral movement"
            }
        }
    }
    
    with open("data/attack_chains.json", "w") as f:
        json.dump(content, f, indent=2)
    print("✅ Created data/attack_chains.json")

def create_target_profiles():
    """Create target_profiles.json"""
    content = {
        "profiles": {
            "vple_vm": {
                "name": "VulnHub VPLE VM",
                "platform": "linux",
                "version": "ubuntu_16.04",
                "architecture": "x64",
                "domain_joined": False,
                "admin_access": False,
                "security_tools": [],
                "network_access": True,
                "internet_access": False,
                "services": [
                    {"name": "apache", "port": 80, "version": "2.4.18"},
                    {"name": "ssh", "port": 22, "version": "OpenSSH 7.2"},
                    {"name": "mysql", "port": 3306, "version": "5.7"}
                ],
                "vulnerabilities": [
                    "web_application_sqli",
                    "web_application_file_upload",
                    "privilege_escalation_kernel",
                    "sudo_misconfiguration"
                ],
                "constraints": {
                    "avoid_elevation": False,
                    "exclude_destructive": True,
                    "focus_categories": ["web_attacks", "execution", "privilege_escalation", "persistence"],
                    "max_techniques_per_category": 3,
                    "preferred_techniques": ["T1190", "T1505.003", "T1059.004", "T1548.001"]
                },
                "attack_objectives": ["web_application", "privilege_escalation", "persistence"],
                "recommended_chain": "vple_web_compromise"
            },
            "windows_workstation": {
                "name": "Windows 10 Workstation",
                "platform": "windows",
                "version": "10",
                "architecture": "x64",
                "domain_joined": False,
                "admin_access": False,
                "security_tools": ["windows_defender", "windows_firewall"],
                "network_access": True,
                "internet_access": True,
                "constraints": {
                    "avoid_elevation": True,
                    "exclude_destructive": True,
                    "focus_categories": ["execution", "defense_evasion", "credential_access", "discovery"],
                    "max_techniques_per_category": 2
                }
            }
        }
    }
    
    with open("data/target_profiles.json", "w") as f:
        json.dump(content, f, indent=2)
    print("✅ Created data/target_profiles.json")

def create_setup_script():
    """Create setup.py"""
    content = '''#!/usr/bin/env python3
"""
Setup script for Atomic Red Team Attack Orchestrator
"""

import os
import sys
import subprocess
import platform
import json
from pathlib import Path

def print_banner():
    """Print setup banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║              Atomic Red Team Attack Orchestrator             ║
    ║                         Setup Script                         ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Check if Python version is compatible"""
    print("[+] Checking Python version...")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ is required. Current version:", sys.version_info)
        return False
    print("✅ Python version:", sys.version_info)
    return True

def create_directories():
    """Create necessary directories"""
    print("[+] Creating project directories...")
    directories = [
        "core",
        "data", 
        "utils",
        "output",
        "logs",
        "config",
        "examples"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")

def install_python_dependencies():
    """Install Python dependencies"""
    print("[+] Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False

def check_atomic_red_team():
    """Check if Atomic Red Team is available"""
    print("[+] Checking for Atomic Red Team...")
    
    possible_paths = [
        "./atomic-red-team/atomics",
        "../atomic-red-team/atomics",
        "./atomics",
        "../atomics"
    ]
    
    for path in possible_paths:
        if Path(path).exists():
            print(f"✅ Found Atomic Red Team at: {path}")
            return path
    
    print("❌ Atomic Red Team not found. Please download it:")
    print("   git clone https://github.com/redcanaryco/atomic-red-team.git")
    return None

def create_sample_config():
    """Create sample configuration file"""
    print("[+] Creating sample configuration...")
    
    config = {
        "atomics_path": "./atomic-red-team/atomics",
        "output_dir": "./output",
        "log_level": "INFO",
        "default_platform": "linux",
        "default_target_profile": "vple_vm",
        "execution": {
            "dry_run": True,
            "interactive": True,
            "delay_between_steps": 5,
            "timeout_per_step": 300
        }
    }
    
    config_file = Path("config/config.json")
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Sample configuration created: {config_file}")

def run_initial_test():
    """Run initial test to verify installation"""
    print("[+] Running initial test...")
    
    try:
        # Import core modules to test
        sys.path.append(".")
        from core.technique_parser import TechniqueParser
        from core.categorizer import AttackCategorizer
        
        print("✅ Core modules import successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import core modules: {e}")
        return False

def print_next_steps(atomics_path):
    """Print next steps for the user"""
    print("\\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    print("\\n📋 NEXT STEPS:")
    print("\\n1. Test the installation:")
    if atomics_path:
        print(f"   python main.py --atomics {atomics_path} --analyze --platform linux")
    else:
        print("   python main.py --atomics ./atomic-red-team/atomics --analyze --platform linux")
    
    print("\\n2. Try building an attack chain:")
    print("   python main.py --atomics ./atomic-red-team/atomics --build web_application --platform linux --dry-run")
    
    print("\\n3. For VPLE VM testing:")
    print("   cd examples && python vple_attack_example.py")
    
    print("\\n⚠️  IMPORTANT REMINDERS:")
    print("   • Always test in isolated lab environments")
    print("   • Use --dry-run first to test chains")
    print("   • Review generated PowerShell scripts before execution")
    
    if not atomics_path:
        print("\\n❗ ACTION REQUIRED:")
        print("   Download Atomic Red Team: git clone https://github.com/redcanaryco/atomic-red-team.git")

def main():
    """Main setup function"""
    print_banner()
    
    # Check system requirements
    if not check_python_version():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_python_dependencies():
        print("⚠️  Continuing with limited functionality...")
    
    # Check for Atomic Red Team
    atomics_path = check_atomic_red_team()
    
    # Create sample config
    create_sample_config()
    
    # Test installation
    if run_initial_test():
        print_next_steps(atomics_path)
    else:
        print("❌ Setup completed with errors. Check the output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
    
    with open("setup.py", "w") as f:
        f.write(content)
    print("✅ Created setup.py")

def create_vple_example():
    """Create VPLE attack example"""
    content = '''#!/usr/bin/env python3
"""
VPLE VM Attack Example
Demonstrates how to use the Atomic Red Team Orchestrator for black box testing
"""

import sys
import os
import time
sys.path.append('..')

from core.technique_parser import TechniqueParser
from core.categorizer import AttackCategorizer
from core.dependency_mapper import DependencyMapper
from core.chain_builder import AttackChainBuilder, AttackObjective
from main_orchestrator import AtomicOrchestrator

def vple_reconnaissance_phase(orchestrator):
    """Phase 1: Reconnaissance and Target Analysis"""
    print("\\n" + "="*60)
    print("🔍 PHASE 1: RECONNAISSANCE & TARGET ANALYSIS")
    print("="*60)
    
    # Analyze target capabilities
    analysis = orchestrator.analyze_target("linux")
    
    print(f"📊 Target Analysis Results:")
    print(f"   • Total Linux techniques available: {analysis['total_techniques']}")
    print(f"   • Web attack vectors: {analysis['categories'].get('web_attacks', {}).get('technique_count', 0)}")
    print(f"   • Privilege escalation paths: {analysis['categories'].get('privilege_escalation', {}).get('technique_count', 0)}")
    
    return analysis

def vple_initial_access_phase(orchestrator):
    """Phase 2: Initial Access Chain"""
    print("\\n" + "="*60)
    print("🚪 PHASE 2: INITIAL ACCESS CHAIN")
    print("="*60)
    
    # Build web application attack chain
    constraints = {
        "avoid_elevation": True,
        "focus_categories": ["web_attacks", "execution"],
        "max_techniques_per_category": 2
    }
    
    chain = orchestrator.build_attack_chain(
        "web_application", 
        "linux", 
        constraints
    )
    
    if chain:
        print(f"🎯 Built initial access chain: {chain.name}")
        print(f"   • Steps: {len(chain.steps)}")
        print(f"   • Duration: {chain.estimated_duration}")
        
        return chain
    else:
        print("❌ Failed to build initial access chain")
        return None

def main():
    """Main VPLE attack demonstration"""
    print("🎯 VPLE VM Attack Demonstration")
    print("Using Atomic Red Team Orchestrator for Black Box Testing")
    
    # Initialize orchestrator
    atomics_path = "../atomic-red-team/atomics"
    if not os.path.exists(atomics_path):
        atomics_path = "./atomics"
    
    print(f"\\n🔧 Initializing orchestrator with atomics path: {atomics_path}")
    orchestrator = AtomicOrchestrator(atomics_path)
    
    if not orchestrator.initialize():
        print("❌ Failed to initialize orchestrator")
        return
    
    try:
        # Phase 1: Reconnaissance
        analysis = vple_reconnaissance_phase(orchestrator)
        
        # Phase 2: Initial Access
        initial_chain = vple_initial_access_phase(orchestrator)
        
        print(f"\\n✅ VPLE attack demonstration completed!")
        print(f"   Review generated scripts and logs before actual execution.")
        
    except KeyboardInterrupt:
        print(f"\\n⚠️  Demonstration interrupted by user")
    except Exception as e:
        print(f"\\n❌ Error during demonstration: {e}")

if __name__ == "__main__":
    main()
'''
    
    with open("examples/vple_attack_example.py", "w") as f:
        f.write(content)
    print("✅ Created examples/vple_attack_example.py")

def create_utils_init():
    """Create utils/__init__.py"""
    with open("utils/__init__.py", "w") as f:
        f.write("# Utils package\n")
    print("✅ Created utils/__init__.py")

def create_requirements():
    """Create requirements.txt"""
    content = '''# Core dependencies
pyyaml>=6.0
pandas>=1.3.0
networkx>=2.6
colorama>=0.4.4
rich>=10.0.0
click>=8.0.0

# Enhanced functionality
requests>=2.25.0
jinja2>=3.0.0
jsonschema>=3.2.0
python-dateutil>=2.8.0

# Data analysis and visualization
matplotlib>=3.3.0
seaborn>=0.11.0

# Development and testing
pytest>=6.0.0
black>=21.0.0
flake8>=3.8.0
'''
    
    with open("requirements.txt", "w") as f:
        f.write(content)
    print("✅ Created requirements.txt")

def create_makefile():
    """Create Makefile"""
    content = '''# Atomic Red Team Attack Orchestrator Makefile

.PHONY: help setup install clean test analyze build-web run-vple

# Default atomics path - adjust as needed
ATOMICS_PATH ?= ./atomic-red-team/atomics
PLATFORM ?= linux

help: ## Show this help message
	@echo "Atomic Red Team Attack Orchestrator"
	@echo "==================================="
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

setup: ## Initial setup (install dependencies, create directories)
	@echo "🚀 Setting up Atomic Red Team Orchestrator..."
	python setup.py

install: ## Install Python dependencies only
	@echo "📦 Installing Python dependencies..."
	pip install -r requirements.txt

clean: ## Clean output and log files
	@echo "🧹 Cleaning up..."
	rm -rf output/* logs/* __pycache__ core/__pycache__ utils/__pycache__

test: ## Test the installation
	@echo "🧪 Testing installation..."
	python -c "from core.technique_parser import TechniqueParser; print('✅ Core modules working')"

analyze: ## Analyze target platform capabilities
	@echo "🔍 Analyzing $(PLATFORM) platform capabilities..."
	python main.py --atomics $(ATOMICS_PATH) --analyze --platform $(PLATFORM)

build-web: ## Build web application attack chain
	@echo "🌐 Building web application attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform $(PLATFORM) --export powershell

run-vple: ## Run VPLE VM attack example
	@echo "🎯 Running VPLE VM attack example..."
	cd examples && python vple_attack_example.py

dry-run-web: ## Execute web attack chain in dry-run mode
	@echo "🧪 Dry run: Web application attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform $(PLATFORM) --execute --dry-run

vple-recon: ## VPLE VM reconnaissance phase
	@echo "🔍 VPLE Reconnaissance..."
	python main.py --atomics $(ATOMICS_PATH) --analyze --platform linux

vple-web-attack: ## Build VPLE web attack chain
	@echo "🌐 Building VPLE web attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform linux --avoid-elevation --export powershell

check-atomics: ## Check if Atomic Red Team is available
	@if [ -d "$(ATOMICS_PATH)" ]; then \\
		echo "✅ Atomic Red Team found at $(ATOMICS_PATH)"; \\
	else \\
		echo "❌ Atomic Red Team not found at $(ATOMICS_PATH)"; \\
		echo "Download with: git clone https://github.com/redcanaryco/atomic-red-team.git"; \\
	fi
'''
    
    with open("Makefile", "w") as f:
        f.write(content)
    print("✅ Created Makefile")

def main():
    print("🚀 Creating missing files for Atomic Red Team Orchestrator...")
    
    # Create directories
    create_directories()
    
    # Create data files
    create_technique_categories()
    create_attack_chains()
    create_target_profiles()
    
    # Create setup and examples
    create_setup_script()
    create_vple_example()
    
    # Create utils
    create_utils_init()
    
    # Create config files
    create_requirements()
    create_makefile()
    
    print("\\n🎉 All files created successfully!")
    print("\\nNext steps:")
    print("1. Run: python setup.py")
    print("2. Download Atomic Red Team: git clone https://github.com/redcanaryco/atomic-red-team.git")
    print("3. Test: python main.py --atomics ./atomic-red-team/atomics --analyze --platform linux")

if __name__ == "__main__":
    main()
'''

if __name__ == "__main__":
    main()
