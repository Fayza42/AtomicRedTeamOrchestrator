#!/usr/bin/env python3
"""
Complete Project Structure Creator for Atomic Red Team Orchestrator
Creates the entire project with all files and directories
"""

import os
import json
from pathlib import Path

def create_project_structure():
    """Create complete project structure"""
    
    print("🚀 Creating Atomic Red Team Orchestrator Project Structure...")
    
    # Project root directory
    project_root = "atomic_orchestrator"
    
    # Create main project directory
    if not os.path.exists(project_root):
        os.makedirs(project_root)
        print(f"✅ Created main project directory: {project_root}/")
    
    # Change to project directory
    os.chdir(project_root)
    
    # Directory structure
    directories = [
        "core",
        "data",
        "utils", 
        "examples",
        "config",
        "output",
        "logs",
        "tests",
        "docs",
        "scripts",
        "templates"
    ]
    
    # Create directories
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/")
    
    # Create __init__.py files
    init_files = [
        "core/__init__.py",
        "utils/__init__.py", 
        "tests/__init__.py"
    ]
    
    for init_file in init_files:
        with open(init_file, "w") as f:
            f.write("# Package initialization\n")
        print(f"✅ Created {init_file}")

def create_core_files():
    """Create core module files"""
    
    print("\n📦 Creating core module files...")
    
    # Core files to create (these will be populated by user)
    core_files = [
        "core/technique_parser.py",
        "core/categorizer.py", 
        "core/dependency_mapper.py",
        "core/chain_builder.py",
        "core/executor.py"
    ]
    
    for core_file in core_files:
        if not os.path.exists(core_file):
            with open(core_file, "w") as f:
                f.write(f'"""\n{core_file.split("/")[1]} module\nTODO: Add your existing code here\n"""\n\n')
            print(f"📝 Created template: {core_file}")
        else:
            print(f"✅ Found existing: {core_file}")

def create_data_files():
    """Create data configuration files"""
    
    print("\n📊 Creating data files...")
    
    # VPLE-optimized technique categories
    technique_categories = {
        "technique_mappings": {
            "web_attacks": {
                "description": "Web application exploitation techniques - Perfect for VPLE's 7 web apps",
                "techniques": [
                    "T1190",      # Exploit Public-Facing Application  
                    "T1505.003",  # Web Shell
                    "T1566.002",  # Spearphishing Link
                    "T1059.007",  # JavaScript execution
                    "T1105"       # Ingress Tool Transfer
                ],
                "keywords": ["web", "http", "browser", "javascript", "sql", "xss", "application", "php", "cms"],
                "priority": 1,
                "color": "bright_cyan",
                "vple_targets": ["dvwa", "mutillidae", "webgoat", "bwapp", "juice-shop", "wordpress"]
            },
            "execution": {
                "description": "Code execution techniques for web shells and system access",
                "techniques": [
                    "T1059.004",  # Unix Shell (perfect for VPLE Linux)
                    "T1059.006",  # Python
                    "T1059.007",  # JavaScript  
                    "T1059",      # Command and Scripting Interpreter
                    "T1106"       # Native API
                ],
                "priority": 2,
                "color": "orange"
            },
            "privilege_escalation": {
                "description": "Linux privilege escalation techniques", 
                "techniques": [
                    "T1548.001",  # Setuid and Setgid (Linux-specific)
                    "T1053.003",  # Cron (Linux scheduling)
                    "T1068",      # Exploitation for Privilege Escalation
                    "T1134"       # Access Token Manipulation
                ],
                "priority": 3,
                "color": "purple"
            },
            "persistence": {
                "description": "Maintain access to VPLE system",
                "techniques": [
                    "T1543.002",  # Systemd Services (Linux)
                    "T1053.003",  # Cron
                    "T1037.004",  # RC Scripts
                    "T1505.003"   # Web Shell persistence
                ],
                "priority": 4,
                "color": "yellow"
            },
            "defense_evasion": {
                "description": "Evade detection on Linux systems",
                "techniques": [
                    "T1027",      # Obfuscated Files or Information
                    "T1070.004",  # File Deletion
                    "T1564.001",  # Hidden Files and Directories
                    "T1222.002"   # Linux File Permissions
                ],
                "priority": 5,
                "color": "blue"
            },
            "discovery": {
                "description": "System and network reconnaissance",
                "techniques": [
                    "T1082",      # System Information Discovery
                    "T1083",      # File and Directory Discovery  
                    "T1087.001",  # Local Account Discovery
                    "T1018",      # Remote System Discovery
                    "T1057"       # Process Discovery
                ],
                "priority": 6,
                "color": "green"
            }
        },
        "vple_specific": {
            "target_ports": {
                "dvwa": 1335,
                "mutillidae": 1336, 
                "webgoat": 1337,
                "bwapp": 8080,
                "juice_shop": 3000,
                "security_ninjas": 8899,
                "wordpress": 8800
            },
            "default_credentials": {
                "system": {"username": "administrator", "password": "password"},
                "dvwa": {"username": "admin", "password": "password"},
                "mutillidae": {"username": "admin", "password": "admin"}
            },
            "vulnerability_types": [
                "sql_injection",
                "xss_reflected",
                "xss_stored", 
                "file_upload_bypass",
                "command_injection",
                "directory_traversal",
                "weak_authentication",
                "session_management_flaws"
            ]
        }
    }
    
    with open("data/technique_categories.json", "w") as f:
        json.dump(technique_categories, f, indent=2)
    print("✅ Created data/technique_categories.json (VPLE-optimized)")
    
    # VPLE-specific attack chains
    attack_chains = {
        "predefined_chains": {
            "vple_dvwa_attack": {
                "name": "VPLE DVWA SQL Injection to Shell",
                "description": "Target DVWA (port 1335) for SQL injection leading to web shell",
                "target_platform": "linux",
                "target_ports": [1335],
                "phases": [
                    {
                        "phase": "reconnaissance", 
                        "description": "Scan VPLE web applications",
                        "techniques": ["T1595.001", "T1046"],
                        "commands": ["nmap -p 1335,1336,1337,8080,3000,8899,8800 {target_ip}"],
                        "mandatory": True
                    },
                    {
                        "phase": "initial_access",
                        "description": "Exploit DVWA SQL injection",
                        "techniques": ["T1190"],
                        "target_app": "dvwa",
                        "mandatory": True
                    },
                    {
                        "phase": "execution", 
                        "description": "Upload and execute web shell",
                        "techniques": ["T1505.003", "T1059.004"],
                        "mandatory": True
                    },
                    {
                        "phase": "privilege_escalation",
                        "description": "Escalate to root privileges", 
                        "techniques": ["T1548.001"],
                        "mandatory": False
                    }
                ],
                "estimated_duration": "15-30 minutes",
                "difficulty": "easy"
            },
            "vple_multi_app_attack": {
                "name": "VPLE Multi-Application Attack Chain",
                "description": "Attack multiple VPLE applications systematically",
                "target_platform": "linux",
                "target_ports": [1335, 1336, 3000, 8080],
                "phases": [
                    {
                        "phase": "reconnaissance",
                        "description": "Enumerate all VPLE web services",
                        "techniques": ["T1046", "T1083"],
                        "mandatory": True
                    },
                    {
                        "phase": "initial_access_dvwa",
                        "description": "Attack DVWA first (easiest target)",
                        "techniques": ["T1190", "T1505.003"],
                        "mandatory": True
                    },
                    {
                        "phase": "initial_access_juice",
                        "description": "Attack Juice Shop (modern app)",
                        "techniques": ["T1190", "T1059.007"],
                        "mandatory": False
                    },
                    {
                        "phase": "privilege_escalation",
                        "description": "Escalate privileges on system",
                        "techniques": ["T1548.001", "T1053.003"],
                        "mandatory": True
                    },
                    {
                        "phase": "persistence",
                        "description": "Establish persistent access",
                        "techniques": ["T1543.002", "T1505.003"],
                        "mandatory": True
                    }
                ],
                "estimated_duration": "45-90 minutes",
                "difficulty": "medium"
            },
            "vple_stealth_attack": {
                "name": "VPLE Stealth Penetration",
                "description": "Low-detection attack chain for VPLE",
                "target_platform": "linux", 
                "phases": [
                    {
                        "phase": "passive_recon",
                        "description": "Passive information gathering",
                        "techniques": ["T1595.002"],
                        "mandatory": True
                    },
                    {
                        "phase": "web_exploitation",
                        "description": "Careful web application exploitation",
                        "techniques": ["T1190", "T1505.003"],
                        "stealth_mode": True,
                        "mandatory": True
                    },
                    {
                        "phase": "living_off_land",
                        "description": "Use built-in tools only",
                        "techniques": ["T1059.004", "T1083"],
                        "mandatory": True
                    },
                    {
                        "phase": "covert_persistence", 
                        "description": "Hidden persistence mechanisms",
                        "techniques": ["T1564.001", "T1037.004"],
                        "mandatory": True
                    }
                ],
                "estimated_duration": "60-120 minutes",
                "difficulty": "hard"
            }
        },
        "vple_methodology": {
            "attack_sequence": [
                "Port scan and service enumeration",
                "Web application vulnerability assessment", 
                "Exploit easiest target first (usually DVWA)",
                "Establish web shell access",
                "Local privilege escalation",
                "System enumeration and persistence",
                "Attack additional web applications",
                "Data collection and exfiltration simulation"
            ],
            "recommended_tools": [
                "nmap - Port scanning",
                "dirb/gobuster - Directory enumeration",
                "sqlmap - SQL injection automation", 
                "burp suite - Web application testing",
                "msfvenom - Payload generation",
                "linpeas - Linux privilege escalation"
            ]
        }
    }
    
    with open("data/attack_chains.json", "w") as f:
        json.dump(attack_chains, f, indent=2)
    print("✅ Created data/attack_chains.json (VPLE-specific chains)")
    
    # VPLE target profile
    target_profiles = {
        "profiles": {
            "vple_vm": {
                "name": "VulnHub VPLE Virtual Machine",
                "description": "Vulnerable Pentesting Lab Environment with 7 web applications",
                "platform": "linux",
                "version": "ubuntu_16.04",
                "architecture": "x64", 
                "default_credentials": {
                    "username": "administrator",
                    "password": "password"
                },
                "network_config": {
                    "dhcp_enabled": True,
                    "typical_ip_range": "192.168.x.x"
                },
                "web_applications": {
                    "dvwa": {
                        "port": 1335,
                        "path": "/",
                        "description": "Damn Vulnerable Web App - PHP/MySQL",
                        "difficulty": "beginner",
                        "vulnerabilities": ["sql_injection", "xss", "file_upload", "command_injection"]
                    },
                    "mutillidae": {
                        "port": 1336, 
                        "path": "/",
                        "description": "OWASP Top 10 + additional vulnerabilities",
                        "difficulty": "intermediate",
                        "vulnerabilities": ["owasp_top_10", "html5_storage", "clickjacking"]
                    },
                    "webgoat": {
                        "port": 1337,
                        "path": "/WebGoat/",
                        "description": "Educational web security platform",
                        "difficulty": "intermediate",
                        "vulnerabilities": ["educational_challenges", "java_specific"]
                    },
                    "bwapp": {
                        "port": 8080,
                        "path": "/",
                        "description": "100+ web vulnerabilities",
                        "difficulty": "advanced",
                        "vulnerabilities": ["comprehensive_web_bugs", "owasp_top_10"]
                    },
                    "juice_shop": {
                        "port": 3000,
                        "path": "/", 
                        "description": "Modern JavaScript-based vulnerable app",
                        "difficulty": "intermediate", 
                        "vulnerabilities": ["owasp_top_10", "javascript_specific", "rest_api"]
                    },
                    "security_ninjas": {
                        "port": 8899,
                        "path": "/",
                        "description": "OpenDNS security training platform",
                        "difficulty": "educational",
                        "vulnerabilities": ["training_exercises", "owasp_top_10"]
                    },
                    "wordpress": {
                        "port": 8800,
                        "path": "/",
                        "description": "WordPress CMS with vulnerabilities", 
                        "difficulty": "intermediate",
                        "vulnerabilities": ["cms_specific", "plugin_vulns", "weak_passwords"]
                    }
                },
                "attack_constraints": {
                    "avoid_elevation": False,
                    "exclude_destructive": True,
                    "focus_categories": ["web_attacks", "execution", "privilege_escalation", "persistence"],
                    "max_techniques_per_category": 3,
                    "preferred_techniques": ["T1190", "T1505.003", "T1059.004", "T1548.001"]
                },
                "recommended_attack_chains": [
                    "vple_dvwa_attack",
                    "vple_multi_app_attack", 
                    "vple_stealth_attack"
                ],
                "testing_notes": [
                    "Start with DVWA (port 1335) - easiest target",
                    "Default system credentials: administrator:password",
                    "All web apps run automatically on boot",
                    "VM must run in VMware (not VirtualBox)",
                    "Perfect for learning web application security"
                ]
            }
        }
    }
    
    with open("data/target_profiles.json", "w") as f:
        json.dump(target_profiles, f, indent=2)
    print("✅ Created data/target_profiles.json (VPLE-specific profile)")

def create_examples():
    """Create example files"""
    
    print("\n📚 Creating example files...")
    
    # VPLE attack example
    vple_example = '''#!/usr/bin/env python3
"""
VPLE VM Complete Attack Example
Demonstrates intelligent attack automation against VPLE's 7 web applications
"""

import sys
import os
import time
sys.path.append('..')

def main():
    """Main VPLE attack demonstration"""
    print("🎯 VPLE VM Complete Attack Demonstration")
    print("=" * 60)
    
    print("This example demonstrates:")
    print("• Target analysis and reconnaissance")
    print("• Multi-application attack chains") 
    print("• Intelligent technique selection")
    print("• Risk-based attack progression")
    print("• VPLE-specific optimizations")
    
    print("\\nVPLE Applications Available:")
    apps = {
        "DVWA": "Port 1335 - SQL injection, XSS, file upload",
        "Mutillidae": "Port 1336 - OWASP Top 10 + more",
        "WebGoat": "Port 1337 - Educational challenges", 
        "bWAPP": "Port 8080 - 100+ vulnerabilities",
        "Juice Shop": "Port 3000 - Modern JavaScript app",
        "Security Ninjas": "Port 8899 - Training platform",
        "WordPress": "Port 8800 - CMS vulnerabilities"
    }
    
    for app, desc in apps.items():
        print(f"  • {app}: {desc}")
    
    print("\\n🚀 Ready to run intelligent attack automation!")
    print("   Execute with your existing core modules...")

if __name__ == "__main__":
    main()
'''
    
    with open("examples/vple_complete_attack.py", "w") as f:
        f.write(vple_example)
    print("✅ Created examples/vple_complete_attack.py")
    
    # Quick start script
    quick_start = '''#!/usr/bin/env python3
"""
Quick Start Script for VPLE Testing
"""

def quick_start_vple():
    """Quick start commands for VPLE testing"""
    
    commands = [
        "# Step 1: Setup and initialization",
        "python setup.py",
        "",
        "# Step 2: Download Atomic Red Team",  
        "git clone https://github.com/redcanaryco/atomic-red-team.git",
        "",
        "# Step 3: Analyze VPLE target",
        "python main.py --atomics ./atomic-red-team/atomics --analyze --platform linux",
        "",
        "# Step 4: Build VPLE web attack chain", 
        "python main.py --atomics ./atomic-red-team/atomics --build web_application --platform linux --export powershell",
        "",
        "# Step 5: Execute with dry run (SAFE)",
        "python main.py --atomics ./atomic-red-team/atomics --build web_application --execute --dry-run",
        "",
        "# Step 6: Run VPLE-specific example",
        "cd examples && python vple_complete_attack.py"
    ]
    
    return "\\n".join(commands)

if __name__ == "__main__":
    print("VPLE Quick Start Commands:")
    print("=" * 40)
    print(quick_start_vple())
'''
    
    with open("examples/quick_start_vple.py", "w") as f:
        f.write(quick_start)
    print("✅ Created examples/quick_start_vple.py")

def create_config_files():
    """Create configuration files"""
    
    print("\n⚙️ Creating configuration files...")
    
    # Main requirements.txt
    requirements = '''# Core dependencies for Atomic Red Team Orchestrator
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

# Optional: Web interface for results
flask>=2.0.0
flask-cors>=3.0.0
'''
    
    with open("requirements.txt", "w") as f:
        f.write(requirements)
    print("✅ Created requirements.txt")
    
    # Setup script
    setup_script = '''#!/usr/bin/env python3
"""
Atomic Red Team Orchestrator Setup Script
Optimized for VPLE VM testing
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    """Main setup function"""
    print("🚀 Setting up Atomic Red Team Orchestrator for VPLE...")
    
    # Install dependencies
    print("📦 Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    # Check for Atomic Red Team
    print("🔍 Checking for Atomic Red Team...")
    if not Path("atomic-red-team").exists():
        print("⬇️ Downloading Atomic Red Team...")
        subprocess.check_call(["git", "clone", "https://github.com/redcanaryco/atomic-red-team.git"])
    
    print("✅ Setup complete! Ready for VPLE testing.")
    print("\\nNext steps:")
    print("1. python main.py --atomics ./atomic-red-team/atomics --analyze --platform linux") 
    print("2. cd examples && python vple_complete_attack.py")

if __name__ == "__main__":
    main()
'''
    
    with open("setup.py", "w") as f:
        f.write(setup_script)
    print("✅ Created setup.py")
    
    # Makefile for easy commands
    makefile = '''# VPLE-Optimized Atomic Red Team Orchestrator Makefile

ATOMICS_PATH ?= ./atomic-red-team/atomics
VPLE_IP ?= 192.168.1.100

.PHONY: help setup vple-recon vple-attack vple-full clean

help: ## Show available commands
	@echo "VPLE-Optimized Atomic Red Team Orchestrator"
	@echo "=========================================="
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

setup: ## Initial setup for VPLE testing
	@echo "🚀 Setting up for VPLE testing..."
	python setup.py

vple-recon: ## Reconnaissance phase for VPLE
	@echo "🔍 VPLE Reconnaissance Phase..."
	python main.py --atomics $(ATOMICS_PATH) --analyze --platform linux

vple-attack: ## Build VPLE web application attack chain  
	@echo "🌐 Building VPLE attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform linux --export powershell

vple-dvwa: ## Target DVWA specifically (port 1335)
	@echo "🎯 Targeting DVWA (port 1335)..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform linux --target-port 1335

vple-multi: ## Multi-application attack chain
	@echo "🎪 Multi-application attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build vple_multi_app_attack --platform linux

vple-stealth: ## Stealth attack chain for VPLE
	@echo "🥷 Stealth attack chain..."
	python main.py --atomics $(ATOMICS_PATH) --build vple_stealth_attack --platform linux

vple-full: ## Complete VPLE attack demonstration
	@echo "🎯 Complete VPLE attack demonstration..."
	cd examples && python vple_complete_attack.py

dry-run: ## Safe dry run of VPLE attacks
	@echo "🧪 Dry run mode (SAFE)..."
	python main.py --atomics $(ATOMICS_PATH) --build web_application --platform linux --execute --dry-run

# Network scanning helpers (if nmap available)
vple-scan: ## Scan VPLE VM for open ports
	@echo "🔍 Scanning VPLE VM at $(VPLE_IP)..."
	nmap -p 22,80,1335,1336,1337,3000,8080,8800,8899 $(VPLE_IP)

vple-web-scan: ## Scan only web application ports
	@echo "🌐 Scanning VPLE web ports..."
	nmap -p 1335,1336,1337,3000,8080,8800,8899 $(VPLE_IP)

clean: ## Clean output and logs
	@echo "🧹 Cleaning up..."
	rm -rf output/* logs/*

test: ## Test the installation
	@echo "🧪 Testing installation..."
	python -c "print('✅ Python working'); import yaml; print('✅ YAML working'); import pandas; print('✅ Pandas working')"
'''
    
    with open("Makefile", "w") as f:
        f.write(makefile)
    print("✅ Created Makefile (VPLE-optimized)")

def create_documentation():
    """Create documentation files"""
    
    print("\n📖 Creating documentation...")
    
    readme = '''# Atomic Red Team Orchestrator
## Optimized for VPLE VM Testing

Intelligent automation framework for Atomic Red Team, specifically optimized for VulnHub VPLE VM with its 7 vulnerable web applications.

## 🎯 VPLE VM Support

Perfect match for VPLE's attack surface:
- **7 Web Applications** on different ports
- **Linux Ubuntu** target platform  
- **Known vulnerabilities** in web apps
- **Educational environment** safe for testing

### VPLE Applications Supported:
- **DVWA** (Port 1335) - SQL injection, XSS, file upload
- **Mutillidae** (Port 1336) - OWASP Top 10 + more
- **WebGoat** (Port 1337) - Educational challenges
- **bWAPP** (Port 8080) - 100+ web vulnerabilities  
- **Juice Shop** (Port 3000) - Modern JavaScript app
- **Security Ninjas** (Port 8899) - Training platform
- **WordPress** (Port 8800) - CMS vulnerabilities

## 🚀 Quick Start for VPLE

```bash
# 1. Setup
make setup

# 2. Reconnaissance 
make vple-recon

# 3. Build attack chain
make vple-attack

# 4. Safe testing
make dry-run

# 5. Full demonstration
make vple-full
```

## 🎮 VPLE Attack Strategies

### Strategy 1: Single Application Focus
```bash
# Target DVWA (easiest)
make vple-dvwa

# Target Juice Shop (modern)
python main.py --atomics ./atomic-red-team/atomics --build web_application --target-app juice_shop
```

### Strategy 2: Multi-Application Chain
```bash
# Attack multiple apps systematically  
make vple-multi
```

### Strategy 3: Stealth Approach
```bash
# Low-detection attack chain
make vple-stealth
```

## 🛡️ Safety Features

- **Dry Run Mode** - Test without execution
- **VPLE-Specific** - Optimized for known environment
- **Educational Focus** - Safe for learning
- **Detailed Logging** - Track all activities

## 📁 Project Structure

```
atomic_orchestrator/
├── core/                   # Core modules (your existing code)
├── data/                   # VPLE-optimized configurations  
├── examples/               # VPLE attack demonstrations
├── output/                 # Generated attack scripts
└── logs/                   # Execution logs
```

## ⚠️ VPLE VM Setup

1. **Download VPLE** from VulnHub
2. **Run in VMware** (not VirtualBox)
3. **Default login**: administrator:password
4. **Get IP**: `hostname -I` 
5. **Access apps**: http://IP:PORT/

## 🎯 Attack Flow for VPLE

1. **Reconnaissance** → Scan ports and enumerate services
2. **Initial Access** → Exploit web application (start with DVWA)  
3. **Execution** → Upload and execute web shell
4. **Privilege Escalation** → Linux-specific techniques
5. **Persistence** → Maintain access to system
6. **Additional Targets** → Attack other web applications

Perfect for red team training and web application security learning!
'''
    
    with open("README.md", "w") as f:
        f.write(readme)
    print("✅ Created README.md (VPLE-focused)")

def create_templates():
    """Create template files"""
    
    print("\n📋 Creating template files...")
    
    # PowerShell execution template for VPLE
    ps_template = '''# VPLE Attack Chain PowerShell Template
# Generated by Atomic Red Team Orchestrator

# Target: VPLE VM (VulnHub)
# Platform: Linux  
# Applications: DVWA, Mutillidae, WebGoat, bWAPP, Juice Shop, Security Ninjas, WordPress

Write-Host "🎯 VPLE VM Attack Chain" -ForegroundColor Cyan
Write-Host "Platform: Linux" -ForegroundColor Green
Write-Host "Applications: 7 vulnerable web apps" -ForegroundColor Yellow

# Variables
$VpleIP = "192.168.1.100"  # Update with actual VPLE IP
$WebApps = @{
    "DVWA" = 1335
    "Mutillidae" = 1336  
    "WebGoat" = 1337
    "bWAPP" = 8080
    "JuiceShop" = 3000
    "SecurityNinjas" = 8899
    "WordPress" = 8800
}

Write-Host "📊 VPLE Web Applications:" -ForegroundColor Magenta
foreach ($app in $WebApps.GetEnumerator()) {
    Write-Host "  • $($app.Key): Port $($app.Value)" -ForegroundColor White
}

# Attack steps will be inserted here by the orchestrator
Write-Host "🚀 Ready to execute Atomic Red Team techniques..." -ForegroundColor Green

# Example technique execution:
# Invoke-AtomicTest T1190 -TestNumbers 1
# Invoke-AtomicTest T1505.003 -TestNumbers 1  
# Invoke-AtomicTest T1059.004 -TestNumbers 1

Write-Host "✅ VPLE attack chain template ready" -ForegroundColor Green
'''
    
    with open("templates/vple_attack_template.ps1", "w") as f:
        f.write(ps_template)
    print("✅ Created templates/vple_attack_template.ps1")

def create_main_file():
    """Create main orchestrator file template"""
    
    print("\n🎯 Creating main orchestrator template...")
    
    main_template = '''#!/usr/bin/env python3
"""
Atomic Red Team Orchestrator - Main Entry Point
Optimized for VPLE VM and web application testing
"""

import argparse
import sys
from pathlib import Path

def main():
    """Main orchestrator entry point"""
    parser = argparse.ArgumentParser(
        description="Atomic Red Team Orchestrator - VPLE Optimized",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
VPLE VM Examples:
  %(prog)s --atomics ./atomic-red-team/atomics --analyze --platform linux
  %(prog)s --atomics ./atomic-red-team/atomics --build web_application --platform linux  
  %(prog)s --atomics ./atomic-red-team/atomics --build web_application --execute --dry-run
        """
    )
    
    # Add your existing argument parsing here
    parser.add_argument("--atomics", required=True, help="Path to Atomic Red Team atomics")
    parser.add_argument("--analyze", action="store_true", help="Analyze target capabilities")
    parser.add_argument("--build", help="Build attack chain")
    parser.add_argument("--platform", default="linux", help="Target platform")
    parser.add_argument("--execute", action="store_true", help="Execute attack chain")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--export", choices=["json", "powershell"], help="Export format")
    
    args = parser.parse_args()
    
    print("🎯 Atomic Red Team Orchestrator")
    print("Optimized for VPLE VM Testing")
    print(f"Atomics path: {args.atomics}")
    print(f"Platform: {args.platform}")
    
    # TODO: Add your existing orchestrator logic here
    # from core.technique_parser import TechniqueParser
    # from core.categorizer import AttackCategorizer  
    # etc.
    
    print("🚀 Ready for VPLE attack automation!")

if __name__ == "__main__":
    main()
'''
    
    with open("main.py", "w") as f:
        f.write(main_template)
    print("✅ Created main.py template")

def create_final_summary():
    """Show final project summary"""
    
    print("\n" + "="*60)
    print("🎉 ATOMIC RED TEAM ORCHESTRATOR PROJECT CREATED!")
    print("="*60)
    
    print("\n📁 Complete Project Structure:")
    print("atomic_orchestrator/")
    print("├── core/                    # Your existing modules go here")
    print("├── data/                    # VPLE-optimized configurations")  
    print("├── examples/                # VPLE attack demonstrations")
    print("├── config/                  # Configuration files")
    print("├── templates/               # PowerShell templates")
    print("├── output/                  # Generated scripts")
    print("├── logs/                    # Execution logs")
    print("├── main.py                  # Main orchestrator")
    print("├── setup.py                 # Setup script")
    print("├── requirements.txt         # Dependencies")
    print("├── Makefile                 # Easy commands")
    print("└── README.md                # Documentation")
    
    print("\n🎯 VPLE VM Optimization:")
    print("✅ 7 web applications supported")
    print("✅ Linux platform techniques")  
    print("✅ Web exploitation focused")
    print("✅ VPLE-specific attack chains")
    print("✅ Educational/safe testing")
    
    print("\n🚀 Next Steps:")
    print("1. Copy your existing core/*.py files into core/")
    print("2. Run: python setup.py")
    print("3. Test: make vple-recon")
    print("4. Attack: make vple-attack")
    
    print("\n⚠️ VPLE VM Requirements:")
    print("• Download VPLE from VulnHub")
    print("• Run in VMware (not VirtualBox)")  
    print("• Login: administrator:password")
    print("• 7 web apps on different ports")
    
    print("\n✨ Your orchestrator is PERFECTLY suited for VPLE!")

def main():
    """Main function to create everything"""
    
    # Create the complete project structure
    create_project_structure()
    create_core_files()
    create_data_files()
    create_examples()
    create_config_files()
    create_documentation()
    create_templates()
    create_main_file()
    create_final_summary()

if __name__ == "__main__":
    main()
