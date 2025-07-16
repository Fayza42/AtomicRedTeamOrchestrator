#!/usr/bin/env python3
"""
Fix Python Import Issues for Atomic Red Team Orchestrator
Creates proper package structure and fixes import paths
"""

import os
from pathlib import Path

def create_init_files():
    """Create __init__.py files for proper Python packages"""
    
    print("🔧 Creating __init__.py files for proper Python packages...")
    
    # Directories that need __init__.py files
    package_dirs = [
        ".",  # Root directory
        "core",
        "utils", 
        "examples",
        "config",
        "data"
    ]
    
    for directory in package_dirs:
        init_file = Path(directory) / "__init__.py"
        
        if directory == ".":
            # Root __init__.py
            content = '''"""
Atomic Red Team Orchestrator
SSH Remote Execution for VPLE VM
"""

__version__ = "1.0.0"
__author__ = "Red Team Automation"
'''
        elif directory == "core":
            # Core package __init__.py
            content = '''"""
Core modules for Atomic Red Team Orchestrator
"""

# Make SSH executor easily importable
try:
    from .ssh_executor import SSHExecutor, VPLEConnection
    __all__ = ['SSHExecutor', 'VPLEConnection']
except ImportError:
    pass
'''
        elif directory == "examples":
            # Examples package __init__.py
            content = '''"""
Example scripts and demonstrations
"""
'''
        else:
            # Generic __init__.py
            content = f'"""\n{directory.title()} package\n"""\n'
        
        with open(init_file, "w", encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Created {init_file}")

def create_runner_script():
    """Create a runner script in the root directory"""
    
    runner_content = '''#!/usr/bin/env python3
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
        print("\\n🔧 Setup Instructions:")
        print("1. Make sure you're in the atomic_orchestrator directory")
        print("2. Run: python fix_imports.py")
        print("3. Install dependencies: pip install paramiko scp")
        print("4. Try again: python run_vple_attack.py --ip YOUR_IP")

if __name__ == "__main__":
    main()
'''
    
    with open("run_vple_attack.py", "w", encoding='utf-8') as f:
        f.write(runner_content)
    
    print("✅ Created run_vple_attack.py (root directory runner)")

def create_setup_script():
    """Create a complete setup script"""
    
    setup_content = '''#!/usr/bin/env python3
"""
Complete Setup Script for SSH Remote Execution
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing SSH dependencies...")
    
    dependencies = [
        "paramiko>=2.9.0",
        "scp>=0.14.0", 
        "pyyaml>=6.0",
        "colorama>=0.4.4"
    ]
    
    for dep in dependencies:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
            print(f"✅ Installed {dep}")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {dep}")

def test_imports():
    """Test that all imports work"""
    print("🧪 Testing imports...")
    
    try:
        import paramiko
        print("✅ Paramiko import successful")
    except ImportError:
        print("❌ Paramiko import failed")
        return False
    
    try:
        from core.ssh_executor import VPLEConnection
        print("✅ SSH executor import successful")
    except ImportError as e:
        print(f"❌ SSH executor import failed: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up SSH Remote Execution for VPLE...")
    
    # Install dependencies
    install_dependencies()
    
    # Fix imports
    from fix_imports import create_init_files, create_runner_script
    create_init_files()
    create_runner_script()
    
    # Test imports
    if test_imports():
        print("\\n✅ Setup completed successfully!")
        print("\\n🎯 Next steps:")
        print("1. Start VPLE VM and note its IP address")
        print("2. Test connection: python run_vple_attack.py --test-connection --ip YOUR_IP")
        print("3. Run attack: python run_vple_attack.py --ip YOUR_IP")
        print("\\nAlternative methods:")
        print("• From root: python examples/vple_remote_attack.py --ip YOUR_IP")
        print("• From examples: cd examples && python -m vple_remote_attack --ip YOUR_IP")
    else:
        print("\\n❌ Setup had issues. Check the errors above.")

if __name__ == "__main__":
    main()
'''
    
    with open("setup_ssh.py", "w", encoding='utf-8') as f:
        f.write(setup_content)
    
    print("✅ Created setup_ssh.py (complete setup script)")

def create_makefile_fix():
    """Create an updated Makefile with proper paths"""
    
    makefile_content = '''# Fixed Makefile for SSH Remote Execution
VPLE_IP ?= 192.168.1.100

.PHONY: help setup test-ssh run-remote fix-imports

help: ## Show available commands
	@echo "VPLE SSH Remote Execution - Fixed Imports"
	@echo "========================================"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

setup: ## Complete setup with import fixes
	@echo "🚀 Setting up SSH remote execution..."
	python setup_ssh.py

fix-imports: ## Fix Python import issues
	@echo "🔧 Fixing Python imports..."
	python fix_imports.py

test-ssh: ## Test SSH connection to VPLE
	@echo "🔍 Testing SSH connection..."
	python run_vple_attack.py --test-connection --ip $(VPLE_IP)

run-remote: ## Run remote attack
	@echo "🎯 Running remote attack..."
	python run_vple_attack.py --ip $(VPLE_IP)

run-dry: ## Run in dry-run mode
	@echo "🧪 Running dry-run..."
	python run_vple_attack.py --dry-run --ip $(VPLE_IP)

# Alternative running methods
run-from-root: ## Run from root directory (recommended)
	python run_vple_attack.py --ip $(VPLE_IP)

run-from-examples: ## Run from examples directory
	cd examples && python vple_remote_attack.py --ip $(VPLE_IP)

install-deps: ## Install only dependencies
	pip install paramiko scp pyyaml colorama

clean: ## Clean up generated files
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +

# Debug commands
debug-imports: ## Debug import issues
	@echo "🔍 Debugging imports..."
	@echo "Current directory: $$(pwd)"
	@echo "Python path:"
	@python -c "import sys; [print(p) for p in sys.path]"
	@echo "Core module check:"
	@ls -la core/
	@echo "SSH executor check:"
	@ls -la core/ssh_executor.py || echo "❌ ssh_executor.py not found"

debug-structure: ## Show project structure
	@echo "📁 Project structure:"
	@find . -type f -name "*.py" | head -20
'''
    
    with open("Makefile", "w", encoding='utf-8') as f:
        f.write(makefile_content)
    
    print("✅ Updated Makefile with import fixes")

def main():
    """Main function to fix all import issues"""
    print("🔧 Fixing Python Import Issues...")
    
    create_init_files()
    create_runner_script()
    create_setup_script()
    create_makefile_fix()
    
    print("\n🎉 Import fixes completed!")
    print("\n🚀 Next steps:")
    print("1. Run complete setup: python setup_ssh.py")
    print("2. Test connection: python run_vple_attack.py --test-connection --ip YOUR_IP")
    print("3. Run attack: python run_vple_attack.py --ip YOUR_IP")
    
    print("\n📋 Multiple ways to run:")
    print("• Recommended: python run_vple_attack.py --ip YOUR_IP")
    print("• From examples: cd examples && python vple_remote_attack.py --ip YOUR_IP")
    print("• Via Makefile: make run-remote VPLE_IP=YOUR_IP")

if __name__ == "__main__":
    main()
