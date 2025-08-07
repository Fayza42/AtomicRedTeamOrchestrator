# Auto-Install Enhanced RAG Knowledge Base
# Run this to automatically set up CAPEC + MITRE + Atomic Red Team

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description):
    """Run command with error handling"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def install_packages():
    """Install required Python packages"""
    packages = [
        "langchain>=0.0.350",
        "chromadb>=0.4.15", 
        "ollama>=0.1.7",
        "PyYAML>=6.0",
        "gitpython>=3.1.0",
        "stix2>=3.0.0"
    ]
    
    for package in packages:
        if not run_command(f"{sys.executable} -m pip install {package}", f"Installing {package}"):
            return False
    
    return True

def clone_repositories():
    """Clone required repositories"""
    data_dir = Path("./cti_data")
    data_dir.mkdir(exist_ok=True)
    
    repos = [
        {
            "url": "https://github.com/mitre/cti.git",
            "path": data_dir / "cti",
            "name": "MITRE CTI (CAPEC + ATT&CK)"
        },
        {
            "url": "https://github.com/redcanaryco/atomic-red-team.git", 
            "path": data_dir / "atomic-red-team",
            "name": "Atomic Red Team"
        }
    ]
    
    for repo in repos:
        if repo["path"].exists():
            print(f"✅ {repo['name']} already exists")
            continue
            
        if not run_command(
            f"git clone {repo['url']} {repo['path']}", 
            f"Cloning {repo['name']}"
        ):
            return False
    
    return True

def verify_installation():
    """Verify everything is properly installed"""
    print("🔍 Verifying installation...")
    
    # Check repositories
    required_paths = [
        Path("./cti_data/cti/capec"),
        Path("./cti_data/cti/enterprise-attack"), 
        Path("./cti_data/atomic-red-team/atomics")
    ]
    
    for path in required_paths:
        if not path.exists():
            print(f"❌ Missing: {path}")
            return False
        else:
            print(f"✅ Found: {path}")
    
    # Check Python imports
    try:
        import yaml
        import stix2
        import git
        print("✅ All Python packages imported successfully")
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    
    return True

def main():
    """Main installation function"""
    print("🚀 ENHANCED RAG KNOWLEDGE BASE AUTO-INSTALLER")
    print("=" * 60)
    print("This will install and configure:")
    print("  📊 CAPEC Attack Patterns")
    print("  🎯 MITRE ATT&CK Techniques") 
    print("  ⚡ Atomic Red Team Scripts")
    print("  💾 Enhanced ChromaDB Vector Store")
    
    input("\nPress Enter to continue or Ctrl+C to cancel...")
    
    # Step 1: Install packages
    print(f"\n📦 STEP 1: Installing Python packages...")
    if not install_packages():
        print("❌ Package installation failed")
        return False
    
    # Step 2: Clone repositories
    print(f"\n📥 STEP 2: Cloning knowledge repositories...")
    if not clone_repositories():
        print("❌ Repository cloning failed") 
        return False
    
    # Step 3: Verify installation
    print(f"\n🔍 STEP 3: Verifying installation...")
    if not verify_installation():
        print("❌ Installation verification failed")
        return False
    
    print(f"\n✅ INSTALLATION COMPLETE!")
    print("=" * 40)
    print("🎯 Ready to run enhanced notebooks:")
    print("   1. Run enhanced notebook 03 to build knowledge base")
    print("   2. Run enhanced notebook 05 to generate executable scripts")
    
    # Create quick start script
    quick_start = """#!/bin/bash
# Quick start script for enhanced RAG system

echo "🚀 Starting enhanced RAG system..."
echo "1. Building knowledge base..."
python notebook_03_enhanced.py

echo "2. Testing knowledge base..."
python notebook_04_test.py

echo "3. Generating autonomous attack scripts..."
python notebook_05_enhanced.py

echo "✅ Enhanced autonomous red team agent ready!"
"""
    
    with open("quick_start_enhanced.sh", "w") as f:
        f.write(quick_start)
    
    os.chmod("quick_start_enhanced.sh", 0o755)
    
    print(f"\n🎬 Quick start script created: quick_start_enhanced.sh")
    print(f"Run: ./quick_start_enhanced.sh")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print(f"\n🏆 ENHANCED RAG SYSTEM READY!")
            print(f"Your agent can now generate executable attack scripts!")
        else:
            print(f"\n❌ Installation failed. Please check errors above.")
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n❌ Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
