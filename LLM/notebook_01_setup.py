# Notebook 1: Setup Dependencies and Ollama Installation

# %% [markdown]
"""
# VPLE Attack Scenario Generator - Setup Phase

Ce notebook configure l'environnement complet pour générer des scénarios d'attaque 
contre la machine VPLE en utilisant LLaMA + RAG.

## Architecture du Système:
- Container avec GPU RTX 4090
- Ollama + LLaMA 13B pour génération de scénarios
- RAG avec base de connaissances VPLE + MITRE ATT&CK
- Output: Scénarios d'attaque à exécuter manuellement

## VPLE Target Info:
- IP: Variable (hostname -I sur la VM)
- Login: administrator:password  
- Applications: DVWA, Mutillidae, WebGoat, bWAPP, Juice Shop, Security Ninjas, WordPress
- Platform: Linux VM
"""

# %%
# Step 1: Install Required Dependencies
import subprocess
import sys
import os
from pathlib import Path

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Core dependencies for LLM and RAG
required_packages = [
    "langchain>=0.0.350",
    "chromadb>=0.4.15", 
    "ollama>=0.1.7",
    "requests>=2.31.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
    "matplotlib>=3.7.0",
    "seaborn>=0.12.0",
    "sentence-transformers>=2.2.0",
    "tiktoken>=0.5.0"
]

print("Installing required packages...")
for package in required_packages:
    try:
        install_package(package)
        print(f"✓ Installed: {package}")
    except Exception as e:
        print(f"✗ Failed to install {package}: {e}")

print("\nPackage installation complete!")

# %%
# Step 2: Verify GPU and System
print("System Verification:")
print("=" * 50)

# Check GPU
try:
    gpu_result = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,memory.used", 
                               "--format=csv,noheader,nounits"], 
                              capture_output=True, text=True)
    if gpu_result.returncode == 0:
        gpu_info = gpu_result.stdout.strip().split(',')
        print(f"GPU: {gpu_info[0].strip()}")
        print(f"Total VRAM: {gpu_info[1].strip()}MB")
        print(f"Used VRAM: {gpu_info[2].strip()}MB")
        
        total_vram = int(gpu_info[1].strip())
        if total_vram >= 20000:  # 20GB+
            print("✓ GPU suitable for LLaMA 13B")
            recommended_model = "llama2:13b"
        elif total_vram >= 10000:  # 10GB+
            print("✓ GPU suitable for LLaMA 7B")
            recommended_model = "llama2:7b"
        else:
            print("⚠ Limited VRAM - using smallest model")
            recommended_model = "llama2:7b"
    else:
        print("⚠ Could not detect GPU")
        recommended_model = "llama2:7b"
except:
    print("⚠ nvidia-smi not available")
    recommended_model = "llama2:7b"

print(f"Recommended model: {recommended_model}")

# Save config for other notebooks
config = {
    "recommended_model": recommended_model,
    "vple_info": {
        "default_ip": "192.168.255.143",  # From VPLE docs
        "login": "administrator:password",
        "applications": {
            "dvwa": {"port": 1335, "path": "/"},
            "mutillidae": {"port": 1336, "path": "/"},
            "webgoat": {"port": 1337, "path": "/WebGoat/"},
            "bwapp": {"port": 8080, "path": "/install.php"},
            "juice_shop": {"port": 3000, "path": "/"},
            "security_ninjas": {"port": 8899, "path": "/"},
            "wordpress": {"port": 8800, "path": "/"}
        },
        "platform": "linux",
        "description": "VPLE - Vulnerable Penetration Testing Lab Environment with 7 web applications"
    }
}

import json
with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("✓ Configuration saved to vple_config.json")

# %%
# Step 3: Install Ollama
print("Installing Ollama...")
print("=" * 30)

try:
    # Check if Ollama is already installed
    result = subprocess.run(["ollama", "--version"], capture_output=True, text=True)
    if result.returncode == 0:
        print("✓ Ollama already installed")
        print(f"Version: {result.stdout.strip()}")
    else:
        raise FileNotFoundError
except FileNotFoundError:
    print("Installing Ollama...")
    
    # Download and install Ollama
    install_script = """
    curl -fsSL https://ollama.ai/install.sh | sh
    """
    
    result = subprocess.run(install_script, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✓ Ollama installed successfully")
    else:
        print(f"✗ Ollama installation failed: {result.stderr}")
        exit(1)

# %%
# Step 4: Start Ollama Service
print("Starting Ollama service...")

# Kill any existing Ollama processes
subprocess.run(["pkill", "-f", "ollama"], capture_output=True)

# Start Ollama server in background
import time
import threading

def start_ollama_server():
    subprocess.run(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Start server in background thread
server_thread = threading.Thread(target=start_ollama_server, daemon=True)
server_thread.start()

# Wait for server to start
time.sleep(10)

# Test connection
try:
    import requests
    response = requests.get("http://localhost:11434/api/version", timeout=5)
    if response.status_code == 200:
        print("✓ Ollama server started successfully")
        version_info = response.json()
        print(f"Ollama version: {version_info.get('version', 'unknown')}")
    else:
        print("⚠ Ollama server status unclear")
except:
    print("⚠ Could not verify Ollama server status")

print("\nSetup Phase Complete!")
print("=" * 50)
print("Next: Run notebook 02_Download_Model.ipynb")
