# Notebook 2: Download and Setup LLaMA Model

# %% [markdown]
"""
# VPLE Attack Scenario Generator - Model Download

Ce notebook télécharge et configure le modèle LLaMA optimal pour votre GPU.
Le téléchargement peut prendre 15-30 minutes selon votre connexion.

## Modèles Disponibles:
- llama2:7b (~4GB) - Rapide, pour GPU 8GB+
- llama2:13b (~7GB) - Recommandé pour RTX 4090
- codellama:13b (~7GB) - Optimisé pour code/technique

## Estimations de Téléchargement:
- 100 Mbps: ~10-15 minutes
- 50 Mbps: ~20-30 minutes  
- 25 Mbps: ~40-60 minutes
"""

# %%
# Load configuration from previous notebook
import json
import subprocess
import time
import requests
from datetime import datetime

try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    print("✓ Configuration loaded")
    recommended_model = config["recommended_model"]
    print(f"Recommended model: {recommended_model}")
except FileNotFoundError:
    print("✗ Configuration not found. Please run notebook 01 first.")
    exit(1)

# %%
# Step 1: Check Current GPU Usage
print("Current GPU Status:")
print("=" * 40)

try:
    gpu_result = subprocess.run(["nvidia-smi", "--query-gpu=memory.used,memory.total", 
                               "--format=csv,noheader,nounits"], 
                              capture_output=True, text=True)
    if gpu_result.returncode == 0:
        memory_info = gpu_result.stdout.strip().split(',')
        used_mb = int(memory_info[0])
        total_mb = int(memory_info[1])
        free_mb = total_mb - used_mb
        
        print(f"Used VRAM: {used_mb}MB")
        print(f"Free VRAM: {free_mb}MB") 
        print(f"Total VRAM: {total_mb}MB")
        
        # Model size estimates
        model_sizes = {
            "llama2:7b": 4000,
            "llama2:13b": 7000, 
            "codellama:13b": 7000
        }
        
        model_size = model_sizes.get(recommended_model, 4000)
        if free_mb >= model_size + 2000:  # 2GB overhead
            print(f"✓ Sufficient VRAM for {recommended_model}")
        else:
            print(f"⚠ Tight VRAM for {recommended_model}")
            if total_mb >= 10000:
                recommended_model = "llama2:7b"
                print(f"Switching to smaller model: {recommended_model}")
    else:
        print("⚠ Could not check GPU status")
except:
    print("⚠ GPU monitoring unavailable")

# %%
# Step 2: Check if Model Already Exists
print("Checking existing models...")

try:
    result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
    if result.returncode == 0:
        existing_models = result.stdout
        print("Existing models:")
        print(existing_models)
        
        if recommended_model in existing_models:
            print(f"✓ Model {recommended_model} already exists")
            model_exists = True
        else:
            print(f"Model {recommended_model} not found - will download")
            model_exists = False
    else:
        print("⚠ Could not check existing models")
        model_exists = False
except:
    print("⚠ Ollama command failed")
    model_exists = False

# %%
# Step 3: Download Model (if needed)
if not model_exists:
    print(f"Downloading {recommended_model}...")
    print("=" * 50)
    print("This will take 15-30 minutes depending on your connection.")
    print("Please be patient and do not interrupt the process.")
    print("")
    
    start_time = time.time()
    
    try:
        # Use Popen for real-time output
        import subprocess
        process = subprocess.Popen(
            ["ollama", "pull", recommended_model],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(line.strip())
        
        process.wait()
        
        if process.returncode == 0:
            download_time = time.time() - start_time
            print(f"✓ Model downloaded successfully in {download_time/60:.1f} minutes")
        else:
            print("✗ Model download failed")
            exit(1)
            
    except Exception as e:
        print(f"✗ Download error: {e}")
        exit(1)
else:
    print("✓ Model already available, skipping download")

# %%
# Step 4: Test Model
print("Testing model...")
print("=" * 30)

test_prompt = "What is cybersecurity penetration testing?"

try:
    start_time = time.time()
    
    result = subprocess.run([
        "ollama", "run", recommended_model, test_prompt
    ], capture_output=True, text=True, timeout=60)
    
    response_time = time.time() - start_time
    
    if result.returncode == 0 and len(result.stdout) > 50:
        print("✓ Model test successful")
        print(f"Response time: {response_time:.1f} seconds")
        print(f"Response preview: {result.stdout[:200]}...")
        
        # Estimate tokens per second
        estimated_tokens = len(result.stdout.split())
        tokens_per_sec = estimated_tokens / response_time
        print(f"Estimated speed: {tokens_per_sec:.1f} tokens/second")
        
    else:
        print("⚠ Model test unclear")
        print(f"Return code: {result.returncode}")
        print(f"Output: {result.stdout[:100]}")

except subprocess.TimeoutExpired:
    print("⚠ Model test timed out - may still be loading")
except Exception as e:
    print(f"⚠ Model test error: {e}")

# %%
# Step 5: Check Final GPU Usage
print("Final GPU Status:")
print("=" * 35)

try:
    gpu_result = subprocess.run(["nvidia-smi", "--query-gpu=memory.used,memory.total", 
                               "--format=csv,noheader,nounits"], 
                              capture_output=True, text=True)
    if gpu_result.returncode == 0:
        memory_info = gpu_result.stdout.strip().split(',')
        used_mb = int(memory_info[0])
        total_mb = int(memory_info[1])
        usage_pct = (used_mb / total_mb) * 100
        
        print(f"VRAM Usage: {used_mb}MB / {total_mb}MB ({usage_pct:.1f}%)")
        
        if usage_pct > 90:
            print("⚠ High VRAM usage - monitor during RAG setup")
        elif usage_pct > 70:
            print("✓ Moderate VRAM usage - should be fine")
        else:
            print("✓ Low VRAM usage - plenty of headroom")
except:
    print("⚠ Could not check final GPU status")

# %%
# Update configuration with confirmed model
config["confirmed_model"] = recommended_model
config["model_ready"] = True
config["setup_timestamp"] = datetime.now().isoformat()

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("Model Setup Complete!")
print("=" * 40)
print(f"Model ready: {recommended_model}")
print("Next: Run notebook 03_Create_RAG_Knowledge.ipynb")
