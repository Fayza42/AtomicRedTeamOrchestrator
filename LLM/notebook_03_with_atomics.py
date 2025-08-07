# Notebook 3: Enhanced RAG Knowledge Base avec CAPEC + MITRE + ATOMIC RED TEAM

# %% [markdown]
"""
# VPLE Enhanced RAG Knowledge Base

Base de connaissances complète avec:
- CAPEC Attack Patterns (techniques d'attaque)
- MITRE ATT&CK Enterprise (tactiques et techniques)
- ATOMIC RED TEAM (scripts exécutables et tests pratiques)

L'agent aura accès à des milliers de techniques ET aux scripts pour les exécuter !
"""

# %%
# Load configuration and setup
import json
import os
import time
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import yaml
import re

try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    print("✓ Configuration loaded")
    
    if not config.get("model_ready"):
        print("✗ Model not ready. Please run notebook 02 first.")
        exit(1)
        
    model_name = config["confirmed_model"]
    vple_info = config["vple_info"]
    print(f"Using model: {model_name}")
    
except FileNotFoundError:
    print("✗ Configuration not found. Please run previous notebooks first.")
    exit(1)

# %%
# Create enhanced knowledge directory
knowledge_dir = Path("enhanced_knowledge")
knowledge_dir.mkdir(exist_ok=True)
print(f"Creating enhanced knowledge base in: {knowledge_dir}")

# %%
# Install required dependencies for enhanced parsing
required_packages = [
    "PyYAML>=6.0",
    "gitpython>=3.1.0"
]

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

for package in required_packages:
    try:
        install_package(package)
        print(f"✓ Installed: {package}")
    except Exception as e:
        print(f"✗ Failed to install {package}: {e}")

# %%
# Step 1: Download MITRE CTI Data (existing)
print("Setting up MITRE CAPEC and ATT&CK data...")

import stix2

data_dir = Path("./cti_data")
data_dir.mkdir(exist_ok=True)

# Clone MITRE CTI if not exists
cti_repo_path = data_dir / "cti"
if not cti_repo_path.exists():
    print("Cloning MITRE CTI repository...")
    try:
        subprocess.run([
            "git", "clone", "https://github.com/mitre/cti.git", str(cti_repo_path)
        ], check=True, cwd=data_dir)
        print("✓ MITRE CTI repository cloned")
    except subprocess.CalledProcessError as e:
        print(f"✗ Git clone failed: {e}")
        exit(1)
else:
    print("✓ MITRE CTI repository already exists")

# %%
# Step 2: Download Atomic Red Team
print("Setting up Atomic Red Team repository...")

atomics_repo_path = data_dir / "atomic-red-team"
if not atomics_repo_path.exists():
    print("Cloning Atomic Red Team repository...")
    try:
        subprocess.run([
            "git", "clone", "https://github.com/redcanaryco/atomic-red-team.git", 
            str(atomics_repo_path)
        ], check=True, cwd=data_dir)
        print("✓ Atomic Red Team repository cloned")
    except subprocess.CalledProcessError as e:
        print(f"✗ Atomic Red Team clone failed: {e}")
        exit(1)
else:
    print("✓ Atomic Red Team repository already exists")

# Verify atomics directory
atomics_dir = atomics_repo_path / "atomics"
if not atomics_dir.exists():
    print("✗ Atomics directory not found")
    exit(1)
else:
    print("✓ Atomics directory found")

# %%
# Step 3: Load CAPEC and MITRE data (existing functions)
def load_capec_attack_patterns():
    """Load CAPEC attack patterns"""
    capec_dir = cti_repo_path / "capec"
    capec_fs = stix2.FileSystemSource(str(capec_dir), allow_custom=True)
    attack_pattern_filter = stix2.Filter('type', '=', 'attack-pattern')
    attack_patterns = capec_fs.query([attack_pattern_filter])
    print(f"✓ Loaded {len(attack_patterns)} CAPEC attack patterns")
    return attack_patterns

def load_mitre_attack_patterns():
    """Load MITRE ATT&CK patterns"""
    enterprise_attack_dir = cti_repo_path / "enterprise-attack"
    if enterprise_attack_dir.exists():
        mitre_fs = stix2.FileSystemSource(str(enterprise_attack_dir), allow_custom=True)
        attack_pattern_filter = stix2.Filter('type', '=', 'attack-pattern')
        mitre_patterns = mitre_fs.query([attack_pattern_filter])
        print(f"✓ Loaded {len(mitre_patterns)} MITRE ATT&CK techniques")
        return mitre_patterns
    return []

# Load existing data
capec_patterns = load_capec_attack_patterns()
mitre_patterns = load_mitre_attack_patterns()

# %%
# Step 4: Load and Parse Atomic Red Team Tests
print("Loading and parsing Atomic Red Team tests...")

def parse_atomic_test_file(yaml_file_path):
    """Parse individual atomic test YAML file"""
    try:
        with open(yaml_file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'atomic_tests' not in data:
            return None
        
        return data
    except Exception as e:
        print(f"Warning: Could not parse {yaml_file_path}: {e}")
        return None

def load_all_atomic_tests():
    """Load all atomic tests from the repository"""
    atomic_tests = []
    
    # Find all .yaml files in atomics directory
    yaml_files = list(atomics_dir.glob("*/*.yaml"))
    
    print(f"Found {len(yaml_files)} atomic test files")
    
    for yaml_file in yaml_files:
        parsed_data = parse_atomic_test_file(yaml_file)
        
        if parsed_data:
            # Extract technique ID from filename or data
            technique_id = yaml_file.parent.name  # Directory name is usually technique ID
            
            parsed_data['technique_id'] = technique_id
            parsed_data['file_path'] = str(yaml_file)
            
            atomic_tests.append(parsed_data)
    
    print(f"✓ Successfully parsed {len(atomic_tests)} atomic test files")
    return atomic_tests

# Load atomic tests
atomic_tests = load_all_atomic_tests()

# %%
# Step 5: Convert Atomic Tests to RAG Documents
def convert_atomic_to_document(atomic_data):
    """Convert atomic test data to document format"""
    technique_id = atomic_data.get('technique_id', 'Unknown')
    attack_technique = atomic_data.get('attack_technique', technique_id)
    display_name = atomic_data.get('display_name', 'Unknown Technique')
    
    # Build document text
    doc_parts = []
    doc_parts.append(f"ATOMIC RED TEAM TEST: {technique_id}")
    doc_parts.append(f"Display Name: {display_name}")
    doc_parts.append(f"Attack Technique: {attack_technique}")
    doc_parts.append("Type: Atomic Red Team Executable Test")
    
    # Process atomic tests
    if 'atomic_tests' in atomic_data:
        doc_parts.append(f"\nAtomic Tests Available: {len(atomic_data['atomic_tests'])}")
        
        for i, test in enumerate(atomic_data['atomic_tests'][:3], 1):  # Limit to first 3 tests
            test_name = test.get('name', f'Test {i}')
            description = test.get('description', 'No description')
            
            doc_parts.append(f"\nATOMIC TEST {i}: {test_name}")
            doc_parts.append(f"Description: {description[:300]}{'...' if len(description) > 300 else ''}")
            
            # Supported platforms
            if 'supported_platforms' in test:
                platforms = ', '.join(test['supported_platforms'])
                doc_parts.append(f"Supported Platforms: {platforms}")
            
            # Executor information
            if 'executor' in test:
                executor = test['executor']
                executor_name = executor.get('name', 'unknown')
                doc_parts.append(f"Executor: {executor_name}")
                
                # Include command preview
                if 'command' in executor:
                    command = executor['command'][:200] + "..." if len(executor['command']) > 200 else executor['command']
                    doc_parts.append(f"Command Preview: {command}")
            
            # Input arguments
            if 'input_arguments' in test:
                args = test['input_arguments']
                doc_parts.append(f"Input Arguments: {len(args)} parameters")
                
                # Show first few arguments
                for arg_name, arg_info in list(args.items())[:3]:
                    arg_desc = arg_info.get('description', 'No description')
                    arg_default = arg_info.get('default', 'No default')
                    doc_parts.append(f"  - {arg_name}: {arg_desc} (Default: {arg_default})")
    
    return '\n'.join(doc_parts)

print("Converting Atomic Red Team tests to documents...")

atomic_documents = []
for atomic_data in atomic_tests:
    try:
        doc_text = convert_atomic_to_document(atomic_data)
        atomic_documents.append(doc_text)
    except Exception as e:
        print(f"Warning: Error converting atomic test: {e}")

print(f"✓ Created {len(atomic_documents)} Atomic Red Team documents")

# %%
# Step 6: Convert existing CAPEC/MITRE to documents (existing functions)
def extract_capec_info(pattern):
    """Extract CAPEC information (existing function)"""
    capec_id = "Unknown"
    for ref in pattern.get('external_references', []):
        if ref.get('source_name') == 'capec':
            capec_id = ref.get('external_id', 'Unknown')
            break
    
    doc_parts = []
    doc_parts.append(f"CAPEC {capec_id}: {pattern.get('name', 'Unknown')}")
    doc_parts.append(f"Type: CAPEC Attack Pattern")
    
    if pattern.get('description'):
        doc_parts.append(f"Description: {pattern['description']}")
    
    # Additional CAPEC details (simplified for space)
    if pattern.get('x_capec_abstraction'):
        doc_parts.append(f"Abstraction Level: {pattern['x_capec_abstraction']}")
    
    if pattern.get('x_capec_prerequisites'):
        prereqs = '; '.join(pattern['x_capec_prerequisites'][:2])  # Limit
        doc_parts.append(f"Prerequisites: {prereqs}")
    
    return '\n'.join(doc_parts)

def extract_mitre_info(pattern):
    """Extract MITRE information (existing function)"""
    technique_id = "Unknown"
    for ref in pattern.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            technique_id = ref.get('external_id', 'Unknown')
            break
    
    doc_parts = []
    doc_parts.append(f"MITRE {technique_id}: {pattern.get('name', 'Unknown')}")
    doc_parts.append(f"Type: MITRE ATT&CK Technique")
    
    if pattern.get('description'):
        doc_parts.append(f"Description: {pattern['description']}")
    
    if pattern.get('x_mitre_platforms'):
        platforms = ', '.join(pattern['x_mitre_platforms'])
        doc_parts.append(f"Platforms: {platforms}")
    
    return '\n'.join(doc_parts)

# Convert existing patterns
print("Converting CAPEC and MITRE patterns...")

capec_documents = []
for pattern in capec_patterns:
    try:
        doc_text = extract_capec_info(pattern)
        capec_documents.append(doc_text)
    except Exception as e:
        print(f"Warning: Error processing CAPEC pattern: {e}")

mitre_documents = []
for pattern in mitre_patterns:
    try:
        doc_text = extract_mitre_info(pattern)
        mitre_documents.append(doc_text)
    except Exception as e:
        print(f"Warning: Error processing MITRE pattern: {e}")

print(f"✓ CAPEC documents: {len(capec_documents)}")
print(f"✓ MITRE documents: {len(mitre_documents)}")
print(f"✓ Atomic documents: {len(atomic_documents)}")

# %%
# Step 7: Add VPLE system information
vple_system_info = """
VPLE TARGET SYSTEM INFORMATION

SYSTEM OVERVIEW:
VPLE (Vulnerable Penetration Testing Lab Environment) is a Linux-based virtual machine containing multiple intentionally vulnerable web applications for security testing and training.

BASIC SYSTEM SPECS:
- Platform: Linux Virtual Machine
- Default Credentials: administrator:password
- Network: Standard private network configuration
- Access: Web applications accessible via HTTP

AVAILABLE APPLICATIONS:
1. DVWA - Port 1335 (PHP/MySQL web application)
2. Mutillidae II - Port 1336 (PHP/MySQL application)  
3. WebGoat - Port 1337 (Java-based web application)
4. bWAPP - Port 8080 (PHP/MySQL application)
5. Juice Shop - Port 3000 (Node.js/JavaScript application)
6. Security Ninjas - Port 8899 (PHP-based platform)
7. WordPress - Port 8800 (PHP/MySQL CMS)

GENERAL CHARACTERISTICS:
- All applications are intentionally vulnerable for training purposes
- Applications contain various types of security weaknesses
- System designed for penetration testing practice
- Standard Linux web server environment
- Multiple web technologies represented (PHP, Java, Node.js)

ACCESS INFORMATION:
- Applications accessible via web browser
- Standard HTTP protocols
- No specific security controls mentioned
- Training/educational environment
"""

# Combine all documents
all_documents = capec_documents + mitre_documents + atomic_documents + [vple_system_info]

print(f"✓ Total enhanced knowledge base: {len(all_documents)} documents")
print(f"  - CAPEC patterns: {len(capec_documents)}")
print(f"  - MITRE techniques: {len(mitre_documents)}")
print(f"  - Atomic Red Team tests: {len(atomic_documents)}")
print(f"  - VPLE system info: 1")

# %%
# Step 8: Create Enhanced Vector Store with all three knowledge bases
print("Creating enhanced vector store with CAPEC + MITRE + Atomic Red Team...")

# Import RAG components
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings  
from langchain.vectorstores import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

# Convert to LangChain Documents with metadata
langchain_documents = []

for i, content in enumerate(all_documents):
    # Determine document type
    if content.startswith("CAPEC"):
        doc_type = "CAPEC"
        doc_id = content.split('\n')[0].split(':')[0].strip()
    elif content.startswith("MITRE"):
        doc_type = "MITRE"
        doc_id = content.split('\n')[0].split(':')[0].strip()
    elif content.startswith("ATOMIC RED TEAM"):
        doc_type = "ATOMIC"
        doc_id = content.split('\n')[0].replace("ATOMIC RED TEAM TEST:", "").strip()
    elif "VPLE TARGET SYSTEM" in content:
        doc_type = "VPLE"
        doc_id = "VPLE_SYSTEM"
    else:
        doc_type = "OTHER"
        doc_id = f"DOC_{i}"
    
    doc = Document(
        page_content=content,
        metadata={
            "doc_type": doc_type,
            "doc_id": doc_id,
            "source": f"{doc_type.lower()}_enhanced_knowledge_base",
            "index": i,
            "has_scripts": doc_type == "ATOMIC"  # Flag for executable content
        }
    )
    
    langchain_documents.append(doc)

print(f"✓ Created {len(langchain_documents)} enhanced LangChain documents")

# Split documents for embeddings
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1500,  # Larger chunks for atomic tests
    chunk_overlap=200,
    length_function=len,
    separators=["\n\n", "\n", ". ", " ", ""]
)

docs = text_splitter.split_documents(langchain_documents)
print(f"✓ Split into {len(docs)} enhanced chunks for embeddings")

# Document statistics
doc_stats = {}
for doc in docs:
    doc_type = doc.metadata.get("doc_type", "OTHER")
    doc_stats[doc_type] = doc_stats.get(doc_type, 0) + 1

print("Enhanced knowledge base distribution:")
for doc_type, count in doc_stats.items():
    print(f"  {doc_type}: {count} chunks")

# %%
# Step 9: Create Enhanced ChromaDB Vector Store
print(f"Creating enhanced ChromaDB with {len(docs)} total chunks...")

try:
    # Clear previous vector store
    import shutil
    chroma_path = "./enhanced_vple_chroma_db"
    if os.path.exists(chroma_path):
        shutil.rmtree(chroma_path)
        print("✓ Cleared previous enhanced vector store")
    
    # Initialize embeddings
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Test embedding capability
    test_embedding = embeddings.embed_query("test enhanced knowledge base")
    print(f"✓ Embeddings working (dimension: {len(test_embedding)})")
    
    # Create enhanced vector store
    start_time = time.time()
    
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory=chroma_path
    )
    
    creation_time = time.time() - start_time
    
    print(f"✓ Enhanced vector store created successfully!")
    print(f"✓ Creation time: {creation_time/60:.1f} minutes")
    print(f"✓ Total documents: {len(docs)} chunks")
    print(f"✓ Storage location: {chroma_path}")
    
    # Test enhanced vector store
    print(f"\nTesting enhanced vector store...")
    test_queries = [
        "web application SQL injection techniques",
        "atomic red team PowerShell scripts", 
        "CAPEC attack patterns for file upload",
        "MITRE techniques for privilege escalation",
        "executable scripts for VPLE testing"
    ]
    
    for query in test_queries[:3]:  # Test first 3
        search_start = time.time()
        results = vectorstore.similarity_search(query, k=3)
        search_time = time.time() - search_start
        
        print(f"Query: '{query[:40]}...'")
        print(f"  Results: {len(results)}, Time: {search_time:.3f}s")
        
        # Show result types
        result_types = {}
        for doc in results:
            doc_type = doc.metadata.get("doc_type", "unknown")
            result_types[doc_type] = result_types.get(doc_type, 0) + 1
        
        print(f"  Types: {result_types}")
    
    print(f"✓ Enhanced vector store is operational!")
    
except Exception as e:
    print(f"✗ Enhanced vector store creation failed: {e}")
    raise e

# %%
# Step 10: Update Configuration with Enhanced Knowledge Base
enhanced_config = {
    "enhanced_rag_setup": {
        "knowledge_type": "CAPEC + MITRE ATT&CK + Atomic Red Team",
        "capec_patterns": len(capec_patterns),
        "mitre_patterns": len(mitre_patterns), 
        "atomic_tests": len(atomic_tests),
        "total_documents": len(all_documents),
        "total_chunks": len(docs),
        "vector_db": chroma_path,
        "data_sources": [
            "CAPEC via STIX 2.x",
            "MITRE ATT&CK Enterprise", 
            "Atomic Red Team GitHub Repository",
            "VPLE System Information"
        ],
        "capabilities": [
            "Attack pattern knowledge",
            "Technique identification",
            "Executable script generation",
            "Multi-platform support",
            "Complete red team methodology"
        ],
        "approach": "Enhanced autonomous agent with executable capabilities",
        "setup_timestamp": datetime.now().isoformat(),
        "repositories_cloned": [
            str(cti_repo_path),
            str(atomics_repo_path)
        ]
    }
}

config.update(enhanced_config)

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\n🎯 ENHANCED KNOWLEDGE BASE SETUP COMPLETE!")
print("=" * 70)
print(f"📚 CAPEC Attack Patterns: {len(capec_patterns)}")
print(f"🎯 MITRE ATT&CK Techniques: {len(mitre_patterns)}")
print(f"⚡ Atomic Red Team Tests: {len(atomic_tests)}")
print(f"📦 Total Knowledge Documents: {len(all_documents)}")
print(f"🧩 Vector Database Chunks: {len(docs)}")
print(f"💾 Enhanced Vector Store: {chroma_path}")

print(f"\n✅ AGENT NOW HAS ACCESS TO:")
print(f"   🧠 Comprehensive attack knowledge (CAPEC + MITRE)")
print(f"   ⚡ Executable scripts and commands (Atomic Red Team)")
print(f"   🎯 Target system information (VPLE)")
print(f"   🚀 Multi-platform attack capabilities")

print(f"\n🎪 ENHANCED AUTONOMOUS AGENT CAPABILITIES:")
print(f"   ✅ Can identify vulnerabilities (CAPEC/MITRE)")
print(f"   ✅ Can generate executable attack scripts (Atomic)")
print(f"   ✅ Can provide step-by-step commands")
print(f"   ✅ Can support multiple platforms (Windows/Linux)")
print(f"   ✅ Can create complete attack workflows")

print(f"\n🏆 NEXT: Update notebook 05 to use enhanced knowledge base!")
print(f"Your agent will now generate both analysis AND executable scripts!")
