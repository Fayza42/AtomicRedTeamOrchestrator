# Notebook 3: Create RAG Knowledge Base

# %% [markdown]
"""
# VPLE Attack Scenario Generator - RAG Knowledge Base

Ce notebook crée une base de connaissances RAG avec:
- Informations détaillées sur VPLE (basées sur la documentation officielle)
- Techniques MITRE ATT&CK pertinentes pour web applications
- Vulnérabilités connues des 7 applications VPLE
- Contexte pour génération de scénarios d'attaque

IMPORTANT: La base de connaissances ne contient PAS les solutions optimales.
Le LLM doit découvrir les scénarios par lui-même.
"""

# %%
# Load configuration and setup
import json
import os
from pathlib import Path
from datetime import datetime

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
# Step 1: Create Knowledge Directory Structure
knowledge_dir = Path("vple_knowledge")
knowledge_dir.mkdir(exist_ok=True)

print(f"Creating knowledge base in: {knowledge_dir}")

# %%
# Step 2: Install STIX2 Library and Setup CAPEC Data Loading
print("Installing required dependencies for CAPEC/MITRE data loading...")

import subprocess
import sys

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Install STIX2 library if not already installed
try:
    import stix2
    print("✓ STIX2 library already available")
except ImportError:
    print("Installing STIX2 library...")
    install_package("stix2")
    import stix2

# Install additional dependencies
try:
    import requests
    print("✓ Requests library available")
except ImportError:
    install_package("requests")
    import requests

# %%
# Step 3: Download CAPEC and MITRE ATT&CK Data
print("Setting up CAPEC and MITRE ATT&CK data sources...")

import os
import subprocess
from pathlib import Path

# Create data directory
data_dir = Path("./cti_data")
data_dir.mkdir(exist_ok=True)

# Clone MITRE CTI repository if not exists
cti_repo_path = data_dir / "cti"
if not cti_repo_path.exists():
    print("Cloning MITRE CTI repository (this may take a few minutes)...")
    try:
        subprocess.run([
            "git", "clone", "https://github.com/mitre/cti.git", str(cti_repo_path)
        ], check=True, cwd=data_dir)
        print("✓ MITRE CTI repository cloned successfully")
    except subprocess.CalledProcessError as e:
        print(f"✗ Git clone failed: {e}")
        print("Please manually download https://github.com/mitre/cti and extract to ./cti_data/cti/")
        exit(1)
else:
    print("✓ MITRE CTI repository already exists")

# Verify CAPEC data directory exists
capec_dir = cti_repo_path / "capec"
if not capec_dir.exists():
    print("✗ CAPEC directory not found in CTI repository")
    print("Please ensure the repository contains the capec/ directory")
    exit(1)
else:
    print("✓ CAPEC data directory found")

# %%
# Step 4: Load Complete CAPEC Attack Patterns Database
print("Loading complete CAPEC attack patterns database...")

from stix2 import FileSystemSource, Filter

def load_capec_attack_patterns():
    """Load all CAPEC attack patterns from STIX 2.x data"""
    
    # Create filesystem source for CAPEC data
    capec_fs = FileSystemSource(str(capec_dir), allow_custom=True)
    
    # Filter to get all attack patterns
    attack_pattern_filter = Filter('type', '=', 'attack-pattern')
    
    # Query all attack patterns
    print("Querying CAPEC attack patterns...")
    attack_patterns = capec_fs.query([attack_pattern_filter])
    
    print(f"✓ Loaded {len(attack_patterns)} CAPEC attack patterns")
    
    return attack_patterns, capec_fs

def load_mitre_attack_patterns():
    """Load MITRE ATT&CK attack patterns"""
    
    # MITRE ATT&CK data paths
    enterprise_attack_dir = cti_repo_path / "enterprise-attack"
    
    if enterprise_attack_dir.exists():
        print("Loading MITRE ATT&CK Enterprise data...")
        mitre_fs = FileSystemSource(str(enterprise_attack_dir), allow_custom=True)
        
        # Get all attack patterns
        attack_pattern_filter = Filter('type', '=', 'attack-pattern')
        mitre_patterns = mitre_fs.query([attack_pattern_filter])
        
        print(f"✓ Loaded {len(mitre_patterns)} MITRE ATT&CK techniques")
        return mitre_patterns, mitre_fs
    else:
        print("⚠ MITRE ATT&CK Enterprise data not found")
        return [], None

# Load all attack pattern data
capec_patterns, capec_fs = load_capec_attack_patterns()
mitre_patterns, mitre_fs = load_mitre_attack_patterns()

total_patterns = len(capec_patterns) + len(mitre_patterns)
print(f"✓ Total attack patterns loaded: {total_patterns}")

# %%
# Step 5: Convert Attack Patterns to RAG Documents
print("Converting attack patterns to RAG documents...")

def extract_capec_info(pattern):
    """Extract relevant information from CAPEC attack pattern"""
    
    # Get CAPEC ID
    capec_id = "Unknown"
    for ref in pattern.get('external_references', []):
        if ref.get('source_name') == 'capec':
            capec_id = ref.get('external_id', 'Unknown')
            break
    
    # Build comprehensive document text
    doc_parts = []
    
    # Basic info
    doc_parts.append(f"CAPEC {capec_id}: {pattern.get('name', 'Unknown')}")
    doc_parts.append(f"Type: CAPEC Attack Pattern")
    
    # Description
    if pattern.get('description'):
        doc_parts.append(f"Description: {pattern['description']}")
    
    # Extended definition
    if pattern.get('x_capec_extended_definition'):
        doc_parts.append(f"Extended Definition: {pattern['x_capec_extended_definition']}")
    
    # Abstraction level
    if pattern.get('x_capec_abstraction'):
        doc_parts.append(f"Abstraction Level: {pattern['x_capec_abstraction']}")
    
    # Prerequisites
    if pattern.get('x_capec_prerequisites'):
        prereqs = '; '.join(pattern['x_capec_prerequisites'])
        doc_parts.append(f"Prerequisites: {prereqs}")
    
    # Skills required
    if pattern.get('x_capec_skills_required'):
        skills = []
        for skill, level in pattern['x_capec_skills_required'].items():
            skills.append(f"{skill} ({level})")
        doc_parts.append(f"Skills Required: {'; '.join(skills)}")
    
    # Likelihood and severity
    if pattern.get('x_capec_likelihood_of_attack'):
        doc_parts.append(f"Likelihood of Attack: {pattern['x_capec_likelihood_of_attack']}")
    
    if pattern.get('x_capec_typical_severity'):
        doc_parts.append(f"Typical Severity: {pattern['x_capec_typical_severity']}")
    
    # Example instances
    if pattern.get('x_capec_example_instances'):
        for i, example in enumerate(pattern['x_capec_example_instances'][:2], 1):  # Limit to 2 examples
            doc_parts.append(f"Example {i}: {example}")
    
    # Execution flow (simplified)
    if pattern.get('x_capec_execution_flow'):
        # Remove HTML tags for cleaner text
        import re
        clean_flow = re.sub(r'<[^>]+>', '', pattern['x_capec_execution_flow'])
        clean_flow = re.sub(r'\s+', ' ', clean_flow).strip()
        if len(clean_flow) > 500:
            clean_flow = clean_flow[:500] + "..."
        doc_parts.append(f"Execution Flow: {clean_flow}")
    
    # Related weaknesses (CWE)
    cwe_refs = []
    for ref in pattern.get('external_references', []):
        if ref.get('source_name') == 'cwe':
            cwe_refs.append(ref.get('external_id', ''))
    if cwe_refs:
        doc_parts.append(f"Related CWE: {', '.join(cwe_refs)}")
    
    return '\n'.join(doc_parts)

def extract_mitre_info(pattern):
    """Extract relevant information from MITRE ATT&CK pattern"""
    
    # Get technique ID
    technique_id = "Unknown"
    for ref in pattern.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            technique_id = ref.get('external_id', 'Unknown')
            break
    
    # Build document text
    doc_parts = []
    
    doc_parts.append(f"MITRE {technique_id}: {pattern.get('name', 'Unknown')}")
    doc_parts.append(f"Type: MITRE ATT&CK Technique")
    
    if pattern.get('description'):
        doc_parts.append(f"Description: {pattern['description']}")
    
    # Tactics
    if pattern.get('x_mitre_tactics'):
        tactics = [tactic.replace('-', ' ').title() for tactic in pattern['x_mitre_tactics']]
        doc_parts.append(f"Tactics: {', '.join(tactics)}")
    
    # Platforms
    if pattern.get('x_mitre_platforms'):
        platforms = ', '.join(pattern['x_mitre_platforms'])
        doc_parts.append(f"Platforms: {platforms}")
    
    # Data sources
    if pattern.get('x_mitre_data_sources'):
        data_sources = ', '.join(pattern['x_mitre_data_sources'])
        doc_parts.append(f"Data Sources: {data_sources}")
    
    return '\n'.join(doc_parts)

# Convert all patterns to documents
documents_content = []

print("Processing CAPEC attack patterns...")
for i, pattern in enumerate(capec_patterns):
    try:
        doc_text = extract_capec_info(pattern)
        documents_content.append(doc_text)
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(capec_patterns)} CAPEC patterns")
    except Exception as e:
        print(f"  Warning: Error processing CAPEC pattern {i}: {e}")

print("Processing MITRE ATT&CK patterns...")
for i, pattern in enumerate(mitre_patterns):
    try:
        doc_text = extract_mitre_info(pattern)
        documents_content.append(doc_text)
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(mitre_patterns)} MITRE patterns")
    except Exception as e:
        print(f"  Warning: Error processing MITRE pattern {i}: {e}")

print(f"✓ Total documents created: {len(documents_content)}")

# %%
# Step 6: Add VPLE Target Information (Minimal and Unbiased)
print("Adding minimal VPLE target system information...")

# Minimal VPLE system information (not biased toward specific techniques)
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

# Add VPLE info to documents
documents_content.append(vple_system_info)

print(f"✓ Added VPLE target information")
print(f"✓ Final document count: {len(documents_content)}")

# Optional: Save complete knowledge base for reference
try:
    with open("complete_attack_knowledge.txt", 'w', encoding='utf-8') as f:
        f.write('\n\n' + '='*80 + '\n\n'.join(documents_content))
    print("✓ Complete knowledge base saved to complete_attack_knowledge.txt")
except Exception as e:
    print(f"⚠ Could not save knowledge base file: {e}")


# %%
# Step 6: Write Knowledge Files
knowledge_files = {
    "vple_system.txt": vple_system_info,
    "vple_applications.txt": applications_info,
    "mitre_techniques.txt": mitre_techniques,
    "vulnerability_patterns.txt": vulnerability_patterns
}

for filename, content in knowledge_files.items():
    file_path = knowledge_dir / filename
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content.strip())
    print(f"✓ Created: {filename}")

print(f"\n✓ Knowledge base created with {len(knowledge_files)} files")

# %%
# Step 7: Setup RAG System Components
print("Setting up RAG system components...")

try:
    from langchain.llms import Ollama
    from langchain.embeddings import OllamaEmbeddings  
    from langchain.vectorstores import Chroma
    from langchain.document_loaders import DirectoryLoader, TextLoader
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate
    
    print("✓ All RAG components imported successfully")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    print("Please ensure all dependencies are installed from notebook 01")
    exit(1)

# %%
# Step 7: Process Documents for RAG System
print("Processing complete CAPEC/MITRE knowledge base for RAG system...")

from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Convert text content to LangChain Documents
langchain_documents = []

for i, content in enumerate(documents_content):
    # Create metadata for each document
    if content.startswith("CAPEC"):
        doc_type = "CAPEC"
        # Extract CAPEC ID from first line
        first_line = content.split('\n')[0]
        doc_id = first_line.split(':')[0].strip() if ':' in first_line else f"CAPEC_{i}"
    elif content.startswith("MITRE"):
        doc_type = "MITRE"
        # Extract MITRE ID from first line
        first_line = content.split('\n')[0]
        doc_id = first_line.split(':')[0].strip() if ':' in first_line else f"MITRE_{i}"
    elif "VPLE TARGET SYSTEM" in content:
        doc_type = "VPLE"
        doc_id = "VPLE_SYSTEM"
    else:
        doc_type = "OTHER"
        doc_id = f"DOC_{i}"
    
    # Create LangChain document with metadata
    doc = Document(
        page_content=content,
        metadata={
            "doc_type": doc_type,
            "doc_id": doc_id,
            "source": f"{doc_type.lower()}_knowledge_base",
            "index": i
        }
    )
    
    langchain_documents.append(doc)

print(f"✓ Created {len(langchain_documents)} LangChain documents")

# Split documents into appropriate chunks for embeddings
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1200,  # Slightly larger chunks for complex attack patterns
    chunk_overlap=300,  # More overlap to preserve context
    length_function=len,
    separators=["\n\n", "\n", ". ", " ", ""]
)

docs = text_splitter.split_documents(langchain_documents)
print(f"✓ Split into {len(docs)} chunks for embeddings")

# Display sample chunks
print("\nSample knowledge chunks:")
print("-" * 50)

# Show CAPEC sample
capec_chunks = [d for d in docs if d.metadata.get("doc_type") == "CAPEC"]
if capec_chunks:
    print("CAPEC Sample:")
    print(capec_chunks[0].page_content[:300] + "...")
    print()

# Show MITRE sample  
mitre_chunks = [d for d in docs if d.metadata.get("doc_type") == "MITRE"]
if mitre_chunks:
    print("MITRE Sample:")
    print(mitre_chunks[0].page_content[:300] + "...")
    print()

# Show statistics
doc_types = {}
for doc in docs:
    doc_type = doc.metadata.get("doc_type", "OTHER")
    doc_types[doc_type] = doc_types.get(doc_type, 0) + 1

print("Document chunk distribution:")
for doc_type, count in doc_types.items():
    print(f"  {doc_type}: {count} chunks")

print(f"\n✓ Total chunks ready for embeddings: {len(docs)}")

# %%
# Step 8: Create Vector Store with Complete Knowledge Base
print("Creating vector store with complete CAPEC/MITRE knowledge...")

try:
    # Initialize embeddings with the same model
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Create vector store directly from our processed documents
    vectorstore = Chroma.from_documents(
        documents=docs,  # Use the docs we created in Step 7
        embedding=embeddings,
        persist_directory="./vple_chroma_db"
    )
    
    print("✓ Vector store created successfully")
    print(f"✓ Stored {len(docs)} chunks in ChromaDB")
    
    # Test similarity search with Red Team queries
    test_queries = [
        "web application attack patterns",
        "SQL injection techniques", 
        "command execution methods",
        "privilege escalation attacks"
    ]
    
    print("\nTesting vector search with Red Team queries:")
    for query in test_queries:
        similar_docs = vectorstore.similarity_search(query, k=3)
        doc_types = [doc.metadata.get("doc_type", "unknown") for doc in similar_docs]
        print(f"  '{query}': Found {len(similar_docs)} docs, types: {set(doc_types)}")
    
except Exception as e:
    print(f"✗ Vector store creation failed: {e}")
    print("Check that Ollama is running and the model is available")
    exit(1)

# %%
# Step 9: Update Configuration with Complete Knowledge Base
config["rag_setup"] = {
    "knowledge_type": "Complete CAPEC + MITRE ATT&CK Database",
    "capec_patterns": len(capec_patterns),
    "mitre_patterns": len(mitre_patterns), 
    "total_attack_patterns": len(capec_patterns) + len(mitre_patterns),
    "vector_db": "./vple_chroma_db", 
    "chunks_created": len(docs),
    "data_sources": ["CAPEC via STIX 2.x", "MITRE ATT&CK Enterprise", "VPLE System Info"],
    "approach": "Unbiased complete database - Red Team Agent must choose techniques autonomously",
    "setup_timestamp": datetime.now().isoformat()
}


