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
# Step 2: Create VPLE System Information (Based on Official Documentation)
vple_system_info = """
VPLE - Vulnerable Penetration Testing Lab Environment

SYSTEM OVERVIEW:
VPLE is an intentionally vulnerable Linux virtual machine designed for security training and penetration testing practice. 

SYSTEM SPECIFICATIONS:
- Platform: Linux Virtual Machine
- Default Credentials: administrator:password
- Network: Typically 192.168.x.x range (use hostname -I to identify)
- VMware Compatible: Designed for VMware Player/Workstation
- Web Server: Apache with multiple vulnerable applications

ACCESSING VPLE:
1. Login via console: administrator:password
2. Find IP address: hostname -I command
3. Access web applications via browser: http://[IP]:[PORT]/[PATH]

TARGET APPLICATIONS (7 Total):
Each application runs on a specific port and has distinct vulnerabilities.
All applications are pre-installed and start automatically with the VM.

TESTING ENVIRONMENT:
- Safe and legal environment for security testing
- All applications are intentionally vulnerable
- No actual user data at risk
- Designed for learning and skill development

NETWORK CONFIGURATION:
- Single Linux VM with multiple web services
- Standard HTTP ports (80) plus custom ports for each app
- SSH access available (port 22)
- MySQL database backend for several applications
"""

# %%
# Step 3: Create Detailed Application Information
applications_info = """
VPLE APPLICATION DETAILS

1. DVWA (Damn Vulnerable Web Application) - Port 1335
TECHNOLOGY: PHP/MySQL web application
ACCESS: http://[VPLE_IP]:1335/
VULNERABILITY FOCUS: Classic web vulnerabilities in controlled environment
SECURITY LEVELS: Low, Medium, High (adjustable difficulty)
MAIN VULNERABILITIES:
- SQL Injection (various types)
- Cross-Site Scripting (XSS)
- Command Injection
- File Upload vulnerabilities
- Cross-Site Request Forgery (CSRF)
- Insecure file inclusion
LEARNING PURPOSE: Security professionals testing tools and skills

2. MUTILLIDAE II - Port 1336
TECHNOLOGY: PHP/MySQL application
ACCESS: http://[VPLE_IP]:1336/
VULNERABILITY FOCUS: OWASP Top 10 plus additional vulnerabilities
SECURITY LEVELS: 0 (insecure) to 5 (secure)
HINT LEVELS: 0 (no hints) to 2 (maximum hints)
MAIN VULNERABILITIES:
- All OWASP Top 10 vulnerabilities
- HTML-5 web storage issues
- Forms caching vulnerabilities
- Click-jacking attacks
- XML injection
- LDAP injection
SPECIAL FEATURES: Reset DB button to restore original state

3. WEBGOAT - Port 1337
TECHNOLOGY: Java-based web application
ACCESS: http://[VPLE_IP]:1337/WebGoat/
VULNERABILITY FOCUS: Interactive teaching environment
PLATFORM: Apache Tomcat server
MAIN VULNERABILITIES:
- Injection flaws (A1)
- Broken authentication (A2)
- Sensitive data exposure (A3)
- Cross-site scripting (A7)
- Insecure communications
- Parameter tampering
- Session management flaws
LEARNING APPROACH: Lesson-based with guided exercises

4. BWAPP (Buggy Web Application) - Port 8080
TECHNOLOGY: PHP/MySQL application
ACCESS: http://[VPLE_IP]:8080/install.php (first time)
ACCESS: http://[VPLE_IP]:8080/ (after installation)
VULNERABILITY FOCUS: 100+ web vulnerabilities
COVERAGE: All OWASP Top 10 risks plus many more
MAIN VULNERABILITIES:
- All major known web bugs
- Complete OWASP Top 10 coverage
- Session management flaws
- HTTP parameter pollution
- Various injection types
- Authentication bypasses
INSTALLATION: Requires initial setup via install.php

5. JUICE SHOP - Port 3000
TECHNOLOGY: Node.js, Express, Angular (JavaScript)
ACCESS: http://[VPLE_IP]:3000/
VULNERABILITY FOCUS: Modern JavaScript application vulnerabilities
CHALLENGES: Gamified approach with scoreboard
MAIN VULNERABILITIES:
- OWASP Top 10 in modern context
- JWT token manipulation
- NoSQL injection
- XXE (XML External Entity)
- Client-side security bypasses
- REST API vulnerabilities
UNIQUE FEATURES: First all-JavaScript app for security training

6. SECURITY NINJAS - Port 8899
TECHNOLOGY: PHP-based training platform
ACCESS: http://[VPLE_IP]:8899/
VULNERABILITY FOCUS: OWASP Top 10 (2013) training program
TRAINING APPROACH: 10 hands-on exercises with hints and solutions
MAIN VULNERABILITIES:
- Complete OWASP Top 10 coverage
- Real-world like scenarios
- Code review challenges
- Static analysis training
PURPOSE: Developer security awareness training

7. WORDPRESS - Port 8800
TECHNOLOGY: PHP/MySQL Content Management System
ACCESS: http://[VPLE_IP]:8800/
VULNERABILITY FOCUS: CMS-specific vulnerabilities
ADMIN ACCESS: Standard WordPress admin panel
MAIN VULNERABILITIES:
- Plugin vulnerabilities
- Theme vulnerabilities
- Admin panel attacks
- File inclusion vulnerabilities
- User enumeration
- Weak authentication
- Database exposure risks
REAL-WORLD RELEVANCE: Most popular CMS platform globally
"""

# %%
# Step 4: Create MITRE ATT&CK Techniques for Web Applications
mitre_techniques = """
MITRE ATT&CK TECHNIQUES FOR WEB APPLICATION PENETRATION TESTING

INITIAL ACCESS:
T1190 - Exploit Public-Facing Application
DESCRIPTION: Adversaries may attempt to exploit a weakness in an Internet-facing computer or program
WEB APPLICATION CONTEXT: Target vulnerable web applications directly via HTTP/HTTPS
VPLE APPLICABILITY: All 7 applications are public-facing and contain known vulnerabilities
ATTACK VECTORS: SQL injection, XSS, command injection, file upload bypasses

DISCOVERY:
T1083 - File and Directory Discovery
DESCRIPTION: Adversaries may enumerate files and directories or search in specific locations
WEB APPLICATION CONTEXT: Directory traversal, path enumeration, file disclosure
VPLE APPLICABILITY: Discover application structure, configuration files, backup files
TECHNIQUES: Directory brute forcing, path traversal, information disclosure

T1018 - Remote System Discovery
DESCRIPTION: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier
WEB APPLICATION CONTEXT: Network reconnaissance via web interfaces
VPLE APPLICABILITY: Discover network configuration through web applications
TECHNIQUES: Network scanning via web proxies, internal network discovery

T1057 - Process Discovery
DESCRIPTION: Adversaries may attempt to get information about running processes
WEB APPLICATION CONTEXT: Process enumeration via web application vulnerabilities
VPLE APPLICABILITY: Command injection to enumerate system processes
TECHNIQUES: Command injection, system information disclosure

EXECUTION:
T1059.004 - Unix Shell
DESCRIPTION: Adversaries may abuse Unix shell commands and scripts for execution
WEB APPLICATION CONTEXT: Command injection via web parameters
VPLE APPLICABILITY: Linux-based system allows shell command execution
TECHNIQUES: Command injection, web shell upload, parameter manipulation

T1203 - Exploitation for Client Execution
DESCRIPTION: Adversaries may exploit software vulnerabilities in client applications
WEB APPLICATION CONTEXT: Client-side attacks via malicious web content
VPLE APPLICABILITY: XSS, malicious file uploads, client-side template injection
TECHNIQUES: Cross-site scripting, malicious downloads, browser exploitation

PERSISTENCE:
T1505.003 - Web Shell
DESCRIPTION: Adversaries may backdoor web servers with web shells
WEB APPLICATION CONTEXT: Upload malicious scripts for persistent access
VPLE APPLICABILITY: File upload vulnerabilities in multiple applications
TECHNIQUES: PHP web shells, script uploads, backdoor installation

T1543.002 - Systemd Services
DESCRIPTION: Adversaries may create or modify systemd services
WEB APPLICATION CONTEXT: Persistence via system service modification
VPLE APPLICABILITY: Linux system allows service manipulation
TECHNIQUES: Service creation, modification, automatic startup

PRIVILEGE ESCALATION:
T1068 - Exploitation for Privilege Escalation
DESCRIPTION: Adversaries may exploit software vulnerabilities to escalate privileges
WEB APPLICATION CONTEXT: Local privilege escalation from web application context
VPLE APPLICABILITY: Escalate from web user to administrative privileges
TECHNIQUES: Kernel exploits, SUID binaries, configuration weaknesses

CREDENTIAL ACCESS:
T1552.001 - Credentials In Files
DESCRIPTION: Adversaries may search local file systems for stored credentials
WEB APPLICATION CONTEXT: Configuration files containing database credentials
VPLE APPLICABILITY: Application config files, database connection strings
TECHNIQUES: File disclosure, directory traversal, configuration exposure

T1003.008 - /etc/passwd and /etc/shadow
DESCRIPTION: Adversaries may attempt to dump system account databases
WEB APPLICATION CONTEXT: File disclosure vulnerabilities exposing system files
VPLE APPLICABILITY: Linux system files accessible via web vulnerabilities
TECHNIQUES: Local file inclusion, directory traversal, unauthorized file access

COLLECTION:
T1005 - Data from Local System
DESCRIPTION: Adversaries may search local system sources for data of interest
WEB APPLICATION CONTEXT: Database extraction, file system access
VPLE APPLICABILITY: Extract application data, user information, system files
TECHNIQUES: SQL injection, file disclosure, database dumping

T1119 - Automated Collection
DESCRIPTION: Adversaries may use automated techniques to collect internal data
WEB APPLICATION CONTEXT: Automated data extraction via web interfaces
VPLE APPLICABILITY: Automated SQL injection, web scraping, API abuse
TECHNIQUES: Automated tools, scripted attacks, bulk data extraction
"""

# %%
# Step 5: Create Vulnerability Patterns
vulnerability_patterns = """
COMMON VULNERABILITY PATTERNS IN VPLE APPLICATIONS

SQL INJECTION PATTERNS:
- Login bypasses: ' OR '1'='1' --
- Union-based extraction: UNION SELECT version() --
- Blind SQL injection: time-based and boolean-based
- Error-based injection: extracting data through error messages
APPLICATIONS: DVWA, Mutillidae, bWAPP, WordPress

CROSS-SITE SCRIPTING (XSS) PATTERNS:
- Reflected XSS: <script>alert('XSS')</script>
- Stored XSS: persistent payload storage
- DOM-based XSS: client-side JavaScript manipulation
APPLICATIONS: DVWA, Mutillidae, bWAPP, WebGoat

COMMAND INJECTION PATTERNS:
- Direct command execution: ; ls -la
- Command chaining: && whoami
- Output redirection: | cat /etc/passwd
APPLICATIONS: DVWA, Mutillidae, bWAPP

FILE UPLOAD VULNERABILITIES:
- PHP web shell upload: <?php system($_GET['cmd']); ?>
- Bypass filters: double extensions, MIME type manipulation
- Path traversal: ../../../uploads/shell.php
APPLICATIONS: DVWA, bWAPP, WordPress

AUTHENTICATION BYPASSES:
- Weak password policies
- Session management flaws
- JWT token manipulation (Juice Shop)
- Admin panel default credentials
APPLICATIONS: All applications

DIRECTORY TRAVERSAL:
- Path traversal: ../../../etc/passwd
- Null byte injection: file.txt%00.php
- URL encoding: %2e%2e%2f
APPLICATIONS: DVWA, Mutillidae, bWAPP

INFORMATION DISCLOSURE:
- Configuration file exposure
- Database connection strings
- System information leakage
- Error message information
APPLICATIONS: All applications

CLIENT-SIDE VULNERABILITIES:
- HTML5 storage manipulation
- JavaScript-based attacks
- CSRF vulnerabilities
- Click-jacking
APPLICATIONS: Mutillidae, Juice Shop, WebGoat
"""

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
# Step 8: Load and Process Documents
print("Loading and processing knowledge documents...")

# Load documents
loader = DirectoryLoader(
    str(knowledge_dir),
    glob="*.txt",
    loader_cls=TextLoader
)

documents = loader.load()
print(f"✓ Loaded {len(documents)} documents")

# Split documents into chunks
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200,
    length_function=len
)

docs = text_splitter.split_documents(documents)
print(f"✓ Split into {len(docs)} chunks")

# Display sample chunk
print("\nSample knowledge chunk:")
print("-" * 40)
print(docs[0].page_content[:300] + "...")

# %%
# Step 9: Create Vector Store
print("Creating vector embeddings...")

try:
    # Initialize embeddings with the same model
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Create vector store
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory="./vple_chroma_db"
    )
    
    print("✓ Vector store created successfully")
    print(f"✓ Stored {len(docs)} chunks in ChromaDB")
    
    # Test similarity search
    test_query = "web application vulnerabilities"
    similar_docs = vectorstore.similarity_search(test_query, k=3)
    
    print(f"\nTest query: '{test_query}'")
    print(f"Found {len(similar_docs)} similar documents")
    print(f"Top result preview: {similar_docs[0].page_content[:150]}...")
    
except Exception as e:
    print(f"✗ Vector store creation failed: {e}")
    exit(1)

# %%
# Step 10: Update Configuration
config["rag_setup"] = {
    "knowledge_dir": str(knowledge_dir),
    "vector_db": "./vple_chroma_db", 
    "chunks_created": len(docs),
    "setup_timestamp": datetime.now().isoformat()
}

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("RAG Knowledge Base Setup Complete!")
print("=" * 50)
print(f"Knowledge files: {len(knowledge_files)}")
print(f"Document chunks: {len(docs)}")
print(f"Vector database: ./vple_chroma_db")
print("\nNext: Run notebook 04_Test_RAG_System.ipynb")
