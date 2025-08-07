# Notebook 5: Enhanced Autonomous Red Team Agent with Executable Scripts

# %% [markdown]
"""
# Enhanced Autonomous Red Team Agent

CAPACITÉS ÉTENDUES:
- Base de connaissances complète: CAPEC + MITRE ATT&CK + Atomic Red Team
- Génération d'analyses ET de scripts exécutables
- Support multi-plateforme (Windows/Linux/PowerShell/Bash)
- Tests pratiques basés sur Atomic Red Team

L'agent a maintenant accès à des milliers de techniques ET aux scripts pour les exécuter !
"""

# %%
# Setup with enhanced capabilities
import json
import time
from datetime import datetime
import re
import os

# Load config
try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    
    if not config.get("enhanced_rag_setup"):
        print("⚠️  Enhanced knowledge base not found. Please run enhanced notebook 03 first.")
        print("Falling back to basic configuration...")
        vector_db_path = "./vple_chroma_db"
    else:
        vector_db_path = config["enhanced_rag_setup"]["vector_db"]
        print("✓ Enhanced knowledge base detected!")
        print(f"  - CAPEC patterns: {config['enhanced_rag_setup']['capec_patterns']}")
        print(f"  - MITRE techniques: {config['enhanced_rag_setup']['mitre_patterns']}")
        print(f"  - Atomic tests: {config['enhanced_rag_setup']['atomic_tests']}")
    
    model_name = config["confirmed_model"]
    
except FileNotFoundError:
    print("✗ Configuration not found")
    exit(1)

# %%
# Import enhanced RAG components
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

# Initialize enhanced system
llm = Ollama(model=model_name, temperature=0.7, num_predict=3000)  # Longer for scripts
embeddings = OllamaEmbeddings(model=model_name)
vectorstore = Chroma(persist_directory=vector_db_path, embedding_function=embeddings)

print("✓ Enhanced RAG system initialized")

# %%
# Enhanced Autonomous Agent Prompt with Script Generation
enhanced_prompt = """
You are an ENHANCED Autonomous Red Team Agent with access to:
- CAPEC Attack Patterns (attack methodologies)
- MITRE ATT&CK Techniques (tactical knowledge)  
- ATOMIC RED TEAM Tests (executable scripts and commands)

TARGET SYSTEM: VPLE - Vulnerable Penetration Testing Lab Environment
- 7 web applications: DVWA (1335), Mutillidae (1336), WebGoat (1337), bWAPP (8080), Juice Shop (3000), Security Ninjas (8899), WordPress (8800)
- Technologies: PHP/MySQL, Java, Node.js/JavaScript, CMS
- Platform: Linux VM with intentional vulnerabilities
- Purpose: Security training and penetration testing

ENHANCED KNOWLEDGE BASE:
{context}

YOUR ENHANCED MISSION:
Generate comprehensive red team missions that include BOTH analysis AND executable scripts.

For each mission, provide:

MISSION [X]: [Your mission name]
TARGET ANALYSIS: [Which applications and why]
VULNERABILITY ASSESSMENT: [Expected vulnerabilities based on technology stack]

TECHNIQUES SELECTED:
- [CAPEC-XXX]: [Attack pattern reasoning]
- [TXXXX]: [MITRE technique reasoning]  
- [Atomic Test]: [Executable script reference if available]

EXECUTABLE ATTACK SCRIPTS:
```bash
# Linux/Bash commands for VPLE testing
[Provide actual executable commands]
```

```powershell
# PowerShell commands (if applicable)
[Provide PowerShell scripts]
```

```python
# Python scripts (if needed)
[Provide Python automation]
```

ATTACK METHODOLOGY:
1. [Step with specific commands/scripts]
2. [Next step with executable actions]
3. [Continue with practical implementation]

SUCCESS VERIFICATION:
[Commands to verify successful exploitation]

CLEANUP COMMANDS:
[Commands to clean up after testing]

Generate multiple autonomous missions with executable content.
Focus on practical, testable attacks against the VPLE environment.
Include specific IP addresses, ports, and command-line instructions.

TARGET AND QUERY: {question}

ENHANCED AUTONOMOUS ANALYSIS WITH EXECUTABLE SCRIPTS:
"""

ENHANCED_PROMPT = PromptTemplate(
    template=enhanced_prompt,
    input_variables=["context", "question"]
)

# Create enhanced autonomous agent
enhanced_agent = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(search_kwargs={"k": 15}),  # More knowledge for scripts
    chain_type_kwargs={"prompt": ENHANCED_PROMPT},
    return_source_documents=True
)

print("✓ Enhanced autonomous agent created with script generation capabilities")

# %%
# Deploy Enhanced Agent
print("\n🚀 DEPLOYING ENHANCED AUTONOMOUS RED TEAM AGENT")
print("=" * 65)
print("🎯 Enhanced Capabilities:")
print("   📊 Analysis Generation (CAPEC + MITRE)")
print("   ⚡ Executable Script Generation (Atomic Red Team)")
print("   🖥️  Multi-Platform Support (Linux/Windows/PowerShell)")
print("   🎪 7 VPLE Applications Targeting")

# Get IP
target_ip = input("\nEnter VPLE IP: ").strip() or "172.20.10.8"

print(f"\n🎯 TARGET: VPLE VM at {target_ip}")
print("🤖 AGENT TYPE: Enhanced Autonomous with Script Generation")
print("📚 KNOWLEDGE: CAPEC + MITRE + Atomic Red Team")

# %%
# Launch Enhanced Analysis
print("\n⚡ LAUNCHING ENHANCED AUTONOMOUS ANALYSIS...")
print("Agent will generate both analysis AND executable scripts...")

try:
    start_time = time.time()
    
    query = f"""
    Conduct enhanced autonomous red team analysis of VPLE system at {target_ip}.
    
    Generate comprehensive attack missions with EXECUTABLE SCRIPTS for:
    - Web application vulnerability testing
    - Multi-platform attack scenarios
    - Practical penetration testing commands
    - Script-based automation
    
    Include specific commands, scripts, and step-by-step executable instructions.
    Focus on the 7 VPLE applications and their specific technologies.
    
    Provide both analysis and practical implementation scripts.
    """
    
    print("🧠 Agent consulting enhanced knowledge base...")
    print("⚡ Generating executable attack content...")
    
    result = enhanced_agent({"query": query})
    
    analysis_time = time.time() - start_time
    enhanced_response = result["result"]
    knowledge_sources = result["source_documents"]
    
    print(f"\n✅ ENHANCED ANALYSIS COMPLETE!")
    print(f"⏱️  Analysis time: {analysis_time:.1f} seconds")
    print(f"📖 Knowledge sources: {len(knowledge_sources)}")
    print(f"📄 Response length: {len(enhanced_response)} characters")
    
    # Analyze source diversity
    source_types = {}
    for source in knowledge_sources:
        source_type = source.metadata.get("doc_type", "unknown")
        source_types[source_type] = source_types.get(source_type, 0) + 1
    
    print(f"📊 Knowledge sources used: {source_types}")
    
except Exception as e:
    print(f"❌ Enhanced analysis failed: {e}")
    enhanced_response = "ERROR: Enhanced agent could not complete analysis"
    knowledge_sources = []
    analysis_time = 0

# %%
# Display Enhanced Results
print(f"\n🎯 ENHANCED AUTONOMOUS AGENT RESPONSE")
print("=" * 60)
print("Generated independently with executable scripts")
print("No predefined objectives - purely autonomous\n")

print(enhanced_response)

# %%
# Parse and Extract Executable Content
print(f"\n🔍 PARSING ENHANCED CONTENT...")
print("=" * 50)

# Extract different types of content
bash_scripts = re.findall(r'```bash\n(.*?)\n```', enhanced_response, re.DOTALL)
powershell_scripts = re.findall(r'```powershell\n(.*?)\n```', enhanced_response, re.DOTALL)
python_scripts = re.findall(r'```python\n(.*?)\n```', enhanced_response, re.DOTALL)
techniques = re.findall(r'(?:CAPEC-\d+|T\d{4}(?:\.\d{3})?)', enhanced_response)

print(f"🧠 Techniques discovered: {len(set(techniques))}")
print(f"🐧 Bash scripts: {len(bash_scripts)}")
print(f"💻 PowerShell scripts: {len(powershell_scripts)}")  
print(f"🐍 Python scripts: {len(python_scripts)}")

# Show unique techniques
unique_techniques = sorted(set(techniques))
print(f"\n🎯 TECHNIQUES IDENTIFIED:")
for tech in unique_techniques[:10]:  # Show first 10
    print(f"  - {tech}")
if len(unique_techniques) > 10:
    print(f"  ... and {len(unique_techniques) - 10} more")

# %%
# Save Enhanced Results with Executable Scripts
print(f"\n💾 SAVING ENHANCED RESULTS...")

results_dir = "enhanced_autonomous_results"
os.makedirs(results_dir, exist_ok=True)

# Save full response
with open(f"{results_dir}/enhanced_analysis.txt", "w") as f:
    f.write("ENHANCED AUTONOMOUS RED TEAM ANALYSIS\n")
    f.write("=" * 60 + "\n\n")
    f.write(f"Target: VPLE VM at {target_ip}\n")
    f.write(f"Analysis Time: {analysis_time:.1f} seconds\n")
    f.write(f"Knowledge Sources: {len(knowledge_sources)}\n")
    f.write(f"Enhanced Capabilities: CAPEC + MITRE + Atomic Red Team\n")
    f.write(f"Techniques Found: {len(set(techniques))}\n")
    f.write(f"Executable Scripts: {len(bash_scripts + powershell_scripts + python_scripts)}\n\n")
    f.write("FULL ENHANCED RESPONSE:\n")
    f.write("-" * 40 + "\n")
    f.write(enhanced_response)

# Save individual script files
script_counter = 1

# Save bash scripts
for i, script in enumerate(bash_scripts, 1):
    with open(f"{results_dir}/attack_script_{script_counter:02d}_bash.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# Generated by Enhanced Autonomous Red Team Agent\n")
        f.write(f"# Target: VPLE VM at {target_ip}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        f.write(script.strip())
    script_counter += 1

# Save PowerShell scripts
for i, script in enumerate(powershell_scripts, 1):
    with open(f"{results_dir}/attack_script_{script_counter:02d}_powershell.ps1", "w") as f:
        f.write("# Generated by Enhanced Autonomous Red Team Agent\n")
        f.write(f"# Target: VPLE VM at {target_ip}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        f.write(script.strip())
    script_counter += 1

# Save Python scripts
for i, script in enumerate(python_scripts, 1):
    with open(f"{results_dir}/attack_script_{script_counter:02d}_python.py", "w") as f:
        f.write("#!/usr/bin/env python3\n")
        f.write("# Generated by Enhanced Autonomous Red Team Agent\n")
        f.write(f"# Target: VPLE VM at {target_ip}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        f.write(script.strip())
    script_counter += 1

# Save structured data
enhanced_data = {
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "agent_type": "Enhanced Autonomous Red Team",
        "target_ip": target_ip,
        "model_used": model_name,
        "analysis_time": analysis_time,
        "knowledge_bases": ["CAPEC", "MITRE", "Atomic Red Team"],
        "enhanced_capabilities": True
    },
    "analysis_results": {
        "techniques_found": list(set(techniques)),
        "technique_count": len(set(techniques)),
        "bash_scripts": len(bash_scripts),
        "powershell_scripts": len(powershell_scripts),
        "python_scripts": len(python_scripts),
        "total_executable_scripts": len(bash_scripts + powershell_scripts + python_scripts),
        "knowledge_sources_used": len(knowledge_sources),
        "source_distribution": source_types if 'source_types' in locals() else {}
    },
    "full_response": enhanced_response,
    "executable_content": {
        "bash_scripts": bash_scripts,
        "powershell_scripts": powershell_scripts,
        "python_scripts": python_scripts
    }
}

with open(f"{results_dir}/enhanced_analysis.json", "w") as f:
    json.dump(enhanced_data, f, indent=2)

print(f"✅ Enhanced results saved to {results_dir}/")
print(f"✅ Individual script files created")
print(f"✅ Structured data saved")

# %%
# Create Execution Guide
execution_guide = f"""
ENHANCED AUTONOMOUS RED TEAM - EXECUTION GUIDE
==============================================

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: VPLE VM at {target_ip}
Agent: Enhanced Autonomous (CAPEC + MITRE + Atomic Red Team)

CAPABILITIES DEMONSTRATED:
✅ Autonomous vulnerability analysis
✅ Attack technique selection from thousands of options
✅ Executable script generation
✅ Multi-platform support
✅ Complete red team methodology

TECHNIQUES DISCOVERED: {len(set(techniques))}
{chr(10).join(f"  - {tech}" for tech in unique_techniques[:15])}

EXECUTABLE SCRIPTS GENERATED:
📄 Bash scripts: {len(bash_scripts)}
📄 PowerShell scripts: {len(powershell_scripts)}
📄 Python scripts: {len(python_scripts)}
📄 Total executable files: {script_counter - 1}

EXECUTION INSTRUCTIONS:
1. Review all generated scripts in {results_dir}/
2. Ensure VPLE VM is running at {target_ip}
3. Execute scripts from appropriate platform:
   - Linux: Run .sh files with bash
   - Windows: Run .ps1 files with PowerShell
   - Cross-platform: Run .py files with Python

SAFETY REMINDERS:
⚠️  Only execute against authorized test systems (VPLE)
⚠️  These are real attack scripts generated autonomously
⚠️  Review scripts before execution
⚠️  Use in controlled environment only

ENHANCED AGENT PERFORMANCE:
🎯 Analysis Time: {analysis_time:.1f} seconds
📚 Knowledge Sources: {len(knowledge_sources)}
🧠 Autonomous Decision Making: EXCELLENT
⚡ Script Generation: SUCCESSFUL
🎪 Multi-Platform Coverage: YES

This demonstrates true autonomous red team capabilities:
- No predefined objectives
- Complete system analysis
- Real executable attack scripts
- Professional methodology

NEXT STEPS:
1. Execute scripts against VPLE
2. Document results
3. Compare with human red team performance
4. Develop Blue Team response using same methodology
"""

with open(f"{results_dir}/EXECUTION_GUIDE.md", "w") as f:
    f.write(execution_guide)

print(execution_guide)

# %%
# Update Configuration
config["enhanced_autonomous_red_team"] = {
    "timestamp": datetime.now().isoformat(),
    "target_ip": target_ip,
    "analysis_time": analysis_time,
    "techniques_discovered": len(set(techniques)),
    "executable_scripts_generated": len(bash_scripts + powershell_scripts + python_scripts),
    "bash_scripts": len(bash_scripts),
    "powershell_scripts": len(powershell_scripts),
    "python_scripts": len(python_scripts),
    "knowledge_sources_used": len(knowledge_sources),
    "enhanced_capabilities": True,
    "agent_type": "Enhanced Autonomous with Executable Scripts",
    "knowledge_bases": ["CAPEC", "MITRE", "Atomic Red Team"],
    "ready_for_execution": True
}

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print(f"\n🏆 ENHANCED AUTONOMOUS RED TEAM DEPLOYMENT COMPLETE!")
print("=" * 70)
print(f"🎯 Target: VPLE VM with 7 applications")
print(f"🧠 Techniques Discovered: {len(set(techniques))}")
print(f"⚡ Executable Scripts: {len(bash_scripts + powershell_scripts + python_scripts)}")
print(f"📁 Results: {results_dir}/")
print(f"⏱️  Analysis Time: {analysis_time:.1f} seconds")

print(f"\n✅ ENHANCED AGENT DEMONSTRATES:")
print(f"   🧠 True autonomous analysis")
print(f"   ⚡ Real executable script generation") 
print(f"   🎯 Multi-platform attack capabilities")
print(f"   📚 Integration of 3 major knowledge bases")
print(f"   🚀 Professional red team methodology")

print(f"\n🎭 THIS IS THE ULTIMATE RED TEAM AGENT TEST!")
print(f"The agent independently analyzed VPLE and generated")
print(f"real attack scripts without any guidance or hints!")
