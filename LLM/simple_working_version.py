# VERSION SIMPLE QUI MARCHE - Pas de variables compliquées

# %%
# Setup simple
import json
import time
from datetime import datetime
import re

# Load config
with open("vple_config.json", "r") as f:
    config = json.load(f)
model_name = config["confirmed_model"]

# %%
# Import RAG
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

# Initialize
llm = Ollama(model=model_name, temperature=0.8, num_predict=2000)
embeddings = OllamaEmbeddings(model=model_name)
vectorstore = Chroma(persist_directory="./vple_chroma_db", embedding_function=embeddings)

print("✓ RAG system ready")

# %%
# Prompt SIMPLE - seulement context et question
simple_prompt = """
You are an autonomous Red Team Agent. 

TARGET SYSTEM: VPLE - Vulnerable Penetration Testing Lab Environment
- 7 web applications on different ports
- DVWA (PHP/MySQL) on port 1335 - deliberately vulnerable
- Mutillidae (PHP/MySQL) on port 1336 - OWASP Top 10 vulnerabilities  
- WebGoat (Java) on port 1337 - web app security training
- bWAPP (PHP/MySQL) on port 8080 - 100+ web vulnerabilities
- Juice Shop (Node.js) on port 3000 - modern insecure app
- Security Ninjas (PHP) on port 8899 - OWASP Top 10 training
- WordPress (PHP/MySQL) on port 8800 - popular CMS

KNOWLEDGE BASE:
{context}

MISSION: Analyze the target and generate autonomous attack missions. Use your CAPEC/MITRE knowledge to identify appropriate techniques for each application type.

TARGET IP and ANALYSIS REQUEST:
{question}

Generate multiple attack missions with:
- Mission name
- Target applications  
- CAPEC/MITRE techniques
- Attack methodology
- Success criteria

AUTONOMOUS ANALYSIS:
"""

SIMPLE_PROMPT = PromptTemplate(
    template=simple_prompt,
    input_variables=["context", "question"]
)

# Create agent
agent = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(search_kwargs={"k": 10}),
    chain_type_kwargs={"prompt": SIMPLE_PROMPT},
    return_source_documents=True
)

print("✓ Simple autonomous agent created")

# %%
# Deploy agent
print("\nDEPLOYING SIMPLE AUTONOMOUS AGENT")
print("=" * 50)

# Get IP
target_ip = input("Enter VPLE IP: ").strip() or "172.20.10.8"

print(f"Target: {target_ip}")
print("Launching autonomous analysis...")

# %%
# Run analysis
try:
    start_time = time.time()
    
    # Simple query - everything in the question
    query = f"""
    Conduct autonomous red team analysis of VPLE system at {target_ip}.
    
    Generate independent attack missions for this vulnerable environment.
    The system has 7 web applications with different technologies.
    
    Create comprehensive attack plans using CAPEC and MITRE ATT&CK techniques.
    """
    
    result = agent({"query": query})
    
    analysis_time = time.time() - start_time
    response = result["result"]
    sources = result["source_documents"]
    
    print(f"\n✅ SUCCESS!")
    print(f"Time: {analysis_time:.1f}s")
    print(f"Sources: {len(sources)}")
    print(f"Response: {len(response)} chars")
    
    print(f"\n🎯 AUTONOMOUS AGENT RESPONSE:")
    print("=" * 50)
    print(response)
    
    # Extract techniques
    techniques = re.findall(r'(?:CAPEC-\d+|T\d{4}(?:\.\d{3})?)', response)
    print(f"\n🧠 TECHNIQUES DISCOVERED: {len(set(techniques))}")
    for tech in sorted(set(techniques))[:10]:
        print(f"  - {tech}")
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "target_ip": target_ip,
        "analysis_time": analysis_time,
        "techniques_found": list(set(techniques)),
        "full_response": response,
        "agent_type": "Simple Autonomous"
    }
    
    with open("simple_autonomous_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    with open("simple_autonomous_results.txt", "w") as f:
        f.write(f"SIMPLE AUTONOMOUS RED TEAM ANALYSIS\n")
        f.write(f"Target: {target_ip}\n")
        f.write(f"Time: {analysis_time:.1f}s\n")
        f.write(f"Techniques: {len(set(techniques))}\n\n")
        f.write(response)
    
    print(f"\n✅ Results saved!")
    print(f"✅ Agent generated {len(set(techniques))} unique techniques")
    print(f"✅ Analysis completed in {analysis_time:.1f} seconds")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print(f"Error details: {type(e).__name__}")
    
    # Debug info
    print(f"\nDEBUG INFO:")
    print(f"Model: {model_name}")
    print(f"Vector store: {'OK' if vectorstore else 'ERROR'}")
    print(f"Query length: {len(query) if 'query' in locals() else 'undefined'}")

print(f"\n🏆 SIMPLE VERSION COMPLETE!")
print(f"This version avoids complex variable passing")
print(f"and focuses on autonomous capability testing")
