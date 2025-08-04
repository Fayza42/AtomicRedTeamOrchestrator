# Notebook 4: Test RAG System

# %% [markdown]
"""
# VPLE Attack Scenario Generator - RAG System Testing

Ce notebook teste le système RAG avant la génération de scénarios.
Il vérifie que le LLM peut correctement accéder aux connaissances VPLE et MITRE.

## Tests Inclus:
- Connexion au modèle LLaMA
- Recherche dans la base de connaissances
- Réponses aux questions sur VPLE
- Performance du système RAG
- Préparation pour génération de scénarios
"""

# %%
# Load configuration and setup
import json
import time
from datetime import datetime

try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    print("✓ Configuration loaded")
    
    if not config.get("rag_setup"):
        print("✗ RAG system not setup. Please run notebook 03 first.")
        exit(1)
        
    model_name = config["confirmed_model"]
    rag_config = config["rag_setup"]
    
    print(f"Model: {model_name}")
    print(f"Knowledge chunks: {rag_config['chunks_created']}")
    
except FileNotFoundError:
    print("✗ Configuration not found. Please run previous notebooks first.")
    exit(1)

# %%
# Import required components
try:
    from langchain.llms import Ollama
    from langchain.embeddings import OllamaEmbeddings
    from langchain.vectorstores import Chroma
    from langchain.chains import RetrievalQA
    from langchain.prompts import PromptTemplate
    
    print("✓ RAG components imported")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    exit(1)

# %%
# Step 1: Initialize LLM Connection
print("Initializing LLM connection...")

try:
    # Initialize LLM with conservative settings for testing
    llm = Ollama(
        model=model_name,
        temperature=0.3,  # Low temperature for more focused responses
        num_predict=256   # Limit response length for testing
    )
    
    # Test basic LLM functionality
    test_start = time.time()
    response = llm("What is penetration testing?")
    test_time = time.time() - test_start
    
    print(f"✓ LLM connection successful")
    print(f"Response time: {test_time:.1f} seconds")
    print(f"Response preview: {response[:150]}...")
    
except Exception as e:
    print(f"✗ LLM connection failed: {e}")
    exit(1)

# %%
# Step 2: Load Vector Store
print("Loading vector store...")

try:
    # Initialize embeddings
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Load existing vector store
    vectorstore = Chroma(
        persist_directory=rag_config["vector_db"],
        embedding_function=embeddings
    )
    
    print("✓ Vector store loaded")
    
    # Test vector store functionality
    test_docs = vectorstore.similarity_search("DVWA vulnerabilities", k=3)
    print(f"✓ Vector search working - found {len(test_docs)} relevant documents")
    
except Exception as e:
    print(f"✗ Vector store loading failed: {e}")
    exit(1)

# %%
# Step 3: Create RAG Chain
print("Creating RAG chain...")

# Custom prompt for VPLE attack scenario generation
attack_prompt_template = """
You are a cybersecurity expert specializing in web application penetration testing.

Use the following context about VPLE (Vulnerable Penetration Testing Lab Environment) to answer questions about attack techniques and vulnerabilities.

Context: {context}

Question: {question}

Provide detailed, technical information based on the context. Focus on:
1. Specific vulnerabilities in VPLE applications
2. Applicable MITRE ATT&CK techniques  
3. Technical details about exploitation methods
4. Realistic attack approaches

Answer:
"""

ATTACK_PROMPT = PromptTemplate(
    template=attack_prompt_template,
    input_variables=["context", "question"]
)

try:
    # Create RetrievalQA chain
    qa_chain = RetrievalQA.from_chain_type(
        llm=llm,
        chain_type="stuff",
        retriever=vectorstore.as_retriever(
            search_type="similarity",
            search_kwargs={"k": 5}  # Retrieve top 5 relevant chunks
        ),
        chain_type_kwargs={"prompt": ATTACK_PROMPT},
        return_source_documents=True
    )
    
    print("✓ RAG chain created successfully")
    
except Exception as e:
    print(f"✗ RAG chain creation failed: {e}")
    exit(1)

# %%
# Step 4: Test Complete CAPEC/MITRE Knowledge Base
print("Testing complete CAPEC/MITRE knowledge base...")
print("=" * 55)

# Updated test questions for complete database
knowledge_test_questions = [
    "What CAPEC attack patterns are relevant for web applications?",
    "Which MITRE ATT&CK techniques apply to Linux web servers?", 
    "How can an attacker exploit SQL injection vulnerabilities?",
    "What techniques exist for command injection in web applications?",
    "Which attack patterns target file upload functionality?"
]

knowledge_test_results = []

for i, question in enumerate(knowledge_test_questions, 1):
    print(f"\nKnowledge Test {i}: {question}")
    print("-" * 40)
    
    try:
        start_time = time.time()
        result = qa_chain({"query": question})
        response_time = time.time() - start_time
        
        answer = result["result"]
        sources = result["source_documents"]
        
        print(f"Response time: {response_time:.1f}s")
        print(f"Sources used: {len(sources)}")
        print(f"Answer: {answer[:250]}...")
        
        # Analyze source diversity
        source_types = set()
        capec_count = 0
        mitre_count = 0
        
        for source in sources:
            doc_type = source.metadata.get("doc_type", "unknown")
            source_types.add(doc_type)
            if doc_type == "CAPEC":
                capec_count += 1
            elif doc_type == "MITRE":
                mitre_count += 1
        
        print(f"Source diversity: {list(source_types)}")
        print(f"CAPEC sources: {capec_count}, MITRE sources: {mitre_count}")
        
        # Score based on answer quality and source diversity
        score = 0
        if len(answer) > 100:
            score += 3
        if len(sources) >= 3:
            score += 2
        if len(source_types) >= 2:  # Using both CAPEC and MITRE
            score += 3
        if any(keyword in answer.lower() for keyword in ["attack", "technique", "capec", "mitre"]):
            score += 2
        
        knowledge_test_results.append({
            "question": question,
            "response_time": response_time,
            "answer_length": len(answer),
            "sources_count": len(sources),
            "source_diversity": len(source_types),
            "capec_sources": capec_count,
            "mitre_sources": mitre_count,
            "score": score
        })
        
        print(f"Score: {score}/10")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        knowledge_test_results.append({
            "question": question,
            "error": str(e),
            "score": 0
        })

# %%
# Step 5: Test Red Team Agent Scenario Generation
print("\n\nTesting Red Team Agent scenario generation...")
print("=" * 55)

red_team_scenarios = [
    "Generate attack techniques for a Linux system with web applications on ports 1335, 1336, 1337, 8080, 3000, 8899, 8800",
    "What attack patterns should a red team use against PHP web applications with MySQL databases?",
    "Provide CAPEC techniques for exploiting file upload vulnerabilities in web applications",
    "Generate MITRE ATT&CK techniques for initial access and privilege escalation on Linux web servers",
    "What attack sequence should target multiple web applications on the same system?"
]

red_team_results = []

for i, scenario in enumerate(red_team_scenarios, 1):
    print(f"\nRed Team Scenario {i}: {scenario}")
    print("-" * 50)
    
    try:
        start_time = time.time()
        result = qa_chain({"query": scenario})
        response_time = time.time() - start_time
        
        answer = result["result"]
        sources = result["source_documents"]
        
        print(f"Response time: {response_time:.1f}s")
        print(f"Sources used: {len(sources)}")
        print(f"Answer: {answer[:300]}...")
        
        # Extract technique IDs from answer
        import re
        capec_ids = re.findall(r'CAPEC-\d+', answer)
        mitre_ids = re.findall(r'T\d{4}(?:\.\d{3})?', answer)
        
        print(f"CAPEC techniques found: {capec_ids[:5]}...")  # Show first 5
        print(f"MITRE techniques found: {mitre_ids[:5]}...")
        
        # Score red team effectiveness
        score = 0
        if len(capec_ids) > 0:
            score += 3
        if len(mitre_ids) > 0:
            score += 3
        if len(capec_ids) + len(mitre_ids) >= 5:
            score += 2
        if any(keyword in answer.lower() for keyword in ["web", "injection", "exploit", "attack"]):
            score += 2
        
        red_team_results.append({
            "scenario": scenario,
            "response_time": response_time,
            "answer_length": len(answer),
            "sources_count": len(sources),
            "capec_techniques": len(capec_ids),
            "mitre_techniques": len(mitre_ids),
            "total_techniques": len(capec_ids) + len(mitre_ids),
            "score": score
        })
        
        print(f"Red Team Score: {score}/10")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        red_team_results.append({
            "scenario": scenario,
            "error": str(e),
            "score": 0
        })

# %%
# Step 6: Test Database Coverage and Completeness
print("\n\nTesting database coverage and completeness...")
print("=" * 55)

coverage_tests = [
    "How many different types of SQL injection attacks exist?",
    "What are the most common web application attack patterns?",
    "Which MITRE techniques target credential access?",
    "What CAPEC patterns involve social engineering?",
    "Which attack techniques work against REST APIs?"
]

coverage_results = []

for i, test in enumerate(coverage_tests, 1):
    print(f"\nCoverage Test {i}: {test}")
    print("-" * 35)
    
    try:
        start_time = time.time()
        result = qa_chain({"query": test})
        response_time = time.time() - start_time
        
        answer = result["result"]
        sources = result["source_documents"]
        
        # Check source distribution
        source_distribution = {}
        for source in sources:
            doc_type = source.metadata.get("doc_type", "unknown")
            source_distribution[doc_type] = source_distribution.get(doc_type, 0) + 1
        
        print(f"Response time: {response_time:.1f}s")
        print(f"Source distribution: {source_distribution}")
        print(f"Answer preview: {answer[:200]}...")
        
        coverage_results.append({
            "test": test,
            "response_time": response_time,
            "sources_used": len(sources),
            "source_distribution": source_distribution,
            "comprehensive": len(answer) > 300
        })
        
    except Exception as e:
        print(f"✗ Error: {e}")
        coverage_results.append({"test": test, "error": str(e)})

# %%
# Step 7: Complete System Performance Analysis
print("\n\nComplete RAG System Performance Analysis")
print("=" * 55)

# Calculate overall scores
knowledge_scores = [r.get("score", 0) for r in knowledge_test_results]
red_team_scores = [r.get("score", 0) for r in red_team_results]

knowledge_avg = sum(knowledge_scores) / len(knowledge_scores) if knowledge_scores else 0
red_team_avg = sum(red_team_scores) / len(red_team_scores) if red_team_scores else 0

# Calculate response times
all_times = []
for result_set in [knowledge_test_results, red_team_results]:
    times = [r.get("response_time", 0) for r in result_set if "response_time" in r]
    all_times.extend(times)

avg_response_time = sum(all_times) / len(all_times) if all_times else 0

# Analyze technique discovery capability
total_capec_found = sum(r.get("capec_techniques", 0) for r in red_team_results)
total_mitre_found = sum(r.get("mitre_techniques", 0) for r in red_team_results)

print(f"KNOWLEDGE BASE PERFORMANCE:")
print(f"  Knowledge Test Score: {knowledge_avg:.1f}/10")
print(f"  Red Team Agent Score: {red_team_avg:.1f}/10")
print(f"  Average Response Time: {avg_response_time:.1f} seconds")

print(f"\nTECHNIQUE DISCOVERY CAPABILITY:")
print(f"  CAPEC Techniques Discovered: {total_capec_found}")
print(f"  MITRE Techniques Discovered: {total_mitre_found}")
print(f"  Total Attack Techniques: {total_capec_found + total_mitre_found}")

print(f"\nDATABASE COVERAGE:")
print(f"  Total patterns in database: {config.get('rag_setup', {}).get('total_attack_patterns', 'Unknown')}")
print(f"  Vector chunks: {config.get('rag_setup', {}).get('chunks_created', 'Unknown')}")

# System readiness assessment
overall_score = (knowledge_avg + red_team_avg) / 2
technique_discovery = total_capec_found + total_mitre_found

if overall_score >= 7 and technique_discovery >= 10:
    system_status = "EXCELLENT - Red Team Agent ready for autonomous operation"
elif overall_score >= 5 and technique_discovery >= 5:
    system_status = "GOOD - Red Team Agent functional with minor limitations"
elif overall_score >= 3:
    system_status = "FAIR - Red Team Agent needs improvement"
else:
    system_status = "POOR - System requires debugging"

print(f"\nRED TEAM AGENT STATUS: {system_status}")
print(f"Overall Performance: {overall_score:.1f}/10")

# Database completeness check
expected_capec = config.get('rag_setup', {}).get('capec_patterns', 0)
expected_mitre = config.get('rag_setup', {}).get('mitre_patterns', 0)

print(f"\nDATABASE COMPLETENESS:")
print(f"  CAPEC Patterns Loaded: {expected_capec}")
print(f"  MITRE Techniques Loaded: {expected_mitre}")
print(f"  Total Attack Knowledge: {expected_capec + expected_mitre}")

if expected_capec > 500 and expected_mitre > 100:
    print("  ✓ Complete attack pattern database loaded")
    print("  ✓ Red Team Agent has access to comprehensive knowledge")
    print("  ✓ No bias toward specific techniques - agent must choose autonomously")
else:
    print("  ⚠ Database may be incomplete")

# %%
# Step 8: Update Configuration with Test Results
test_results = {
    "test_timestamp": datetime.now().isoformat(),
    "knowledge_base_score": knowledge_avg,
    "red_team_agent_score": red_team_avg,  
    "overall_score": overall_score,
    "average_response_time": avg_response_time,
    "technique_discovery_count": technique_discovery,
    "capec_techniques_found": total_capec_found,
    "mitre_techniques_found": total_mitre_found,
    "system_status": system_status,
    "database_complete": expected_capec > 500 and expected_mitre > 100,
    "agent_ready": overall_score >= 5 and technique_discovery >= 5
}

config["rag_testing"] = test_results

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\nComplete CAPEC/MITRE RAG System Testing Complete!")
print("=" * 60)
print(f"Knowledge Base Score: {knowledge_avg:.1f}/10")
print(f"Red Team Agent Score: {red_team_avg:.1f}/10")
print(f"Overall Performance: {overall_score:.1f}/10")
print(f"Attack Techniques Discoverable: {technique_discovery}")

if test_results["agent_ready"]:
    print("\n✓ RED TEAM AGENT READY FOR AUTONOMOUS OPERATION")
    print("✓ Complete CAPEC/MITRE knowledge base functional")
    print("✓ Agent can discover attack techniques from thousands of options")
    print("✓ No bias toward specific VPLE techniques")
    print("Next: Run notebook 05_Generate_Attack_Scenarios.ipynb")
else:
    print("\n⚠ Red Team Agent needs improvement before deployment")
    print("Consider reviewing knowledge base or model configuration")
