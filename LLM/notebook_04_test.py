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
# Step 4: Test VPLE Knowledge
print("Testing VPLE knowledge...")
print("=" * 40)

vple_test_questions = [
    "What applications are available in VPLE?",
    "What are the default credentials for VPLE?", 
    "Which VPLE applications run on which ports?",
    "What types of vulnerabilities are found in DVWA?",
    "How do you access Mutillidae II?"
]

vple_test_results = []

for i, question in enumerate(vple_test_questions, 1):
    print(f"\nTest {i}: {question}")
    print("-" * 30)
    
    try:
        start_time = time.time()
        result = qa_chain({"query": question})
        response_time = time.time() - start_time
        
        answer = result["result"]
        sources = result["source_documents"]
        
        print(f"Response time: {response_time:.1f}s")
        print(f"Sources used: {len(sources)}")
        print(f"Answer: {answer[:200]}...")
        
        # Score the response (basic heuristic)
        answer_lower = answer.lower()
        score = 0
        
        if question.lower().find("applications") != -1:
            apps = ["dvwa", "mutillidae", "webgoat", "bwapp", "juice shop", "wordpress", "security ninjas"]
            score = sum(1 for app in apps if app in answer_lower)
        elif question.lower().find("credentials") != -1:
            if "administrator" in answer_lower and "password" in answer_lower:
                score = 10
        elif question.lower().find("ports") != -1:
            ports = ["1335", "1336", "1337", "8080", "3000", "8899", "8800"]
            score = sum(1 for port in ports if port in answer)
        else:
            score = 5 if len(answer) > 100 else 2
        
        vple_test_results.append({
            "question": question,
            "response_time": response_time,
            "answer_length": len(answer),
            "sources_count": len(sources),
            "score": score
        })
        
        print(f"Score: {score}/10")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        vple_test_results.append({
            "question": question,
            "error": str(e),
            "score": 0
        })

# %%
# Step 5: Test MITRE ATT&CK Knowledge  
print("\n\nTesting MITRE ATT&CK knowledge...")
print("=" * 45)

mitre_test_questions = [
    "What is MITRE technique T1190?",
    "How can T1083 be used in web application testing?",
    "What techniques are useful for command injection?",
    "Which MITRE techniques apply to credential access?",
    "How does T1505.003 work for persistence?"
]

mitre_test_results = []

for i, question in enumerate(mitre_test_questions, 1):
    print(f"\nMITRE Test {i}: {question}")
    print("-" * 35)
    
    try:
        start_time = time.time()
        result = qa_chain({"query": question})
        response_time = time.time() - start_start
        
        answer = result["result"]
        sources = result["source_documents"]
        
        print(f"Response time: {response_time:.1f}s")
        print(f"Sources used: {len(sources)}")
        print(f"Answer: {answer[:200]}...")
        
        # Score MITRE knowledge
        answer_lower = answer.lower()
        score = 0
        
        if "t1190" in answer_lower or "exploit public-facing" in answer_lower:
            score += 3
        if "t1083" in answer_lower or "file and directory" in answer_lower:
            score += 3
        if "command injection" in answer_lower or "unix shell" in answer_lower:
            score += 2
        if "credential" in answer_lower:
            score += 2
        
        if len(answer) > 150:
            score += 2
            
        mitre_test_results.append({
            "question": question,
            "response_time": response_time,
            "answer_length": len(answer),
            "sources_count": len(sources),
            "score": min(10, score)
        })
        
        print(f"Score: {min(10, score)}/10")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        mitre_test_results.append({
            "question": question,
            "error": str(e),
            "score": 0
        })

# %%
# Step 6: Test Attack Scenario Understanding
print("\n\nTesting attack scenario understanding...")
print("=" * 50)

scenario_question = """
You need to test a VPLE system for web application vulnerabilities. 
The target has DVWA, Mutillidae, and bWAPP running.
What approach would you take to systematically test these applications?
"""

print(f"Scenario Question: {scenario_question}")
print("-" * 60)

try:
    start_time = time.time()
    result = qa_chain({"query": scenario_question})
    response_time = time.time() - start_time
    
    scenario_answer = result["result"]
    scenario_sources = result["source_documents"]
    
    print(f"Response time: {response_time:.1f}s")
    print(f"Sources used: {len(scenario_sources)}")
    print(f"Full answer:\n{scenario_answer}")
    
    # Analyze scenario quality
    answer_words = scenario_answer.lower()
    
    scenario_score = 0
    if "sql injection" in answer_words: scenario_score += 2
    if "xss" in answer_words or "cross-site" in answer_words: scenario_score += 2
    if "command injection" in answer_words: scenario_score += 2
    if "file upload" in answer_words: scenario_score += 1
    if "dvwa" in answer_words: scenario_score += 1
    if "mutillidae" in answer_words: scenario_score += 1
    if "bwapp" in answer_words: scenario_score += 1
    
    print(f"\nScenario Score: {scenario_score}/10")
    
except Exception as e:
    print(f"✗ Scenario test error: {e}")
    scenario_score = 0

# %%
# Step 7: Performance Analysis
print("\n\nRAG System Performance Analysis")
print("=" * 45)

# Calculate overall scores
vple_scores = [r.get("score", 0) for r in vple_test_results]
mitre_scores = [r.get("score", 0) for r in mitre_test_results]

vple_avg = sum(vple_scores) / len(vple_scores) if vple_scores else 0
mitre_avg = sum(mitre_scores) / len(mitre_scores) if mitre_scores else 0

# Calculate response times
vple_times = [r.get("response_time", 0) for r in vple_test_results if "response_time" in r]
mitre_times = [r.get("response_time", 0) for r in mitre_test_results if "response_time" in r]

avg_response_time = (sum(vple_times) + sum(mitre_times)) / (len(vple_times) + len(mitre_times)) if vple_times or mitre_times else 0

print(f"VPLE Knowledge Score: {vple_avg:.1f}/10")
print(f"MITRE Knowledge Score: {mitre_avg:.1f}/10") 
print(f"Scenario Understanding: {scenario_score}/10")
print(f"Average Response Time: {avg_response_time:.1f} seconds")

# Overall system readiness
overall_score = (vple_avg + mitre_avg + scenario_score) / 3
print(f"\nOverall RAG Performance: {overall_score:.1f}/10")

if overall_score >= 7:
    system_status = "EXCELLENT - Ready for scenario generation"
elif overall_score >= 5:
    system_status = "GOOD - Ready with minor limitations"
elif overall_score >= 3:
    system_status = "FAIR - May need knowledge base improvements"
else:
    system_status = "POOR - Requires debugging"

print(f"System Status: {system_status}")

# %%
# Step 8: Update Configuration with Test Results
test_results = {
    "test_timestamp": datetime.now().isoformat(),
    "vple_knowledge_score": vple_avg,
    "mitre_knowledge_score": mitre_avg,  
    "scenario_score": scenario_score,
    "overall_score": overall_score,
    "average_response_time": avg_response_time,
    "system_status": system_status,
    "system_ready": overall_score >= 5
}

config["rag_testing"] = test_results

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\nRAG System Testing Complete!")
print("=" * 45)
print(f"Overall Performance: {overall_score:.1f}/10")
print(f"System Status: {system_status}")

if test_results["system_ready"]:
    print("\n✓ System ready for attack scenario generation")
    print("Next: Run notebook 05_Generate_Attack_Scenarios.ipynb")
else:
    print("\n⚠ System may need improvements before scenario generation")
    print("Consider reviewing knowledge base or model configuration")
