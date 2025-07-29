# Notebook 5: Generate Attack Scenarios

# %% [markdown]
"""
# VPLE Attack Scenario Generator - Scenario Generation

Ce notebook génère des scénarios d'attaque pour la machine VPLE en utilisant le LLM + RAG.
Le LLM ne connaît PAS vos solutions optimales - il doit les découvrir par lui-même.

## Objectifs de Test:
- Web Application Compromise: Compromettre les applications web
- Data Exfiltration: Extraire des données sensibles  
- Privilege Escalation: Élever les privilèges sur le système
- Lateral Movement: Mouvement latéral dans l'environnement
- Full System Compromise: Compromission complète du système

## Output Format:
Chaque scénario contient:
- Liste ordonnée de techniques MITRE ATT&CK
- Applications cibles spécifiques
- Étapes d'attaque détaillées
- Résultats attendus pour chaque étape
"""

# %%
# Load configuration and setup
import json
import time
from datetime import datetime
from typing import Dict, List, Any
import pandas as pd

try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    print("✓ Configuration loaded")
    
    if not config.get("rag_testing", {}).get("system_ready"):
        print("⚠ RAG system may not be ready. Please run notebook 04 first.")
        print("Continuing anyway...")
        
    model_name = config["confirmed_model"]
    vple_info = config["vple_info"]
    
    print(f"Model: {model_name}")
    print(f"VPLE IP: {vple_info['default_ip']} (adjust as needed)")
    
except FileNotFoundError:
    print("✗ Configuration not found. Please run previous notebooks first.")
    exit(1)

# %%
# Import RAG components
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
# Step 1: Setup RAG System
print("Setting up RAG system for scenario generation...")

# Initialize components
llm = Ollama(
    model=model_name,
    temperature=0.7,  # Higher temperature for creative scenarios
    num_predict=1024  # Longer responses for detailed scenarios
)

embeddings = OllamaEmbeddings(model=model_name)

vectorstore = Chroma(
    persist_directory="./vple_chroma_db",
    embedding_function=embeddings
)

print("✓ RAG system initialized")

# %%
# Step 2: Create Scenario Generation Prompt
scenario_prompt_template = """
You are an expert penetration tester tasked with creating detailed attack scenarios for VPLE (Vulnerable Penetration Testing Lab Environment).

VPLE System Information:
- Target IP: {target_ip}
- Platform: Linux virtual machine  
- Default credentials: administrator:password
- Available applications: DVWA (1335), Mutillidae (1336), WebGoat (1337), bWAPP (8080), Juice Shop (3000), Security Ninjas (8899), WordPress (8800)

Use the following context about VPLE vulnerabilities and MITRE ATT&CK techniques:

Context: {context}

Objective: {objective}

Create a detailed attack scenario that includes:

1. ATTACK CHAIN: List specific MITRE ATT&CK technique IDs in order (e.g., T1190, T1083, T1059.004)

2. TARGET APPLICATIONS: Which VPLE applications to focus on and why

3. STEP-BY-STEP EXECUTION:
   - Step 1: [Technique ID] - [Description] - [Expected outcome]
   - Step 2: [Technique ID] - [Description] - [Expected outcome]
   - Continue for each step...

4. SUCCESS INDICATORS: How to know each step worked

5. ALTERNATIVE PATHS: Backup techniques if primary approach fails

Base your scenario ONLY on the provided context about VPLE. Be specific about:
- Exact applications and ports to target
- Specific vulnerability types to exploit
- Technical details of each attack step
- Realistic expected outcomes

Scenario:
"""

SCENARIO_PROMPT = PromptTemplate(
    template=scenario_prompt_template,
    input_variables=["target_ip", "context", "objective"]
)

# Create RAG chain for scenario generation
scenario_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(search_kwargs={"k": 8}),  # More context for scenarios
    chain_type_kwargs={"prompt": SCENARIO_PROMPT},
    return_source_documents=True
)

print("✓ Scenario generation chain created")

# %%
# Step 3: Define Attack Objectives
attack_objectives = [
    {
        "name": "Web Application Compromise",
        "description": "Gain unauthorized access to VPLE web applications and extract sensitive data",
        "priority": "HIGH",
        "focus": "Initial access through web vulnerabilities"
    },
    {
        "name": "Database Access",
        "description": "Access underlying databases of VPLE applications to extract user data and credentials",
        "priority": "HIGH", 
        "focus": "SQL injection and database exploitation"
    },
    {
        "name": "Command Execution",
        "description": "Achieve command execution on the VPLE system through web application vulnerabilities",
        "priority": "CRITICAL",
        "focus": "Command injection and web shell deployment"
    },
    {
        "name": "Privilege Escalation", 
        "description": "Escalate from web application user to administrative privileges on VPLE system",
        "priority": "HIGH",
        "focus": "Local privilege escalation techniques"
    },
    {
        "name": "Data Exfiltration",
        "description": "Systematically extract sensitive data from all VPLE applications and system",
        "priority": "MEDIUM",
        "focus": "Data collection and exfiltration methods"
    }
]

print(f"Defined {len(attack_objectives)} attack objectives")

# %%
# Step 4: Generate Attack Scenarios
print("Generating attack scenarios...")
print("=" * 50)

# Get current VPLE IP (user should update this)
current_vple_ip = input("Enter your VPLE VM IP address (or press Enter for default 192.168.255.143): ").strip()
if not current_vple_ip:
    current_vple_ip = "192.168.255.143"

print(f"Using VPLE IP: {current_vple_ip}")

generated_scenarios = []

for i, objective in enumerate(attack_objectives, 1):
    print(f"\nGenerating Scenario {i}: {objective['name']}")
    print("-" * 40)
    
    try:
        start_time = time.time()
        
        # Generate scenario using RAG
        result = scenario_chain({
            "query": objective["description"],
            "target_ip": current_vple_ip
        })
        
        generation_time = time.time() - start_time
        
        scenario_text = result["result"]
        source_docs = result["source_documents"]
        
        print(f"✓ Generated in {generation_time:.1f} seconds")
        print(f"Sources used: {len(source_docs)}")
        print(f"Scenario length: {len(scenario_text)} characters")
        
        # Extract MITRE techniques from scenario
        import re
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        techniques = list(set(re.findall(technique_pattern, scenario_text)))
        
        print(f"MITRE techniques identified: {techniques}")
        
        # Parse scenario structure
        scenario_data = {
            "objective": objective["name"],
            "description": objective["description"],
            "priority": objective["priority"],
            "target_ip": current_vple_ip,
            "techniques": techniques,
            "full_scenario": scenario_text,
            "generation_time": generation_time,
            "sources_count": len(source_docs),
            "timestamp": datetime.now().isoformat()
        }
        
        generated_scenarios.append(scenario_data)
        
        # Display preview
        print(f"\nScenario Preview:")
        print("-" * 20)
        print(scenario_text[:300] + "...")
        
    except Exception as e:
        print(f"✗ Error generating scenario: {e}")
        
        # Create fallback scenario
        fallback_scenario = {
            "objective": objective["name"],
            "description": objective["description"],
            "priority": objective["priority"],
            "target_ip": current_vple_ip,
            "techniques": ["T1190"],  # Basic web exploitation
            "full_scenario": f"Basic web application testing scenario for {objective['name']}",
            "generation_time": 0,
            "sources_count": 0,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        
        generated_scenarios.append(fallback_scenario)

print(f"\n✓ Generated {len(generated_scenarios)} attack scenarios")

# %%
# Step 5: Analyze Generated Scenarios
print("\nAnalyzing generated scenarios...")
print("=" * 40)

scenario_analysis = []

for scenario in generated_scenarios:
    analysis = {
        "objective": scenario["objective"],
        "technique_count": len(scenario["techniques"]),
        "techniques": scenario["techniques"],
        "scenario_length": len(scenario["full_scenario"]),
        "generation_time": scenario["generation_time"],
        "sources_used": scenario["sources_count"]
    }
    
    # Quality scoring
    quality_score = 0
    
    # Score based on technique diversity
    if len(scenario["techniques"]) >= 3:
        quality_score += 3
    elif len(scenario["techniques"]) >= 2:
        quality_score += 2
    elif len(scenario["techniques"]) >= 1:
        quality_score += 1
    
    # Score based on scenario detail
    if scenario["scenario_length"] >= 1500:
        quality_score += 3
    elif scenario["scenario_length"] >= 1000:
        quality_score += 2
    elif scenario["scenario_length"] >= 500:
        quality_score += 1
    
    # Score based on VPLE-specific content
    scenario_lower = scenario["full_scenario"].lower()
    vple_terms = ["dvwa", "mutillidae", "webgoat", "bwapp", "juice shop", "wordpress", "security ninjas"]
    vple_mentions = sum(1 for term in vple_terms if term in scenario_lower)
    quality_score += min(4, vple_mentions)
    
    analysis["quality_score"] = quality_score
    analysis["max_score"] = 10
    
    scenario_analysis.append(analysis)
    
    print(f"{scenario['objective']}: {quality_score}/10")

# %%
# Step 6: Create Executable Attack Plans
print("\nCreating executable attack plans...")
print("=" * 40)

executable_plans = []

for scenario in generated_scenarios:
    print(f"\nProcessing: {scenario['objective']}")
    
    # Parse the scenario to create structured attack plan
    plan = {
        "scenario_name": scenario['objective'],
        "target_system": f"VPLE VM at {scenario['target_ip']}",
        "objective": scenario['description'],
        "priority": scenario['priority'],
        "techniques": scenario['techniques'],
        "execution_steps": [],
        "success_criteria": [],
        "tools_needed": [],
        "estimated_time": "30-60 minutes"
    }
    
    # Extract steps from scenario text
    scenario_text = scenario['full_scenario']
    
    # Look for numbered steps or technique descriptions
    lines = scenario_text.split('\n')
    step_count = 1
    
    for line in lines:
        line = line.strip()
        
        # Look for step indicators
        if any(indicator in line.lower() for indicator in ['step', 'phase', 'stage', 'first', 'next', 'then']):
            if len(line) > 20:  # Skip very short lines
                
                # Extract technique ID if present
                technique_match = re.search(r'T\d{4}(?:\.\d{3})?', line)
                technique_id = technique_match.group() if technique_match else "MANUAL"
                
                step = {
                    "step_number": step_count,
                    "technique_id": technique_id,
                    "description": line[:200],  # Limit description length
                    "target": "Web Applications",
                    "expected_outcome": "See scenario details"
                }
                
                plan["execution_steps"].append(step)
                step_count += 1
    
    # If no structured steps found, create basic plan from techniques
    if not plan["execution_steps"]:
        for i, technique in enumerate(scenario['techniques'], 1):
            step = {
                "step_number": i,
                "technique_id": technique,
                "description": f"Execute MITRE technique {technique}",
                "target": "VPLE Applications",
                "expected_outcome": "Technique-specific results"
            }
            plan["execution_steps"].append(step)
    
    # Add basic success criteria
    plan["success_criteria"] = [
        "Successful authentication bypass or unauthorized access",
        "Data extraction or command execution achieved", 
        "Evidence of compromise documented"
    ]
    
    # Add common tools
    plan["tools_needed"] = [
        "Web browser with proxy (Burp Suite/OWASP ZAP)",
        "SQL injection tools (sqlmap)",
        "Web shells and payloads",
        "Network scanning tools"
    ]
    
    executable_plans.append(plan)
    
    print(f"  ✓ Created plan with {len(plan['execution_steps'])} steps")

print(f"\n✓ Created {len(executable_plans)} executable attack plans")

# %%
# Step 7: Display Attack Plans
print("\nGENERATED ATTACK SCENARIOS FOR MANUAL EXECUTION")
print("=" * 60)

for i, plan in enumerate(executable_plans, 1):
    print(f"\n### SCENARIO {i}: {plan['scenario_name'].upper()}")
    print("=" * 50)
    print(f"Target: {plan['target_system']}")
    print(f"Objective: {plan['objective']}")
    print(f"Priority: {plan['priority']}")
    print(f"Estimated Time: {plan['estimated_time']}")
    
    print(f"\nMITRE ATT&CK Techniques:")
    for technique in plan['techniques']:
        print(f"  - {technique}")
    
    print(f"\nExecution Steps:")
    for step in plan['execution_steps']:
        print(f"  {step['step_number']}. [{step['technique_id']}] {step['description']}")
    
    print(f"\nSuccess Criteria:")
    for criteria in plan['success_criteria']:
        print(f"  - {criteria}")
    
    print(f"\nRequired Tools:")
    for tool in plan['tools_needed']:
        print(f"  - {tool}")
    
    print("\n" + "-" * 50)

# %%
# Step 8: Save Attack Scenarios
print("Saving attack scenarios...")

# Save individual scenarios
scenarios_dir = "generated_scenarios"
import os
os.makedirs(scenarios_dir, exist_ok=True)

for i, plan in enumerate(executable_plans, 1):
    # Save as JSON
    filename = f"{scenarios_dir}/scenario_{i}_{plan['scenario_name'].replace(' ', '_').lower()}.json"
    with open(filename, 'w') as f:
        json.dump(plan, f, indent=2)
    
    # Save as readable text
    text_filename = f"{scenarios_dir}/scenario_{i}_{plan['scenario_name'].replace(' ', '_').lower()}.txt"
    with open(text_filename, 'w') as f:
        f.write(f"ATTACK SCENARIO: {plan['scenario_name']}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Target: {plan['target_system']}\n")
        f.write(f"Objective: {plan['objective']}\n")
        f.write(f"Priority: {plan['priority']}\n\n")
        
        f.write("MITRE ATT&CK Techniques:\n")
        for technique in plan['techniques']:
            f.write(f"  - {technique}\n")
        f.write("\n")
        
        f.write("Execution Steps:\n")
        for step in plan['execution_steps']:
            f.write(f"  {step['step_number']}. [{step['technique_id']}] {step['description']}\n")
        f.write("\n")
        
        f.write("Success Criteria:\n")
        for criteria in plan['success_criteria']:
            f.write(f"  - {criteria}\n")
        f.write("\n")
        
        f.write("Required Tools:\n")
        for tool in plan['tools_needed']:
            f.write(f"  - {tool}\n")

# Save complete dataset
complete_data = {
    "generation_metadata": {
        "timestamp": datetime.now().isoformat(),
        "model_used": model_name,
        "vple_target": current_vple_ip,
        "scenarios_generated": len(executable_plans)
    },
    "scenarios": executable_plans,
    "raw_llm_output": generated_scenarios,
    "analysis": scenario_analysis
}

with open("vple_attack_scenarios_complete.json", "w") as f:
    json.dump(complete_data, f, indent=2)

print(f"✓ Saved {len(executable_plans)} scenarios to {scenarios_dir}/")
print("✓ Complete dataset saved to vple_attack_scenarios_complete.json")

# %%
# Step 9: Create Summary Report
print("\nCREATING SUMMARY REPORT")
print("=" * 40)

# Calculate statistics
total_techniques = sum(len(plan['techniques']) for plan in executable_plans)
avg_techniques = total_techniques / len(executable_plans) if executable_plans else 0
avg_steps = sum(len(plan['execution_steps']) for plan in executable_plans) / len(executable_plans) if executable_plans else 0

# Most common techniques
all_techniques = []
for plan in executable_plans:
    all_techniques.extend(plan['techniques'])

from collections import Counter
technique_counts = Counter(all_techniques)
top_techniques = technique_counts.most_common(5)

# Create summary
summary = f"""
VPLE ATTACK SCENARIO GENERATION SUMMARY
======================================

Generation Details:
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- LLM Model: {model_name}
- Target System: VPLE VM at {current_vple_ip}
- Scenarios Generated: {len(executable_plans)}

Scenario Statistics:
- Total MITRE Techniques: {total_techniques}
- Average Techniques per Scenario: {avg_techniques:.1f}
- Average Steps per Scenario: {avg_steps:.1f}

Most Common Techniques:
"""

for technique, count in top_techniques:
    summary += f"- {technique}: {count} scenarios\n"

summary += f"""
Quality Analysis:
- Average Quality Score: {sum(a['quality_score'] for a in scenario_analysis) / len(scenario_analysis):.1f}/10
- High Quality Scenarios (8+): {sum(1 for a in scenario_analysis if a['quality_score'] >= 8)}
- Medium Quality Scenarios (5-7): {sum(1 for a in scenario_analysis if 5 <= a['quality_score'] < 8)}
- Low Quality Scenarios (<5): {sum(1 for a in scenario_analysis if a['quality_score'] < 5)}

Files Generated:
- Individual scenario files: {scenarios_dir}/scenario_*.json
- Text formats: {scenarios_dir}/scenario_*.txt  
- Complete dataset: vple_attack_scenarios_complete.json
- Summary report: vple_scenario_summary.txt

READY FOR MANUAL EXECUTION
========================
You can now manually execute these scenarios against your VPLE VM.
Each scenario provides step-by-step instructions with MITRE ATT&CK techniques.

Next Steps:
1. Review individual scenario files
2. Set up your VPLE VM environment
3. Execute scenarios manually
4. Document results for comparison with human expertise
"""

print(summary)

# Save summary
with open("vple_scenario_summary.txt", "w") as f:
    f.write(summary)

print("✓ Summary saved to vple_scenario_summary.txt")

# %%
# Update configuration
config["scenario_generation"] = {
    "timestamp": datetime.now().isoformat(),
    "scenarios_generated": len(executable_plans),
    "target_ip": current_vple_ip,
    "average_quality": sum(a['quality_score'] for a in scenario_analysis) / len(scenario_analysis) if scenario_analysis else 0,
    "files_created": len(executable_plans) * 2 + 2  # JSON + TXT per scenario + complete + summary
}

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\nSCENARIO GENERATION COMPLETE!")
print("=" * 50)
print(f"Generated: {len(executable_plans)} attack scenarios")
print(f"Target: VPLE VM at {current_vple_ip}")
print(f"Files: {scenarios_dir}/ directory")
print("\nYou can now manually execute these scenarios against your VPLE VM!")
print("Next: Use notebook 06_Compare_Results.ipynb after execution")
