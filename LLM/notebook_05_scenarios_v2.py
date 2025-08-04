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
# Step 2: Create Red Team Agent Prompt
red_team_prompt_template = """
You are an autonomous Red Team Agent tasked with planning cyber attacks against target systems. Your goal is to identify and chain attack techniques to achieve maximum impact.

TARGET SYSTEM:
- IP Address: {target_ip}
- Platform: Linux virtual machine
- Services: Multiple web applications on different ports
- Applications: DVWA (1335), Mutillidae (1336), WebGoat (1337), bWAPP (8080), Juice Shop (3000), Security Ninjas (8899), WordPress (8800)

MISSION OBJECTIVE: {objective}

Using the attack pattern knowledge provided in the context, develop a comprehensive attack strategy:

Context: {context}

REQUIRED OUTPUT FORMAT:

1. RECONNAISSANCE PLAN:
   - Information gathering techniques
   - Target analysis approach

2. ATTACK TECHNIQUE SELECTION:
   - List CAPEC and/or MITRE ATT&CK technique IDs you choose to use
   - Justify why each technique is appropriate for this target
   - Consider technique prerequisites and skill requirements

3. ATTACK EXECUTION SEQUENCE:
   - Step-by-step attack chain with technique IDs
   - Expected outcomes for each step
   - Contingency plans if techniques fail

4. TARGET PRIORITIZATION:
   - Which applications/services to target first and why
   - Risk vs reward analysis for each target

5. SUCCESS METRICS:
   - How to measure attack effectiveness
   - Indicators of successful compromise

IMPORTANT: Select techniques based on your analysis of the target system and available attack patterns. You have access to a comprehensive database of attack techniques - choose the most effective ones for this scenario.

Red Team Attack Plan:
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
# Step 3: Define Red Team Mission Objectives
red_team_missions = [
    {
        "name": "Initial Compromise",
        "description": "Gain initial foothold on the target system through any available attack vector",
        "priority": "CRITICAL",
        "focus": "Initial access and reconnaissance"
    },
    {
        "name": "Privilege Escalation Campaign",
        "description": "Escalate privileges from initial access to administrative control of the system",
        "priority": "HIGH", 
        "focus": "Local privilege escalation and persistence"
    },
    {
        "name": "Data Exfiltration Operation",
        "description": "Locate, access, and extract sensitive data from all applications and databases",
        "priority": "HIGH",
        "focus": "Credential harvesting and data collection"
    },
    {
        "name": "Persistence and Stealth",
        "description": "Establish persistent access while avoiding detection mechanisms",
        "priority": "MEDIUM",
        "focus": "Long-term access and evasion techniques"
    },
    {
        "name": "Multi-Vector Attack",
        "description": "Simultaneously target multiple applications using different attack vectors for maximum impact",
        "priority": "HIGH",
        "focus": "Coordinated multi-application exploitation"
    }
]

print(f"Defined {len(red_team_missions)} Red Team mission objectives")

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
# Step 6: Create Executable Red Team Plans
print("\nCreating executable Red Team attack plans...")
print("=" * 50)

executable_plans = []

for plan in generated_attack_plans:
    print(f"\nProcessing: {plan['mission']}")
    
    # Create structured Red Team execution plan
    red_team_plan = {
        "mission_name": plan['mission'],
        "target_system": f"VPLE VM at {plan['target_ip']}",
        "objective": plan['objective'],
        "priority": plan['priority'],
        "mitre_techniques": plan['mitre_techniques'],
        "capec_patterns": plan['capec_patterns'],
        "total_attack_vectors": plan['total_techniques'],
        "execution_phases": [],
        "success_criteria": [],
        "required_tools": [],
        "estimated_duration": "45-90 minutes",
        "agent_autonomy": "HIGH - Agent selected techniques from complete database"
    }
    
    # Parse the attack plan to create structured execution phases
    attack_plan_text = plan['full_attack_plan']
    
    # Look for structured sections in the LLM response
    lines = attack_plan_text.split('\n')
    current_phase = None
    phase_count = 1
    
    for line in lines:
        line = line.strip()
        
        # Look for phase indicators
        if any(indicator in line.lower() for indicator in ['reconnaissance', 'recon', 'discovery', 'initial', 'exploit', 'persistence', 'escalation']):
            if len(line) > 10 and len(line) < 100:  # Reasonable phase header length
                current_phase = {
                    "phase_number": phase_count,
                    "phase_name": line,
                    "techniques": [],
                    "description": "",
                    "expected_duration": "15-30 minutes"
                }
                red_team_plan["execution_phases"].append(current_phase)
                phase_count += 1
        
        # Look for technique references
        elif current_phase and (any(tech_id in line for tech_id in plan['mitre_techniques'] + plan['capec_patterns'])):
            # Extract technique ID and description
            technique_match = re.search(r'(T\d{4}(?:\.\d{3})?|CAPEC-\d+)', line)
            if technique_match:
                technique_id = technique_match.group(1)
                technique_desc = line.replace(technique_id, '').strip(' :-')
                
                current_phase["techniques"].append({
                    "technique_id": technique_id,
                    "description": technique_desc[:150],  # Limit description length
                    "target": "Web Applications",
                    "expected_outcome": "Technique-specific results"
                })
    
    # If no structured phases found, create generic phases from techniques
    if not red_team_plan["execution_phases"]:
        phases = [
            {"name": "Reconnaissance", "techniques": plan['mitre_techniques'][:2]},
            {"name": "Initial Access", "techniques": plan['capec_patterns'][:2]},
            {"name": "Exploitation", "techniques": (plan['mitre_techniques'] + plan['capec_patterns'])[2:5]}
        ]
        
        for i, phase in enumerate(phases, 1):
            if phase["techniques"]:
                execution_phase = {
                    "phase_number": i,
                    "phase_name": phase["name"],
                    "techniques": [
                        {
                            "technique_id": tech_id,
                            "description": f"Execute {tech_id} against VPLE applications",
                            "target": "VPLE Web Applications",
                            "expected_outcome": "Phase-specific compromise"
                        }
                        for tech_id in phase["techniques"]
                    ],
                    "expected_duration": "20-40 minutes"
                }
                red_team_plan["execution_phases"].append(execution_phase)
    
    # Add success criteria
    red_team_plan["success_criteria"] = [
        "Initial foothold established on target system",
        "Attack techniques successfully executed", 
        "Evidence of compromise documented",
        "Mission objectives achieved"
    ]
    
    # Add required tools
    red_team_plan["required_tools"] = [
        "Web browser with security extensions",
        "HTTP proxy tools (Burp Suite, OWASP ZAP)",
        "Custom payloads and exploits",
        "Command line tools and scripts",
        "Attack technique frameworks"
    ]
    
    executable_plans.append(red_team_plan)
    
    print(f"  ✓ Created execution plan with {len(red_team_plan['execution_phases'])} phases")
    print(f"  ✓ Total attack vectors: {red_team_plan['total_attack_vectors']}")

print(f"\n✓ Created {len(executable_plans)} executable Red Team plans")

# %%
# Step 7: Display Red Team Attack Plans
print("\nGENERATED RED TEAM ATTACK PLANS FOR AUTONOMOUS EXECUTION")
print("=" * 70)

for i, plan in enumerate(executable_plans, 1):
    print(f"\n### RED TEAM MISSION {i}: {plan['mission_name'].upper()}")
    print("=" * 60)
    print(f"Target: {plan['target_system']}")
    print(f"Objective: {plan['objective']}")
    print(f"Priority: {plan['priority']}")
    print(f"Estimated Duration: {plan['estimated_duration']}")
    print(f"Agent Autonomy: {plan['agent_autonomy']}")
    
    print(f"\nAttack Techniques Selected by Agent:")
    if plan['mitre_techniques']:
        print(f"  MITRE ATT&CK: {', '.join(plan['mitre_techniques'])}")
    if plan['capec_patterns']:
        print(f"  CAPEC Patterns: {', '.join(plan['capec_patterns'])}")
    print(f"  Total Vectors: {plan['total_attack_vectors']}")
    
    print(f"\nExecution Phases:")
    for phase in plan['execution_phases']:
        print(f"  Phase {phase['phase_number']}: {phase['phase_name']}")
        for technique in phase['techniques']:
            print(f"    - [{technique['technique_id']}] {technique['description'][:60]}...")
    
    print(f"\nSuccess Criteria:")
    for criteria in plan['success_criteria']:
        print(f"  - {criteria}")
    
    print(f"\nRequired Tools:")
    for tool in plan['required_tools']:
        print(f"  - {tool}")
    
    print("\n" + "-" * 60)

# %%
# Step 8: Save Red Team Attack Plans
print("Saving Red Team attack plans...")

# Save individual plans
plans_dir = "red_team_plans"
import os
os.makedirs(plans_dir, exist_ok=True)

for i, plan in enumerate(executable_plans, 1):
    # Save as JSON
    filename = f"{plans_dir}/red_team_mission_{i}_{plan['mission_name'].replace(' ', '_').lower()}.json"
    with open(filename, 'w') as f:
        json.dump(plan, f, indent=2)
    
    # Save as readable text
    text_filename = f"{plans_dir}/red_team_mission_{i}_{plan['mission_name'].replace(' ', '_').lower()}.txt"
    with open(text_filename, 'w') as f:
        f.write(f"RED TEAM MISSION: {plan['mission_name']}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target: {plan['target_system']}\n")
        f.write(f"Objective: {plan['objective']}\n")
        f.write(f"Priority: {plan['priority']}\n\n")
        
        f.write("Attack Techniques Selected by Agent:\n")
        if plan['mitre_techniques']:
            f.write(f"  MITRE ATT&CK: {', '.join(plan['mitre_techniques'])}\n")
        if plan['capec_patterns']:
            f.write(f"  CAPEC Patterns: {', '.join(plan['capec_patterns'])}\n")
        f.write(f"  Total Attack Vectors: {plan['total_attack_vectors']}\n\n")
        
        f.write("Execution Phases:\n")
        for phase in plan['execution_phases']:
            f.write(f"  Phase {phase['phase_number']}: {phase['phase_name']}\n")
            for technique in phase['techniques']:
                f.write(f"    - [{technique['technique_id']}] {technique['description']}\n")
        f.write("\n")
        
        f.write("Success Criteria:\n")
        for criteria in plan['success_criteria']:
            f.write(f"  - {criteria}\n")
        f.write("\n")
        
        f.write("Required Tools:\n")
        for tool in plan['required_tools']:
            f.write(f"  - {tool}\n")

# Save complete dataset  
complete_data = {
    "generation_metadata": {
        "timestamp": datetime.now().isoformat(),
        "model_used": model_name,
        "target_system": current_vple_ip,
        "missions_generated": len(executable_plans),
        "knowledge_base": "Complete CAPEC + MITRE ATT&CK Database",
        "agent_type": "Autonomous Red Team Agent"
    },
    "red_team_plans": executable_plans,
    "raw_llm_output": generated_attack_plans,
    "agent_analysis": agent_analysis,
    "technique_summary": {
        "total_mitre_techniques": total_mitre_techniques,
        "total_capec_patterns": total_capec_patterns,
        "unique_techniques_discovered": len(total_unique_techniques),
        "technique_diversity": list(total_unique_techniques)
    }
}

with open("red_team_attack_plans_complete.json", "w") as f:
    json.dump(complete_data, f, indent=2)

print(f"✓ Saved {len(executable_plans)} Red Team plans to {plans_dir}/")
print("✓ Complete dataset saved to red_team_attack_plans_complete.json")

# %%
# Step 9: Create Red Team Agent Summary Report
print("\nCREATING RED TEAM AGENT SUMMARY REPORT")
print("=" * 55)

# Calculate comprehensive statistics
total_missions = len(executable_plans)
avg_techniques_per_mission = sum(plan['total_attack_vectors'] for plan in executable_plans) / total_missions if total_missions > 0 else 0
avg_phases_per_mission = sum(len(plan['execution_phases']) for plan in executable_plans) / total_missions if total_missions > 0 else 0

# Analyze technique diversity
all_mitre = []
all_capec = []
for plan_data in generated_attack_plans:
    all_mitre.extend(plan_data['mitre_techniques'])
    all_capec.extend(plan_data['capec_patterns'])

from collections import Counter
mitre_frequency = Counter(all_mitre)
capec_frequency = Counter(all_capec)

# Most used techniques
top_mitre = mitre_frequency.most_common(5)
top_capec = capec_frequency.most_common(5)

# Calculate agent performance score
total_agent_score = sum(a['agent_score'] for a in agent_analysis)
avg_agent_score = total_agent_score / len(agent_analysis) if agent_analysis else 0

# Create comprehensive summary
summary = f"""
RED TEAM AGENT PERFORMANCE SUMMARY
=====================================

Agent Configuration:
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- LLM Model: {model_name}
- Knowledge Base: Complete CAPEC + MITRE ATT&CK Database
- Target System: VPLE VM at {current_vple_ip}
- Agent Type: Autonomous Red Team Agent

Mission Generation Statistics:
- Total Missions Generated: {total_missions}
- Average Attack Vectors per Mission: {avg_techniques_per_mission:.1f}
- Average Execution Phases per Mission: {avg_phases_per_mission:.1f}
- Agent Performance Score: {avg_agent_score:.1f}/10

Technique Discovery Analysis:
- Total MITRE ATT&CK Techniques Used: {total_mitre_techniques}
- Total CAPEC Attack Patterns Used: {total_capec_patterns}
- Unique Techniques Discovered: {len(total_unique_techniques)}
- Knowledge Base Utilization: {len(total_unique_techniques)}/{config.get('rag_setup', {}).get('total_attack_patterns', '?')} patterns

Most Frequently Selected Techniques:
MITRE ATT&CK:
"""

for technique, count in top_mitre:
    summary += f"- {technique}: {count} missions\n"

summary += f"\nCAPEC Attack Patterns:\n"
for pattern, count in top_capec:
    summary += f"- {pattern}: {count} missions\n"

summary += f"""
Agent Capability Assessment:
- Autonomous Technique Selection: {'✓ YES' if len(total_unique_techniques) > 10 else '✗ LIMITED'}
- Multi-Vector Attack Planning: {'✓ YES' if avg_techniques_per_mission > 3 else '✗ LIMITED'}
- Knowledge Base Integration: {'✓ EXCELLENT' if avg_agent_score > 7 else '✓ GOOD' if avg_agent_score > 5 else '✗ NEEDS IMPROVEMENT'}
- Mission Complexity: {'✓ HIGH' if avg_phases_per_mission > 2 else '✓ MEDIUM' if avg_phases_per_mission > 1 else '✗ LOW'}

Files Generated:
- Individual mission files: red_team_plans/red_team_mission_*.json
- Text formats: red_team_plans/red_team_mission_*.txt  
- Complete dataset: red_team_attack_plans_complete.json
- Agent summary: red_team_agent_summary.txt

RED TEAM AGENT STATUS: {'OPERATIONAL' if avg_agent_score > 6 else 'NEEDS IMPROVEMENT'}
====================
The autonomous Red Team Agent has successfully generated {total_missions} attack missions
using techniques selected from a complete CAPEC/MITRE knowledge base containing 
{config.get('rag_setup', {}).get('total_attack_patterns', 'thousands of')} attack patterns.

Agent demonstrates {'excellent' if avg_agent_score > 7 else 'good' if avg_agent_score > 5 else 'basic'} capability in:
- Autonomous attack vector selection
- Multi-phase mission planning
- Comprehensive knowledge utilization
- Target-specific technique adaptation

Next Phase: Deploy Blue Team Agent for defensive analysis and iterative improvement.
"""

print(summary)

# Save summary
with open("red_team_agent_summary.txt", "w") as f:
    f.write(summary)

print("✓ Red Team Agent summary saved to red_team_agent_summary.txt")

# %%
# Step 10: Update Configuration for Red Team Agent
config["red_team_agent"] = {
    "timestamp": datetime.now().isoformat(),
    "missions_generated": total_missions,
    "target_ip": current_vple_ip,
    "agent_performance_score": avg_agent_score,
    "total_attack_vectors": total_mitre_techniques + total_capec_patterns,
    "unique_techniques_discovered": len(total_unique_techniques),
    "mitre_techniques_used": total_mitre_techniques,
    "capec_patterns_used": total_capec_patterns,
    "knowledge_base_utilization": len(total_unique_techniques) / config.get('rag_setup', {}).get('total_attack_patterns', 1),
    "agent_status": "OPERATIONAL" if avg_agent_score > 6 else "NEEDS_IMPROVEMENT",
    "ready_for_blue_team": avg_agent_score > 5,
    "files_created": total_missions * 2 + 2  # JSON + TXT per mission + complete + summary
}

with open("vple_config.json", "w") as f:
    json.dump(config, f, indent=2)

print("\nRED TEAM AGENT DEPLOYMENT COMPLETE!")
print("=" * 60)
print(f"✓ Generated: {total_missions} autonomous attack missions")
print(f"✓ Target: VPLE VM at {current_vple_ip}")
print(f"✓ Agent Score: {avg_agent_score:.1f}/10")
print(f"✓ Techniques Discovered: {len(total_unique_techniques)}")
print(f"✓ Knowledge Utilization: {len(total_unique_techniques)}/{config.get('rag_setup', {}).get('total_attack_patterns', '?')} patterns")

if config["red_team_agent"]["agent_status"] == "OPERATIONAL":
    print(f"\n🎯 RED TEAM AGENT IS OPERATIONAL AND READY!")
    print(f"The agent successfully selected attack techniques from a complete")
    print(f"CAPEC/MITRE database without bias or pre-filtering.")
    print(f"\nNext: Execute these missions manually, then develop Blue Team Agent")
    print(f"for defensive analysis and iterative Red Team vs Blue Team cycles.")
else:
    print(f"\n⚠ Red Team Agent needs improvement before full deployment")
    print(f"Consider refining the knowledge base or agent prompts")

print(f"\nFiles ready for manual execution in red_team_plans/ directory!")

