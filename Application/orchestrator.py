
---
### **Notebook 6: `notebook_06_interactive_orchestrator.ipynb`**

Ce dernier notebook sert de point d'entrée pour l'utilisateur. Il gère l'interaction et appelle l'agent d'analyse.

```python
# Notebook 6: Interactive Orchestrator

# %% [markdown]
"""
# VPLE & Vulhub Attack Scenario Generator - Notebook 6
## Orchestrateur Interactif

Ce notebook est le point d'entrée principal pour l'utilisateur. Il pilote le système 
multi-agents en posant des questions et en invoquant les agents appropriés.

### Rôle de l'Orchestrateur :
1.  **Interagir avec l'utilisateur** pour identifier la cible.
2.  **Instancier et lancer l'agent** `VulnerabilityAnalyzerAgent`.
3.  **Afficher les résultats** de manière claire et structurée.
4.  **Préparer le passage** des informations à un futur agent d'exploitation (Red Team).
"""

# %%
# Step 1: Imports et rechargement des classes/fonctions nécessaires
import json
import os
import sys
import re
import socket
import requests
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

# Pour installer des paquets dans le notebook
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", package])

# Installer questionary pour des prompts interactifs
try:
    import questionary
except ImportError:
    print("Installation de 'questionary' pour l'interface interactive...")
    install_package('questionary')
    import questionary

# Re-définition de l'agent et des outils pour un notebook autonome
# (Dans une application réelle, on importerait depuis des modules .py)

# --- Outils ---
def network_scanner(host, ports):
    results = {}
    print(f"TOOL: [network_scanner] - scan de {host} sur les ports {ports}")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1); s.connect((host, port)); results[port] = "ouvert"
        except: results[port] = "fermé"
    return json.dumps(results)

def http_prober(command):
    print(f"TOOL: [http_prober] - exécution : {command}")
    try:
        url = re.search(r"https?://[^\s\'\"]+", command).group(0)
        response = requests.get(url, timeout=5, verify=False)
        return json.dumps({"status_code": response.status_code, "content_preview": response.text[:250]})
    except Exception as e: return f"Erreur: {e}"

def cve_enricher(cve_id):
    print(f"TOOL: [cve_enricher] - recherche de {cve_id}")
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id.upper()}.json"
    try:
        r = requests.get(url, timeout=5)
        return r.json() if r.ok else {"error": r.status_code}
    except Exception as e: return {"error": str(e)}

# --- Prompts ---
EXTRACTION_PROMPT_TEMPLATE = """Analyse cette doc Vulhub et extrais en JSON : `ports_exposed` (list[int]), `cve_ids` (list[str]), `reproduction_commands` (list[str]), `success_indicators` (list[str]).\n\nDoc: {vulhub_doc}\n\nJSON:"""
ANALYSIS_PROMPT_TEMPLATE = """Crée un rapport d'exploitation JSON basé sur ces données. Champs: `target_confirmed` (bool, reason), `vulnerability_details` (cve, cvss_score, attack_vector), `exploitation_plan` (primary_technique, commands_to_execute, success_criteria), `next_steps_suggestion` (list[str]).\n\nDoc extraite: {extracted_info}\nScan: {scan_results}\nProbes: {probe_results}\nCVE data: {cve_results}\n\nJSON:"""

# --- Agent Class ---
# Note : C'est une version simplifiée pour la clarté de l'orchestrateur.
# La version complète est dans le notebook 05.
class VulnerabilityAnalyzerAgent:
    def __init__(self, llm, retriever):
        self.llm = llm
        self.retriever = retriever
        self.tools = {"network_scanner": network_scanner, "http_prober": http_prober, "cve_enricher": cve_enricher}
    def run(self, vulnhub_id, target_ip):
        print(f"\n--- Analyse de {vulnhub_id} sur {target_ip} ---")
        docs = self.retriever.get_relevant_documents(vulnhub_id)
        if not docs: return {"error": "Doc non trouvée"}
        
        extraction_prompt = PromptTemplate.from_template(EXTRACTION_PROMPT_TEMPLATE)
        extraction_chain = LLMChain(llm=self.llm, prompt=extraction_prompt)
        extracted_info_raw = extraction_chain.run(vulhub_doc=docs[0].page_content)
        extracted_info = json.loads(re.search(r'\{.*\}', extracted_info_raw, re.DOTALL).group(0))
        
        ports = extracted_info.get("ports_exposed", [])
        scan_res = self.tools['network_scanner'](target_ip.split(':')[0], ports)
        
        probe_res = {}
        for cmd in extracted_info.get("reproduction_commands", []):
            final_cmd = cmd.replace("your-ip:8080", target_ip).replace("your-ip", target_ip.split(':')[0])
            probe_res[final_cmd] = self.tools['http_prober'](final_cmd)
        
        cve_res = self.tools['cve_enricher'](extracted_info.get("cve_ids", [None])[0]) if extracted_info.get("cve_ids") else {}
        
        analysis_prompt = PromptTemplate.from_template(ANALYSIS_PROMPT_TEMPLATE)
        analysis_chain = LLMChain(llm=self.llm, prompt=analysis_prompt)
        final_report_raw = analysis_chain.run(extracted_info=json.dumps(extracted_info), scan_results=scan_res, probe_results=json.dumps(probe_res), cve_results=json.dumps(cve_res))
        final_report = json.loads(re.search(r'\{.*\}', final_report_raw, re.DOTALL).group(0))
        
        return final_report

# %%
# Step 2: Initialisation de l'environnement de l'orchestrateur
print("Initialisation de l'orchestrateur...")
try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    model_name = config["confirmed_model"]
    vulhub_db_path = config["vulhub_rag_setup"]["db_path"]

    llm = Ollama(model=model_name)
    embeddings = OllamaEmbeddings(model=model_name)
    vectorstore = Chroma(persist_directory=vulhub_db_path, embedding_function=embeddings)
    retriever = vectorstore.as_retriever(search_kwargs={"k": 1})
    
    agent = VulnerabilityAnalyzerAgent(llm, retriever)
    print("✓ Orchestrateur prêt.")
except Exception as e:
    print(f"✗ Erreur d'initialisation : {e}. Veuillez vérifier les notebooks précédents.")
    exit(1)

# %%
# Step 3: Boucle d'interaction principale
def main_loop():
    print("\n" + "="*50)
    print("🤖 Bienvenue dans l'Orchestrateur d'Analyse de Vulnérabilités")
    print("="*50)

    try:
        vulnhub_id = questionary.text(
            "Quelle VM Vulhub est actuellement UP ? (format: service/CVE-ID)",
            default="apache/CVE-2021-41773"
        ).ask()

        if not vulnhub_id:
            print("Annulation.")
            return

        target_ip = questionary.text(
            f"Quelle est l'adresse IP et le port de la cible pour '{vulnhub_id}' ?",
            default="127.0.0.1:8080"
        ).ask()
        
        if not target_ip:
            print("Annulation.")
            return

        # Lancer l'agent d'analyse
        with open("analysis_report.json", "w") as f: # Préparer un fichier pour le rapport
            f.write("")

        analysis_report = agent.run(vulnhub_id, target_ip)

        # Afficher le rapport final
        print("\n" + "---" * 20)
        print("✅ RAPPORT D'ANALYSE FINAL REÇU PAR L'ORCHESTRATEUR")
        print("---" * 20)
        
        if analysis_report and "error" not in analysis_report:
            report_str = json.dumps(analysis_report, indent=2)
            print(report_str)
            
            # Sauvegarder le rapport pour l'agent Red Team
            with open("analysis_report.json", "w") as f:
                f.write(report_str)
            print(f"\n✓ Le rapport a été sauvegardé dans 'analysis_report.json' pour l'agent Red Team.")
            
            print("\nProchaine étape : Lancer `notebook_07_red_team_agent.ipynb` (à développer) avec ce rapport.")
        else:
            print("\n✗ L'analyse a échoué.")
            print(f"Raison : {analysis_report.get('error', 'Inconnue')}")

    except KeyboardInterrupt:
        print("\n👋 Au revoir !")
    except Exception as e:
        print(f"\n💥 Une erreur inattendue est survenue : {e}")

if __name__ == "__main__":
    main_loop()

# %%
print("\n✅ ORCHESTRATEUR INTERACTIF PRÊT.")
print("Exécutez la cellule ci-dessus (`main_loop()`) pour démarrer l'interaction.")