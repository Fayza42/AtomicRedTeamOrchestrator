# Notebook 5: Vulnerability Analyzer Agent

# %% [markdown]
"""
# VPLE & Vulhub Attack Scenario Generator - Notebook 5
## Agent d'Analyse de Vulnérabilités

Cet agent a pour mission de combiner la connaissance passive (RAG Vulhub) 
avec une reconnaissance active pour confirmer la présence d'une vulnérabilité sur une cible.

### Workflow de l'Agent :
1.  **Input** : Nom de la VM Vulhub (ex: `apache/CVE-2021-41773`) et son adresse IP/port.
2.  **Interroger le RAG** : Récupérer la documentation Vulhub correspondante.
3.  **Analyser la Documentation** : Le LLM extrait les informations clés (ports, commandes, payloads).
4.  **Utiliser les Outils Actifs** :
    -   `network_scanner` : Vérifier si les ports sont ouverts.
    -   `http_prober` : Exécuter les commandes `curl` de la documentation.
    -   `cve_enricher` : Obtenir des détails (CVSS) sur les CVEs associés.
5.  **Synthétiser les Résultats** : Le LLM combine toutes les informations pour produire un rapport structuré.
6.  **Output** : Rapport JSON contenant le plan d'attaque validé.
"""

# %%
# Step 1: Imports, configuration et initialisation
import os
import json
import subprocess
import sys
import requests
import socket
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

print("Chargement de la configuration...")
try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    model_name = config.get("confirmed_model")
    vulhub_db_path = config.get("vulhub_rag_setup", {}).get("db_path")
    if not model_name or not vulhub_db_path:
        raise ValueError("Configuration incomplète. Veuillez exécuter les notebooks 1 à 4.")
    print(f"✓ Configuration chargée. Modèle: {model_name}, DB Vulhub: {vulhub_db_path}")
except (FileNotFoundError, ValueError) as e:
    print(f"✗ Erreur de configuration : {e}")
    exit(1)

# Initialisation du LLM et des Embeddings
llm = Ollama(model=model_name)
embeddings = OllamaEmbeddings(model=model_name)

# Connexion à la base de données Vulhub
print("Connexion à la base de données vectorielle Vulhub...")
vectorstore_vulhub = Chroma(persist_directory=vulhub_db_path, embedding_function=embeddings)
retriever = vectorstore_vulhub.as_retriever(search_kwargs={"k": 1})
print("✓ Connecté à la base de données Vulhub.")

# %%
# Step 2: Définition des Outils de l'Agent (Tools)
print("Définition des outils de l'agent...")

def network_scanner(host, ports):
    """Vérifie si une liste de ports est ouverte sur un hôte donné."""
    results = {}
    print(f"TOOL: [network_scanner] - scan de {host} sur les ports {ports}")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((host, port))
                results[port] = "ouvert"
        except (socket.timeout, ConnectionRefusedError):
            results[port] = "fermé"
        except Exception as e:
            results[port] = f"erreur ({e})"
    return json.dumps(results)

def http_prober(command):
    """Exécute une commande curl-like en utilisant la bibliothèque requests."""
    print(f"TOOL: [http_prober] - exécution de la commande : {command}")
    try:
        # Parsing basique de la commande curl
        parts = command.split()
        url_part = next((part for part in parts if part.startswith('http')), None)
        if not url_part:
            return "Erreur: URL non trouvée dans la commande."
        
        # Nettoyer l'URL (enlever les guillemets)
        url = url_part.strip("'\"")
        
        # Simulation simple - on ne gère pas les headers/data pour ce prototype
        response = requests.get(url, timeout=5, verify=False)
        
        return json.dumps({
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_preview": response.text[:500]
        })
    except Exception as e:
        return f"Erreur lors de l'exécution de la requête HTTP: {e}"

def cve_enricher(cve_id):
    """Récupère les détails d'une CVE depuis l'API Red Hat."""
    print(f"TOOL: [cve_enricher] - recherche de {cve_id}")
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id.upper()}.json"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return json.dumps({
                "cvss3_score": data.get("cvss3", {}).get("cvss3_base_score"),
                "cvss3_vector": data.get("cvss3", {}).get("cvss3_attack_vector"),
                "description": data.get("bugzilla", {}).get("description")
            })
        else:
            return f"CVE non trouvée ou erreur API (status: {response.status_code})"
    except Exception as e:
        return f"Erreur de connexion à l'API Red Hat: {e}"

tools = {
    "network_scanner": network_scanner,
    "http_prober": http_prober,
    "cve_enricher": cve_enricher
}
print("✓ Outils définis.")


# %%
# Step 3: Définition des Prompts pour le LLM

EXTRACTION_PROMPT_TEMPLATE = """
ROLE: Tu es un expert en cybersécurité spécialisé dans l'analyse de documentation technique.
TACHE: Analyse la documentation Vulhub fournie ci-dessous et extrais les informations critiques dans un format JSON strict. Ne réponds rien d'autre que le JSON.

INFORMATIONS A EXTRAIRE:
1.  `ports_exposed`: La liste des ports TCP exposés par le service vulnérable (ex: [8080, 80]).
2.  `cve_ids`: La liste des identifiants CVE mentionnés (ex: ["CVE-2021-41773"]).
3.  `reproduction_commands`: Une liste des commandes exactes (curl, wget, etc.) pour tester ou exploiter la vulnérabilité. Ne liste que les commandes complètes.
4.  `success_indicators`: Une liste de chaînes de caractères ou de comportements qui indiquent que l'exploitation a réussi (ex: ["root:x:0:0", "uid=0(root)"]).

DOCUMENTATION VULHUB:
---
{vulhub_doc}
---

FORMAT DE SORTIE (JSON uniquement):
```json
{{
    "ports_exposed": [],
    "cve_ids": [],
    "reproduction_commands": [],
    "success_indicators": []
}}```
"""
EXTRACTION_PROMPT = PromptTemplate(template=EXTRACTION_PROMPT_TEMPLATE, input_variables=["vulhub_doc"])

ANALYSIS_PROMPT_TEMPLATE = """
ROLE: Tu es un analyste en sécurité offensif. Ta mission est de créer un plan d'attaque basé sur les informations collectées.
CONTEXTE: Tu as récupéré la documentation d'une vulnérabilité (Vulhub) et tu as les résultats de tests actifs sur une cible réelle.
TACHE: Synthétise toutes les informations pour confirmer la vulnérabilité et générer un rapport d'exploitation structuré en JSON. Sois concis et direct.

DONNÉES DISPONIBLES:
1.  **Documentation Vulhub (extraite)**:
    {extracted_info}
2.  **Résultats du Scan de Ports**:
    {scan_results}
3.  **Résultats des Tests HTTP (Probing)**:
    {probe_results}
4.  **Enrichissement des données CVE**:
    {cve_results}

GÉNÈRE LE RAPPORT D'EXPLOITATION SUIVANT (JSON uniquement):```json
{{
  "target_confirmed": {{
    "status": boolean,
    "reason": "Description de pourquoi la cible est confirmée ou non."
  }},
  "vulnerability_details": {{
    "cve": "CVE-XXXX-XXXXX",
    "cvss_score": "X.X",
    "attack_vector": "NETWORK"
  }},
  "exploitation_plan": {{
    "primary_technique": "Description courte de la meilleure technique (ex: Path Traversal to RCE).",
    "commands_to_execute": [
        "commande 1 à exécuter pour l'exploitation",
        "commande 2 si nécessaire"
    ],
    "success_criteria": "Comment vérifier que l'exploitation a fonctionné (ex: 'Obtenir le contenu de /etc/passwd')."
  }},
  "next_steps_suggestion": [
    "Étape post-exploitation suggérée (ex: 'Uploader un reverse shell')."
  ]
}}