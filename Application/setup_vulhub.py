# Notebook 4: Setup Vulhub Knowledge Base for RAG

# %% [markdown]
"""
# VPLE & Vulhub Attack Scenario Generator - Notebook 4
## Création de la Base de Connaissances (RAG) Vulhub

Ce notebook a pour objectif de construire une base de connaissances vectorielle (RAG) 
spécifiquement à partir du projet Vulhub.

### Étapes :
1.  **Cloner le dépôt Vulhub** : Assurer une copie locale des données.
2.  **Parser les vulnérabilités** : Itérer sur chaque répertoire de vulnérabilité.
3.  **Extraire les informations** des fichiers `README.md`, `README.zh-cn.md` et `docker-compose.yml`.
4.  **Structurer les données** : Créer des documents clairs pour l'indexation.
5.  **Créer les Embeddings** : Utiliser le modèle Ollama pour vectoriser les documents.
6.  **Stocker dans ChromaDB** : Persister la base de données vectorielle pour une utilisation par les agents.
"""

# %%
# Step 1: Importer les dépendances et charger la configuration
import os
import json
import subprocess
import sys
from pathlib import Path
import yaml
import re
from langchain.vectorstores import Chroma
from langchain.embeddings import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document

print("Chargement de la configuration...")
try:
    with open("vple_config.json", "r") as f:
        config = json.load(f)
    model_name = config.get("confirmed_model", "llama2:13b")
    print(f"✓ Configuration chargée. Utilisation du modèle : {model_name}")
except FileNotFoundError:
    print("✗ Fichier de configuration 'vple_config.json' non trouvé. Veuillez exécuter les notebooks précédents.")
    exit(1)

# %%
# Step 2: Installer les dépendances requises
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", package])

required_packages = ["gitpython", "pyyaml", "unidecode"]
print("Installation des dépendances pour le parsing de Vulhub...")
for package in required_packages:
    try:
        install_package(package)
        print(f"✓ {package} installé.")
    except Exception as e:
        print(f"✗ Échec de l'installation de {package}: {e}")

# %%
# Step 3: Cloner ou mettre à jour le dépôt Vulhub
from git import Repo

vulhub_dir = Path("./vulhub_repo")

if not vulhub_dir.exists():
    print(f"Clonage de Vulhub dans {vulhub_dir}...")
    try:
        Repo.clone_from("https://github.com/vulhub/vulhub.git", vulhub_dir)
        print("✓ Dépôt Vulhub cloné avec succès.")
    except Exception as e:
        print(f"✗ Échec du clonage du dépôt : {e}")
        exit(1)
else:
    print("Le dépôt Vulhub existe déjà. Mise à jour...")
    try:
        repo = Repo(vulhub_dir)
        origin = repo.remotes.origin
        origin.pull()
        print("✓ Dépôt Vulhub mis à jour.")
    except Exception as e:
        print(f"✗ Échec de la mise à jour du dépôt : {e}")

# %%
# Step 4: Parser la structure de Vulhub pour extraire les informations
print("Début du parsing du dépôt Vulhub...")

def parse_vulhub_entry(vuln_path):
    """
    Extrait les informations d'un répertoire de vulnérabilité Vulhub.
    """
    entry_data = {
        "path": str(vuln_path.relative_to(vulhub_dir)),
        "readme_content": "",
        "docker_compose_content": "",
        "service": vuln_path.parent.name,
        "vulnerability_id": vuln_path.name,
        "cve_ids": []
    }

    # Extraire les CVEs depuis le nom du répertoire
    entry_data["cve_ids"] = re.findall(r'CVE-\d{4}-\d{4,7}', vuln_path.name, re.IGNORECASE)

    # Lire README.md
    readme_file = vuln_path / "README.md"
    if readme_file.exists():
        entry_data["readme_content"] = readme_file.read_text(encoding='utf-8', errors='ignore')
    
    # Lire README.zh-cn.md (souvent plus détaillé)
    readme_zh_file = vuln_path / "README.zh-cn.md"
    if readme_zh_file.exists():
        entry_data["readme_content"] += "\n\n--- CHINESE README ---\n"
        entry_data["readme_content"] += readme_zh_file.read_text(encoding='utf-8', errors='ignore')

    # Extraire les CVEs depuis le contenu du README
    entry_data["cve_ids"].extend(re.findall(r'CVE-\d{4}-\d{4,7}', entry_data["readme_content"], re.IGNORECASE))
    entry_data["cve_ids"] = sorted(list(set(entry_data["cve_ids"]))) # Dédoublonnage

    # Lire docker-compose.yml
    docker_compose_file = vuln_path / "docker-compose.yml"
    if docker_compose_file.exists():
        try:
            with open(docker_compose_file, 'r', encoding='utf-8') as f:
                compose_data = yaml.safe_load(f)
                entry_data["docker_compose_content"] = yaml.dump(compose_data)
        except Exception as e:
            entry_data["docker_compose_content"] = f"Error parsing docker-compose.yml: {e}"

    return entry_data

# Itérer sur tous les sous-répertoires qui contiennent un docker-compose.yml
vuln_entries = []
for docker_compose_file in vulhub_dir.glob('*/*/docker-compose.yml'):
    vuln_path = docker_compose_file.parent
    entry = parse_vulhub_entry(vuln_path)
    if entry["readme_content"]: # On ne garde que les entrées avec un README
        vuln_entries.append(entry)

print(f"✓ Parsing terminé. {len(vuln_entries)} vulnérabilités documentées trouvées.")
# Afficher un exemple
print("\n--- Exemple d'entrée parsée ---")
print(json.dumps(vuln_entries[20], indent=2))
print("----------------------------")

# %%
# Step 5: Convertir les données parsées en Documents LangChain
from unidecode import unidecode

langchain_docs = []
for entry in vuln_entries:
    # Nettoyer le contenu pour le LLM
    # unidecode aide à gérer les caractères non-ASCII des README chinois
    clean_readme = unidecode(entry['readme_content'])
    
    content = f"""
Vulnerability Documentation for: {entry['path']}
Associated CVEs: {', '.join(entry['cve_ids']) if entry['cve_ids'] else 'N/A'}
Service Affected: {entry['service']}

## README Content:
{clean_readme}

## Docker-Compose Configuration:
{entry['docker_compose_content']}
"""
    
    metadata = {
        "source": "vulhub",
        "path": entry['path'],
        "service": entry['service'],
        "vulnerability_id": entry['vulnerability_id'],
        "cves": ', '.join(entry['cve_ids'])
    }
    
    doc = Document(page_content=content, metadata=metadata)
    langchain_docs.append(doc)

print(f"✓ {len(langchain_docs)} documents LangChain créés.")

# %%
# Step 6: Créer la base de données vectorielle ChromaDB
print("Création de la base de données vectorielle Vulhub...")

chroma_path_vulhub = "./vulhub_chroma_db"

# Supprimer l'ancienne base de données si elle existe
if os.path.exists(chroma_path_vulhub):
    import shutil
    shutil.rmtree(chroma_path_vulhub)
    print(f"✓ Ancienne base de données supprimée de '{chroma_path_vulhub}'.")

try:
    # Initialiser les embeddings via Ollama
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Tester si le service d'embedding fonctionne
    print("Test de la génération d'embedding...")
    test_emb = embeddings.embed_query("testing vulhub knowledge base setup")
    print(f"✓ Service d'embedding fonctionnel (dimension: {len(test_emb)}).")
    
    # Créer la base de données vectorielle
    # Pas besoin de splitter les documents ici, car chaque document représente une vulnérabilité unique et atomique.
    # Le contexte complet est important.
    print(f"Indexation de {len(langchain_docs)} documents dans ChromaDB. Cela peut prendre plusieurs minutes...")
    vectorstore_vulhub = Chroma.from_documents(
        documents=langchain_docs,
        embedding=embeddings,
        persist_directory=chroma_path_vulhub
    )
    
    print(f"✓ Base de données vectorielle Vulhub créée avec succès à l'emplacement : '{chroma_path_vulhub}'")
    
    # Sauvegarder l'information dans le fichier de config
    config['vulhub_rag_setup'] = {
        'db_path': chroma_path_vulhub,
        'total_documents': len(langchain_docs),
        'model_used': model_name
    }
    with open("vple_config.json", "w") as f:
        json.dump(config, f, indent=2)
    print("✓ Configuration mise à jour avec les informations du RAG Vulhub.")

except Exception as e:
    print(f"✗ Une erreur est survenue lors de la création de la base de données vectorielle : {e}")
    print("Veuillez vérifier que le service Ollama est bien démarré et que le modèle est disponible.")
    raise e

# %%
# Step 7: Tester la base de données RAG Vulhub
print("\n--- Test de la base de données RAG Vulhub ---")
test_queries = [
    "apache CVE-2021-41773 path traversal",
    "struts2 s2-001 remote code execution",
    "weblogic deserialization rce"
]

retriever = vectorstore_vulhub.as_retriever(search_kwargs={"k": 1})

for query in test_queries:
    print(f"\n> Recherche pour : '{query}'")
    results = retriever.get_relevant_documents(query)
    if results:
        doc = results[0]
        print(f"  [✓] Document trouvé : {doc.metadata['path']}")
        print(f"      Service : {doc.metadata['service']}")
        print(f"      CVEs    : {doc.metadata['cves']}")
        print("      Extrait : " + doc.page_content[:400].replace('\n', ' ') + "...")
    else:
        print("  [✗] Aucun document pertinent trouvé.")
        
print("\n--- Test terminé ---")


# %%
print("\n✅ SETUP DE LA BASE DE CONNAISSANCES VULHUB TERMINÉ !")
print("Prochaine étape : développer l'agent d'analyse de vulnérabilités dans `notebook_05_agent_vulnerability_analyzer.ipynb`.")