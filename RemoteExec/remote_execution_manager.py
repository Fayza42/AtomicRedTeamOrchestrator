# Remote Execution Manager - SSH + Docker Integration
# Filename: remote_execution_manager.py

"""
Module pour l'exécution distante sur les machines Docker via SSH
Architecture: Container LLM → SSH (100.91.1.1) → docker exec → Container Vulhub
"""

import paramiko
import json
import time
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import subprocess
from pathlib import Path

# Installation paramiko si nécessaire
try:
    import paramiko
except ImportError:
    print("Installation de paramiko...")
    subprocess.check_call(["pip", "install", "paramiko"])
    import paramiko

print("🐳 Remote Execution Manager - SSH + Docker")

# %%
@dataclass
class RemoteTarget:
    """Configuration d'une cible distante"""
    
    container_id: str
    container_name: str
    vulhub_path: str  # ex: "apache/CVE-2021-41773"
    exposed_ports: List[int]
    internal_ip: str = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "container_id": self.container_id,
            "container_name": self.container_name,
            "vulhub_path": self.vulhub_path,
            "exposed_ports": self.exposed_ports,
            "internal_ip": self.internal_ip
        }

@dataclass 
class SSHConfig:
    """Configuration SSH pour la machine hôte"""
    
    host: str = "100.91.1.1"
    port: int = 22
    username: str = "root"  # Ou utilisateur avec accès Docker
    password: str = None
    key_file: str = None
    timeout: int = 30
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port, 
            "username": self.username,
            "timeout": self.timeout,
            "has_password": bool(self.password),
            "has_key": bool(self.key_file)
        }

print("✅ Configuration classes defined")

# %%
class SSHDockerManager:
    """
    Gestionnaire pour les connexions SSH + Docker
    Permet l'exécution de commandes sur des containers distants
    """
    
    def __init__(self, ssh_config: SSHConfig):
        self.ssh_config = ssh_config
        self.ssh_client = None
        self.connected = False
        self.active_containers = {}
        
        print(f"🔗 Initialisation SSH Manager pour {ssh_config.host}")
    
    def connect(self) -> bool:
        """Établit la connexion SSH vers la machine hôte"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Tentative de connexion
            if self.ssh_config.key_file:
                print(f"🔑 Connexion SSH avec clé: {self.ssh_config.key_file}")
                self.ssh_client.connect(
                    hostname=self.ssh_config.host,
                    port=self.ssh_config.port,
                    username=self.ssh_config.username,
                    key_filename=self.ssh_config.key_file,
                    timeout=self.ssh_config.timeout
                )
            elif self.ssh_config.password:
                print(f"🔐 Connexion SSH avec mot de passe")
                self.ssh_client.connect(
                    hostname=self.ssh_config.host,
                    port=self.ssh_config.port,
                    username=self.ssh_config.username,
                    password=self.ssh_config.password,
                    timeout=self.ssh_config.timeout
                )
            else:
                print(f"🔓 Connexion SSH sans authentification")
                self.ssh_client.connect(
                    hostname=self.ssh_config.host,
                    port=self.ssh_config.port,
                    username=self.ssh_config.username,
                    timeout=self.ssh_config.timeout
                )
            
            self.connected = True
            print(f"✅ Connexion SSH établie vers {self.ssh_config.host}")
            
            # Test de base
            result = self.execute_host_command("echo 'SSH Test OK'")
            if result['success']:
                print(f"✅ Test SSH réussi: {result['stdout'].strip()}")
                return True
            else:
                print(f"❌ Test SSH échoué: {result['stderr']}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur connexion SSH: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Ferme la connexion SSH"""
        if self.ssh_client:
            self.ssh_client.close()
            self.connected = False
            print("🔌 Connexion SSH fermée")
    
    def execute_host_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Exécute une commande sur la machine hôte"""
        if not self.connected:
            return {"success": False, "error": "SSH non connecté"}
        
        try:
            print(f"🖥️ Commande hôte: {command}")
            
            stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
            
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            return_code = stdout.channel.recv_exit_status()
            
            result = {
                "success": return_code == 0,
                "return_code": return_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "command": command
            }
            
            if result["success"]:
                print(f"  ✅ Succès (code {return_code})")
            else:
                print(f"  ❌ Échec (code {return_code}): {stderr_data[:100]}")
            
            return result
            
        except Exception as e:
            print(f"  💥 Erreur exécution: {e}")
            return {"success": False, "error": str(e)}
    
    def list_docker_containers(self) -> List[Dict[str, str]]:
        """Liste tous les containers Docker disponibles"""
        print("🐳 Énumération des containers Docker...")
        
        # Commande pour lister les containers avec format personnalisé
        cmd = "docker ps --format 'table {{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'"
        result = self.execute_host_command(cmd)
        
        if not result['success']:
            print(f"❌ Impossible de lister les containers: {result.get('stderr', 'Erreur inconnue')}")
            return []
        
        containers = []
        lines = result['stdout'].strip().split('\n')[1:]  # Skip header
        
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 4:
                    container_info = {
                        "id": parts[0].strip(),
                        "name": parts[1].strip(),
                        "image": parts[2].strip(),
                        "status": parts[3].strip(),
                        "ports": parts[4].strip() if len(parts) > 4 else ""
                    }
                    containers.append(container_info)
        
        print(f"  📦 {len(containers)} containers trouvés")
        for container in containers:
            print(f"    🐳 {container['id'][:12]} | {container['name']} | {container['image']}")
        
        return containers
    
    def execute_container_command(self, container_id: str, command: str, timeout: int = 30) -> Dict[str, Any]:
        """Exécute une commande dans un container spécifique via docker exec"""
        if not self.connected:
            return {"success": False, "error": "SSH non connecté"}
        
        # Construction de la commande docker exec
        docker_cmd = f"docker exec {container_id} /bin/bash -c '{command}'"
        
        print(f"🐳 Container {container_id[:12]}: {command}")
        
        result = self.execute_host_command(docker_cmd, timeout)
        
        # Ajout d'informations spécifiques au container
        result['container_id'] = container_id
        result['container_command'] = command
        
        return result
    
    def get_container_info(self, container_id: str) -> Dict[str, Any]:
        """Récupère les informations détaillées d'un container"""
        print(f"🔍 Inspection du container {container_id[:12]}...")
        
        # Inspection Docker
        inspect_cmd = f"docker inspect {container_id}"
        result = self.execute_host_command(inspect_cmd)
        
        if not result['success']:
            return {"success": False, "error": "Impossible d'inspecter le container"}
        
        try:
            # Parse du JSON Docker
            import json
            inspect_data = json.loads(result['stdout'])[0]
            
            container_info = {
                "id": inspect_data['Id'][:12],
                "name": inspect_data['Name'].lstrip('/'),
                "image": inspect_data['Config']['Image'],
                "status": inspect_data['State']['Status'],
                "ip_address": inspect_data['NetworkSettings'].get('IPAddress', ''),
                "ports": inspect_data['NetworkSettings'].get('Ports', {}),
                "env_vars": inspect_data['Config'].get('Env', []),
                "working_dir": inspect_data['Config'].get('WorkingDir', '/'),
                "volumes": inspect_data.get('Mounts', [])
            }
            
            print(f"  📋 Container: {container_info['name']}")
            print(f"  🏷️ Image: {container_info['image']}")
            print(f"  🌐 IP: {container_info['ip_address']}")
            print(f"  🔌 Ports: {len(container_info['ports'])} exposés")
            
            return {"success": True, "info": container_info}
            
        except json.JSONDecodeError as e:
            return {"success": False, "error": f"Erreur parsing JSON: {e}"}
    
    def test_container_connectivity(self, container_id: str) -> Dict[str, Any]:
        """Teste la connectivité et les capacités d'un container"""
        print(f"🧪 Test de connectivité du container {container_id[:12]}...")
        
        tests = {}
        
        # Test 1: Commande de base
        result = self.execute_container_command(container_id, "echo 'Container Test OK'")
        tests['basic_command'] = result['success']
        
        if not tests['basic_command']:
            return {"success": False, "error": "Container non accessible", "tests": tests}
        
        # Test 2: Informations système
        result = self.execute_container_command(container_id, "uname -a")
        tests['system_info'] = result['success']
        if tests['system_info']:
            tests['os_info'] = result['stdout'].strip()
        
        # Test 3: Outils réseau disponibles
        network_tools = {}
        for tool in ['curl', 'wget', 'nmap', 'netstat', 'ss']:
            result = self.execute_container_command(container_id, f"which {tool}")
            network_tools[tool] = result['success']
        
        tests['network_tools'] = network_tools
        
        # Test 4: Permissions et utilisateur
        result = self.execute_container_command(container_id, "id")
        tests['user_info'] = result['success']
        if tests['user_info']:
            tests['current_user'] = result['stdout'].strip()
        
        # Test 5: Système de fichiers
        result = self.execute_container_command(container_id, "ls -la /")
        tests['filesystem_access'] = result['success']
        
        print(f"  ✅ Tests terminés: {sum(tests.values())} succès")
        
        return {
            "success": True,
            "tests": tests,
            "connectivity_score": sum(tests.values()) / len(tests)
        }

print("✅ SSHDockerManager class defined")

# %%
class RemoteReconnaissanceTools:
    """
    Outils de reconnaissance avancés pour l'agent Analyzer
    Exécution directe sur les containers via SSH + Docker
    """
    
    def __init__(self, ssh_manager: SSHDockerManager):
        self.ssh_manager = ssh_manager
        self.target_container = None
        
        print("🔍 Remote Reconnaissance Tools initialized")
    
    def set_target_container(self, container_id: str):
        """Définit le container cible pour les opérations"""
        self.target_container = container_id
        print(f"🎯 Container cible défini: {container_id[:12]}")
    
    def nmap_scan(self, target: str = "127.0.0.1", ports: str = "1-1000") -> Dict[str, Any]:
        """Scan nmap depuis le container"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print(f"🔍 Scan nmap de {target} ports {ports}")
        
        # Vérifier si nmap est disponible
        nmap_check = self.ssh_manager.execute_container_command(
            self.target_container, "which nmap"
        )
        
        if not nmap_check['success']:
            # Tentative d'installation de nmap
            print("  📦 Installation de nmap...")
            install_cmd = "apt-get update && apt-get install -y nmap"
            install_result = self.ssh_manager.execute_container_command(
                self.target_container, install_cmd, timeout=120
            )
            
            if not install_result['success']:
                return {"success": False, "error": "Impossible d'installer nmap"}
        
        # Exécution du scan nmap
        nmap_cmd = f"nmap -sT -O -sV {target} -p {ports}"
        result = self.ssh_manager.execute_container_command(
            self.target_container, nmap_cmd, timeout=60
        )
        
        if result['success']:
            # Parse basique des résultats nmap
            nmap_output = result['stdout']
            
            # Extraction des ports ouverts
            open_ports = []
            for line in nmap_output.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port_match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', line)
                    if port_match:
                        open_ports.append({
                            "port": int(port_match.group(1)),
                            "service": port_match.group(2)
                        })
            
            print(f"  ✅ {len(open_ports)} ports ouverts trouvés")
            
            return {
                "success": True,
                "raw_output": nmap_output,
                "open_ports": open_ports,
                "target": target,
                "scan_type": "nmap"
            }
        else:
            return {"success": False, "error": result.get('stderr', 'Scan nmap échoué')}
    
    def netstat_scan(self) -> Dict[str, Any]:
        """Analyse des connexions réseau avec netstat"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print("🌐 Analyse netstat...")
        
        # Commandes netstat diverses
        commands = {
            "listening_ports": "netstat -tuln",
            "established_connections": "netstat -tun",
            "processes": "netstat -tulnp 2>/dev/null || netstat -tuln"
        }
        
        results = {}
        
        for cmd_name, cmd in commands.items():
            result = self.ssh_manager.execute_container_command(
                self.target_container, cmd
            )
            
            if result['success']:
                results[cmd_name] = {
                    "raw_output": result['stdout'],
                    "parsed": self._parse_netstat_output(result['stdout'], cmd_name)
                }
            else:
                results[cmd_name] = {"error": result.get('stderr', 'Commande échouée')}
        
        return {"success": True, "netstat_results": results}
    
    def _parse_netstat_output(self, output: str, cmd_type: str) -> List[Dict[str, Any]]:
        """Parse la sortie netstat"""
        parsed = []
        
        for line in output.split('\n'):
            if 'tcp' in line.lower() or 'udp' in line.lower():
                parts = line.split()
                if len(parts) >= 4:
                    parsed.append({
                        "protocol": parts[0],
                        "local_address": parts[3],
                        "foreign_address": parts[4] if len(parts) > 4 else "",
                        "state": parts[5] if len(parts) > 5 else ""
                    })
        
        return parsed
    
    def process_scan(self) -> Dict[str, Any]:
        """Analyse des processus en cours"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print("⚙️ Analyse des processus...")
        
        # Commandes pour analyser les processus
        commands = {
            "ps_aux": "ps aux",
            "ps_tree": "ps -ef --forest",
            "top_snapshot": "top -b -n 1"
        }
        
        results = {}
        
        for cmd_name, cmd in commands.items():
            result = self.ssh_manager.execute_container_command(
                self.target_container, cmd
            )
            
            if result['success']:
                results[cmd_name] = result['stdout']
            else:
                results[cmd_name] = f"Erreur: {result.get('stderr', 'Commande échouée')}"
        
        return {"success": True, "process_results": results}
    
    def web_service_discovery(self, base_url: str = "http://localhost") -> Dict[str, Any]:
        """Découverte des services web depuis le container"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print(f"🌐 Découverte web sur {base_url}")
        
        # Ports web communs à tester
        web_ports = [80, 8080, 8443, 443, 3000, 8000, 8888, 9000]
        
        discoveries = {}
        
        for port in web_ports:
            test_url = f"{base_url}:{port}"
            
            # Test avec curl
            curl_cmd = f"curl -s -I -m 5 {test_url}"
            result = self.ssh_manager.execute_container_command(
                self.target_container, curl_cmd
            )
            
            if result['success'] and result['stdout']:
                # Parse des headers HTTP
                headers = {}
                for line in result['stdout'].split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                discoveries[port] = {
                    "accessible": True,
                    "headers": headers,
                    "url": test_url
                }
                print(f"  ✅ Service trouvé sur port {port}")
            else:
                discoveries[port] = {"accessible": False}
        
        return {"success": True, "web_discoveries": discoveries}
    
    def filesystem_reconnaissance(self) -> Dict[str, Any]:
        """Reconnaissance du système de fichiers"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print("📁 Reconnaissance filesystem...")
        
        recon_commands = {
            "root_listing": "ls -la /",
            "home_dirs": "ls -la /home/ 2>/dev/null || echo 'No /home'",
            "var_www": "ls -la /var/www/ 2>/dev/null || echo 'No /var/www'",
            "etc_configs": "ls -la /etc/ | head -20",
            "tmp_contents": "ls -la /tmp/",
            "proc_version": "cat /proc/version 2>/dev/null || echo 'No /proc/version'",
            "passwd_users": "cat /etc/passwd | head -10"
        }
        
        results = {}
        
        for cmd_name, cmd in recon_commands.items():
            result = self.ssh_manager.execute_container_command(
                self.target_container, cmd
            )
            
            results[cmd_name] = {
                "success": result['success'],
                "output": result['stdout'] if result['success'] else result.get('stderr', '')
            }
        
        return {"success": True, "filesystem_recon": results}

print("✅ RemoteReconnaissanceTools class defined")

# %%
class RemoteExploitExecutor:
    """
    Exécuteur d'exploits pour l'agent Red Team
    Exécution directe des scripts sur les containers cibles
    """
    
    def __init__(self, ssh_manager: SSHDockerManager):
        self.ssh_manager = ssh_manager
        self.target_container = None
        self.exploit_workspace = "/tmp/exploits"
        
        print("💥 Remote Exploit Executor initialized")
    
    def set_target_container(self, container_id: str):
        """Définit le container cible pour l'exploitation"""
        self.target_container = container_id
        print(f"🎯 Container cible pour exploitation: {container_id[:12]}")
        
        # Création du workspace d'exploits
        self._setup_exploit_workspace()
    
    def _setup_exploit_workspace(self):
        """Crée l'espace de travail pour les exploits"""
        if not self.target_container:
            return
        
        setup_cmd = f"mkdir -p {self.exploit_workspace} && chmod 755 {self.exploit_workspace}"
        result = self.ssh_manager.execute_container_command(
            self.target_container, setup_cmd
        )
        
        if result['success']:
            print(f"  📁 Workspace créé: {self.exploit_workspace}")
        else:
            print(f"  ⚠ Erreur création workspace: {result.get('stderr', '')}")
    
    def upload_and_execute_script(self, script_content: str, script_name: str, 
                                 script_language: str = "python") -> Dict[str, Any]:
        """Upload et exécution d'un script d'exploit"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print(f"📤 Upload et exécution: {script_name}")
        
        # Détermination de l'extension et de l'exécuteur
        extensions = {
            "python": ".py",
            "bash": ".sh", 
            "shell": ".sh",
            "perl": ".pl",
            "php": ".php"
        }
        
        executors = {
            "python": "python3",
            "bash": "/bin/bash",
            "shell": "/bin/bash", 
            "perl": "perl",
            "php": "php"
        }
        
        extension = extensions.get(script_language.lower(), ".txt")
        executor = executors.get(script_language.lower(), "cat")
        
        script_path = f"{self.exploit_workspace}/{script_name}{extension}"
        
        # Étape 1: Upload du script via echo (évite les problèmes de transfert de fichier)
        # Encode le script pour éviter les problèmes avec les caractères spéciaux
        import base64
        encoded_script = base64.b64encode(script_content.encode()).decode()
        
        upload_cmd = f"echo '{encoded_script}' | base64 -d > {script_path}"
        upload_result = self.ssh_manager.execute_container_command(
            self.target_container, upload_cmd
        )
        
        if not upload_result['success']:
            return {
                "success": False, 
                "error": f"Échec upload script: {upload_result.get('stderr', '')}"
            }
        
        # Étape 2: Rendre le script exécutable
        chmod_cmd = f"chmod +x {script_path}"
        self.ssh_manager.execute_container_command(self.target_container, chmod_cmd)
        
        # Étape 3: Exécution du script
        if script_language.lower() in ["bash", "shell"]:
            exec_cmd = f"{executor} {script_path}"
        else:
            exec_cmd = f"{executor} {script_path}"
        
        print(f"  ⚡ Exécution: {exec_cmd}")
        
        exec_result = self.ssh_manager.execute_container_command(
            self.target_container, exec_cmd, timeout=60
        )
        
        return {
            "success": exec_result['success'],
            "script_path": script_path,
            "execution_output": exec_result['stdout'],
            "execution_errors": exec_result.get('stderr', ''),
            "return_code": exec_result.get('return_code', -1),
            "executor_used": executor
        }
    
    def execute_direct_command(self, command: str, description: str = "") -> Dict[str, Any]:
        """Exécution directe d'une commande d'exploit"""
        if not self.target_container:
            return {"success": False, "error": "Container cible non défini"}
        
        print(f"⚡ Commande directe: {description or command[:50]}...")
        
        result = self.ssh_manager.execute_container_command(
            self.target_container, command, timeout=30
        )
        
        return {
            "success": result['success'],
            "command": command,
            "description": description,
            "output": result['stdout'],
            "errors": result.get('stderr', ''),
            "return_code": result.get('return_code', -1)
        }
    
    def setup_reverse_shell_listener(self, listen_port: int = 4444) -> Dict[str, Any]:
        """Configure un listener reverse shell sur la machine hôte"""
        print(f"🎧 Configuration listener reverse shell sur port {listen_port}")
        
        # Vérifier si netcat est disponible sur l'hôte
        nc_check = self.ssh_manager.execute_host_command("which nc")
        
        if not nc_check['success']:
            return {
                "success": False,
                "error": "Netcat non disponible sur la machine hôte"
            }
        
        # Démarrage du listener en arrière-plan
        # Note: Cette commande démarre le listener mais ne bloque pas
        listener_cmd = f"nohup nc -lvp {listen_port} > /tmp/reverse_shell_{listen_port}.log 2>&1 &"
        
        result = self.ssh_manager.execute_host_command(listener_cmd)
        
        if result['success']:
            print(f"  ✅ Listener démarré sur port {listen_port}")
            
            # Récupération du PID du listener
            pid_cmd = f"ps aux | grep 'nc -lvp {listen_port}' | grep -v grep | awk '{{print $2}}'"
            pid_result = self.ssh_manager.execute_host_command(pid_cmd)
            
            return {
                "success": True,
                "port": listen_port,
                "pid": pid_result['stdout'].strip() if pid_result['success'] else None,
                "log_file": f"/tmp/reverse_shell_{listen_port}.log"
            }
        else:
            return {
                "success": False,
                "error": f"Échec démarrage listener: {result.get('stderr', '')}"
            }
    
    def check_reverse_shell_connection(self, listen_port: int) -> Dict[str, Any]:
        """Vérifie si une connexion reverse shell a été établie"""
        print(f"🔍 Vérification connexion reverse shell port {listen_port}")
        
        # Vérification du log du listener
        log_cmd = f"tail -20 /tmp/reverse_shell_{listen_port}.log 2>/dev/null || echo 'No log file'"
        result = self.ssh_manager.execute_host_command(log_cmd)
        
        log_content = result['stdout'] if result['success'] else ""
        
        # Recherche d'indicateurs de connexion
        connection_indicators = [
            "connect to",
            "connection from",
            "connected",
            "listening on"
        ]
        
        has_connection = any(indicator in log_content.lower() for indicator in connection_indicators)
        
        return {
            "success": True,
            "has_connection": has_connection,
            "log_content": log_content,
            "connection_indicators": connection_indicators
        }
    
    def cleanup_exploits(self):
        """Nettoie les fichiers d'exploits du container"""
        if not self.target_container:
            return
        
        print("🧹 Nettoyage des exploits...")
        
        cleanup_cmd = f"rm -rf {self.exploit_workspace}/*"
        result = self.ssh_manager.execute_container_command(
            self.target_container, cleanup_cmd
        )
        
        if result['success']:
            print("  ✅ Exploits nettoyés")
        else:
            print(f"  ⚠ Erreur nettoyage: {result.get('stderr', '')}")

print("✅ RemoteExploitExecutor class defined")

# %%
# Configuration et initialisation
def get_ssh_config_interactive() -> SSHConfig:
    """Récupère la configuration SSH de manière interactive"""
    print("\n🔧 Configuration SSH pour accès machine hôte")
    
    try:
        import questionary
        
        host = questionary.text(
            "Adresse de la machine hôte:",
            default="100.91.1.1"
        ).ask()
        
        username = questionary.text(
            "Nom d'utilisateur SSH:",
            default="root"
        ).ask()
        
        auth_method = questionary.select(
            "Méthode d'authentification:",
            choices=["Mot de passe", "Clé SSH", "Aucune (accès direct)"]
        ).ask()
        
        password = None
        key_file = None
        
        if auth_method == "Mot de passe":
            password = questionary.password("Mot de passe SSH:").ask()
        elif auth_method == "Clé SSH":
            key_file = questionary.path("Chemin vers la clé privée:").ask()
        
        return SSHConfig(
            host=host,
            username=username,
            password=password,
            key_file=key_file
        )
        
    except ImportError:
        # Fallback sans questionary
        print("Configuration SSH par défaut (100.91.1.1:root)")
        return SSHConfig()

def select_target_container_interactive(ssh_manager: SSHDockerManager) -> Optional[str]:
    """Sélection interactive du container cible"""
    containers = ssh_manager.list_docker_containers()
    
    if not containers:
        print("❌ Aucun container trouvé")
        return None
    
    try:
        import questionary
        
        # Création des choix avec informations détaillées
        choices = []
        for container in containers:
            choice_text = f"{container['name']} ({container['id'][:12]}) - {container['image']}"
            choices.append(questionary.Choice(choice_text, container['id']))
        
        selected = questionary.select(
            "Sélectionnez le container cible:",
            choices=choices
        ).ask()
        
        return selected
        
    except ImportError:
        # Fallback sans questionary
        print("\n📦 Containers disponibles:")
        for i, container in enumerate(containers):
            print(f"  {i}: {container['name']} ({container['id'][:12]})")
        
        try:
            choice = int(input("Sélectionnez le numéro du container: "))
            return containers[choice]['id']
        except (ValueError, IndexError):
            print("❌ Sélection invalide")
            return None

# Fonction de test/démonstration
def demo_remote_execution():
    """Démonstration du système d'exécution distante"""
    print("\n🎭 DÉMONSTRATION - EXÉCUTION DISTANTE SSH + DOCKER")
    print("="*60)
    
    # Configuration SSH
    ssh_config = get_ssh_config_interactive()
    print(f"\n📋 Configuration SSH: {ssh_config.to_dict()}")
    
    # Connexion SSH
    ssh_manager = SSHDockerManager(ssh_config)
    
    if not ssh_manager.connect():
        print("❌ Impossible de se connecter en SSH")
        return
    
    # Sélection du container cible
    container_id = select_target_container_interactive(ssh_manager)
    
    if not container_id:
        ssh_manager.disconnect()
        return
    
    print(f"\n🎯 Container sélectionné: {container_id}")
    
    # Test de connectivité
    connectivity = ssh_manager.test_container_connectivity(container_id)
    print(f"\n📊 Score de connectivité: {connectivity.get('connectivity_score', 0):.2f}")
    
    # Démonstration des outils de reconnaissance
    recon_tools = RemoteReconnaissanceTools(ssh_manager)
    recon_tools.set_target_container(container_id)
    
    print("\n🔍 TESTS DE RECONNAISSANCE:")
    
    # Scan nmap
    nmap_result = recon_tools.nmap_scan()
    if nmap_result['success']:
        print(f"  ✅ Nmap: {len(nmap_result['open_ports'])} ports ouverts")
    
    # Analyse netstat
    netstat_result = recon_tools.netstat_scan()
    if netstat_result['success']:
        print(f"  ✅ Netstat: Analyse réseau terminée")
    
    # Démonstration de l'exécuteur d'exploits
    exploit_executor = RemoteExploitExecutor(ssh_manager)
    exploit_executor.set_target_container(container_id)
    
    print("\n💥 TEST D'EXÉCUTION D'EXPLOIT:")
    
    # Script d'exemple
    test_script = """#!/bin/bash
echo "=== Test d'exploit ==="
whoami
id
pwd
ls -la
echo "=== Fin du test ==="
"""
    
    exec_result = exploit_executor.upload_and_execute_script(
        test_script, "test_exploit", "bash"
    )
    
    if exec_result['success']:
        print(f"  ✅ Exploit test exécuté avec succès")
        print(f"  📋 Sortie: {exec_result['execution_output'][:200]}...")
    else:
        print(f"  ❌ Échec exécution: {exec_result.get('error', '')}")
    
    # Nettoyage
    exploit_executor.cleanup_exploits()
    ssh_manager.disconnect()
    
    print("\n🎉 DÉMONSTRATION TERMINÉE")

if __name__ == "__main__":
    demo_remote_execution()

print("\n✅ REMOTE EXECUTION MANAGER COMPLET!")
print("Utilisez demo_remote_execution() pour tester le système")
