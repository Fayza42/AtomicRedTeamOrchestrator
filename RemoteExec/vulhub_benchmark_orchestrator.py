# Vulhub Benchmark Orchestrator - Système Automatisé de Test d'Agents LLM
# Filename: vulhub_benchmark_orchestrator.py

"""
Système complet d'orchestration pour tester automatiquement l'agent Analyzer
sur toutes les vulnérabilités Vulhub et calculer des métriques de performance.

Architecture:
1. VulhubOrchestrator: Gestion SSH + Docker + Navigation
2. GroundTruthExtractor: Parse README et docker-compose.yml 
3. MetricsCalculator: Compare agent vs réalité
4. BatchProcessor: Automatisation complète du pipeline
"""

import paramiko
import yaml
import json
import time
import re
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import de l'agent Analyzer existant
try:
    from enhanced_analyzer_remote import EnhancedVulnerabilityAnalyzer
    from remote_execution_manager import SSHConfig
except ImportError:
    print("⚠️ Agent Analyzer non trouvé. Assurez-vous que les modules sont disponibles.")

# ==================== MODÈLES DE DONNÉES ====================

@dataclass
class VulnerabilityGroundTruth:
    """Ground Truth extraite du README et docker-compose"""
    vulhub_id: str
    service: str
    cve_id: str
    description: str
    exposed_ports: List[int]
    attack_type: str
    docker_image: str
    readme_content: str
    compose_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalysisResult:
    """Résultat de l'analyse par l'agent"""
    vulhub_id: str
    container_id: str
    detected_cve: Optional[str]
    detected_service: str
    detected_ports: List[int]
    confidence_score: float
    analysis_time: float
    full_report: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None

@dataclass
class BenchmarkMetrics:
    """Métriques de performance pour une vulnérabilité"""
    vulhub_id: str
    cve_match: bool
    service_match: bool
    port_precision: float
    port_recall: float
    port_f1: float
    confidence_score: float
    analysis_time: float
    overall_accuracy: float
    details: Dict[str, Any] = field(default_factory=dict)

# ==================== EXTRACTEUR DE GROUND TRUTH ====================

class GroundTruthExtractor:
    """Extrait la vérité terrain depuis README et docker-compose.yml"""
    
    def __init__(self, ssh_client: paramiko.SSHClient):
        self.ssh_client = ssh_client
        
    def extract_from_vulhub_dir(self, vulhub_path: str) -> Optional[VulnerabilityGroundTruth]:
        """Extrait les informations d'une vulnérabilité spécifique"""
        print(f"📋 Extraction ground truth: {vulhub_path}")
        
        # Parse vulhub_id
        parts = vulhub_path.strip('/').split('/')
        if len(parts) >= 2:
            service = parts[-2]
            cve_or_vuln = parts[-1]
            vulhub_id = f"{service}/{cve_or_vuln}"
        else:
            return None
        
        # Lire README
        readme_content = self._read_file(f"{vulhub_path}/README.md")
        if not readme_content:
            readme_content = self._read_file(f"{vulhub_path}/README.zh-cn.md")
        
        # Lire docker-compose.yml
        compose_content = self._read_file(f"{vulhub_path}/docker-compose.yml")
        
        if not compose_content:
            print(f"  ⚠️ Pas de docker-compose.yml trouvé")
            return None
        
        # Parser docker-compose pour les ports
        exposed_ports = self._parse_compose_ports(compose_content)
        
        # Parser README pour CVE et détails
        cve_id = self._extract_cve_from_readme(readme_content, cve_or_vuln)
        attack_type = self._extract_attack_type(readme_content)
        description = self._extract_description(readme_content)
        
        # Extraire l'image Docker
        docker_image = self._extract_docker_image(compose_content)
        
        return VulnerabilityGroundTruth(
            vulhub_id=vulhub_id,
            service=service,
            cve_id=cve_id,
            description=description,
            exposed_ports=exposed_ports,
            attack_type=attack_type,
            docker_image=docker_image,
            readme_content=readme_content[:1000],  # Limiter la taille
            compose_content=compose_content[:1000],
            metadata={
                "extraction_time": datetime.now().isoformat(),
                "has_readme": bool(readme_content),
                "has_compose": bool(compose_content)
            }
        )
    
    def _read_file(self, filepath: str) -> str:
        """Lit un fichier via SSH"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(f"cat {filepath}")
            content = stdout.read().decode('utf-8', errors='ignore')
            return content
        except:
            return ""
    
    def _parse_compose_ports(self, compose_content: str) -> List[int]:
        """Parse les ports depuis docker-compose.yml"""
        ports = []
        try:
            compose_data = yaml.safe_load(compose_content)
            
            # Parcourir tous les services
            if 'services' in compose_data:
                for service_name, service_config in compose_data['services'].items():
                    if 'ports' in service_config:
                        for port_mapping in service_config['ports']:
                            # Format: "8080:80" ou "80"
                            port_str = str(port_mapping).split(':')[0]
                            try:
                                port = int(port_str)
                                ports.append(port)
                            except:
                                pass
        except:
            # Fallback: regex pour trouver les ports
            port_pattern = r'(\d+):\d+'
            matches = re.findall(port_pattern, compose_content)
            ports = [int(p) for p in matches]
        
        return sorted(list(set(ports)))
    
    def _extract_docker_image(self, compose_content: str) -> str:
        """Extrait l'image Docker principale"""
        try:
            compose_data = yaml.safe_load(compose_content)
            if 'services' in compose_data:
                for service_config in compose_data['services'].values():
                    if 'image' in service_config:
                        return service_config['image']
        except:
            pass
        return "unknown"
    
    def _extract_cve_from_readme(self, readme: str, folder_name: str) -> str:
        """Extrait le CVE du README ou du nom du dossier"""
        # Pattern CVE standard
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # Chercher dans le README
        if readme:
            matches = re.findall(cve_pattern, readme, re.IGNORECASE)
            if matches:
                return matches[0].upper()
        
        # Chercher dans le nom du dossier
        matches = re.findall(cve_pattern, folder_name, re.IGNORECASE)
        if matches:
            return matches[0].upper()
        
        return folder_name  # Fallback sur le nom du dossier
    
    def _extract_attack_type(self, readme: str) -> str:
        """Détermine le type d'attaque depuis le README"""
        if not readme:
            return "Unknown"
        
        readme_lower = readme.lower()
        
        # Patterns de types d'attaques
        attack_patterns = {
            "RCE": ["remote code execution", "rce", "command execution"],
            "SQL Injection": ["sql injection", "sqli", "sql"],
            "XSS": ["cross-site scripting", "xss"],
            "XXE": ["xml external entity", "xxe"],
            "SSRF": ["server-side request forgery", "ssrf"],
            "File Upload": ["file upload", "arbitrary file", "upload vulnerability"],
            "Path Traversal": ["path traversal", "directory traversal", "lfi"],
            "Deserialization": ["deserialization", "unserialize", "pickle"],
            "Authentication Bypass": ["authentication bypass", "auth bypass"],
            "Privilege Escalation": ["privilege escalation", "privesc"]
        }
        
        for attack_type, patterns in attack_patterns.items():
            for pattern in patterns:
                if pattern in readme_lower:
                    return attack_type
        
        return "Web Vulnerability"
    
    def _extract_description(self, readme: str) -> str:
        """Extrait une description courte du README"""
        if not readme:
            return "No description available"
        
        # Prendre les premières lignes non vides
        lines = readme.split('\n')
        description_lines = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 20:
                description_lines.append(line)
                if len(description_lines) >= 2:
                    break
        
        return ' '.join(description_lines)[:200]

# ==================== ORCHESTRATEUR PRINCIPAL ====================

class VulhubOrchestrator:
    """Orchestrateur principal pour le benchmark automatisé"""
    
    def __init__(self, ssh_config: SSHConfig):
        self.ssh_config = ssh_config
        self.ssh_client = None
        self.ground_truth_extractor = None
        self.analyzer = None
        self.vulhub_base = "/vulhub"
        
        print("🎯 Initialisation Vulhub Orchestrator")
    
    def connect(self) -> bool:
        """Établit la connexion SSH"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.ssh_config.password:
                self.ssh_client.connect(
                    hostname=self.ssh_config.host,
                    port=self.ssh_config.port,
                    username=self.ssh_config.username,
                    password=self.ssh_config.password,
                    timeout=self.ssh_config.timeout
                )
            else:
                self.ssh_client.connect(
                    hostname=self.ssh_config.host,
                    port=self.ssh_config.port,
                    username=self.ssh_config.username,
                    key_filename=self.ssh_config.key_file,
                    timeout=self.ssh_config.timeout
                )
            
            print(f"✅ Connecté à {self.ssh_config.host}")
            
            # Initialiser les composants
            self.ground_truth_extractor = GroundTruthExtractor(self.ssh_client)
            self.analyzer = EnhancedVulnerabilityAnalyzer()
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur connexion: {e}")
            return False
    
    def discover_vulnerabilities(self, limit: Optional[int] = None) -> List[str]:
        """Découvre toutes les vulnérabilités disponibles"""
        print("🔍 Découverte des vulnérabilités dans Vulhub...")
        
        # Commande pour lister les répertoires à 2 niveaux
        cmd = f"find {self.vulhub_base} -mindepth 2 -maxdepth 2 -type d -name '*CVE*' -o -name '*s2-*' -o -name '*struts*' | sort"
        
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
        vuln_paths = stdout.read().decode('utf-8').strip().split('\n')
        
        # Filtrer les chemins valides
        valid_paths = []
        for path in vuln_paths:
            if path and 'docker-compose.yml' in self._list_files(path):
                valid_paths.append(path)
        
        if limit:
            valid_paths = valid_paths[:limit]
        
        print(f"✅ {len(valid_paths)} vulnérabilités trouvées")
        return valid_paths
    
    def _list_files(self, directory: str) -> List[str]:
        """Liste les fichiers d'un répertoire"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(f"ls {directory}")
            files = stdout.read().decode('utf-8').strip().split('\n')
            return files
        except:
            return []
    
    def deploy_vulnerability(self, vuln_path: str) -> Optional[str]:
        """Déploie une vulnérabilité et retourne le container ID"""
        print(f"🐳 Déploiement: {vuln_path}")
        
        # docker-compose up -d
        cmd = f"cd {vuln_path} && docker-compose up -d"
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=120)
        
        output = stdout.read().decode('utf-8')
        errors = stderr.read().decode('utf-8')
        
        if "error" in errors.lower():
            print(f"  ❌ Erreur déploiement: {errors[:100]}")
            return None
        
        # Attendre que les containers démarrent
        time.sleep(10)
        
        # Récupérer l'ID du container principal
        cmd = f"cd {vuln_path} && docker-compose ps -q | head -1"
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd)
        
        container_id = stdout.read().decode('utf-8').strip()
        
        if container_id:
            print(f"  ✅ Container déployé: {container_id[:12]}")
            return container_id
        else:
            print(f"  ❌ Pas de container trouvé")
            return None
    
    def analyze_container(self, container_id: str, vulhub_id: str) -> AnalysisResult:
        """Lance l'agent Analyzer sur le container"""
        print(f"🤖 Analyse par l'agent: {container_id[:12]}")
        
        start_time = time.time()
        
        try:
            # Configurer l'agent pour ce container spécifique
            self.analyzer.ssh_manager = self.ssh_client
            self.analyzer.target_container = container_id
            
            # Lancer l'analyse
            result = self.analyzer.run_enhanced_analysis(vulhub_id)
            
            analysis_time = time.time() - start_time
            
            if result['status'] == 'SUCCESS':
                enhanced_info = result.get('enhanced_vulhub_info', {})
                enhanced_report = result.get('enhanced_analysis_report', {})
                
                # Extraire les informations détectées
                detected_cve = enhanced_info.get('cve_id')
                detected_service = enhanced_info.get('target_service', 'Unknown')
                detected_ports = enhanced_info.get('real_vs_documented_ports', {}).get('real', [])
                confidence = enhanced_report.get('confidence_score', 0.0)
                
                return AnalysisResult(
                    vulhub_id=vulhub_id,
                    container_id=container_id,
                    detected_cve=detected_cve,
                    detected_service=detected_service,
                    detected_ports=detected_ports,
                    confidence_score=confidence,
                    analysis_time=analysis_time,
                    full_report=result,
                    success=True
                )
            else:
                return AnalysisResult(
                    vulhub_id=vulhub_id,
                    container_id=container_id,
                    detected_cve=None,
                    detected_service="Unknown",
                    detected_ports=[],
                    confidence_score=0.0,
                    analysis_time=analysis_time,
                    full_report=result,
                    success=False,
                    error_message=result.get('error', 'Analysis failed')
                )
                
        except Exception as e:
            print(f"  ❌ Erreur analyse: {e}")
            return AnalysisResult(
                vulhub_id=vulhub_id,
                container_id=container_id,
                detected_cve=None,
                detected_service="Unknown",
                detected_ports=[],
                confidence_score=0.0,
                analysis_time=time.time() - start_time,
                full_report={},
                success=False,
                error_message=str(e)
            )
    
    def cleanup_vulnerability(self, vuln_path: str):
        """Nettoie une vulnérabilité (docker-compose down)"""
        print(f"🧹 Nettoyage: {vuln_path}")
        
        cmd = f"cd {vuln_path} && docker-compose down -v"
        stdin, stdout, stderr = self.ssh_client.exec_command(cmd, timeout=60)
        
        output = stdout.read().decode('utf-8')
        
        if "Removing" in output:
            print(f"  ✅ Nettoyage effectué")
        else:
            print(f"  ⚠️ Nettoyage incertain")
    
    def process_single_vulnerability(self, vuln_path: str) -> Tuple[Optional[VulnerabilityGroundTruth], Optional[AnalysisResult]]:
        """Traite une vulnérabilité complète"""
        print(f"\n{'='*60}")
        print(f"📦 Traitement: {vuln_path}")
        print(f"{'='*60}")
        
        # Extraire ground truth
        ground_truth = self.ground_truth_extractor.extract_from_vulhub_dir(vuln_path)
        if not ground_truth:
            print("  ❌ Impossible d'extraire ground truth")
            return None, None
        
        print(f"  📋 Ground Truth:")
        print(f"     CVE: {ground_truth.cve_id}")
        print(f"     Service: {ground_truth.service}")
        print(f"     Ports: {ground_truth.exposed_ports}")
        print(f"     Type: {ground_truth.attack_type}")
        
        # Déployer
        container_id = self.deploy_vulnerability(vuln_path)
        if not container_id:
            print("  ❌ Échec déploiement")
            return ground_truth, None
        
        # Analyser
        analysis_result = self.analyze_container(container_id, ground_truth.vulhub_id)
        
        print(f"  🤖 Résultats Agent:")
        print(f"     CVE détecté: {analysis_result.detected_cve}")
        print(f"     Service détecté: {analysis_result.detected_service}")
        print(f"     Ports détectés: {analysis_result.detected_ports}")
        print(f"     Confiance: {analysis_result.confidence_score:.2f}")
        
        # Nettoyer
        self.cleanup_vulnerability(vuln_path)
        
        return ground_truth, analysis_result

# ==================== CALCULATEUR DE MÉTRIQUES ====================

class MetricsCalculator:
    """Calcule les métriques de performance"""
    
    @staticmethod
    def calculate_metrics(ground_truth: VulnerabilityGroundTruth, 
                         analysis: AnalysisResult) -> BenchmarkMetrics:
        """Calcule les métriques pour une vulnérabilité"""
        
        # CVE Match
        cve_match = False
        if ground_truth.cve_id and analysis.detected_cve:
            cve_match = ground_truth.cve_id.upper() == analysis.detected_cve.upper()
        
        # Service Match
        service_match = False
        if ground_truth.service and analysis.detected_service:
            service_match = ground_truth.service.lower() in analysis.detected_service.lower() or \
                          analysis.detected_service.lower() in ground_truth.service.lower()
        
        # Port Metrics
        true_ports = set(ground_truth.exposed_ports)
        detected_ports = set(analysis.detected_ports)
        
        if true_ports:
            port_precision = len(true_ports & detected_ports) / len(detected_ports) if detected_ports else 0
            port_recall = len(true_ports & detected_ports) / len(true_ports)
            port_f1 = 2 * (port_precision * port_recall) / (port_precision + port_recall) \
                     if (port_precision + port_recall) > 0 else 0
        else:
            port_precision = port_recall = port_f1 = 0
        
        # Overall Accuracy
        scores = [
            1.0 if cve_match else 0.0,
            1.0 if service_match else 0.5,  # Partial credit
            port_f1
        ]
        overall_accuracy = sum(scores) / len(scores)
        
        return BenchmarkMetrics(
            vulhub_id=ground_truth.vulhub_id,
            cve_match=cve_match,
            service_match=service_match,
            port_precision=port_precision,
            port_recall=port_recall,
            port_f1=port_f1,
            confidence_score=analysis.confidence_score,
            analysis_time=analysis.analysis_time,
            overall_accuracy=overall_accuracy,
            details={
                "true_cve": ground_truth.cve_id,
                "detected_cve": analysis.detected_cve,
                "true_service": ground_truth.service,
                "detected_service": analysis.detected_service,
                "true_ports": list(true_ports),
                "detected_ports": list(detected_ports),
                "ports_intersection": list(true_ports & detected_ports)
            }
        )

# ==================== PROCESSEUR BATCH ====================

class BatchProcessor:
    """Traite plusieurs vulnérabilités en batch"""
    
    def __init__(self, orchestrator: VulhubOrchestrator):
        self.orchestrator = orchestrator
        self.results = []
        self.metrics = []
        
    def process_all(self, limit: Optional[int] = None, 
                   save_results: bool = True) -> Dict[str, Any]:
        """Traite toutes les vulnérabilités disponibles"""
        print("\n🚀 DÉMARRAGE DU BENCHMARK BATCH")
        print("="*70)
        
        start_time = time.time()
        
        # Découvrir les vulnérabilités
        vuln_paths = self.orchestrator.discover_vulnerabilities(limit)
        
        if not vuln_paths:
            print("❌ Aucune vulnérabilité trouvée")
            return {}
        
        print(f"📊 {len(vuln_paths)} vulnérabilités à traiter")
        
        success_count = 0
        failure_count = 0
        
        # Traiter chaque vulnérabilité
        for i, vuln_path in enumerate(vuln_paths, 1):
            print(f"\n[{i}/{len(vuln_paths)}] Processing...")
            
            try:
                ground_truth, analysis = self.orchestrator.process_single_vulnerability(vuln_path)
                
                if ground_truth and analysis:
                    # Calculer les métriques
                    metrics = MetricsCalculator.calculate_metrics(ground_truth, analysis)
                    
                    self.results.append({
                        "ground_truth": ground_truth,
                        "analysis": analysis,
                        "metrics": metrics
                    })
                    
                    self.metrics.append(metrics)
                    success_count += 1
                    
                    print(f"  ✅ Succès - Accuracy: {metrics.overall_accuracy:.2%}")
                else:
                    failure_count += 1
                    print(f"  ❌ Échec du traitement")
                    
            except Exception as e:
                print(f"  💥 Erreur inattendue: {e}")
                failure_count += 1
            
            # Pause entre les tests
            time.sleep(5)
        
        # Calculer les statistiques globales
        total_time = time.time() - start_time
        
        global_stats = self._calculate_global_stats()
        
        # Rapport final
        print("\n" + "="*70)
        print("📊 RAPPORT FINAL DU BENCHMARK")
        print("="*70)
        print(f"✅ Succès: {success_count}")
        print(f"❌ Échecs: {failure_count}")
        print(f"⏱️ Temps total: {total_time/60:.1f} minutes")
        print(f"⚡ Temps moyen par vuln: {total_time/len(vuln_paths):.1f} secondes")
        
        if global_stats:
            print(f"\n📈 MÉTRIQUES GLOBALES:")
            print(f"   CVE Accuracy: {global_stats['cve_accuracy']:.2%}")
            print(f"   Service Accuracy: {global_stats['service_accuracy']:.2%}")
            print(f"   Port F1 Score: {global_stats['avg_port_f1']:.2%}")
            print(f"   Overall Accuracy: {global_stats['overall_accuracy']:.2%}")
            print(f"   Avg Confidence: {global_stats['avg_confidence']:.2f}")
        
        # Sauvegarder les résultats
        if save_results:
            self._save_results()
        
        return {
            "total_processed": len(vuln_paths),
            "success": success_count,
            "failures": failure_count,
            "total_time": total_time,
            "global_stats": global_stats,
            "detailed_results": self.results
        }
    
    def _calculate_global_stats(self) -> Dict[str, float]:
        """Calcule les statistiques globales"""
        if not self.metrics:
            return {}
        
        n = len(self.metrics)
        
        return {
            "cve_accuracy": sum(m.cve_match for m in self.metrics) / n,
            "service_accuracy": sum(m.service_match for m in self.metrics) / n,
            "avg_port_precision": sum(m.port_precision for m in self.metrics) / n,
            "avg_port_recall": sum(m.port_recall for m in self.metrics) / n,
            "avg_port_f1": sum(m.port_f1 for m in self.metrics) / n,
            "avg_confidence": sum(m.confidence_score for m in self.metrics) / n,
            "avg_analysis_time": sum(m.analysis_time for m in self.metrics) / n,
            "overall_accuracy": sum(m.overall_accuracy for m in self.metrics) / n
        }
    
    def _save_results(self):
        """Sauvegarde les résultats dans des fichiers"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Sauvegarder les métriques
        metrics_file = f"benchmark_metrics_{timestamp}.json"
        metrics_data = []
        for m in self.metrics:
            metrics_data.append({
                "vulhub_id": m.vulhub_id,
                "cve_match": m.cve_match,
                "service_match": m.service_match,
                "port_f1": m.port_f1,
                "confidence": m.confidence_score,
                "overall_accuracy": m.overall_accuracy,
                "details": m.details
            })
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics_data, f, indent=2)
        
        print(f"💾 Métriques sauvegardées: {metrics_file}")
        
        # Sauvegarder le rapport complet
        report_file = f"benchmark_report_{timestamp}.json"
        report_data = {
            "timestamp": timestamp,
            "summary": self._calculate_global_stats(),
            "individual_results": metrics_data
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"💾 Rapport complet sauvegardé: {report_file}")

# ==================== FONCTION PRINCIPALE ====================

def run_vulhub_benchmark(limit: Optional[int] = None, 
                        ssh_host: str = "100.91.1.1",
                        ssh_user: str = "fayza",
                        ssh_password: str = None):
    """
    Lance le benchmark complet sur Vulhub
    
    Args:
        limit: Nombre maximum de vulnérabilités à tester
        ssh_host: Adresse de la machine hôte
        ssh_user: Utilisateur SSH
        ssh_password: Mot de passe SSH
    """
    print("🎯 VULHUB BENCHMARK ORCHESTRATOR")
    print("="*70)
    
    # Configuration SSH
    ssh_config = SSHConfig(
        host=ssh_host,
        username=ssh_user,
        password=ssh_password
    )
    
    # Initialiser l'orchestrateur
    orchestrator = VulhubOrchestrator(ssh_config)
    
    if not orchestrator.connect():
        print("❌ Impossible de se connecter")
        return
    
    # Initialiser le processeur batch
    processor = BatchProcessor(orchestrator)
    
    # Lancer le traitement
    results = processor.process_all(limit=limit, save_results=True)
    
    # Fermer la connexion
    if orchestrator.ssh_client:
        orchestrator.ssh_client.close()
    
    return results

# ==================== DEMO ====================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Vulhub Benchmark Orchestrator")
    parser.add_argument("--limit", type=int, help="Nombre de vulnérabilités à tester")
    parser.add_argument("--host", default="100.91.1.1", help="SSH host")
    parser.add_argument("--user", default="fayza", help="SSH user")
    parser.add_argument("--password", help="SSH password")
    
    args = parser.parse_args()
    
    # Demander le mot de passe si non fourni
    if not args.password:
        import getpass
        args.password = getpass.getpass(f"SSH password for {args.user}@{args.host}: ")
    
    # Lancer le benchmark
    results = run_vulhub_benchmark(
        limit=args.limit,
        ssh_host=args.host,
        ssh_user=args.user,
        ssh_password=args.password
    )
    
    print("\n🏁 BENCHMARK TERMINÉ!")
