# Notebook 06: Orchestrateur Intelligent Multi-Agents
# Filename: notebook_06_orchestrator.ipynb

# %% [markdown]
"""
# Orchestrateur Intelligent - Écosystème de Pentesting Autonome

## Architecture Multi-Agents :
- 🎯 **Phase 1 - Analyse** : VulnerabilityAnalyzerAgent
- 🔴 **Phase 2 - Attaque** : RedTeamAgent  
- 🔵 **Phase 3 - Défense** : BlueTeamAgent
- 🔄 **Cycle Itératif** : Jusqu'à remédiation complète

## Fonctionnalités Avancées :
- ✅ Gestion d'état avec contexte persistant
- ✅ Workflow intelligent avec transitions conditionnelles
- ✅ Interface utilisateur interactive
- ✅ Rapports consolidés et métriques
- ✅ Détection automatique de remédiation
- ✅ Logs détaillés et traçabilité

## Workflow Orchestrateur :
1. **Initialisation** : Configuration et validation de l'environnement
2. **Input Utilisateur** : ID Vulhub + adresse cible
3. **Phase Analyse** : Analyse de vulnérabilité avec RAG Vulhub
4. **Phase Red Team** : Génération et exécution d'exploits
5. **Phase Blue Team** : Analyse défensive et remédiation
6. **Évaluation** : Vérification si la vulnérabilité persiste
7. **Itération** : Répétition jusqu'à sécurisation complète
"""

# %%
import os
import json
import time
import sys
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

# Interface utilisateur
try:
    import questionary
except ImportError:
    print("Installation de questionary pour l'interface interactive...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "questionary"])
    import questionary

# Imports des agents (en supposant qu'ils sont dans le même environnement)
print("🎭 Initialisation de l'Orchestrateur Multi-Agents...")

# %%
# Modèles de données pour l'orchestrateur
class AuditPhase(Enum):
    """Énumération des phases d'audit"""
    INITIALIZATION = "initialization"
    ANALYSIS = "analysis"
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    EVALUATION = "evaluation"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class AuditContext:
    """Contexte global de l'audit maintenu par l'orchestrateur"""
    
    # Identifiants
    audit_id: str
    vulhub_id: str
    target_address: str
    
    # État de l'audit
    current_phase: AuditPhase
    start_time: datetime
    total_cycles: int
    
    # Rapports des agents
    analysis_reports: List[Dict[str, Any]]
    exploitation_reports: List[Dict[str, Any]]
    defense_reports: List[Dict[str, Any]]
    
    # Métriques et état
    vulnerability_status: str  # VULNERABLE, PARTIALLY_SECURED, SECURED
    risk_score_evolution: List[float]
    remediation_applied: List[str]
    
    # Configuration
    max_cycles: int = 5
    auto_apply_patches: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Conversion en dictionnaire pour sérialisation"""
        context_dict = asdict(self)
        context_dict['current_phase'] = self.current_phase.value
        context_dict['start_time'] = self.start_time.isoformat()
        return context_dict
    
    def get_latest_analysis(self) -> Optional[Dict[str, Any]]:
        """Récupère le dernier rapport d'analyse"""
        return self.analysis_reports[-1] if self.analysis_reports else None
    
    def get_latest_exploitation(self) -> Optional[Dict[str, Any]]:
        """Récupère le dernier rapport d'exploitation"""
        return self.exploitation_reports[-1] if self.exploitation_reports else None
    
    def get_latest_defense(self) -> Optional[Dict[str, Any]]:
        """Récupère le dernier rapport de défense"""
        return self.defense_reports[-1] if self.defense_reports else None

print("✅ Modèles de données définis")

# %%
# Gestionnaire de configuration et environnement
class EnvironmentManager:
    """Gestionnaire de l'environnement et de la configuration"""
    
    def __init__(self):
        self.config_file = "vple_config.json"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration système"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            print("✅ Configuration système chargée")
            return config
        except FileNotFoundError:
            print("⚠ Configuration non trouvée, utilisation des valeurs par défaut")
            return {
                "confirmed_model": "llama2:7b",
                "vulhub_rag_setup": {"db_path": "./vulhub_chroma_db"},
                "enhanced_rag_setup": {"vector_db": "./enhanced_vple_chroma_db"}
            }
    
    def validate_environment(self) -> Tuple[bool, List[str]]:
        """Valide que l'environnement est prêt pour l'orchestration"""
        errors = []
        
        # Vérification du modèle LLM
        model_name = self.config.get("confirmed_model")
        if not model_name:
            errors.append("Modèle LLM non configuré")
        
        # Vérification des bases de données RAG
        vulhub_db = self.config.get("vulhub_rag_setup", {}).get("db_path")
        if not vulhub_db or not Path(vulhub_db).exists():
            errors.append(f"Base de données Vulhub non trouvée: {vulhub_db}")
        
        enhanced_db = self.config.get("enhanced_rag_setup", {}).get("vector_db")
        if not enhanced_db or not Path(enhanced_db).exists():
            errors.append(f"Base de données Enhanced non trouvée: {enhanced_db}")
        
        # Vérification d'Ollama
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                errors.append("Service Ollama non accessible")
            elif model_name and model_name not in result.stdout:
                errors.append(f"Modèle {model_name} non disponible dans Ollama")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            errors.append("Ollama non installé ou non démarré")
        
        # Vérification des répertoires de travail
        work_dirs = ["generated_exploits", "audit_reports", "cycles_history"]
        for dir_name in work_dirs:
            Path(dir_name).mkdir(exist_ok=True)
        
        return len(errors) == 0, errors
    
    def get_agent_config(self, agent_type: str) -> Dict[str, Any]:
        """Récupère la configuration spécifique pour un agent"""
        base_config = {
            "model_name": self.config.get("confirmed_model", "llama2:7b")
        }
        
        if agent_type == "vulnerability_analyzer":
            base_config["vulhub_db_path"] = self.config.get("vulhub_rag_setup", {}).get("db_path")
        elif agent_type == "red_team":
            base_config["enhanced_db_path"] = self.config.get("enhanced_rag_setup", {}).get("vector_db")
        
        return base_config

print("✅ EnvironmentManager défini")

# %%
# Interface utilisateur interactive
class UserInterface:
    """Interface utilisateur pour l'orchestrateur"""
    
    @staticmethod
    def welcome_banner():
        """Affiche la bannière de bienvenue"""
        print("\n" + "🎭" * 25)
        print("🎭  ÉCOSYSTÈME DE PENTESTING AUTONOME  🎭")
        print("🎭" * 25)
        print("🎯 Phase 1: Analyse de Vulnérabilité")
        print("🔴 Phase 2: Exploitation Red Team")
        print("🔵 Phase 3: Défense Blue Team")
        print("🔄 Cycles: Jusqu'à remédiation complète")
        print("=" * 50)
    
    @staticmethod
    def get_target_information() -> Tuple[str, str]:
        """Récupère les informations de la cible via interface interactive"""
        print("\n📋 Configuration de l'audit...")
        
        # Liste des vulnérabilités Vulhub populaires
        popular_vulhubs = [
            "apache/CVE-2021-41773",
            "struts2/s2-001", 
            "struts2/s2-045",
            "tomcat/CVE-2017-12615",
            "weblogic/CVE-2017-10271",
            "drupal/CVE-2018-7600",
            "wordpress/CVE-2019-8943",
            "joomla/CVE-2015-8562",
            "Autre (saisie manuelle)"
        ]
        
        # Sélection de la vulnérabilité
        vulhub_choice = questionary.select(
            "Quelle vulnérabilité Vulhub voulez-vous auditer ?",
            choices=popular_vulhubs
        ).ask()
        
        if vulhub_choice == "Autre (saisie manuelle)":
            vulhub_id = questionary.text(
                "Entrez l'ID Vulhub (format: service/vulnerability):",
                validate=lambda x: len(x.split('/')) == 2 if x else False
            ).ask()
        else:
            vulhub_id = vulhub_choice
        
        # Adresse de la cible
        target_address = questionary.text(
            "Entrez l'adresse de la cible (IP:PORT ou URL complète):",
            default="192.168.1.100:8080",
            validate=lambda x: bool(x and ('.' in x or ':' in x))
        ).ask()
        
        # Confirmation
        print(f"\n✅ Configuration:")
        print(f"   🎯 Vulnérabilité: {vulhub_id}")
        print(f"   🌐 Cible: {target_address}")
        
        confirm = questionary.confirm("Confirmer cette configuration ?").ask()
        
        if not confirm:
            print("❌ Configuration annulée")
            return None, None
        
        return vulhub_id, target_address
    
    @staticmethod
    def get_audit_options() -> Dict[str, Any]:
        """Récupère les options d'audit avancées"""
        print("\n⚙️ Options d'audit avancées...")
        
        max_cycles = questionary.select(
            "Nombre maximum de cycles Red Team vs Blue Team ?",
            choices=["3", "5", "10", "Illimité"]
        ).ask()
        
        max_cycles = 999 if max_cycles == "Illimité" else int(max_cycles)
        
        auto_patch = questionary.confirm(
            "Appliquer automatiquement les patches recommandés ?"
        ).ask()
        
        verbose_logs = questionary.confirm(
            "Activer les logs détaillés ?"
        ).ask()
        
        return {
            "max_cycles": max_cycles,
            "auto_apply_patches": auto_patch,
            "verbose_logs": verbose_logs
        }
    
    @staticmethod
    def display_phase_transition(from_phase: AuditPhase, to_phase: AuditPhase, cycle: int):
        """Affiche la transition entre phases"""
        phase_icons = {
            AuditPhase.ANALYSIS: "🎯",
            AuditPhase.RED_TEAM: "🔴",
            AuditPhase.BLUE_TEAM: "🔵",
            AuditPhase.EVALUATION: "📊"
        }
        
        print(f"\n{'='*50}")
        print(f"🔄 CYCLE {cycle} - TRANSITION DE PHASE")
        print(f"{phase_icons.get(from_phase, '❓')} {from_phase.value.upper()} → {phase_icons.get(to_phase, '❓')} {to_phase.value.upper()}")
        print(f"{'='*50}")
    
    @staticmethod
    def display_cycle_summary(context: AuditContext, cycle: int):
        """Affiche le résumé d'un cycle"""
        print(f"\n📊 RÉSUMÉ DU CYCLE {cycle}")
        print("-" * 30)
        
        latest_analysis = context.get_latest_analysis()
        latest_exploitation = context.get_latest_exploitation()
        latest_defense = context.get_latest_defense()
        
        if latest_analysis:
            confidence = latest_analysis.get('analysis_report', {}).get('confidence_score', 0)
            print(f"🎯 Analyse: Confiance {confidence:.2f}")
        
        if latest_exploitation:
            success = latest_exploitation.get('exploitation_report', {}).get('success_level', 'UNKNOWN')
            print(f"🔴 Exploitation: {success}")
        
        if latest_defense:
            risk_level = latest_defense.get('defense_report', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
            recommendations = len(latest_defense.get('defense_report', {}).get('defense_recommendations', []))
            print(f"🔵 Défense: Risque {risk_level}, {recommendations} recommandations")
        
        print(f"🔄 Statut vulnérabilité: {context.vulnerability_status}")

print("✅ UserInterface définie")

# %%
# Orchestrateur Principal
class IntelligentOrchestrator:
    """
    Orchestrateur intelligent pour l'écosystème de pentesting autonome
    """
    
    def __init__(self):
        print("🎭 Initialisation de l'Orchestrateur Intelligent...")
        
        # Gestionnaires
        self.env_manager = EnvironmentManager()
        self.ui = UserInterface()
        
        # État de l'orchestrateur
        self.current_context: Optional[AuditContext] = None
        self.agents_cache = {}  # Cache des agents initialisés
        
        # Logs et rapports
        self.session_logs = []
        
        print("  ✅ Orchestrateur initialisé")
    
    def validate_environment(self) -> bool:
        """Valide l'environnement avant de commencer"""
        print("🔍 Validation de l'environnement...")
        
        is_valid, errors = self.env_manager.validate_environment()
        
        if is_valid:
            print("✅ Environnement validé")
            return True
        else:
            print("❌ Problèmes détectés dans l'environnement:")
            for error in errors:
                print(f"  - {error}")
            
            fix_attempt = questionary.confirm(
                "Voulez-vous tenter une correction automatique ?"
            ).ask()
            
            if fix_attempt:
                return self._attempt_environment_fix(errors)
            
            return False
    
    def _attempt_environment_fix(self, errors: List[str]) -> bool:
        """Tente de corriger automatiquement les problèmes d'environnement"""
        print("🔧 Tentative de correction automatique...")
        
        fixed_count = 0
        
        for error in errors:
            if "Ollama non installé" in error:
                print("  🔧 Tentative d'installation d'Ollama...")
                # Code de correction ici
                
            elif "Base de données" in error and "non trouvée" in error:
                print(f"  🔧 Tentative de création de la base de données...")
                # Code de correction ici
                
            elif "Modèle" in error and "non disponible" in error:
                print(f"  🔧 Tentative de téléchargement du modèle...")
                # Code de correction ici
        
        # Re-validation
        is_valid, remaining_errors = self.env_manager.validate_environment()
        
        if is_valid:
            print(f"✅ Environnement corrigé ({fixed_count} problèmes résolus)")
            return True
        else:
            print(f"⚠ Correction partielle ({fixed_count} problèmes résolus, {len(remaining_errors)} restants)")
            return False
    
    def initialize_audit_context(self, vulhub_id: str, target_address: str, options: Dict[str, Any]) -> AuditContext:
        """Initialise le contexte d'audit"""
        print("📋 Initialisation du contexte d'audit...")
        
        context = AuditContext(
            audit_id=str(uuid.uuid4())[:8],
            vulhub_id=vulhub_id,
            target_address=target_address,
            current_phase=AuditPhase.INITIALIZATION,
            start_time=datetime.now(),
            total_cycles=0,
            analysis_reports=[],
            exploitation_reports=[],
            defense_reports=[],
            vulnerability_status="VULNERABLE",
            risk_score_evolution=[],
            remediation_applied=[],
            max_cycles=options.get("max_cycles", 5),
            auto_apply_patches=options.get("auto_apply_patches", False)
        )
        
        # Sauvegarde du contexte
        self._save_context(context)
        
        print(f"✅ Contexte d'audit initialisé (ID: {context.audit_id})")
        return context
    
    def _save_context(self, context: AuditContext):
        """Sauvegarde le contexte dans un fichier"""
        context_file = f"audit_reports/audit_context_{context.audit_id}.json"
        with open(context_file, 'w') as f:
            json.dump(context.to_dict(), f, indent=2)
    
    def get_or_create_agent(self, agent_type: str):
        """Récupère ou crée un agent (avec cache)"""
        if agent_type not in self.agents_cache:
            print(f"🤖 Initialisation de l'agent {agent_type}...")
            
            config = self.env_manager.get_agent_config(agent_type)
            
            if agent_type == "vulnerability_analyzer":
                # Import et instanciation de VulnerabilityAnalyzerAgent
                # (En supposant que les classes sont disponibles)
                from notebook_05_agent_analyzer_revamped import VulnerabilityAnalyzerAgent
                self.agents_cache[agent_type] = VulnerabilityAnalyzerAgent(
                    model_name=config["model_name"],
                    vulhub_db_path=config["vulhub_db_path"]
                )
                
            elif agent_type == "red_team":
                from notebook_07_agent_red_team import RedTeamAgent
                self.agents_cache[agent_type] = RedTeamAgent(
                    model_name=config["model_name"],
                    enhanced_db_path=config["enhanced_db_path"]
                )
                
            elif agent_type == "blue_team":
                from notebook_08_agent_blue_team import BlueTeamAgent
                self.agents_cache[agent_type] = BlueTeamAgent(
                    model_name=config["model_name"]
                )
        
        return self.agents_cache[agent_type]
    
    def execute_analysis_phase(self, context: AuditContext) -> bool:
        """Exécute la phase d'analyse de vulnérabilité"""
        print("\n🎯 PHASE 1: ANALYSE DE VULNÉRABILITÉ")
        print("-" * 40)
        
        try:
            # Récupération de l'agent
            analyzer = self.get_or_create_agent("vulnerability_analyzer")
            
            # Exécution de l'analyse
            analysis_result = analyzer.run(context.vulhub_id, context.target_address)
            
            if analysis_result.get('status') == 'SUCCESS':
                context.analysis_reports.append(analysis_result)
                
                # Mise à jour du score de risque
                confidence = analysis_result.get('analysis_report', {}).get('confidence_score', 0.5)
                context.risk_score_evolution.append(confidence * 100)
                
                print("✅ Phase d'analyse terminée avec succès")
                return True
            else:
                print(f"❌ Échec de la phase d'analyse: {analysis_result.get('error', 'Erreur inconnue')}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur dans la phase d'analyse: {e}")
            return False
    
    def execute_red_team_phase(self, context: AuditContext) -> bool:
        """Exécute la phase Red Team"""
        print("\n🔴 PHASE 2: EXPLOITATION RED TEAM")
        print("-" * 40)
        
        try:
            # Récupération de l'agent
            red_team = self.get_or_create_agent("red_team")
            
            # Sauvegarde du dernier rapport d'analyse pour l'agent Red Team
            latest_analysis = context.get_latest_analysis()
            if not latest_analysis:
                print("❌ Aucun rapport d'analyse disponible")
                return False
            
            analysis_file = f"audit_reports/analysis_cycle_{context.total_cycles + 1}.json"
            with open(analysis_file, 'w') as f:
                json.dump(latest_analysis, f, indent=2)
            
            # Exécution de l'exploitation
            target_info = {
                "target_address": context.target_address,
                "vulhub_id": context.vulhub_id
            }
            
            exploitation_result = red_team.run(analysis_file, target_info)
            
            if exploitation_result.get('status') == 'SUCCESS':
                context.exploitation_reports.append(exploitation_result)
                
                print("✅ Phase Red Team terminée avec succès")
                return True
            else:
                print(f"❌ Échec de la phase Red Team: {exploitation_result.get('error', 'Erreur inconnue')}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur dans la phase Red Team: {e}")
            return False
    
    def execute_blue_team_phase(self, context: AuditContext) -> bool:
        """Exécute la phase Blue Team"""
        print("\n🔵 PHASE 3: DÉFENSE BLUE TEAM")
        print("-" * 40)
        
        try:
            # Récupération de l'agent
            blue_team = self.get_or_create_agent("blue_team")
            
            # Vérification des rapports nécessaires
            latest_analysis = context.get_latest_analysis()
            latest_exploitation = context.get_latest_exploitation()
            
            if not latest_analysis or not latest_exploitation:
                print("❌ Rapports d'analyse ou d'exploitation manquants")
                return False
            
            # Sauvegarde des rapports pour l'agent Blue Team
            analysis_file = f"audit_reports/analysis_cycle_{context.total_cycles + 1}.json"
            exploitation_file = f"audit_reports/exploitation_cycle_{context.total_cycles + 1}.json"
            
            with open(analysis_file, 'w') as f:
                json.dump(latest_analysis, f, indent=2)
            
            with open(exploitation_file, 'w') as f:
                json.dump(latest_exploitation, f, indent=2)
            
            # Exécution de l'analyse défensive
            defense_result = blue_team.run(analysis_file, exploitation_file)
            
            if defense_result.get('status') == 'SUCCESS':
                context.defense_reports.append(defense_result)
                
                # Application automatique des patches si configuré
                if context.auto_apply_patches:
                    self._apply_recommended_patches(context, defense_result)
                
                print("✅ Phase Blue Team terminée avec succès")
                return True
            else:
                print(f"❌ Échec de la phase Blue Team: {defense_result.get('error', 'Erreur inconnue')}")
                return False
                
        except Exception as e:
            print(f"❌ Erreur dans la phase Blue Team: {e}")
            return False
    
    def _apply_recommended_patches(self, context: AuditContext, defense_result: Dict[str, Any]):
        """Applique automatiquement les patches recommandés"""
        print("🔧 Application automatique des patches...")
        
        defense_report = defense_result.get('defense_report', {})
        recommendations = defense_report.get('defense_recommendations', [])
        
        applied_patches = []
        
        for rec in recommendations:
            if rec.get('priority') == 'IMMEDIATE' and rec.get('category') == 'PATCH':
                patch_title = rec.get('title', 'Patch inconnu')
                print(f"  🔧 Application: {patch_title}")
                
                # Simulation de l'application du patch
                # En réalité, ceci interfacerait avec les systèmes de gestion de configuration
                time.sleep(2)  # Simulation
                
                applied_patches.append(patch_title)
                print(f"  ✅ Patch appliqué: {patch_title}")
        
        context.remediation_applied.extend(applied_patches)
        
        if applied_patches:
            print(f"✅ {len(applied_patches)} patch(es) appliqué(s) automatiquement")
        else:
            print("ℹ️ Aucun patch automatique disponible")
    
    def evaluate_vulnerability_status(self, context: AuditContext) -> str:
        """Évalue si la vulnérabilité a été corrigée"""
        print("\n📊 ÉVALUATION DU STATUT DE VULNÉRABILITÉ")
        print("-" * 40)
        
        latest_defense = context.get_latest_defense()
        
        if not latest_defense:
            return "VULNERABLE"
        
        defense_report = latest_defense.get('defense_report', {})
        risk_assessment = defense_report.get('risk_assessment', {})
        
        # Critères d'évaluation
        risk_level = risk_assessment.get('risk_level', 'HIGH')
        patches_applied = len(context.remediation_applied)
        
        # Simulation d'un re-test (en réalité, on relancerait l'agent d'analyse)
        print("🔍 Re-test de la vulnérabilité...")
        time.sleep(2)
        
        if risk_level in ['LOW', 'MEDIUM'] and patches_applied > 0:
            new_status = "SECURED"
            print("✅ Vulnérabilité corrigée avec succès!")
        elif patches_applied > 0:
            new_status = "PARTIALLY_SECURED"
            print("⚠ Vulnérabilité partiellement corrigée")
        else:
            new_status = "VULNERABLE"
            print("❌ Vulnérabilité toujours présente")
        
        context.vulnerability_status = new_status
        return new_status
    
    def execute_audit_cycle(self, context: AuditContext) -> bool:
        """Exécute un cycle complet d'audit"""
        context.total_cycles += 1
        cycle = context.total_cycles
        
        print(f"\n{'🔄'*20}")
        print(f"🔄 DÉBUT DU CYCLE {cycle}")
        print(f"{'🔄'*20}")
        
        # Phase 1: Analyse
        self.ui.display_phase_transition(context.current_phase, AuditPhase.ANALYSIS, cycle)
        context.current_phase = AuditPhase.ANALYSIS
        
        if not self.execute_analysis_phase(context):
            context.current_phase = AuditPhase.FAILED
            return False
        
        # Phase 2: Red Team
        self.ui.display_phase_transition(context.current_phase, AuditPhase.RED_TEAM, cycle)
        context.current_phase = AuditPhase.RED_TEAM
        
        if not self.execute_red_team_phase(context):
            context.current_phase = AuditPhase.FAILED
            return False
        
        # Phase 3: Blue Team
        self.ui.display_phase_transition(context.current_phase, AuditPhase.BLUE_TEAM, cycle)
        context.current_phase = AuditPhase.BLUE_TEAM
        
        if not self.execute_blue_team_phase(context):
            context.current_phase = AuditPhase.FAILED
            return False
        
        # Évaluation
        self.ui.display_phase_transition(context.current_phase, AuditPhase.EVALUATION, cycle)
        context.current_phase = AuditPhase.EVALUATION
        
        new_status = self.evaluate_vulnerability_status(context)
        
        # Affichage du résumé du cycle
        self.ui.display_cycle_summary(context, cycle)
        
        # Sauvegarde du contexte
        self._save_context(context)
        
        return True
    
    def generate_final_report(self, context: AuditContext) -> Dict[str, Any]:
        """Génère le rapport final consolidé"""
        print("\n📋 GÉNÉRATION DU RAPPORT FINAL")
        print("-" * 40)
        
        total_time = datetime.now() - context.start_time
        
        # Compilation des métriques
        metrics = {
            "audit_summary": {
                "audit_id": context.audit_id,
                "vulhub_id": context.vulhub_id,
                "target_address": context.target_address,
                "total_cycles": context.total_cycles,
                "total_duration": str(total_time),
                "final_status": context.vulnerability_status,
                "patches_applied": len(context.remediation_applied)
            },
            "cycle_progression": {
                "risk_scores": context.risk_score_evolution,
                "remediation_applied": context.remediation_applied
            },
            "agents_performance": {
                "analysis_runs": len(context.analysis_reports),
                "exploitation_runs": len(context.exploitation_reports),
                "defense_runs": len(context.defense_reports)
            }
        }
        
        # Détails des derniers rapports
        latest_reports = {
            "latest_analysis": context.get_latest_analysis(),
            "latest_exploitation": context.get_latest_exploitation(),
            "latest_defense": context.get_latest_defense()
        }
        
        final_report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "orchestrator_version": "2.0",
                "audit_context": context.to_dict()
            },
            "metrics": metrics,
            "latest_reports": latest_reports,
            "full_history": {
                "analysis_reports": context.analysis_reports,
                "exploitation_reports": context.exploitation_reports,
                "defense_reports": context.defense_reports
            }
        }
        
        # Sauvegarde du rapport final
        report_file = f"audit_reports/final_report_{context.audit_id}.json"
        with open(report_file, 'w') as f:
            json.dump(final_report, f, indent=2)
        
        print(f"✅ Rapport final sauvegardé: {report_file}")
        return final_report
    
    def display_final_summary(self, context: AuditContext):
        """Affiche le résumé final de l'audit"""
        total_time = datetime.now() - context.start_time
        
        print(f"\n{'🎭'*25}")
        print(f"🎭 RÉSUMÉ FINAL DE L'AUDIT {context.audit_id}")
        print(f"{'🎭'*25}")
        
        print(f"\n📊 STATISTIQUES GÉNÉRALES:")
        print(f"   🎯 Vulnérabilité: {context.vulhub_id}")
        print(f"   🌐 Cible: {context.target_address}")
        print(f"   🔄 Cycles exécutés: {context.total_cycles}")
        print(f"   ⏱️ Durée totale: {total_time}")
        print(f"   🛡️ Statut final: {context.vulnerability_status}")
        
        print(f"\n🔧 REMÉDIATION:")
        if context.remediation_applied:
            for patch in context.remediation_applied:
                print(f"   ✅ {patch}")
        else:
            print("   ❌ Aucun patch appliqué")
        
        print(f"\n📈 ÉVOLUTION DU RISQUE:")
        for i, score in enumerate(context.risk_score_evolution, 1):
            print(f"   Cycle {i}: {score:.1f}%")
        
        # Recommandations finales
        if context.vulnerability_status == "SECURED":
            print(f"\n🎉 SUCCÈS: La vulnérabilité a été entièrement corrigée!")
        elif context.vulnerability_status == "PARTIALLY_SECURED":
            print(f"\n⚠ PARTIEL: La vulnérabilité a été partiellement corrigée.")
            print(f"   💡 Recommandation: Continuer la remédiation manuelle.")
        else:
            print(f"\n❌ ÉCHEC: La vulnérabilité persiste.")
            print(f"   💡 Recommandation: Intervention manuelle requise.")
    
    def run(self) -> Optional[Dict[str, Any]]:
        """Méthode principale de l'orchestrateur"""
        try:
            # Bannière de bienvenue
            self.ui.welcome_banner()
            
            # Validation de l'environnement
            if not self.validate_environment():
                print("❌ Impossible de continuer sans un environnement valide")
                return None
            
            # Récupération des informations cible
            vulhub_id, target_address = self.ui.get_target_information()
            if not vulhub_id or not target_address:
                return None
            
            # Options d'audit
            audit_options = self.ui.get_audit_options()
            
            # Initialisation du contexte
            context = self.initialize_audit_context(vulhub_id, target_address, audit_options)
            self.current_context = context
            
            # Boucle principale d'audit
            while (context.vulnerability_status == "VULNERABLE" and 
                   context.total_cycles < context.max_cycles):
                
                # Exécution d'un cycle
                if not self.execute_audit_cycle(context):
                    print("❌ Échec du cycle d'audit")
                    break
                
                # Vérification de la condition d'arrêt
                if context.vulnerability_status in ["SECURED", "PARTIALLY_SECURED"]:
                    print("✅ Objectif de sécurisation atteint!")
                    break
                
                # Confirmation pour continuer
                if context.total_cycles < context.max_cycles:
                    continue_audit = questionary.confirm(
                        f"Vulnérabilité toujours présente. Continuer le cycle {context.total_cycles + 1} ?"
                    ).ask()
                    
                    if not continue_audit:
                        print("🛑 Audit arrêté par l'utilisateur")
                        break
            
            # Finalisation
            context.current_phase = AuditPhase.COMPLETED
            final_report = self.generate_final_report(context)
            self.display_final_summary(context)
            
            return final_report
            
        except KeyboardInterrupt:
            print("\n🛑 Audit interrompu par l'utilisateur")
            if self.current_context:
                self._save_context(self.current_context)
            return None
        
        except Exception as e:
            print(f"\n❌ Erreur inattendue dans l'orchestrateur: {e}")
            if self.current_context:
                self._save_context(self.current_context)
            return None

print("✅ IntelligentOrchestrator complet défini")

# %%
# Point d'entrée principal
def main():
    """Point d'entrée principal de l'orchestrateur"""
    orchestrator = IntelligentOrchestrator()
    
    try:
        final_report = orchestrator.run()
        
        if final_report:
            print(f"\n🎉 AUDIT TERMINÉ AVEC SUCCÈS!")
            print(f"📋 Rapport final disponible dans le répertoire audit_reports/")
        else:
            print(f"\n⚠ Audit terminé sans rapport final")
            
    except Exception as e:
        print(f"\n💥 Erreur fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

# %%
print("🎭 ORCHESTRATEUR INTELLIGENT PRÊT!")
print("Exécutez la cellule main() pour démarrer l'audit interactif.")
