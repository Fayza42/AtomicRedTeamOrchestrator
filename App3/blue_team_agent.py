# Notebook 08: Agent Blue Team - Analyse Défensive et Remédiation
# Filename: notebook_08_agent_blue_team.ipynb

# %% [markdown]
"""
# Agent Blue Team - Analyse Défensive et Remédiation

## Capacités Défensives :
- ✅ Analyse des scripts d'exploitation du Red Team
- ✅ Identification des indicateurs d'attaque (IoC/IoA) 
- ✅ Génération de recommandations de remédiation
- ✅ Création de règles de détection (SIEM, IDS, WAF)
- ✅ Propositions de durcissement du système
- ✅ Métriques de sécurité et KPI de risque

## Workflow :
1. **Input** : analysis_report.json + exploitation_report.json
2. **Analyse des Artefacts** : Examen du script d'exploit et des techniques
3. **Identification IoC/IoA** : Extraction des indicateurs d'attaque
4. **Génération de Défenses** : Règles de détection et de prévention
5. **Plan de Remédiation** : Corrections à court et long terme
6. **Output** : defense_report.json avec plan complet
"""

# %%
import os
import json
import re
import hashlib
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
import subprocess

# Imports LangChain et Pydantic
from pydantic import BaseModel, Field, validator
from langchain.llms import Ollama
from langchain.embeddings import OllamaEmbeddings
from langchain.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.output_parsers import PydanticOutputParser

print("🔵 Initialisation de l'Agent Blue Team...")

# %%
# Modèles Pydantic pour l'Agent Blue Team
class IndicatorOfCompromise(BaseModel):
    """Modèle pour un indicateur de compromission"""
    
    ioc_type: str = Field(
        description="Type d'IoC (IP, URL, file_hash, process_name, etc.)"
    )
    
    value: str = Field(
        description="Valeur de l'indicateur"
    )
    
    severity: str = Field(
        description="Sévérité (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    
    description: str = Field(
        description="Description de l'indicateur et de son contexte"
    )
    
    detection_rule: str = Field(
        description="Règle de détection associée (Sigma, Snort, etc.)"
    )
    
    @validator('severity')
    def validate_severity(cls, v):
        allowed = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if v not in allowed:
            raise ValueError(f"severity doit être dans {allowed}")
        return v

class DefenseRecommendation(BaseModel):
    """Modèle pour une recommandation défensive"""
    
    category: str = Field(
        description="Catégorie (PATCH, CONFIGURATION, MONITORING, NETWORK)"
    )
    
    priority: str = Field(
        description="Priorité (IMMEDIATE, HIGH, MEDIUM, LOW)"
    )
    
    title: str = Field(
        description="Titre court de la recommandation"
    )
    
    description: str = Field(
        description="Description détaillée de la recommandation"
    )
    
    implementation_steps: List[str] = Field(
        description="Étapes d'implémentation",
        default_factory=list
    )
    
    estimated_effort: str = Field(
        description="Effort estimé (minutes, heures, jours)"
    )
    
    risk_reduction: int = Field(
        description="Réduction du risque en pourcentage (0-100)",
        ge=0,
        le=100
    )

class DefenseReport(BaseModel):
    """Modèle pour le rapport de défense complet"""
    
    attack_analysis: Dict[str, Any] = Field(
        description="Analyse de l'attaque du Red Team"
    )
    
    indicators_of_compromise: List[IndicatorOfCompromise] = Field(
        description="Indicateurs de compromission identifiés",
        default_factory=list
    )
    
    defense_recommendations: List[DefenseRecommendation] = Field(
        description="Recommandations de défense",
        default_factory=list
    )
    
    detection_rules: Dict[str, List[str]] = Field(
        description="Règles de détection par type (WAF, IDS, SIEM)",
        default_factory=dict
    )
    
    risk_assessment: Dict[str, Any] = Field(
        description="Évaluation du risque et métriques",
        default_factory=dict
    )
    
    remediation_timeline: Dict[str, List[str]] = Field(
        description="Timeline de remédiation par priorité",
        default_factory=dict
    )

print("✅ Modèles Pydantic pour Blue Team définis")

# %%
# Analyseur de Sécurité pour les Scripts d'Exploitation
class SecurityAnalyzer:
    """Analyseur de sécurité pour les scripts et techniques d'attaque"""
    
    def __init__(self):
        # Patterns d'attaque connus
        self.attack_patterns = {
            'command_injection': [
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec\s*\(',
                r'eval\s*\(',
                r'os\.system',
                r'subprocess\.',
                r'cmd\s*/c',
                r'sh\s+-c'
            ],
            'reverse_shell': [
                r'/dev/tcp/',
                r'nc\s+-[lve]+',
                r'netcat',
                r'bash\s+-i',
                r'>& /dev/tcp',
                r'socket\.socket',
                r'subprocess\.call.*sh'
            ],
            'file_access': [
                r'\.\./',
                r'%2e%2e',
                r'/etc/passwd',
                r'/etc/shadow',
                r'file_get_contents',
                r'fopen\s*\(',
                r'readfile'
            ],
            'web_exploitation': [
                r'requests\.post',
                r'urllib\.request',
                r'curl\s+',
                r'wget\s+',
                r'<script>',
                r'javascript:',
                r'SQL.*UNION',
                r'DROP\s+TABLE'
            ],
            'persistence': [
                r'crontab',
                r'/etc/rc\.local',
                r'systemctl',
                r'service\s+',
                r'\.bashrc',
                r'\.profile',
                r'startup',
                r'registry'
            ]
        }
        
        # Signatures de payloads malveillants
        self.malicious_signatures = {
            'php_backdoor': r'<\?php.*system\s*\(',
            'jsp_shell': r'Runtime\.getRuntime\(\)\.exec',
            'python_reverse': r'socket\.connect.*subprocess',
            'bash_oneliner': r'bash\s+-i\s+>&\s+/dev/tcp',
            'powershell_b64': r'powershell.*-enc.*[A-Za-z0-9+/=]{50,}'
        }
    
    def analyze_script(self, script_content: str, script_language: str) -> Dict[str, Any]:
        """Analyse un script d'exploitation pour identifier les techniques"""
        print(f"🔍 Analyse du script {script_language}...")
        
        analysis_result = {
            'script_language': script_language,
            'script_size': len(script_content),
            'attack_techniques': [],
            'malicious_indicators': [],
            'network_indicators': [],
            'file_indicators': [],
            'suspicious_commands': [],
            'risk_score': 0
        }
        
        # Détection des patterns d'attaque
        total_patterns = 0
        for category, patterns in self.attack_patterns.items():
            category_matches = []
            for pattern in patterns:
                matches = re.findall(pattern, script_content, re.IGNORECASE)
                if matches:
                    category_matches.extend(matches)
                    total_patterns += len(matches)
            
            if category_matches:
                analysis_result['attack_techniques'].append({
                    'category': category,
                    'matches': category_matches[:5],  # Limiter les résultats
                    'count': len(category_matches)
                })
        
        # Détection des signatures malveillantes
        for sig_name, sig_pattern in self.malicious_signatures.items():
            if re.search(sig_pattern, script_content, re.IGNORECASE):
                analysis_result['malicious_indicators'].append(sig_name)
        
        # Extraction des indicateurs réseau
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        port_pattern = r':\d{1,5}\b'
        url_pattern = r'https?://[^\s\'"<>]+'
        
        ips = re.findall(ip_pattern, script_content)
        ports = re.findall(port_pattern, script_content)
        urls = re.findall(url_pattern, script_content)
        
        analysis_result['network_indicators'] = {
            'ip_addresses': list(set(ips)),
            'ports': list(set(ports)),
            'urls': list(set(urls))
        }
        
        # Extraction des indicateurs de fichiers
        file_patterns = [
            r'/etc/[a-zA-Z0-9_.-]+',
            r'/var/[a-zA-Z0-9_./=-]+',
            r'/tmp/[a-zA-Z0-9_.-]+',
            r'[a-zA-Z0-9_.-]+\.(?:php|jsp|asp|exe|sh|py)'
        ]
        
        files = []
        for pattern in file_patterns:
            files.extend(re.findall(pattern, script_content))
        
        analysis_result['file_indicators'] = list(set(files))
        
        # Commandes suspectes
        command_patterns = [
            r'(?:sudo|su)\s+[^\n]+',
            r'chmod\s+[^\n]+',
            r'chown\s+[^\n]+',
            r'cat\s+/etc/[^\n]+',
            r'find\s+/.*-name[^\n]+',
            r'grep\s+-r[^\n]+'
        ]
        
        for pattern in command_patterns:
            commands = re.findall(pattern, script_content, re.IGNORECASE)
            analysis_result['suspicious_commands'].extend(commands)
        
        # Calcul du score de risque
        risk_score = 0
        risk_score += len(analysis_result['attack_techniques']) * 10
        risk_score += len(analysis_result['malicious_indicators']) * 20
        risk_score += len(analysis_result['network_indicators']['ip_addresses']) * 5
        risk_score += len(analysis_result['suspicious_commands']) * 3
        
        analysis_result['risk_score'] = min(risk_score, 100)  # Maximum 100
        
        print(f"  📊 Score de risque: {analysis_result['risk_score']}/100")
        print(f"  🎯 Techniques détectées: {len(analysis_result['attack_techniques'])}")
        
        return analysis_result

    def extract_iocs(self, script_analysis: Dict[str, Any], execution_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extrait les IoCs du script et des résultats d'exécution"""
        print("🚨 Extraction des indicateurs de compromission...")
        
        iocs = []
        
        # IoCs des adresses IP
        for ip in script_analysis['network_indicators']['ip_addresses']:
            if not self._is_private_ip(ip):
                iocs.append({
                    'type': 'ip_address',
                    'value': ip,
                    'severity': 'HIGH',
                    'description': f'Adresse IP externe trouvée dans le script d\'exploitation',
                    'source': 'script_analysis'
                })
        
        # IoCs des URLs malveillantes
        for url in script_analysis['network_indicators']['urls']:
            iocs.append({
                'type': 'url',
                'value': url,
                'severity': 'MEDIUM',
                'description': f'URL trouvée dans le script d\'exploitation',
                'source': 'script_analysis'
            })
        
        # IoCs des fichiers suspects
        for file_path in script_analysis['file_indicators']:
            if any(danger in file_path.lower() for danger in ['/etc/', '/var/', '.php', '.jsp']):
                iocs.append({
                    'type': 'file_path',
                    'value': file_path,
                    'severity': 'MEDIUM',
                    'description': f'Fichier suspect accédé: {file_path}',
                    'source': 'script_analysis'
                })
        
        # IoCs des commandes suspectes
        for cmd in script_analysis['suspicious_commands'][:5]:  # Limiter
            iocs.append({
                'type': 'command',
                'value': cmd,
                'severity': 'HIGH',
                'description': f'Commande suspecte exécutée',
                'source': 'script_analysis'
            })
        
        # IoCs des techniques d'attaque
        for technique in script_analysis['attack_techniques']:
            iocs.append({
                'type': 'attack_technique',
                'value': technique['category'],
                'severity': 'CRITICAL',
                'description': f'Technique d\'attaque identifiée: {technique["category"]}',
                'source': 'script_analysis'
            })
        
        print(f"  🚨 {len(iocs)} IoCs extraits")
        return iocs

    def _is_private_ip(self, ip: str) -> bool:
        """Vérifie si une IP est privée"""
        private_ranges = [
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^127\.',
            r'^169\.254\.'
        ]
        
        for range_pattern in private_ranges:
            if re.match(range_pattern, ip):
                return True
        return False

print("✅ SecurityAnalyzer défini")

# %%
# Agent Blue Team Principal
class BlueTeamAgent:
    """
    Agent Blue Team spécialisé dans l'analyse défensive et la remédiation
    """
    
    def __init__(self, model_name: str = "llama2:7b"):
        print("🔵 Initialisation de BlueTeamAgent...")
        
        # Initialisation LLM
        self.llm = Ollama(model=model_name, temperature=0.2)  # Température plus basse pour la précision
        
        # Analyseur de sécurité
        self.security_analyzer = SecurityAnalyzer()
        
        # Parsers Pydantic
        self.defense_parser = PydanticOutputParser(pydantic_object=DefenseReport)
        
        # Configuration des prompts
        self._setup_prompts()
        
        print("  ✅ BlueTeamAgent initialisé")

    def _setup_prompts(self):
        """Configuration des prompts pour l'analyse défensive"""
        
        # Prompt principal d'analyse défensive
        defense_template = """Tu es un expert en cybersécurité défensive avec 15 ans d'expérience en réponse aux incidents.

ANALYSE DE L'ATTAQUE DU RED TEAM:
{attack_analysis}

SCRIPT D'EXPLOITATION ANALYSÉ:
{script_analysis}

INDICATEURS DE COMPROMISSION DÉTECTÉS:
{iocs_detected}

RÉSULTATS D'EXÉCUTION:
{execution_results}

{format_instructions}

MISSION: Créer un plan de défense complet pour contrer cette attaque et prévenir de futures intrusions.

ANALYSE REQUISE:
1. Évaluation de l'impact de l'attaque
2. Identification des failles de sécurité exploitées
3. Recommandations de remédiation par priorité
4. Règles de détection pour SIEM/IDS/WAF
5. Plan de durcissement du système
6. Timeline de remédiation

CONSIDÉRATIONS SPÉCIALES:
- Prioriser les correctifs critiques
- Proposer des mesures temporaires si les correctifs prennent du temps
- Inclure des métriques de sécurité
- Considérer l'impact business des recommandations

RAPPORT DE DÉFENSE:"""

        self.defense_prompt = PromptTemplate(
            template=defense_template,
            input_variables=["attack_analysis", "script_analysis", "iocs_detected", "execution_results"],
            partial_variables={"format_instructions": self.defense_parser.get_format_instructions()}
        )
        
        # Chaîne LangChain
        self.defense_chain = LLMChain(llm=self.llm, prompt=self.defense_prompt)

    def analyze_red_team_attack(self, analysis_report: Dict[str, Any], 
                              exploitation_report: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse complète de l'attaque du Red Team"""
        print("🔍 Analyse de l'attaque du Red Team...")
        
        # Extraction des informations d'attaque
        attack_info = {
            'vulnerability_exploited': analysis_report.get('analysis_report', {}).get('vulnerability_details', {}),
            'exploitation_strategy': exploitation_report.get('exploitation_report', {}).get('exploit_strategy', ''),
            'success_level': exploitation_report.get('exploitation_report', {}).get('success_level', 'UNKNOWN'),
            'attack_duration': exploitation_report.get('metadata', {}).get('execution_time', 0),
            'compromise_evidence': exploitation_report.get('exploitation_report', {}).get('compromise_evidence', [])
        }
        
        # Analyse du script d'exploitation
        generated_script = exploitation_report.get('exploitation_report', {}).get('generated_script', {})
        script_content = generated_script.get('script_content', '')
        script_language = generated_script.get('script_language', 'unknown')
        
        script_analysis = self.security_analyzer.analyze_script(script_content, script_language)
        
        # Exécution des résultats
        execution_results = exploitation_report.get('exploitation_report', {}).get('execution_results', {})
        
        # Extraction des IoCs
        iocs = self.security_analyzer.extract_iocs(script_analysis, execution_results)
        
        print(f"  📊 Niveau de succès de l'attaque: {attack_info['success_level']}")
        print(f"  🚨 IoCs détectés: {len(iocs)}")
        print(f"  🎯 Score de risque du script: {script_analysis['risk_score']}/100")
        
        return {
            'attack_info': attack_info,
            'script_analysis': script_analysis,
            'iocs': iocs,
            'execution_results': execution_results
        }

    def generate_detection_rules(self, script_analysis: Dict[str, Any], iocs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Génère des règles de détection pour différents systèmes"""
        print("🛡️ Génération des règles de détection...")
        
        detection_rules = {
            'waf_rules': [],
            'ids_rules': [],
            'siem_rules': [],
            'endpoint_rules': []
        }
        
        # Règles WAF pour les attaques web
        for technique in script_analysis.get('attack_techniques', []):
            if technique['category'] == 'web_exploitation':
                detection_rules['waf_rules'].append(
                    f"SecRule ARGS \"@detectSQLi\" \"id:1001,phase:2,block,msg:'SQL Injection detected in {technique['category']}'\""
                )
                detection_rules['waf_rules'].append(
                    f"SecRule ARGS \"@contains ../\" \"id:1002,phase:2,block,msg:'Path traversal attempt detected'\""
                )
        
        # Règles IDS pour le trafic réseau
        for ip in script_analysis.get('network_indicators', {}).get('ip_addresses', []):
            if not self.security_analyzer._is_private_ip(ip):
                detection_rules['ids_rules'].append(
                    f"alert tcp any any -> {ip} any (msg:\"Traffic to suspicious IP {ip}\"; sid:2001; rev:1;)"
                )
        
        # Règles SIEM pour les logs
        for cmd in script_analysis.get('suspicious_commands', [])[:3]:
            detection_rules['siem_rules'].append(
                f"DeviceProduct=* AND CommandLine=\"*{cmd}*\" | eval threat_level=\"HIGH\""
            )
        
        # Règles endpoint pour les processus
        if 'reverse_shell' in [t['category'] for t in script_analysis.get('attack_techniques', [])]:
            detection_rules['endpoint_rules'].append(
                "ProcessName=*sh OR ProcessName=*cmd.exe AND CommandLine=\"*/dev/tcp/*\""
            )
            detection_rules['endpoint_rules'].append(
                "NetworkConnection AND DestinationPort IN (4444,1234,9999) AND Direction=Outbound"
            )
        
        total_rules = sum(len(rules) for rules in detection_rules.values())
        print(f"  🛡️ {total_rules} règles de détection générées")
        
        return detection_rules

    def create_remediation_plan(self, attack_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Crée un plan de remédiation détaillé"""
        print("📋 Création du plan de remédiation...")
        
        recommendations = []
        
        # Analyse de la vulnérabilité principale
        vuln_details = attack_analysis['attack_info']['vulnerability_exploited']
        cve = vuln_details.get('cve', '')
        attack_type = vuln_details.get('attack_type', '')
        
        # Recommandations basées sur le type d'attaque
        if 'Path Traversal' in attack_type or 'Directory Traversal' in attack_type:
            recommendations.append({
                'category': 'PATCH',
                'priority': 'IMMEDIATE',
                'title': 'Correction de la vulnérabilité Path Traversal',
                'description': f'Appliquer le patch de sécurité pour {cve}',
                'implementation_steps': [
                    'Identifier la version exacte du logiciel affecté',
                    'Télécharger le patch de sécurité officiel',
                    'Tester le patch en environnement de développement',
                    'Planifier une fenêtre de maintenance',
                    'Appliquer le patch en production',
                    'Vérifier que la vulnérabilité est corrigée'
                ],
                'estimated_effort': '2-4 heures',
                'risk_reduction': 90
            })
            
            recommendations.append({
                'category': 'CONFIGURATION',
                'priority': 'HIGH',
                'title': 'Durcissement de la configuration web',
                'description': 'Configurer le serveur web pour bloquer les tentatives de path traversal',
                'implementation_steps': [
                    'Configurer le serveur web pour bloquer les séquences "../"',
                    'Implémenter une liste blanche de fichiers accessibles',
                    'Activer les logs détaillés des tentatives d\'accès',
                    'Configurer des répertoires en lecture seule'
                ],
                'estimated_effort': '1-2 heures',
                'risk_reduction': 70
            })
        
        if 'Remote Code Execution' in attack_type or 'RCE' in attack_type:
            recommendations.append({
                'category': 'PATCH',
                'priority': 'IMMEDIATE',
                'title': 'Correction critique de RCE',
                'description': f'Correction immédiate de la vulnérabilité RCE {cve}',
                'implementation_steps': [
                    'Isoler immédiatement le service affecté',
                    'Appliquer le patch de sécurité critique',
                    'Redémarrer les services concernés',
                    'Vérifier l\'intégrité du système',
                    'Analyser les logs pour des traces d\'exploitation'
                ],
                'estimated_effort': '1-3 heures',
                'risk_reduction': 95
            })
        
        # Recommandations basées sur les techniques détectées
        attack_techniques = [t['category'] for t in attack_analysis['script_analysis'].get('attack_techniques', [])]
        
        if 'reverse_shell' in attack_techniques:
            recommendations.append({
                'category': 'NETWORK',
                'priority': 'HIGH',
                'title': 'Blocage des connexions sortantes suspectes',
                'description': 'Configurer le firewall pour bloquer les connexions sortantes non autorisées',
                'implementation_steps': [
                    'Identifier les ports utilisés pour les reverse shells',
                    'Configurer des règles de firewall sortant restrictives',
                    'Mettre en place une surveillance des connexions sortantes',
                    'Alerter sur les tentatives de connexion vers des IPs externes'
                ],
                'estimated_effort': '30-60 minutes',
                'risk_reduction': 60
            })
        
        if 'command_injection' in attack_techniques:
            recommendations.append({
                'category': 'CONFIGURATION',
                'priority': 'HIGH',
                'title': 'Durcissement contre l\'injection de commandes',
                'description': 'Renforcer la validation des entrées et l\'isolation des processus',
                'implementation_steps': [
                    'Implémenter une validation stricte des entrées utilisateur',
                    'Utiliser des fonctions sécurisées pour l\'exécution de commandes',
                    'Mettre en place une sandbox pour les processus web',
                    'Limiter les privilèges des comptes de service'
                ],
                'estimated_effort': '4-8 heures',
                'risk_reduction': 85
            })
        
        # Recommandations de surveillance
        recommendations.append({
            'category': 'MONITORING',
            'priority': 'MEDIUM',
            'title': 'Amélioration de la surveillance de sécurité',
            'description': 'Mettre en place une surveillance avancée pour détecter les attaques similaires',
            'implementation_steps': [
                'Déployer des règles de détection dans le SIEM',
                'Configurer des alertes temps réel',
                'Mettre en place des tableaux de bord de sécurité',
                'Former l\'équipe aux nouveaux indicateurs'
            ],
            'estimated_effort': '1-2 jours',
            'risk_reduction': 40
        })
        
        print(f"  📋 {len(recommendations)} recommandations créées")
        return recommendations

    def calculate_risk_metrics(self, attack_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calcule les métriques de risque et KPI"""
        print("📊 Calcul des métriques de risque...")
        
        # Score de base selon le succès de l'attaque
        success_level = attack_analysis['attack_info']['success_level']
        base_risk = {
            'FULL': 100,
            'PARTIAL': 70,
            'FAILED': 30
        }.get(success_level, 50)
        
        # Facteurs de risque supplémentaires
        script_risk = attack_analysis['script_analysis']['risk_score']
        ioc_count = len(attack_analysis['iocs'])
        technique_count = len(attack_analysis['script_analysis'].get('attack_techniques', []))
        
        # Calcul du risque global
        risk_factors = {
            'exploitation_success': base_risk * 0.4,
            'script_complexity': script_risk * 0.3,
            'ioc_severity': min(ioc_count * 5, 50) * 0.2,
            'technique_diversity': min(technique_count * 10, 50) * 0.1
        }
        
        total_risk = sum(risk_factors.values())
        
        # Classification du risque
        if total_risk >= 80:
            risk_level = 'CRITICAL'
        elif total_risk >= 60:
            risk_level = 'HIGH'
        elif total_risk >= 40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        # Métriques additionnelles
        cvss_score = None
        vuln_details = attack_analysis['attack_info']['vulnerability_exploited']
        if 'cvss_score' in vuln_details:
            try:
                cvss_score = float(vuln_details['cvss_score'])
            except:
                pass
        
        metrics = {
            'overall_risk_score': round(total_risk, 1),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'cvss_score': cvss_score,
            'attack_success_rate': base_risk,
            'ioc_count': ioc_count,
            'technique_count': technique_count,
            'estimated_recovery_time': self._estimate_recovery_time(total_risk),
            'business_impact': self._assess_business_impact(total_risk, success_level)
        }
        
        print(f"  📊 Risque global: {total_risk:.1f}/100 ({risk_level})")
        return metrics

    def _estimate_recovery_time(self, risk_score: float) -> str:
        """Estime le temps de récupération basé sur le score de risque"""
        if risk_score >= 80:
            return "24-48 heures"
        elif risk_score >= 60:
            return "8-24 heures"
        elif risk_score >= 40:
            return "4-8 heures"
        else:
            return "1-4 heures"

    def _assess_business_impact(self, risk_score: float, success_level: str) -> str:
        """Évalue l'impact business"""
        if success_level == 'FULL' and risk_score >= 80:
            return "SEVERE - Arrêt potentiel des opérations"
        elif success_level == 'FULL' and risk_score >= 60:
            return "HIGH - Impact significatif sur les opérations"
        elif success_level == 'PARTIAL':
            return "MEDIUM - Impact limité mais surveillance requise"
        else:
            return "LOW - Impact minimal"

    def generate_defense_report(self, attack_analysis: Dict[str, Any]) -> DefenseReport:
        """Génère le rapport de défense complet avec le LLM"""
        print("📋 Génération du rapport de défense avec LLM...")
        
        try:
            # Préparation des données pour le LLM
            defense_result = self.defense_chain.run(
                attack_analysis=json.dumps(attack_analysis['attack_info'], indent=2),
                script_analysis=json.dumps(attack_analysis['script_analysis'], indent=2),
                iocs_detected=json.dumps(attack_analysis['iocs'], indent=2),
                execution_results=json.dumps(attack_analysis['execution_results'], indent=2)
            )
            
            # Parsing avec Pydantic
            defense_report = self.defense_parser.parse(defense_result)
            
            print("  ✅ Rapport de défense généré avec LLM")
            return defense_report
            
        except Exception as e:
            print(f"  ⚠ Erreur génération LLM: {e}, utilisation du fallback...")
            
            # Génération manuelle en cas d'échec LLM
            detection_rules = self.generate_detection_rules(
                attack_analysis['script_analysis'], 
                attack_analysis['iocs']
            )
            
            recommendations = self.create_remediation_plan(attack_analysis)
            risk_metrics = self.calculate_risk_metrics(attack_analysis)
            
            # Conversion des IoCs au format Pydantic
            pydantic_iocs = []
            for ioc in attack_analysis['iocs']:
                pydantic_iocs.append(IndicatorOfCompromise(
                    ioc_type=ioc['type'],
                    value=ioc['value'],
                    severity=ioc['severity'],
                    description=ioc['description'],
                    detection_rule=f"Monitor for {ioc['type']}: {ioc['value']}"
                ))
            
            # Conversion des recommandations
            pydantic_recommendations = []
            for rec in recommendations:
                pydantic_recommendations.append(DefenseRecommendation(**rec))
            
            return DefenseReport(
                attack_analysis=attack_analysis['attack_info'],
                indicators_of_compromise=pydantic_iocs,
                defense_recommendations=pydantic_recommendations,
                detection_rules=detection_rules,
                risk_assessment=risk_metrics,
                remediation_timeline={
                    'immediate': [r.title for r in pydantic_recommendations if r.priority == 'IMMEDIATE'],
                    'high': [r.title for r in pydantic_recommendations if r.priority == 'HIGH'],
                    'medium': [r.title for r in pydantic_recommendations if r.priority == 'MEDIUM']
                }
            )

    def run(self, analysis_report_path: str, exploitation_report_path: str) -> Dict[str, Any]:
        """Méthode principale de l'agent Blue Team"""
        print(f"\n{'🔵'*20}")
        print(f"🔵 DÉMARRAGE DE L'AGENT BLUE TEAM")
        print(f"{'🔵'*20}")
        
        start_time = time.time()
        
        try:
            # Chargement des rapports
            print("\n📖 [1/4] Chargement des rapports Red Team...")
            
            with open(analysis_report_path, 'r') as f:
                analysis_report = json.load(f)
            
            with open(exploitation_report_path, 'r') as f:
                exploitation_report = json.load(f)
            
            # Analyse de l'attaque
            print("\n🔍 [2/4] Analyse de l'attaque Red Team...")
            attack_analysis = self.analyze_red_team_attack(analysis_report, exploitation_report)
            
            # Génération du rapport de défense
            print("\n🛡️ [3/4] Génération du plan de défense...")
            defense_report = self.generate_defense_report(attack_analysis)
            
            # Finalisation
            print("\n📋 [4/4] Finalisation du rapport...")
            
            total_time = time.time() - start_time
            
            complete_result = {
                "metadata": {
                    "agent": "BlueTeamAgent",
                    "version": "2.0",
                    "timestamp": datetime.now().isoformat(),
                    "execution_time": total_time,
                    "analysis_source": analysis_report_path,
                    "exploitation_source": exploitation_report_path
                },
                "defense_report": defense_report.dict(),
                "status": "SUCCESS"
            }
            
            # Sauvegarde du rapport
            report_file = "defense_report.json"
            with open(report_file, 'w') as f:
                json.dump(complete_result, f, indent=2)
            
            print(f"\n✅ ANALYSE DÉFENSIVE TERMINÉE")
            print(f"⏱️ Temps total: {total_time:.2f} secondes")
            print(f"🚨 IoCs détectés: {len(defense_report.indicators_of_compromise)}")
            print(f"🛡️ Recommandations: {len(defense_report.defense_recommendations)}")
            print(f"📊 Niveau de risque: {defense_report.risk_assessment.get('risk_level', 'UNKNOWN')}")
            print(f"💾 Rapport sauvegardé: {report_file}")
            
            return complete_result
            
        except Exception as e:
            print(f"\n❌ ERREUR DANS L'ANALYSE DÉFENSIVE: {e}")
            return {
                "metadata": {
                    "agent": "BlueTeamAgent",
                    "timestamp": datetime.now().isoformat()
                },
                "status": "ERROR",
                "error": str(e)
            }

print("✅ BlueTeamAgent complet défini")

# %%
# Démonstration et test de l'agent Blue Team
if __name__ == "__main__":
    print(f"\n🧪 DÉMONSTRATION DE L'AGENT BLUE TEAM")
    print("="*50)
    
    # Chargement de la configuration
    try:
        with open("vple_config.json", "r") as f:
            config = json.load(f)
        model_name = config.get("confirmed_model", "llama2:7b")
    except:
        model_name = "llama2:7b"
    
    # Initialisation de l'agent
    blue_team_agent = BlueTeamAgent(model_name=model_name)
    
    # Vérification de l'existence des rapports
    analysis_report_path = "analysis_report.json"
    exploitation_report_path = "exploitation_report.json"
    
    if os.path.exists(analysis_report_path) and os.path.exists(exploitation_report_path):
        print("📄 Rapports Red Team trouvés, lancement de l'analyse...")
        
        # Test de l'agent
        result = blue_team_agent.run(analysis_report_path, exploitation_report_path)
        
        if result['status'] == 'SUCCESS':
            defense_report = result['defense_report']
            print(f"\n✅ Test réussi!")
            print(f"   IoCs: {len(defense_report['indicators_of_compromise'])}")
            print(f"   Recommandations: {len(defense_report['defense_recommendations'])}")
            print(f"   Risque: {defense_report['risk_assessment'].get('risk_level', 'UNKNOWN')}")
        else:
            print(f"\n❌ Test échoué: {result.get('error', 'Erreur inconnue')}")
    
    else:
        print("⚠ Rapports Red Team non trouvés, création de données fictives...")
        
        # Création de rapports fictifs pour test
        fake_analysis = {
            "analysis_report": {
                "vulnerability_details": {
                    "cve": "CVE-2021-41773",
                    "attack_type": "Path Traversal to RCE",
                    "cvss_score": "7.5"
                }
            }
        }
        
        fake_exploitation = {
            "exploitation_report": {
                "exploit_strategy": "Path traversal combined with log poisoning",
                "generated_script": {
                    "script_content": "import requests\nrequests.get('http://target/../../../etc/passwd')",
                    "script_language": "python"
                },
                "execution_results": {"return_code": 0},
                "success_level": "PARTIAL",
                "compromise_evidence": ["Script executed successfully"]
            }
        }
        
        with open(analysis_report_path, 'w') as f:
            json.dump(fake_analysis, f, indent=2)
        
        with open(exploitation_report_path, 'w') as f:
            json.dump(fake_exploitation, f, indent=2)
        
        print("📝 Rapports fictifs créés, test de l'agent...")
        
        result = blue_team_agent.run(analysis_report_path, exploitation_report_path)
        
        if result['status'] == 'SUCCESS':
            print(f"✅ Test avec données fictives réussi!")
        else:
            print(f"❌ Test échoué: {result.get('error', 'Erreur inconnue')}")
    
    print(f"\n🎉 DÉMONSTRATION TERMINÉE")
    print("L'agent Blue Team est prêt pour l'orchestrateur!")
