import json
import re
from typing import Dict, List, Set, Any
from pathlib import Path
import logging

class AttackCategorizer:
    """
    Categorizes atomic techniques into logical attack groups
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.categories = self._define_attack_categories()
        self.technique_keywords = self._define_technique_keywords()
        
    def _define_attack_categories(self) -> Dict[str, Dict]:
        """Define attack categories with metadata"""
        return {
            "initial_access": {
                "name": "Initial Access",
                "description": "Techniques used to gain initial foothold",
                "color": "red",
                "priority": 1,
                "tactics": ["initial-access"],
                "techniques": []
            },
            "execution": {
                "name": "Execution",
                "description": "Techniques for executing malicious code",
                "color": "orange",
                "priority": 2,
                "tactics": ["execution"],
                "techniques": []
            },
            "persistence": {
                "name": "Persistence",
                "description": "Techniques to maintain access",
                "color": "yellow",
                "priority": 3,
                "tactics": ["persistence"],
                "techniques": []
            },
            "privilege_escalation": {
                "name": "Privilege Escalation",
                "description": "Techniques to gain higher privileges",
                "color": "purple",
                "priority": 4,
                "tactics": ["privilege-escalation"],
                "techniques": []
            },
            "defense_evasion": {
                "name": "Defense Evasion",
                "description": "Techniques to avoid detection",
                "color": "blue",
                "priority": 5,
                "tactics": ["defense-evasion"],
                "techniques": []
            },
            "credential_access": {
                "name": "Credential Access",
                "description": "Techniques to steal credentials",
                "color": "cyan",
                "priority": 6,
                "tactics": ["credential-access"],
                "techniques": []
            },
            "discovery": {
                "name": "Discovery",
                "description": "Techniques for system/network reconnaissance",
                "color": "green",
                "priority": 7,
                "tactics": ["discovery"],
                "techniques": []
            },
            "lateral_movement": {
                "name": "Lateral Movement",
                "description": "Techniques to move through network",
                "color": "magenta",
                "priority": 8,
                "tactics": ["lateral-movement"],
                "techniques": []
            },
            "collection": {
                "name": "Collection",
                "description": "Techniques to gather data",
                "color": "bright_blue",
                "priority": 9,
                "tactics": ["collection"],
                "techniques": []
            },
            "exfiltration": {
                "name": "Exfiltration",
                "description": "Techniques to steal data",
                "color": "bright_red",
                "priority": 10,
                "tactics": ["exfiltration"],
                "techniques": []
            },
            "command_control": {
                "name": "Command & Control",
                "description": "Techniques for remote communication",
                "color": "bright_yellow",
                "priority": 11,
                "tactics": ["command-and-control"],
                "techniques": []
            },
            "impact": {
                "name": "Impact",
                "description": "Techniques to disrupt operations",
                "color": "bright_red",
                "priority": 12,
                "tactics": ["impact"],
                "techniques": []
            },
            # Special categories for specific attack types
            "web_attacks": {
                "name": "Web Application Attacks",
                "description": "Techniques targeting web applications",
                "color": "bright_cyan",
                "priority": 13,
                "tactics": ["initial-access", "execution"],
                "keywords": ["web", "http", "browser", "javascript", "sql", "xss", "application"],
                "techniques": []
            },
            "process_injection": {
                "name": "Process Injection",
                "description": "Techniques for injecting code into processes",
                "color": "bright_magenta",
                "priority": 14,
                "tactics": ["defense-evasion", "privilege-escalation"],
                "keywords": ["injection", "hollowing", "dll", "process"],
                "techniques": []
            },
            "powershell_attacks": {
                "name": "PowerShell Attacks",
                "description": "PowerShell-based attack techniques",
                "color": "blue",
                "priority": 15,
                "tactics": ["execution", "defense-evasion"],
                "keywords": ["powershell", "ps1", "invoke"],
                "techniques": []
            },
            "network_attacks": {
                "name": "Network Attacks",
                "description": "Network-based attack techniques",
                "color": "green",
                "priority": 16,
                "tactics": ["discovery", "lateral-movement", "credential-access"],
                "keywords": ["network", "smb", "rdp", "ssh", "snmp", "dns"],
                "techniques": []
            },
            "file_system": {
                "name": "File System Attacks",
                "description": "File and directory manipulation techniques",
                "color": "yellow",
                "priority": 17,
                "tactics": ["defense-evasion", "persistence"],
                "keywords": ["file", "directory", "registry", "path"],
                "techniques": []
            }
        }
    
    def _define_technique_keywords(self) -> Dict[str, List[str]]:
        """Define keywords for technique identification"""
        return {
            "web_attacks": [
                "exploit public-facing application", "web shell", "browser", "javascript",
                "sql injection", "xss", "web application", "http", "https", "server"
            ],
            "process_injection": [
                "process injection", "dll injection", "process hollowing", "thread execution hijacking",
                "process doppelgänging", "ptrace", "proc mem", "hollowing", "injection"
            ],
            "powershell_attacks": [
                "powershell", "invoke-", "ps1", "cmdlet", "execution policy", "constrained language",
                "scriptblock", "wmi", "cim"
            ],
            "network_attacks": [
                "network discovery", "remote services", "smb", "rdp", "ssh", "winrm", "llmnr",
                "netbios", "arp", "dns", "snmp", "network sniffing"
            ],
            "credential_attacks": [
                "credential dumping", "password", "hash", "ticket", "lsass", "sam", "ntds",
                "keychain", "credential", "authentication"
            ],
            "privilege_escalation": [
                "privilege escalation", "elevation", "uac bypass", "sudo", "setuid", "escalate",
                "administrator", "root", "elevated"
            ],
            "persistence_attacks": [
                "startup", "registry run", "scheduled task", "service", "autorun", "login",
                "persistence", "startup folder", "cron"
            ],
            "defense_evasion": [
                "masquerading", "obfuscation", "timestomp", "disable security", "process hiding",
                "evasion", "bypass", "steganography", "encoding"
            ]
        }
    
    def categorize_techniques(self, techniques: Dict[str, Any]) -> Dict[str, Any]:
        """Categorize techniques into attack groups"""
        categorized = {cat: self.categories[cat].copy() for cat in self.categories}
        
        # Initialize technique lists
        for category in categorized.values():
            category["techniques"] = []
        
        for tech_id, tech_data in techniques.items():
            assigned_categories = self._assign_technique_to_categories(tech_id, tech_data)
            
            for category in assigned_categories:
                if category in categorized:
                    categorized[category]["techniques"].append({
                        "id": tech_id,
                        "name": tech_data["name"],
                        "platforms": tech_data["platforms"],
                        "test_count": len(tech_data["tests"]),
                        "elevation_required": self._requires_elevation(tech_data),
                        "tactics": tech_data["tactics"]
                    })
        
        # Sort techniques within each category
        for category in categorized.values():
            category["techniques"].sort(key=lambda x: x["name"])
        
        return categorized
    
    def _assign_technique_to_categories(self, tech_id: str, tech_data: Dict) -> List[str]:
        """Assign a technique to appropriate categories"""
        categories = []
        
        # Primary assignment based on tactics
        for tactic in tech_data.get("tactics", []):
            for cat_id, cat_data in self.categories.items():
                if tactic in cat_data.get("tactics", []):
                    categories.append(cat_id)
        
        # Secondary assignment based on keywords
        technique_text = (
            tech_data.get("name", "").lower() + " " + 
            tech_data.get("description", "").lower()
        )
        
        for cat_id, cat_data in self.categories.items():
            if "keywords" in cat_data:
                for keyword in cat_data["keywords"]:
                    if keyword.lower() in technique_text:
                        if cat_id not in categories:
                            categories.append(cat_id)
                        break
        
        # Specific technique ID mappings
        specific_mappings = self._get_specific_technique_mappings()
        for cat_id, tech_ids in specific_mappings.items():
            if tech_id in tech_ids and cat_id not in categories:
                categories.append(cat_id)
        
        return categories if categories else ["discovery"]  # Default category
    
    def _get_specific_technique_mappings(self) -> Dict[str, List[str]]:
        """Define specific technique ID to category mappings"""
        return {
            "web_attacks": ["T1190", "T1505", "T1059.007"],
            "process_injection": ["T1055", "T1055.001", "T1055.002", "T1055.003", 
                                 "T1055.004", "T1055.011", "T1055.012", "T1055.015"],
            "powershell_attacks": ["T1059.001", "T1086", "T1070.001"],
            "network_attacks": ["T1021", "T1018", "T1135", "T1040", "T1557"],
            "credential_access": ["T1003", "T1110", "T1555", "T1552", "T1558"]
        }
    
    def _requires_elevation(self, tech_data: Dict) -> bool:
        """Check if technique requires elevation"""
        for test in tech_data.get("tests", []):
            if test.get("elevation_required", False):
                return True
        return False
    
    def get_attack_chain_suggestions(self, categorized_techniques: Dict) -> List[Dict]:
        """Suggest logical attack chains based on categories"""
        chains = []
        
        # Web Application Attack Chain
        if (categorized_techniques["web_attacks"]["techniques"] and 
            categorized_techniques["execution"]["techniques"]):
            chains.append({
                "name": "Web Application Compromise",
                "description": "Exploit web app -> Execute code -> Escalate privileges",
                "phases": [
                    {"category": "web_attacks", "description": "Initial web exploitation"},
                    {"category": "execution", "description": "Execute malicious code"},
                    {"category": "privilege_escalation", "description": "Escalate privileges"},
                    {"category": "persistence", "description": "Maintain access"}
                ]
            })
        
        # Network Lateral Movement Chain
        if (categorized_techniques["discovery"]["techniques"] and 
            categorized_techniques["credential_access"]["techniques"]):
            chains.append({
                "name": "Network Lateral Movement",
                "description": "Discover network -> Steal creds -> Move laterally",
                "phases": [
                    {"category": "discovery", "description": "Network reconnaissance"},
                    {"category": "credential_access", "description": "Harvest credentials"},
                    {"category": "lateral_movement", "description": "Move to other systems"},
                    {"category": "collection", "description": "Collect sensitive data"}
                ]
            })
        
        # Full Kill Chain
        chains.append({
            "name": "Full Attack Kill Chain",
            "description": "Complete attack lifecycle",
            "phases": [
                {"category": "initial_access", "description": "Gain initial foothold"},
                {"category": "execution", "description": "Execute malicious code"},
                {"category": "persistence", "description": "Establish persistence"},
                {"category": "privilege_escalation", "description": "Escalate privileges"},
                {"category": "defense_evasion", "description": "Evade detection"},
                {"category": "credential_access", "description": "Access credentials"},
                {"category": "discovery", "description": "Reconnaissance"},
                {"category": "lateral_movement", "description": "Move laterally"},
                {"category": "collection", "description": "Collect data"},
                {"category": "exfiltration", "description": "Exfiltrate data"}
            ]
        })
        
        return chains
    
    def filter_by_platform(self, categorized_techniques: Dict, platform: str) -> Dict:
        """Filter categorized techniques by platform"""
        filtered = {}
        
        for cat_id, cat_data in categorized_techniques.items():
            filtered_techniques = []
            for tech in cat_data["techniques"]:
                if platform.lower() in [p.lower() for p in tech["platforms"]]:
                    filtered_techniques.append(tech)
            
            if filtered_techniques:
                filtered[cat_id] = cat_data.copy()
                filtered[cat_id]["techniques"] = filtered_techniques
        
        return filtered
    
    def get_category_summary(self, categorized_techniques: Dict) -> Dict:
        """Get summary statistics for each category"""
        summary = {}
        
        for cat_id, cat_data in categorized_techniques.items():
            techniques = cat_data["techniques"]
            summary[cat_id] = {
                "name": cat_data["name"],
                "description": cat_data["description"],
                "technique_count": len(techniques),
                "elevation_required_count": sum(1 for t in techniques if t["elevation_required"]),
                "platforms": list(set(p for t in techniques for p in t["platforms"])),
                "priority": cat_data["priority"]
            }
        
        return summary

# Example usage
if __name__ == "__main__":
    # This would be used with the TechniqueParser
    categorizer = AttackCategorizer()
    
    # Mock data for testing
    mock_techniques = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "description": "Web application exploitation",
            "tactics": ["initial-access"],
            "platforms": ["windows", "linux"],
            "tests": [{"elevation_required": False}]
        },
        "T1055": {
            "name": "Process Injection",
            "description": "Code injection into processes",
            "tactics": ["defense-evasion", "privilege-escalation"],
            "platforms": ["windows"],
            "tests": [{"elevation_required": True}]
        }
    }
    
    categorized = categorizer.categorize_techniques(mock_techniques)
    summary = categorizer.get_category_summary(categorized)
    
    print("Category Summary:")
    for cat_id, info in summary.items():
        if info["technique_count"] > 0:
            print(f"  {info['name']}: {info['technique_count']} techniques")
