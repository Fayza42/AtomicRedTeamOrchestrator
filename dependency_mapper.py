import networkx as nx
import json
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass
import logging

@dataclass
class TechniqueDependency:
    """Represents a dependency between two techniques"""
    source: str
    target: str
    dependency_type: str
    weight: float
    description: str
    conditional: bool = False

class DependencyMapper:
    """
    Maps dependencies between atomic techniques to create logical attack chains
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.dependency_graph = nx.DiGraph()
        self.dependency_rules = self._define_dependency_rules()
        self.technique_requirements = self._define_technique_requirements()
        
    def _define_dependency_rules(self) -> Dict[str, List[Dict]]:
        """Define logical dependencies between techniques"""
        return {
            # Initial Access -> Execution
            "initial_to_execution": [
                {
                    "from_tactics": ["initial-access"],
                    "to_tactics": ["execution"],
                    "weight": 0.9,
                    "description": "Initial access enables code execution"
                }
            ],
            
            # Execution -> Persistence
            "execution_to_persistence": [
                {
                    "from_tactics": ["execution"],
                    "to_tactics": ["persistence"],
                    "weight": 0.8,
                    "description": "Code execution enables persistence mechanisms"
                }
            ],
            
            # Any -> Privilege Escalation (conditional)
            "to_privilege_escalation": [
                {
                    "from_tactics": ["execution", "persistence", "initial-access"],
                    "to_tactics": ["privilege-escalation"],
                    "weight": 0.7,
                    "description": "Many techniques can lead to privilege escalation",
                    "conditional": True
                }
            ],
            
            # Privilege Escalation -> Defense Evasion
            "escalation_to_evasion": [
                {
                    "from_tactics": ["privilege-escalation"],
                    "to_tactics": ["defense-evasion"],
                    "weight": 0.8,
                    "description": "Elevated privileges enable better evasion"
                }
            ],
            
            # Any elevated -> Credential Access
            "to_credential_access": [
                {
                    "from_tactics": ["privilege-escalation", "defense-evasion"],
                    "to_tactics": ["credential-access"],
                    "weight": 0.9,
                    "description": "Elevated access enables credential dumping"
                }
            ],
            
            # Execution/Persistence -> Discovery
            "to_discovery": [
                {
                    "from_tactics": ["execution", "persistence", "privilege-escalation"],
                    "to_tactics": ["discovery"],
                    "weight": 0.6,
                    "description": "Established access enables reconnaissance"
                }
            ],
            
            # Discovery + Credentials -> Lateral Movement
            "discovery_creds_to_lateral": [
                {
                    "from_tactics": ["discovery", "credential-access"],
                    "to_tactics": ["lateral-movement"],
                    "weight": 1.0,
                    "description": "Discovery and credentials enable lateral movement",
                    "requires_both": True
                }
            ],
            
            # Lateral Movement -> Collection
            "lateral_to_collection": [
                {
                    "from_tactics": ["lateral-movement"],
                    "to_tactics": ["collection"],
                    "weight": 0.7,
                    "description": "Lateral movement enables data collection"
                }
            ],
            
            # Collection -> Exfiltration
            "collection_to_exfiltration": [
                {
                    "from_tactics": ["collection"],
                    "to_tactics": ["exfiltration"],
                    "weight": 0.9,
                    "description": "Data collection enables exfiltration"
                }
            ],
            
            # Command & Control (parallel to many)
            "to_command_control": [
                {
                    "from_tactics": ["execution", "persistence"],
                    "to_tactics": ["command-and-control"],
                    "weight": 0.5,
                    "description": "Established access enables C2 communication"
                }
            ]
        }
    
    def _define_technique_requirements(self) -> Dict[str, Dict]:
        """Define specific requirements for techniques"""
        return {
            # Process injection techniques need existing process access
            "process_injection": {
                "requires": ["execution", "privilege-escalation"],
                "enables": ["defense-evasion", "privilege-escalation"],
                "techniques": ["T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004"]
            },
            
            # Web attacks typically are initial access
            "web_attacks": {
                "requires": [],
                "enables": ["execution", "persistence"],
                "techniques": ["T1190", "T1505"]
            },
            
            # PowerShell attacks need execution capability
            "powershell_execution": {
                "requires": ["execution"],
                "enables": ["defense-evasion", "credential-access", "discovery"],
                "techniques": ["T1059.001", "T1086"]
            },
            
            # Network attacks need network access
            "network_attacks": {
                "requires": ["discovery"],
                "enables": ["lateral-movement", "credential-access"],
                "techniques": ["T1021", "T1135", "T1018"]
            },
            
            # Credential attacks need some level of access
            "credential_dumping": {
                "requires": ["execution", "privilege-escalation"],
                "enables": ["lateral-movement", "persistence"],
                "techniques": ["T1003", "T1003.001", "T1003.002", "T1003.003"]
            },
            
            # Registry attacks need system access
            "registry_attacks": {
                "requires": ["execution"],
                "enables": ["persistence", "defense-evasion", "discovery"],
                "techniques": ["T1112", "T1012", "T1547.001"]
            },
            
            # Service attacks need privileges
            "service_attacks": {
                "requires": ["privilege-escalation"],
                "enables": ["persistence", "defense-evasion"],
                "techniques": ["T1543", "T1569"]
            }
        }
    
    def build_dependency_graph(self, techniques: Dict[str, Any]) -> nx.DiGraph:
        """Build dependency graph from techniques"""
        self.dependency_graph.clear()
        
        # Add all techniques as nodes
        for tech_id, tech_data in techniques.items():
            self.dependency_graph.add_node(
                tech_id,
                name=tech_data.get("name", ""),
                tactics=tech_data.get("tactics", []),
                platforms=tech_data.get("platforms", []),
                elevation_required=self._requires_elevation(tech_data),
                test_count=len(tech_data.get("tests", []))
            )
        
        # Add edges based on dependency rules
        self._add_tactical_dependencies(techniques)
        self._add_specific_technique_dependencies(techniques)
        self._add_platform_dependencies(techniques)
        self._add_elevation_dependencies(techniques)
        
        return self.dependency_graph
    
    def _add_tactical_dependencies(self, techniques: Dict[str, Any]):
        """Add dependencies based on tactical relationships"""
        for rule_name, rules in self.dependency_rules.items():
            for rule in rules:
                from_tactics = rule["from_tactics"]
                to_tactics = rule["to_tactics"]
                weight = rule["weight"]
                description = rule["description"]
                
                # Find techniques matching from_tactics
                from_techniques = [
                    tech_id for tech_id, tech_data in techniques.items()
                    if any(tactic in tech_data.get("tactics", []) for tactic in from_tactics)
                ]
                
                # Find techniques matching to_tactics
                to_techniques = [
                    tech_id for tech_id, tech_data in techniques.items()
                    if any(tactic in tech_data.get("tactics", []) for tactic in to_tactics)
                ]
                
                # Add edges
                for from_tech in from_techniques:
                    for to_tech in to_techniques:
                        if from_tech != to_tech:
                            self.dependency_graph.add_edge(
                                from_tech, to_tech,
                                weight=weight,
                                dependency_type="tactical",
                                description=description,
                                rule=rule_name
                            )
    
    def _add_specific_technique_dependencies(self, techniques: Dict[str, Any]):
        """Add specific technique-to-technique dependencies"""
        specific_deps = {
            # Web exploitation -> Command execution
            "T1190": ["T1059", "T1059.001", "T1059.003", "T1059.004"],
            
            # Process injection prerequisites
            "T1055": ["T1134", "T1134.001", "T1134.002"],  # Token manipulation first
            
            # Credential dumping chain
            "T1003": ["T1055", "T1134"],  # Process manipulation first
            
            # Registry discovery -> Registry modification
            "T1012": ["T1112", "T1547.001"],
            
            # Network discovery -> Lateral movement
            "T1018": ["T1021.001", "T1021.002", "T1021.003"],
            "T1135": ["T1021.001", "T1021.002"],
            
            # Service discovery -> Service manipulation
            "T1007": ["T1543.003", "T1569.002"],
            
            # File discovery -> File manipulation
            "T1083": ["T1107", "T1070.004", "T1564.001"]
        }
        
        for from_tech, to_techs in specific_deps.items():
            if from_tech in techniques:
                for to_tech in to_techs:
                    if to_tech in techniques:
                        self.dependency_graph.add_edge(
                            from_tech, to_tech,
                            weight=0.8,
                            dependency_type="specific",
                            description=f"{from_tech} enables {to_tech}"
                        )
    
    def _add_platform_dependencies(self, techniques: Dict[str, Any]):
        """Add dependencies based on platform compatibility"""
        for tech1_id, tech1_data in techniques.items():
            for tech2_id, tech2_data in techniques.items():
                if tech1_id != tech2_id:
                    # Check platform compatibility
                    platforms1 = set(tech1_data.get("platforms", []))
                    platforms2 = set(tech2_data.get("platforms", []))
                    
                    if platforms1.intersection(platforms2):
                        # Compatible platforms, check if edge exists
                        if self.dependency_graph.has_edge(tech1_id, tech2_id):
                            # Add platform compatibility weight
                            edge_data = self.dependency_graph[tech1_id][tech2_id]
                            edge_data["platform_compatible"] = True
                            edge_data["weight"] *= 1.1  # Boost weight for compatible platforms
    
    def _add_elevation_dependencies(self, techniques: Dict[str, Any]):
        """Add dependencies based on elevation requirements"""
        non_elevated = []
        elevated = []
        
        for tech_id, tech_data in techniques.items():
            if self._requires_elevation(tech_data):
                elevated.append(tech_id)
            else:
                non_elevated.append(tech_id)
        
        # Non-elevated techniques can enable elevated techniques
        for non_elev in non_elevated:
            for elev in elevated:
                if not self.dependency_graph.has_edge(non_elev, elev):
                    # Check if there's a tactical relationship
                    non_elev_tactics = techniques[non_elev].get("tactics", [])
                    elev_tactics = techniques[elev].get("tactics", [])
                    
                    if ("privilege-escalation" in elev_tactics and 
                        any(t in ["execution", "initial-access"] for t in non_elev_tactics)):
                        self.dependency_graph.add_edge(
                            non_elev, elev,
                            weight=0.6,
                            dependency_type="elevation",
                            description=f"Non-elevated {non_elev} can lead to elevated {elev}"
                        )
    
    def _requires_elevation(self, tech_data: Dict) -> bool:
        """Check if technique requires elevation"""
        for test in tech_data.get("tests", []):
            if test.get("elevation_required", False):
                return True
        return False
    
    def get_attack_chains(self, start_techniques: List[str] = None, 
                         max_length: int = 10) -> List[List[str]]:
        """Generate attack chains from the dependency graph"""
        chains = []
        
        if not start_techniques:
            # Find good starting points (techniques with no dependencies or minimal deps)
            start_techniques = [
                node for node in self.dependency_graph.nodes()
                if self.dependency_graph.in_degree(node) <= 2
            ]
        
        for start in start_techniques:
            if start in self.dependency_graph:
                # Find all simple paths from start to all other nodes
                for target in self.dependency_graph.nodes():
                    if start != target:
                        try:
                            paths = list(nx.all_simple_paths(
                                self.dependency_graph, start, target, cutoff=max_length
                            ))
                            chains.extend(paths)
                        except nx.NetworkXNoPath:
                            continue
        
        # Sort chains by cumulative weight
        weighted_chains = []
        for chain in chains:
            weight = self._calculate_chain_weight(chain)
            weighted_chains.append((chain, weight))
        
        weighted_chains.sort(key=lambda x: x[1], reverse=True)
        return [chain for chain, weight in weighted_chains[:20]]  # Top 20 chains
    
    def _calculate_chain_weight(self, chain: List[str]) -> float:
        """Calculate cumulative weight of an attack chain"""
        total_weight = 0.0
        
        for i in range(len(chain) - 1):
            if self.dependency_graph.has_edge(chain[i], chain[i + 1]):
                edge_data = self.dependency_graph[chain[i]][chain[i + 1]]
                total_weight += edge_data.get("weight", 0.0)
        
        # Normalize by chain length
        return total_weight / len(chain) if chain else 0.0
    
    def get_prerequisites(self, technique_id: str) -> List[str]:
        """Get prerequisite techniques for a given technique"""
        if technique_id not in self.dependency_graph:
            return []
        
        # Get all predecessors with high weight edges
        prerequisites = []
        for pred in self.dependency_graph.predecessors(technique_id):
            edge_data = self.dependency_graph[pred][technique_id]
            if edge_data.get("weight", 0.0) > 0.7:
                prerequisites.append(pred)
        
        return prerequisites
    
    def get_enabled_techniques(self, technique_id: str) -> List[str]:
        """Get techniques enabled by a given technique"""
        if technique_id not in self.dependency_graph:
            return []
        
        # Get all successors with high weight edges
        enabled = []
        for succ in self.dependency_graph.successors(technique_id):
            edge_data = self.dependency_graph[technique_id][succ]
            if edge_data.get("weight", 0.0) > 0.7:
                enabled.append(succ)
        
        return enabled
    
    def optimize_chain_for_target(self, chain: List[str], 
                                 target_platform: str,
                                 avoid_elevation: bool = False) -> List[str]:
        """Optimize attack chain for specific target"""
        optimized = []
        
        for technique_id in chain:
            if technique_id in self.dependency_graph:
                node_data = self.dependency_graph.nodes[technique_id]
                
                # Check platform compatibility
                if target_platform.lower() not in [p.lower() for p in node_data.get("platforms", [])]:
                    # Try to find alternative technique
                    alternatives = self._find_alternative_technique(
                        technique_id, target_platform, avoid_elevation
                    )
                    if alternatives:
                        optimized.append(alternatives[0])
                    continue
                
                # Check elevation requirement
                if avoid_elevation and node_data.get("elevation_required", False):
                    alternatives = self._find_alternative_technique(
                        technique_id, target_platform, avoid_elevation
                    )
                    if alternatives:
                        optimized.append(alternatives[0])
                    continue
                
                optimized.append(technique_id)
        
        return optimized
    
    def _find_alternative_technique(self, technique_id: str, 
                                   target_platform: str,
                                   avoid_elevation: bool) -> List[str]:
        """Find alternative techniques with similar purpose"""
        if technique_id not in self.dependency_graph:
            return []
        
        original_tactics = self.dependency_graph.nodes[technique_id].get("tactics", [])
        alternatives = []
        
        for node_id, node_data in self.dependency_graph.nodes(data=True):
            if node_id == technique_id:
                continue
            
            # Check if tactics overlap
            node_tactics = node_data.get("tactics", [])
            if not set(original_tactics).intersection(set(node_tactics)):
                continue
            
            # Check platform compatibility
            platforms = [p.lower() for p in node_data.get("platforms", [])]
            if target_platform.lower() not in platforms:
                continue
            
            # Check elevation requirement
            if avoid_elevation and node_data.get("elevation_required", False):
                continue
            
            alternatives.append(node_id)
        
        return alternatives

# Example usage
if __name__ == "__main__":
    mapper = DependencyMapper()
    
    # Mock techniques for testing
    mock_techniques = {
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactics": ["initial-access"],
            "platforms": ["windows", "linux"],
            "tests": [{"elevation_required": False}]
        },
        "T1059.001": {
            "name": "PowerShell",
            "tactics": ["execution"],
            "platforms": ["windows"],
            "tests": [{"elevation_required": False}]
        },
        "T1055": {
            "name": "Process Injection",
            "tactics": ["defense-evasion", "privilege-escalation"],
            "platforms": ["windows"],
            "tests": [{"elevation_required": True}]
        }
    }
    
    graph = mapper.build_dependency_graph(mock_techniques)
    chains = mapper.get_attack_chains(["T1190"], max_length=5)
    
    print(f"Generated {len(chains)} attack chains")
    for i, chain in enumerate(chains[:3]):
        print(f"Chain {i+1}: {' -> '.join(chain)}")