import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging

class AttackObjective(Enum):
    """Define different attack objectives"""
    INITIAL_COMPROMISE = "initial_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    FULL_COMPROMISE = "full_compromise"
    WEB_APPLICATION = "web_application"
    NETWORK_PENETRATION = "network_penetration"
    CREDENTIAL_HARVESTING = "credential_harvesting"

@dataclass
class AttackStep:
    """Represents a single step in an attack chain"""
    technique_id: str
    technique_name: str
    step_number: int
    category: str
    tactics: List[str]
    platforms: List[str]
    elevation_required: bool
    test_numbers: List[int]
    description: str
    prerequisites: List[str]
    expected_outcome: str
    risk_level: str  # low, medium, high
    detection_likelihood: str  # low, medium, high
    cleanup_required: bool

@dataclass
class AttackChain:
    """Represents a complete attack chain"""
    name: str
    objective: AttackObjective
    description: str
    target_platform: str
    steps: List[AttackStep]
    estimated_duration: str
    overall_risk: str
    prerequisites: List[str]
    cleanup_commands: List[str]
    detection_notes: List[str]

class AttackChainBuilder:
    """
    Builds specific attack chains based on objectives and target constraints
    """
    
    def __init__(self, dependency_mapper, categorizer):
        self.dependency_mapper = dependency_mapper
        self.categorizer = categorizer
        self.logger = logging.getLogger(__name__)
        self.chain_templates = self._define_chain_templates()
        
    def _define_chain_templates(self) -> Dict[AttackObjective, Dict]:
        """Define templates for different attack objectives"""
        return {
            AttackObjective.WEB_APPLICATION: {
                "name": "Web Application Compromise",
                "description": "Target web applications for initial access and escalation",
                "phases": [
                    {"category": "web_attacks", "required": True, "max_techniques": 2},
                    {"category": "execution", "required": True, "max_techniques": 1},
                    {"category": "privilege_escalation", "required": False, "max_techniques": 1},
                    {"category": "persistence", "required": True, "max_techniques": 1},
                    {"category": "defense_evasion", "required": False, "max_techniques": 1}
                ],
                "estimated_duration": "30-60 minutes",
                "risk_level": "medium"
            },
            
            AttackObjective.PRIVILEGE_ESCALATION: {
                "name": "Privilege Escalation Chain",
                "description": "Focus on gaining elevated privileges",
                "phases": [
                    {"category": "execution", "required": True, "max_techniques": 1},
                    {"category": "discovery", "required": True, "max_techniques": 2},
                    {"category": "privilege_escalation", "required": True, "max_techniques": 2},
                    {"category": "defense_evasion", "required": True, "max_techniques": 1}
                ],
                "estimated_duration": "15-30 minutes",
                "risk_level": "high"
            },
            
            AttackObjective.LATERAL_MOVEMENT: {
                "name": "Lateral Movement Chain",
                "description": "Move through network and compromise multiple systems",
                "phases": [
                    {"category": "discovery", "required": True, "max_techniques": 3},
                    {"category": "credential_access", "required": True, "max_techniques": 2},
                    {"category": "lateral_movement", "required": True, "max_techniques": 2},
                    {"category": "collection", "required": False, "max_techniques": 1}
                ],
                "estimated_duration": "45-90 minutes",
                "risk_level": "high"
            },
            
            AttackObjective.DATA_EXFILTRATION: {
                "name": "Data Exfiltration Chain",
                "description": "Locate, collect, and exfiltrate sensitive data",
                "phases": [
                    {"category": "discovery", "required": True, "max_techniques": 2},
                    {"category": "collection", "required": True, "max_techniques": 2},
                    {"category": "exfiltration", "required": True, "max_techniques": 1},
                    {"category": "defense_evasion", "required": True, "max_techniques": 1}
                ],
                "estimated_duration": "20-45 minutes",
                "risk_level": "medium"
            },
            
            AttackObjective.FULL_COMPROMISE: {
                "name": "Full Kill Chain",
                "description": "Complete attack lifecycle from initial access to impact",
                "phases": [
                    {"category": "initial_access", "required": True, "max_techniques": 1},
                    {"category": "execution", "required": True, "max_techniques": 1},
                    {"category": "persistence", "required": True, "max_techniques": 1},
                    {"category": "privilege_escalation", "required": True, "max_techniques": 1},
                    {"category": "defense_evasion", "required": True, "max_techniques": 1},
                    {"category": "credential_access", "required": True, "max_techniques": 1},
                    {"category": "discovery", "required": True, "max_techniques": 2},
                    {"category": "lateral_movement", "required": False, "max_techniques": 1},
                    {"category": "collection", "required": True, "max_techniques": 1},
                    {"category": "exfiltration", "required": True, "max_techniques": 1}
                ],
                "estimated_duration": "2-4 hours",
                "risk_level": "high"
            },
            
            AttackObjective.CREDENTIAL_HARVESTING: {
                "name": "Credential Harvesting Chain",
                "description": "Focus on collecting various types of credentials",
                "phases": [
                    {"category": "execution", "required": True, "max_techniques": 1},
                    {"category": "privilege_escalation", "required": False, "max_techniques": 1},
                    {"category": "credential_access", "required": True, "max_techniques": 3},
                    {"category": "defense_evasion", "required": True, "max_techniques": 1}
                ],
                "estimated_duration": "20-40 minutes",
                "risk_level": "high"
            }
        }
    
    def build_attack_chain(self, objective: AttackObjective,
                          target_platform: str,
                          categorized_techniques: Dict[str, Any],
                          constraints: Dict[str, Any] = None) -> AttackChain:
        """Build an attack chain for a specific objective"""
        
        if constraints is None:
            constraints = {}
        
        template = self.chain_templates.get(objective)
        if not template:
            raise ValueError(f"No template defined for objective: {objective}")
        
        # Filter techniques by platform
        platform_techniques = self.categorizer.filter_by_platform(
            categorized_techniques, target_platform
        )
        
        # Build chain steps
        steps = []
        step_number = 1
        
        for phase in template["phases"]:
            category = phase["category"]
            required = phase["required"]
            max_techniques = phase["max_techniques"]
            
            if category not in platform_techniques:
                if required:
                    self.logger.warning(f"Required category {category} not available for {target_platform}")
                continue
            
            # Select techniques for this phase
            selected_techniques = self._select_techniques_for_phase(
                platform_techniques[category]["techniques"],
                max_techniques,
                constraints
            )
            
            if not selected_techniques and required:
                self.logger.warning(f"No suitable techniques found for required phase: {category}")
                continue
            
            # Create attack steps
            for tech in selected_techniques:
                step = self._create_attack_step(
                    tech, step_number, category, constraints
                )
                steps.append(step)
                step_number += 1
        
        # Optimize chain order based on dependencies
        optimized_steps = self._optimize_step_order(steps)
        
        # Create attack chain
        chain = AttackChain(
            name=template["name"],
            objective=objective,
            description=template["description"],
            target_platform=target_platform,
            steps=optimized_steps,
            estimated_duration=template["estimated_duration"],
            overall_risk=template["risk_level"],
            prerequisites=self._extract_chain_prerequisites(optimized_steps),
            cleanup_commands=self._generate_cleanup_commands(optimized_steps),
            detection_notes=self._generate_detection_notes(optimized_steps)
        )
        
        return chain
    
    def _select_techniques_for_phase(self, techniques: List[Dict],
                                   max_count: int,
                                   constraints: Dict[str, Any]) -> List[Dict]:
        """Select appropriate techniques for a phase"""
        
        # Apply constraints
        filtered = []
        
        for tech in techniques:
            # Skip if elevation required but not allowed
            if (constraints.get("avoid_elevation", False) and 
                tech.get("elevation_required", False)):
                continue
            
            # Skip if platform not supported
            required_platforms = constraints.get("required_platforms", [])
            if required_platforms:
                if not any(p in tech.get("platforms", []) for p in required_platforms):
                    continue
            
            # Skip if technique explicitly excluded
            excluded = constraints.get("excluded_techniques", [])
            if tech["id"] in excluded:
                continue
            
            filtered.append(tech)
        
        # Sort by preference criteria
        sorted_techniques = sorted(filtered, key=lambda x: (
            -x.get("test_count", 0),  # More tests = more options
            x.get("elevation_required", False),  # Prefer non-elevated first
            x["name"]  # Alphabetical for consistency
        ))
        
        return sorted_techniques[:max_count]
    
    def _create_attack_step(self, technique: Dict, step_number: int,
                           category: str, constraints: Dict) -> AttackStep:
        """Create an attack step from technique data"""
        
        # Determine test numbers to use
        test_numbers = list(range(1, technique.get("test_count", 0) + 1))
        if constraints.get("single_test_per_technique", True):
            test_numbers = [1] if test_numbers else []
        
        # Assess risk and detection likelihood
        risk_level = self._assess_risk_level(technique, category)
        detection_likelihood = self._assess_detection_likelihood(technique, category)
        
        return AttackStep(
            technique_id=technique["id"],
            technique_name=technique["name"],
            step_number=step_number,
            category=category,
            tactics=technique.get("tactics", []),
            platforms=technique.get("platforms", []),
            elevation_required=technique.get("elevation_required", False),
            test_numbers=test_numbers,
            description=self._generate_step_description(technique, category),
            prerequisites=self._get_technique_prerequisites(technique["id"]),
            expected_outcome=self._generate_expected_outcome(technique, category),
            risk_level=risk_level,
            detection_likelihood=detection_likelihood,
            cleanup_required=self._requires_cleanup(technique)
        )
    
    def _optimize_step_order(self, steps: List[AttackStep]) -> List[AttackStep]:
        """Optimize the order of steps based on dependencies"""
        if not steps:
            return steps
        
        # Create a simple dependency-aware ordering
        ordered_steps = []
        remaining_steps = steps.copy()
        
        while remaining_steps:
            # Find steps with no unmet prerequisites
            ready_steps = []
            
            for step in remaining_steps:
                prerequisites_met = True
                for prereq in step.prerequisites:
                    if not any(s.technique_id == prereq for s in ordered_steps):
                        prerequisites_met = False
                        break
                
                if prerequisites_met:
                    ready_steps.append(step)
            
            if not ready_steps:
                # No steps ready - take the first one to break deadlock
                ready_steps = [remaining_steps[0]]
            
            # Add the first ready step
            next_step = ready_steps[0]
            ordered_steps.append(next_step)
            remaining_steps.remove(next_step)
        
        # Renumber steps
        for i, step in enumerate(ordered_steps, 1):
            step.step_number = i
        
        return ordered_steps
    
    def _assess_risk_level(self, technique: Dict, category: str) -> str:
        """Assess risk level of a technique"""
        risk_score = 0
        
        # Base risk by category
        high_risk_categories = ["credential_access", "privilege_escalation", "lateral_movement"]
        medium_risk_categories = ["execution", "persistence", "defense_evasion"]
        
        if category in high_risk_categories:
            risk_score += 3
        elif category in medium_risk_categories:
            risk_score += 2
        else:
            risk_score += 1
        
        # Elevation increases risk
        if technique.get("elevation_required", False):
            risk_score += 1
        
        # Multiple tests might indicate complexity
        if technique.get("test_count", 0) > 3:
            risk_score += 1
        
        if risk_score >= 4:
            return "high"
        elif risk_score >= 2:
            return "medium"
        else:
            return "low"
    
    def _assess_detection_likelihood(self, technique: Dict, category: str) -> str:
        """Assess detection likelihood of a technique"""
        detection_score = 0
        
        # Categories with higher detection likelihood
        high_detection = ["credential_access", "privilege_escalation", "lateral_movement"]
        medium_detection = ["execution", "defense_evasion", "persistence"]
        
        if category in high_detection:
            detection_score += 2
        elif category in medium_detection:
            detection_score += 1
        
        # Elevation often increases detection
        if technique.get("elevation_required", False):
            detection_score += 1
        
        # Network-based techniques often more detectable
        if "network" in technique["name"].lower():
            detection_score += 1
        
        if detection_score >= 3:
            return "high"
        elif detection_score >= 1:
            return "medium"
        else:
            return "low"
    
    def _generate_step_description(self, technique: Dict, category: str) -> str:
        """Generate description for an attack step"""
        base_descriptions = {
            "initial_access": f"Gain initial access using {technique['name']}",
            "execution": f"Execute malicious code via {technique['name']}",
            "persistence": f"Establish persistence using {technique['name']}",
            "privilege_escalation": f"Escalate privileges using {technique['name']}",
            "defense_evasion": f"Evade defenses using {technique['name']}",
            "credential_access": f"Access credentials using {technique['name']}",
            "discovery": f"Perform reconnaissance using {technique['name']}",
            "lateral_movement": f"Move laterally using {technique['name']}",
            "collection": f"Collect data using {technique['name']}",
            "exfiltration": f"Exfiltrate data using {technique['name']}",
            "command_control": f"Establish C2 using {technique['name']}",
            "impact": f"Create impact using {technique['name']}"
        }
        
        return base_descriptions.get(category, f"Execute {technique['name']}")
    
    def _generate_expected_outcome(self, technique: Dict, category: str) -> str:
        """Generate expected outcome for an attack step"""
        outcomes = {
            "initial_access": "System access obtained",
            "execution": "Code execution achieved",
            "persistence": "Persistence mechanism established",
            "privilege_escalation": "Elevated privileges obtained",
            "defense_evasion": "Security controls bypassed",
            "credential_access": "Credentials harvested",
            "discovery": "System/network information gathered",
            "lateral_movement": "Access to additional systems",
            "collection": "Sensitive data collected",
            "exfiltration": "Data successfully exfiltrated",
            "command_control": "C2 channel established",
            "impact": "Target objectives achieved"
        }
        
        return outcomes.get(category, "Technique executed successfully")
    
    def _get_technique_prerequisites(self, technique_id: str) -> List[str]:
        """Get prerequisites for a technique"""
        if hasattr(self.dependency_mapper, 'get_prerequisites'):
            return self.dependency_mapper.get_prerequisites(technique_id)
        return []
    
    def _requires_cleanup(self, technique: Dict) -> bool:
        """Determine if technique requires cleanup"""
        # Techniques that modify system state usually need cleanup
        cleanup_categories = [
            "persistence", "privilege_escalation", "defense_evasion"
        ]
        
        # Check if any tactic suggests cleanup is needed
        for tactic in technique.get("tactics", []):
            if any(cat in tactic for cat in cleanup_categories):
                return True
        
        return False
    
    def _extract_chain_prerequisites(self, steps: List[AttackStep]) -> List[str]:
        """Extract overall prerequisites for the chain"""
        prerequisites = set()
        
        for step in steps:
            if step.elevation_required:
                prerequisites.add("Administrative/root privileges may be required")
            
            if "windows" in step.platforms:
                prerequisites.add("Windows target system")
            elif "linux" in step.platforms:
                prerequisites.add("Linux target system")
            elif "macos" in step.platforms:
                prerequisites.add("macOS target system")
        
        return list(prerequisites)
    
    def _generate_cleanup_commands(self, steps: List[AttackStep]) -> List[str]:
        """Generate cleanup commands for the chain"""
        cleanup = []
        
        for step in steps:
            if step.cleanup_required:
                cleanup.append(f"Clean up artifacts from {step.technique_name} ({step.technique_id})")
        
        cleanup.append("Review and remove any temporary files created")
        cleanup.append("Check for persistence mechanisms and remove if unwanted")
        
        return cleanup
    
    def _generate_detection_notes(self, steps: List[AttackStep]) -> List[str]:
        """Generate detection notes for the chain"""
        notes = []
        
        high_detection_steps = [s for s in steps if s.detection_likelihood == "high"]
        if high_detection_steps:
            notes.append(f"High detection risk: {', '.join(s.technique_name for s in high_detection_steps)}")
        
        elevated_steps = [s for s in steps if s.elevation_required]
        if elevated_steps:
            notes.append("Elevated privileges may trigger additional monitoring")
        
        notes.append("Monitor for unusual process creation and network activity")
        notes.append("Check security logs for failed authentication attempts")
        
        return notes
    
    def export_chain_to_json(self, chain: AttackChain) -> str:
        """Export attack chain to JSON format"""
        chain_dict = asdict(chain)
        # Convert enum to string
        chain_dict["objective"] = chain.objective.value
        return json.dumps(chain_dict, indent=2)
    
    def export_chain_to_invoke_script(self, chain: AttackChain) -> str:
        """Export attack chain as Invoke-AtomicTest PowerShell script"""
        script_lines = [
            "# Atomic Red Team Attack Chain",
            f"# Chain: {chain.name}",
            f"# Objective: {chain.objective.value}",
            f"# Platform: {chain.target_platform}",
            f"# Estimated Duration: {chain.estimated_duration}",
            f"# Risk Level: {chain.overall_risk}",
            "",
            "# Prerequisites:",
        ]
        
        for prereq in chain.prerequisites:
            script_lines.append(f"# - {prereq}")
        
        script_lines.extend([
            "",
            "# Attack Steps:",
            ""
        ])
        
        for step in chain.steps:
            script_lines.extend([
                f"# Step {step.step_number}: {step.description}",
                f"# Risk: {step.risk_level}, Detection: {step.detection_likelihood}",
                f"# Expected: {step.expected_outcome}",
                ""
            ])
            
            if step.test_numbers:
                test_param = ",".join(map(str, step.test_numbers))
                script_lines.append(
                    f"Invoke-AtomicTest {step.technique_id} -TestNumbers {test_param}"
                )
            else:
                script_lines.append(f"Invoke-AtomicTest {step.technique_id}")
            
            script_lines.extend(["", "# Wait for execution and review results", "Start-Sleep -Seconds 10", ""])
        
        script_lines.extend([
            "# Cleanup Commands:",
            "# WARNING: Review these commands before execution",
            ""
        ])
        
        for cleanup in chain.cleanup_commands:
            script_lines.append(f"# {cleanup}")
        
        return "\n".join(script_lines)

# Example usage
if __name__ == "__main__":
    # This would be used with the full system
    builder = AttackChainBuilder(None, None)  # Would pass real objects
    
    print("Attack Chain Builder initialized")
    print(f"Available objectives: {[obj.value for obj in AttackObjective]}")
