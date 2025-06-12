import yaml
import os
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

class TechniqueParser:
    """
    Parses Atomic Red Team YAML files to extract technique information
    """
    
    def __init__(self, atomics_path: str):
        self.atomics_path = Path(atomics_path)
        self.techniques = {}
        self.logger = logging.getLogger(__name__)
        
    def parse_all_techniques(self) -> Dict[str, Any]:
        """Parse all technique YAML files"""
        technique_dirs = [d for d in self.atomics_path.iterdir() 
                         if d.is_dir() and d.name.startswith('T')]
        
        for technique_dir in technique_dirs:
            technique_id = technique_dir.name
            yaml_file = technique_dir / f"{technique_id}.yaml"
            
            if yaml_file.exists():
                try:
                    technique_data = self._parse_technique_file(yaml_file)
                    if technique_data:
                        self.techniques[technique_id] = technique_data
                        self.logger.info(f"Parsed technique: {technique_id}")
                except Exception as e:
                    self.logger.error(f"Error parsing {technique_id}: {e}")
        
        return self.techniques
    
    def _parse_technique_file(self, yaml_file: Path) -> Optional[Dict]:
        """Parse individual technique YAML file"""
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return None
                
            technique_info = {
                'id': data.get('attack_technique', ''),
                'name': data.get('display_name', ''),
                'description': self._extract_description(yaml_file),
                'platforms': self._get_supported_platforms(data),
                'tests': self._parse_atomic_tests(data.get('atomic_tests', [])),
                'tactics': self._extract_tactics_from_id(data.get('attack_technique', '')),
                'prerequisites': self._extract_global_prerequisites(data),
                'file_path': str(yaml_file)
            }
            
            return technique_info
            
        except Exception as e:
            self.logger.error(f"Failed to parse {yaml_file}: {e}")
            return None
    
    def _parse_atomic_tests(self, tests: List[Dict]) -> List[Dict]:
        """Parse atomic tests within a technique"""
        parsed_tests = []
        
        for i, test in enumerate(tests, 1):
            test_info = {
                'number': i,
                'name': test.get('name', ''),
                'description': test.get('description', ''),
                'supported_platforms': test.get('supported_platforms', []),
                'executor': test.get('executor', {}),
                'input_arguments': test.get('input_arguments', {}),
                'dependencies': test.get('dependencies', []),
                'auto_generated_guid': test.get('auto_generated_guid', ''),
                'elevation_required': test.get('executor', {}).get('elevation_required', False),
                'attack_commands': self._extract_attack_commands(test),
                'cleanup_commands': self._extract_cleanup_commands(test)
            }
            parsed_tests.append(test_info)
        
        return parsed_tests
    
    def _get_supported_platforms(self, data: Dict) -> List[str]:
        """Extract all supported platforms for a technique"""
        platforms = set()
        
        for test in data.get('atomic_tests', []):
            platforms.update(test.get('supported_platforms', []))
        
        return list(platforms)
    
    def _extract_tactics_from_id(self, technique_id: str) -> List[str]:
        """Map technique ID to MITRE ATT&CK tactics"""
        # This is a simplified mapping - you might want to enhance this
        # with actual MITRE ATT&CK data
        tactic_mapping = {
            'T1003': ['credential-access'],
            'T1055': ['defense-evasion', 'privilege-escalation'],
            'T1059': ['execution'],
            'T1071': ['command-and-control'],
            'T1082': ['discovery'],
            'T1083': ['discovery'],
            'T1087': ['discovery'],
            'T1105': ['command-and-control'],
            'T1190': ['initial-access'],
            'T1210': ['lateral-movement'],
            'T1566': ['initial-access']
        }
        
        base_id = technique_id.split('.')[0]
        return tactic_mapping.get(base_id, ['unknown'])
    
    def _extract_attack_commands(self, test: Dict) -> List[str]:
        """Extract attack commands from test"""
        executor = test.get('executor', {})
        commands = []
        
        if 'command' in executor:
            commands.append(executor['command'])
        elif 'steps' in executor:
            commands.append(executor['steps'])
            
        return commands
    
    def _extract_cleanup_commands(self, test: Dict) -> List[str]:
        """Extract cleanup commands from test"""
        executor = test.get('executor', {})
        cleanup = executor.get('cleanup_command', '')
        
        return [cleanup] if cleanup else []
    
    def _extract_description(self, yaml_file: Path) -> str:
        """Extract description from markdown file if available"""
        md_file = yaml_file.with_suffix('.md')
        if md_file.exists():
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Extract first paragraph after title
                    lines = content.split('\n')
                    for i, line in enumerate(lines):
                        if line.strip() and not line.startswith('#') and not line.startswith('['):
                            return line.strip()
            except Exception:
                pass
        return ""
    
    def _extract_global_prerequisites(self, data: Dict) -> List[str]:
        """Extract global prerequisites for the technique"""
        prereqs = []
        
        for test in data.get('atomic_tests', []):
            test_prereqs = test.get('dependencies', [])
            for prereq in test_prereqs:
                if isinstance(prereq, dict):
                    desc = prereq.get('description', '')
                    if desc and desc not in prereqs:
                        prereqs.append(desc)
        
        return prereqs
    
    def get_techniques_by_platform(self, platform: str) -> Dict[str, Any]:
        """Get techniques that support a specific platform"""
        filtered = {}
        
        for tech_id, tech_data in self.techniques.items():
            if platform.lower() in [p.lower() for p in tech_data['platforms']]:
                filtered[tech_id] = tech_data
        
        return filtered
    
    def get_techniques_by_tactic(self, tactic: str) -> Dict[str, Any]:
        """Get techniques that belong to a specific tactic"""
        filtered = {}
        
        for tech_id, tech_data in self.techniques.items():
            if tactic.lower() in [t.lower() for t in tech_data['tactics']]:
                filtered[tech_id] = tech_data
        
        return filtered
    
    def search_techniques(self, search_term: str) -> Dict[str, Any]:
        """Search techniques by name or description"""
        filtered = {}
        search_lower = search_term.lower()
        
        for tech_id, tech_data in self.techniques.items():
            if (search_lower in tech_data['name'].lower() or 
                search_lower in tech_data['description'].lower()):
                filtered[tech_id] = tech_data
        
        return filtered

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize parser (adjust path to your Atomic Red Team atomics directory)
    parser = TechniqueParser("./atomics")
    
    # Parse all techniques
    techniques = parser.parse_all_techniques()
    
    print(f"Parsed {len(techniques)} techniques")
    
    # Example: Get Windows techniques
    windows_techniques = parser.get_techniques_by_platform("windows")
    print(f"Windows techniques: {len(windows_techniques)}")
    
    # Example: Get credential access techniques
    cred_access = parser.get_techniques_by_tactic("credential-access")
    print(f"Credential access techniques: {len(cred_access)}")
