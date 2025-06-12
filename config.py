# utils/config.py
"""
Configuration management for Atomic Red Team Orchestrator
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass, asdict
import os

@dataclass
class TargetProfile:
    """Target system profile"""
    name: str
    platform: str
    version: str
    architecture: str
    domain_joined: bool
    admin_access: bool
    security_tools: List[str]
    network_access: bool
    internet_access: bool
    constraints: Dict[str, Any]

@dataclass
class ExecutionConfig:
    """Execution configuration"""
    dry_run: bool = True
    interactive: bool = True
    delay_between_steps: int = 5
    timeout_per_step: int = 300
    continue_on_failure: bool = False
    cleanup_after_execution: bool = True
    log_level: str = "INFO"
    output_format: str = "json"

class ConfigManager:
    """Manages configuration for the orchestrator"""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Default configuration files
        self.main_config_file = self.config_dir / "config.yaml"
        self.targets_config_file = self.config_dir / "targets.json"
        self.chains_config_file = self.config_dir / "attack_chains.json"
        
        # Load or create default configs
        self.main_config = self._load_main_config()
        self.target_profiles = self._load_target_profiles()
        self.predefined_chains = self._load_predefined_chains()
    
    def _load_main_config(self) -> Dict[str, Any]:
        """Load main configuration"""
        default_config = {
            "atomics_path": "./atomics",
            "output_dir": "./output",
            "execution": {
                "dry_run": True,
                "interactive": True,
                "delay_between_steps": 5,
                "timeout_per_step": 300,
                "continue_on_failure": False,
                "cleanup_after_execution": True,
                "log_level": "INFO"
            },
            "filters": {
                "avoid_elevation": False,
                "exclude_destructive": True,
                "exclude_network_discovery": False,
                "max_risk_level": "high"
            },
            "platforms": {
                "windows": {
                    "enabled": True,
                    "powershell_path": "powershell.exe",
                    "invoke_atomic_path": None
                },
                "linux": {
                    "enabled": True,
                    "shell_path": "/bin/bash"
                },
                "macos": {
                    "enabled": True,
                    "shell_path": "/bin/bash"
                }
            }
        }
        
        if self.main_config_file.exists():
            try:
                with open(self.main_config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults
                    self._deep_merge(default_config, loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
        
        # Save config (creates file if doesn't exist)
        self.save_main_config(default_config)
        return default_config
    
    def _load_target_profiles(self) -> Dict[str, TargetProfile]:
        """Load target profiles"""
        default_profiles = {
            "windows_workstation": TargetProfile(
                name="Windows Workstation",
                platform="windows",
                version="10",
                architecture="x64",
                domain_joined=False,
                admin_access=False,
                security_tools=["windows_defender"],
                network_access=True,
                internet_access=True,
                constraints={
                    "avoid_elevation": True,
                    "exclude_destructive": True,
                    "max_techniques_per_category": 2
                }
            ),
            "windows_server": TargetProfile(
                name="Windows Server",
                platform="windows",
                version="2019",
                architecture="x64",
                domain_joined=True,
                admin_access=True,
                security_tools=["windows_defender", "sysmon"],
                network_access=True,
                internet_access=False,
                constraints={
                    "avoid_elevation": False,
                    "exclude_destructive": True,
                    "max_techniques_per_category": 3
                }
            ),
            "linux_server": TargetProfile(
                name="Linux Server",
                platform="linux",
                version="ubuntu_20.04",
                architecture="x64",
                domain_joined=False,
                admin_access=True,
                security_tools=["auditd", "fail2ban"],
                network_access=True,
                internet_access=True,
                constraints={
                    "avoid_elevation": False,
                    "exclude_destructive": True,
                    "max_techniques_per_category": 2
                }
            ),
            "vulnerable_webapp": TargetProfile(
                name="Vulnerable Web Application",
                platform="linux",
                version="ubuntu_18.04",
                architecture="x64",
                domain_joined=False,
                admin_access=False,
                security_tools=[],
                network_access=True,
                internet_access=True,
                constraints={
                    "focus_categories": ["web_attacks", "execution", "privilege_escalation"],
                    "exclude_destructive": False,
                    "max_techniques_per_category": 3
                }
            )
        }
        
        if self.targets_config_file.exists():
            try:
                with open(self.targets_config_file, 'r') as f:
                    data = json.load(f)
                    profiles = {}
                    for name, profile_data in data.items():
                        profiles[name] = TargetProfile(**profile_data)
                    return profiles
            except Exception as e:
                print(f"Error loading target profiles: {e}. Using defaults.")
        
        # Save defaults
        self.save_target_profiles(default_profiles)
        return default_profiles
    
    def _load_predefined_chains(self) -> Dict[str, Any]:
        """Load predefined attack chains"""
        default_chains = {
            "web_to_system": {
                "name": "Web Application to System Compromise",
                "description": "Start with web app exploit, escalate to system access",
                "phases": [
                    {"objective": "web_application", "techniques_limit": 1},
                    {"objective": "execution", "techniques_limit": 1},
                    {"objective": "privilege_escalation", "techniques_limit": 1},
                    {"objective": "persistence", "techniques_limit": 1}
                ],
                "target_profiles": ["vulnerable_webapp"]
            },
            "insider_threat": {
                "name": "Insider Threat Simulation",
                "description": "Simulate malicious insider with valid credentials",
                "phases": [
                    {"objective": "discovery", "techniques_limit": 2},
                    {"objective": "credential_access", "techniques_limit": 2},
                    {"objective": "lateral_movement", "techniques_limit": 1},
                    {"objective": "collection", "techniques_limit": 1},
                    {"objective": "exfiltration", "techniques_limit": 1}
                ],
                "target_profiles": ["windows_workstation", "windows_server"]
            },
            "apt_simulation": {
                "name": "APT-style Attack Chain",
                "description": "Advanced persistent threat simulation",
                "phases": [
                    {"objective": "initial_access", "techniques_limit": 1},
                    {"objective": "execution", "techniques_limit": 1},
                    {"objective": "defense_evasion", "techniques_limit": 2},
                    {"objective": "credential_access", "techniques_limit": 2},
                    {"objective": "discovery", "techniques_limit": 2},
                    {"objective": "lateral_movement", "techniques_limit": 1},
                    {"objective": "persistence", "techniques_limit": 2},
                    {"objective": "collection", "techniques_limit": 1}
                ],
                "target_profiles": ["windows_server", "linux_server"]
            }
        }
        
        if self.chains_config_file.exists():
            try:
                with open(self.chains_config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading predefined chains: {e}. Using defaults.")
        
        # Save defaults
        self.save_predefined_chains(default_chains)
        return default_chains
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def save_main_config(self, config: Dict[str, Any]):
        """Save main configuration"""
        with open(self.main_config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
    
    def save_target_profiles(self, profiles: Dict[str, TargetProfile]):
        """Save target profiles"""
        data = {name: asdict(profile) for name, profile in profiles.items()}
        with open(self.targets_config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def save_predefined_chains(self, chains: Dict[str, Any]):
        """Save predefined chains"""
        with open(self.chains_config_file, 'w') as f:
            json.dump(chains, f, indent=2)
    
    def get_target_profile(self, profile_name: str) -> TargetProfile:
        """Get specific target profile"""
        if profile_name not in self.target_profiles:
            raise ValueError(f"Target profile '{profile_name}' not found")
        return self.target_profiles[profile_name]
    
    def get_execution_config(self) -> ExecutionConfig:
        """Get execution configuration"""
        exec_config = self.main_config.get("execution", {})
        return ExecutionConfig(**exec_config)
    
    def get_platform_config(self, platform: str) -> Dict[str, Any]:
        """Get platform-specific configuration"""
        return self.main_config.get("platforms", {}).get(platform, {})
    
    def create_target_profile(self, name: str, **kwargs) -> TargetProfile:
        """Create new target profile"""
        profile = TargetProfile(name=name, **kwargs)
        self.target_profiles[name] = profile
        self.save_target_profiles(self.target_profiles)
        return profile


# utils/logger.py
"""
Enhanced logging utilities
"""

import logging
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime

class StructuredLogger:
    """Structured logger for attack orchestration"""
    
    def __init__(self, name: str, log_dir: str = "./logs", level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler for detailed logs
        log_file = self.log_dir / f"{name}.log"
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.WARNING)
        self.logger.addHandler(console_handler)
        
        # Structured log file for machine-readable logs
        self.structured_log_file = self.log_dir / f"{name}_structured.jsonl"
    
    def log_attack_step(self, step_info: dict, status: str, details: Optional[dict] = None):
        """Log attack step execution"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "attack_step",
            "step_info": step_info,
            "status": status,
            "details": details or {}
        }
        
        self._write_structured_log(log_entry)
        
        # Also log to regular logger
        message = f"Step {step_info.get('step_number', '?')}: {step_info.get('technique_id', '?')} - {status}"
        if status == "success":
            self.logger.info(message)
        elif status == "failed":
            self.logger.error(message)
        else:
            self.logger.warning(message)
    
    def log_chain_execution(self, chain_info: dict, status: str, stats: dict):
        """Log chain execution summary"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "chain_execution",
            "chain_info": chain_info,
            "status": status,
            "statistics": stats
        }
        
        self._write_structured_log(log_entry)
        self.logger.info(f"Chain execution completed: {chain_info.get('name', '?')} - {status}")
    
    def log_system_info(self, system_info: dict):
        """Log target system information"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "system_info",
            "system_info": system_info
        }
        
        self._write_structured_log(log_entry)
        self.logger.info("System information logged")
    
    def _write_structured_log(self, entry: dict):
        """Write structured log entry"""
        with open(self.structured_log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def debug(self, message: str):
        self.logger.debug(message)


# utils/powershell_executor.py
"""
PowerShell execution wrapper for Windows environments
"""

import subprocess
import json
import re
from typing import Dict, List, Optional, Tuple
import tempfile
import os

class PowerShellExecutor:
    """Executes PowerShell commands and Invoke-AtomicTest"""
    
    def __init__(self, powershell_path: str = "powershell.exe"):
        self.powershell_path = powershell_path
        self.invoke_atomic_available = None
        
    def check_invoke_atomic(self) -> bool:
        """Check if Invoke-AtomicRedTeam is available"""
        if self.invoke_atomic_available is not None:
            return self.invoke_atomic_available
        
        cmd = [self.powershell_path, "-Command", "Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.invoke_atomic_available = result.returncode == 0
        except Exception:
            self.invoke_atomic_available = False
        
        return self.invoke_atomic_available
    
    def install_invoke_atomic(self) -> bool:
        """Install Invoke-AtomicRedTeam module"""
        install_script = """
        # Install Invoke-AtomicRedTeam
        if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
            Install-Module -Name invoke-atomicredteam -Force -Scope CurrentUser
        }
        Import-Module invoke-atomicredteam -Force
        """
        
        try:
            result = self.execute_powershell(install_script)
            return result["success"]
        except Exception:
            return False
    
    def execute_powershell(self, script: str, timeout: int = 300) -> Dict:
        """Execute PowerShell script"""
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False) as f:
                f.write(script)
                script_path = f.name
            
            # Execute script
            cmd = [
                self.powershell_path,
                "-ExecutionPolicy", "Bypass",
                "-File", script_path
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            # Cleanup
            os.unlink(script_path)
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out",
                "return_code": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1
            }
    
    def execute_atomic_test(self, technique_id: str, test_numbers: List[int] = None, 
                           check_prereqs: bool = True, cleanup: bool = False) -> Dict:
        """Execute atomic test via Invoke-AtomicTest"""
        
        if not self.check_invoke_atomic():
            return {
                "success": False,
                "stdout": "",
                "stderr": "Invoke-AtomicTest module not available",
                "return_code": -1
            }
        
        # Build command
        cmd_parts = [f"Invoke-AtomicTest {technique_id}"]
        
        if test_numbers:
            test_param = ",".join(map(str, test_numbers))
            cmd_parts.append(f"-TestNumbers {test_param}")
        
        if check_prereqs:
            cmd_parts.append("-CheckPrereqs")
        
        if cleanup:
            cmd_parts.append("-Cleanup")
        
        command = " ".join(cmd_parts)
        
        script = f"""
        Import-Module invoke-atomicredteam -Force
        
        try {{
            {command}
            Write-Output "EXECUTION_STATUS: SUCCESS"
        }}
        catch {{
            Write-Error "EXECUTION_STATUS: FAILED - $($_.Exception.Message)"
            throw
        }}
        """
        
        return self.execute_powershell(script)
    
    def get_atomic_test_info(self, technique_id: str) -> Dict:
        """Get information about atomic tests"""
        script = f"""
        Import-Module invoke-atomicredteam -Force
        
        try {{
            $tests = Invoke-AtomicTest {technique_id} -ShowDetails
            $tests | ConvertTo-Json -Depth 10
        }}
        catch {{
            Write-Error "Failed to get test info: $($_.Exception.Message)"
        }}
        """
        
        result = self.execute_powershell(script)
        
        if result["success"] and result["stdout"]:
            try:
                return {
                    "success": True,
                    "data": json.loads(result["stdout"])
                }
            except json.JSONDecodeError:
                pass
        
        return {"success": False, "data": None}
    
    def check_test_prerequisites(self, technique_id: str, test_numbers: List[int] = None) -> Dict:
        """Check prerequisites for atomic tests"""
        cmd_parts = [f"Invoke-AtomicTest {technique_id} -CheckPrereqs"]
        
        if test_numbers:
            test_param = ",".join(map(str, test_numbers))
            cmd_parts.append(f"-TestNumbers {test_param}")
        
        command = " ".join(cmd_parts)
        
        script = f"""
        Import-Module invoke-atomicredteam -Force
        
        try {{
            {command}
            Write-Output "PREREQ_STATUS: SATISFIED"
        }}
        catch {{
            Write-Output "PREREQ_STATUS: NOT_SATISFIED - $($_.Exception.Message)"
        }}
        """
        
        result = self.execute_powershell(script)
        
        # Parse output to determine if prereqs are satisfied
        satisfied = "PREREQ_STATUS: SATISFIED" in result["stdout"]
        
        return {
            "success": result["success"],
            "prerequisites_satisfied": satisfied,
            "output": result["stdout"],
            "errors": result["stderr"]
        }
    
    def get_available_techniques(self) -> List[str]:
        """Get list of available atomic techniques"""
        script = """
        Import-Module invoke-atomicredteam -Force
        
        try {
            $techniques = Get-AtomicTechnique
            $techniques | ForEach-Object { $_.Id } | Sort-Object | ConvertTo-Json
        }
        catch {
            Write-Error "Failed to get techniques: $($_.Exception.Message)"
        }
        """
        
        result = self.execute_powershell(script)
        
        if result["success"] and result["stdout"]:
            try:
                return json.loads(result["stdout"])
            except json.JSONDecodeError:
                pass
        
        return []


# Example usage and testing
if __name__ == "__main__":
    # Test configuration manager
    print("Testing Configuration Manager...")
    config_manager = ConfigManager()
    
    # Test target profiles
    profile = config_manager.get_target_profile("windows_workstation")
    print(f"Loaded profile: {profile.name}")
    
    # Test PowerShell executor (Windows only)
    try:
        print("\nTesting PowerShell Executor...")
        ps_executor = PowerShellExecutor()
        
        # Check if Invoke-AtomicTest is available
        if ps_executor.check_invoke_atomic():
            print("Invoke-AtomicTest is available")
            
            # Get available techniques
            techniques = ps_executor.get_available_techniques()
            print(f"Found {len(techniques)} available techniques")
        else:
            print("Invoke-AtomicTest is not available")
    except Exception as e:
        print(f"PowerShell testing failed (expected on non-Windows): {e}")
    
    # Test logger
    print("\nTesting Structured Logger...")
    logger = StructuredLogger("test_orchestrator")
    logger.info("Test log message")
    
    # Log a fake attack step
    logger.log_attack_step(
        {"step_number": 1, "technique_id": "T1003", "technique_name": "OS Credential Dumping"},
        "success",
        {"execution_time": 5.2, "output_size": 1024}
    )
    
    print("Configuration and utilities testing completed!")
