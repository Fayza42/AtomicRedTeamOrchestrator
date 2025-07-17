#!/usr/bin/env python3
"""
Real Atomic Red Team SSH Executor
Integrates with actual Invoke-AtomicTest framework while maintaining intelligent attack chaining
"""

import paramiko
import time
import os
import logging
import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import subprocess

class RealAtomicRedTeamExecutor:
    """
    SSH executor that uses the real Invoke-AtomicTest framework with intelligent attack chains
    """
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)
        
        # PowerShell session tracking
        self.powershell_session = None
        self.atomic_framework_ready = False
        
        # Attack session tracking
        self.attack_session = {
            "start_time": datetime.now().isoformat(),
            "target": hostname,
            "attack_chain": None,
            "executed_techniques": [],
            "failed_techniques": [],
            "prerequisites_checked": [],
            "evidence": [],
            "framework_info": {}
        }
        
        # Remote paths
        self.remote_work_dir = "/tmp/atomic_redteam_session"
        self.remote_evidence_dir = f"{self.remote_work_dir}/evidence"
        
    def connect(self) -> bool:
        """Establish SSH connection and prepare Atomic Red Team framework"""
        try:
            self.logger.info(f"🔗 Connecting to {self.hostname}:{self.port}")
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=30
            )
            
            self.sftp = self.client.open_sftp()
            self._setup_remote_directories()
            
            # Initialize PowerShell and Atomic Red Team framework
            if self._initialize_powershell_session():
                if self._verify_atomic_framework():
                    self.atomic_framework_ready = True
                    self.logger.info("✅ SSH connection and Atomic framework ready")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Connection failed: {e}")
            return False
    
    def _setup_remote_directories(self):
        """Create necessary directories on remote system"""
        directories = [self.remote_work_dir, self.remote_evidence_dir]
        
        for directory in directories:
            cmd = f"mkdir -p {directory}"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdout.channel.recv_exit_status()
    
    def _initialize_powershell_session(self) -> bool:
        """Initialize PowerShell session on remote Linux system"""
        try:
            self.logger.info("🔧 Initializing PowerShell session...")
            
            # Check if PowerShell is available
            result = self._execute_command("which pwsh")
            if not result["success"]:
                self.logger.error("❌ PowerShell not found on remote system")
                return False
            
            # Test PowerShell execution
            result = self._execute_command("pwsh -Command 'Write-Host \"PowerShell Ready\"'")
            if result["success"] and "PowerShell Ready" in result["stdout"]:
                self.logger.info("✅ PowerShell session initialized")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"❌ PowerShell initialization failed: {e}")
            return False
    
    def _verify_atomic_framework(self) -> bool:
        """Verify Invoke-AtomicRedTeam framework is available"""
        try:
            self.logger.info("🔍 Verifying Atomic Red Team framework...")
            
            # Check if Invoke-AtomicRedTeam module is available
            check_cmd = "pwsh -Command 'Get-Module -ListAvailable -Name invoke-atomicredteam'"
            result = self._execute_command(check_cmd)
            
            if result["success"] and "invoke-atomicredteam" in result["stdout"].lower():
                self.logger.info("✅ Invoke-AtomicRedTeam module found")
                
                # Get framework information
                info_cmd = "pwsh -Command 'Import-Module invoke-atomicredteam; Get-Module invoke-atomicredteam | Select-Object Name, Version, ModuleBase'"
                info_result = self._execute_command(info_cmd)
                
                if info_result["success"]:
                    self.attack_session["framework_info"] = {
                        "module_check": info_result["stdout"],
                        "verification_time": datetime.now().isoformat()
                    }
                
                # Test basic functionality
                test_cmd = "pwsh -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest T1082 -ShowDetailsBrief'"
                test_result = self._execute_command(test_cmd, timeout=60)
                
                if test_result["success"]:
                    self.logger.info("✅ Atomic Red Team framework verified and functional")
                    return True
            
            self.logger.error("❌ Invoke-AtomicRedTeam framework not available")
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Framework verification failed: {e}")
            return False
    
    def _execute_command(self, command: str, timeout: int = 300) -> Dict:
        """Execute command via SSH with enhanced logging"""
        try:
            self.logger.info(f"🔧 Executing: {command}")
            
            start_time = time.time()
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')
            exit_code = stdout.channel.recv_exit_status()
            execution_time = time.time() - start_time
            
            result = {
                "success": exit_code == 0,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "exit_code": exit_code,
                "command": command,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }
            
            # Store in evidence
            self.attack_session["evidence"].append({
                "type": "command_execution",
                "details": result
            })
            
            if result["success"]:
                self.logger.info(f"✅ Command completed in {execution_time:.2f}s")
            else:
                self.logger.error(f"❌ Command failed (exit code {exit_code})")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "command": command,
                "execution_time": 0,
                "timestamp": datetime.now().isoformat()
            }
    
    def check_technique_prerequisites(self, technique_id: str) -> Dict:
        """Check prerequisites for a technique using Invoke-AtomicTest"""
        try:
            self.logger.info(f"🔍 Checking prerequisites for {technique_id}")
            
            # Check prerequisites using the framework
            prereq_cmd = f"pwsh -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest {technique_id} -CheckPrereqs'"
            result = self._execute_command(prereq_cmd, timeout=120)
            
            prereq_status = {
                "technique_id": technique_id,
                "prerequisites_met": False,
                "missing_prerequisites": [],
                "details": result["stdout"],
                "errors": result["stderr"]
            }
            
            if result["success"]:
                # Parse output to determine if prerequisites are met
                if "Prerequisites met" in result["stdout"] or "All prerequisites met" in result["stdout"]:
                    prereq_status["prerequisites_met"] = True
                    self.logger.info(f"✅ Prerequisites met for {technique_id}")
                else:
                    # Extract missing prerequisites
                    prereq_status["missing_prerequisites"] = self._parse_missing_prerequisites(result["stdout"])
                    self.logger.warning(f"⚠️ Missing prerequisites for {technique_id}: {prereq_status['missing_prerequisites']}")
            else:
                self.logger.error(f"❌ Failed to check prerequisites for {technique_id}")
            
            self.attack_session["prerequisites_checked"].append(prereq_status)
            return prereq_status
            
        except Exception as e:
            self.logger.error(f"Prerequisites check failed for {technique_id}: {e}")
            return {
                "technique_id": technique_id,
                "prerequisites_met": False,
                "error": str(e)
            }
    
    def _parse_missing_prerequisites(self, output: str) -> List[str]:
        """Parse missing prerequisites from Invoke-AtomicTest output"""
        missing = []
        lines = output.split('\n')
        
        for line in lines:
            if "missing" in line.lower() or "not found" in line.lower():
                missing.append(line.strip())
        
        return missing
    
    def get_technique_details(self, technique_id: str) -> Dict:
        """Get detailed information about a technique"""
        try:
            self.logger.info(f"📋 Getting details for {technique_id}")
            
            # Get technique details using ShowDetailsBrief
            details_cmd = f"pwsh -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest {technique_id} -ShowDetailsBrief'"
            result = self._execute_command(details_cmd, timeout=60)
            
            details = {
                "technique_id": technique_id,
                "details_available": result["success"],
                "raw_output": result["stdout"],
                "tests": [],
                "platforms": [],
                "description": ""
            }
            
            if result["success"]:
                details.update(self._parse_technique_details(result["stdout"]))
                self.logger.info(f"✅ Retrieved details for {technique_id}")
            
            return details
            
        except Exception as e:
            self.logger.error(f"Failed to get details for {technique_id}: {e}")
            return {"technique_id": technique_id, "error": str(e)}
    
    def _parse_technique_details(self, output: str) -> Dict:
        """Parse technique details from Invoke-AtomicTest output"""
        details = {
            "tests": [],
            "platforms": [],
            "description": ""
        }
        
        lines = output.split('\n')
        current_test = None
        
        for line in lines:
            line = line.strip()
            
            # Parse test information
            if line.startswith("Test #"):
                if current_test:
                    details["tests"].append(current_test)
                current_test = {"test_number": line, "name": "", "platforms": []}
            elif current_test and "Name:" in line:
                current_test["name"] = line.replace("Name:", "").strip()
            elif current_test and "Platforms:" in line:
                platforms = line.replace("Platforms:", "").strip().split(",")
                current_test["platforms"] = [p.strip() for p in platforms]
                details["platforms"].extend(current_test["platforms"])
        
        if current_test:
            details["tests"].append(current_test)
        
        # Remove duplicates from platforms
        details["platforms"] = list(set(details["platforms"]))
        
        return details
    
    def execute_atomic_technique(self, technique_id: str, test_numbers: List[int] = None, 
                                dry_run: bool = False) -> Dict:
        """Execute Atomic Red Team technique using the real framework"""
        
        if not self.atomic_framework_ready:
            return {"success": False, "error": "Atomic Red Team framework not ready"}
        
        technique_start = datetime.now()
        self.logger.info(f"🎯 Executing technique: {technique_id}")
        
        execution_result = {
            "technique_id": technique_id,
            "start_time": technique_start.isoformat(),
            "test_numbers": test_numbers,
            "dry_run": dry_run,
            "prerequisite_check": {},
            "execution_details": {},
            "cleanup_performed": False,
            "success": False
        }
        
        try:
            # Step 1: Check prerequisites
            prereq_result = self.check_technique_prerequisites(technique_id)
            execution_result["prerequisite_check"] = prereq_result
            
            if not prereq_result.get("prerequisites_met", False) and not dry_run:
                self.logger.warning(f"⚠️ Prerequisites not met for {technique_id}, attempting execution anyway...")
            
            # Step 2: Get technique details
            details = self.get_technique_details(technique_id)
            execution_result["technique_details"] = details
            
            # Step 3: Execute the technique
            if dry_run:
                self.logger.info(f"🧪 DRY RUN: Would execute {technique_id}")
                execution_result["success"] = True
                execution_result["execution_details"] = {"message": "Dry run completed"}
            else:
                # Construct execution command
                exec_cmd = self._build_execution_command(technique_id, test_numbers)
                
                self.logger.info(f"🚀 Executing: {exec_cmd}")
                exec_result = self._execute_command(exec_cmd, timeout=300)
                
                execution_result["execution_details"] = exec_result
                execution_result["success"] = exec_result["success"]
                
                if exec_result["success"]:
                    self.logger.info(f"✅ Technique {technique_id} executed successfully")
                    self.attack_session["executed_techniques"].append(execution_result)
                    
                    # Perform cleanup
                    cleanup_result = self._cleanup_technique(technique_id, test_numbers)
                    execution_result["cleanup_performed"] = cleanup_result["success"]
                else:
                    self.logger.error(f"❌ Technique {technique_id} execution failed")
                    self.attack_session["failed_techniques"].append(execution_result)
            
            execution_result["end_time"] = datetime.now().isoformat()
            execution_result["duration"] = (datetime.now() - technique_start).total_seconds()
            
            return execution_result
            
        except Exception as e:
            self.logger.error(f"Technique execution failed: {e}")
            execution_result["error"] = str(e)
            execution_result["end_time"] = datetime.now().isoformat()
            return execution_result
    
    def _build_execution_command(self, technique_id: str, test_numbers: List[int] = None) -> str:
        """Build the Invoke-AtomicTest execution command"""
        base_cmd = f"pwsh -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest {technique_id}"
        
        if test_numbers:
            test_param = ",".join(map(str, test_numbers))
            base_cmd += f" -TestNumbers {test_param}"
        
        base_cmd += "'"
        return base_cmd
    
    def _cleanup_technique(self, technique_id: str, test_numbers: List[int] = None) -> Dict:
        """Perform cleanup for executed technique"""
        try:
            self.logger.info(f"🧹 Cleaning up {technique_id}")
            
            cleanup_cmd = f"pwsh -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest {technique_id} -Cleanup"
            
            if test_numbers:
                test_param = ",".join(map(str, test_numbers))
                cleanup_cmd += f" -TestNumbers {test_param}"
            
            cleanup_cmd += "'"
            
            result = self._execute_command(cleanup_cmd, timeout=120)
            
            if result["success"]:
                self.logger.info(f"✅ Cleanup completed for {technique_id}")
            else:
                self.logger.warning(f"⚠️ Cleanup may have failed for {technique_id}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Cleanup failed for {technique_id}: {e}")
            return {"success": False, "error": str(e)}
    
    def execute_attack_chain(self, attack_chain: List[Dict], dry_run: bool = False) -> Dict:
        """Execute a complete attack chain using real Atomic Red Team techniques"""
        
        if not self.atomic_framework_ready:
            return {"success": False, "error": "Atomic Red Team framework not ready"}
        
        chain_start = datetime.now()
        self.attack_session["attack_chain"] = attack_chain
        
        self.logger.info(f"🔗 Executing attack chain with {len(attack_chain)} techniques")
        
        chain_result = {
            "start_time": chain_start.isoformat(),
            "chain_length": len(attack_chain),
            "dry_run": dry_run,
            "executed_steps": [],
            "failed_steps": [],
            "overall_success": True
        }
        
        for i, step in enumerate(attack_chain, 1):
            technique_id = step.get("technique_id")
            test_numbers = step.get("test_numbers", None)
            
            self.logger.info(f"🔄 Step {i}/{len(attack_chain)}: {technique_id}")
            
            # Execute technique
            step_result = self.execute_atomic_technique(technique_id, test_numbers, dry_run)
            
            if step_result["success"]:
                chain_result["executed_steps"].append(step_result)
                self.logger.info(f"✅ Step {i} completed: {technique_id}")
                
                # Wait between techniques for realism
                if not dry_run and i < len(attack_chain):
                    wait_time = step.get("wait_time", 5)
                    self.logger.info(f"⏱️ Waiting {wait_time}s before next technique...")
                    time.sleep(wait_time)
            else:
                chain_result["failed_steps"].append(step_result)
                chain_result["overall_success"] = False
                self.logger.error(f"❌ Step {i} failed: {technique_id}")
                
                # Check if we should continue on failure
                if step.get("stop_on_failure", False):
                    self.logger.error("🛑 Stopping attack chain due to critical failure")
                    break
        
        chain_result["end_time"] = datetime.now().isoformat()
        chain_result["total_duration"] = (datetime.now() - chain_start).total_seconds()
        
        self.logger.info(f"🏁 Attack chain completed: {len(chain_result['executed_steps'])}/{chain_result['chain_length']} successful")
        
        return chain_result
    
    def generate_vple_attack_chain(self) -> List[Dict]:
        """Generate intelligent attack chain optimized for VPLE VM"""
        
        # VPLE-optimized attack chain using real MITRE technique IDs
        attack_chain = [
            {
                "technique_id": "T1082",
                "name": "System Information Discovery",
                "test_numbers": [1, 2],
                "category": "discovery",
                "description": "Gather basic system information",
                "wait_time": 3,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1083",
                "name": "File and Directory Discovery", 
                "test_numbers": [1],
                "category": "discovery",
                "description": "Discover file system structure",
                "wait_time": 5,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1018",
                "name": "Remote System Discovery",
                "test_numbers": [1, 2],
                "category": "discovery", 
                "description": "Discover network systems",
                "wait_time": 10,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1059.004",
                "name": "Unix Shell",
                "test_numbers": [1, 2, 3],
                "category": "execution",
                "description": "Execute commands via Unix shell",
                "wait_time": 5,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1548.001",
                "name": "Setuid and Setgid",
                "test_numbers": [1],
                "category": "privilege_escalation",
                "description": "Attempt privilege escalation",
                "wait_time": 8,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1003.008",
                "name": "Credential Dumping",
                "test_numbers": [1],
                "category": "credential_access",
                "description": "Access credential files",
                "wait_time": 10,
                "stop_on_failure": False
            },
            {
                "technique_id": "T1543.002",
                "name": "Systemd Service",
                "test_numbers": [1],
                "category": "persistence",
                "description": "Create persistence mechanism",
                "wait_time": 5,
                "stop_on_failure": False
            }
        ]
        
        return attack_chain
    
    def get_session_report(self) -> Dict:
        """Generate comprehensive session report"""
        
        self.attack_session["end_time"] = datetime.now().isoformat()
        
        if self.attack_session.get("start_time"):
            start = datetime.fromisoformat(self.attack_session["start_time"])
            end = datetime.now()
            self.attack_session["total_duration"] = (end - start).total_seconds()
        
        summary = {
            "session_overview": {
                "target": self.attack_session["target"],
                "duration": self.attack_session.get("total_duration", 0),
                "techniques_executed": len(self.attack_session["executed_techniques"]),
                "techniques_failed": len(self.attack_session["failed_techniques"]),
                "prerequisites_checked": len(self.attack_session["prerequisites_checked"]),
                "commands_executed": len(self.attack_session["evidence"]),
                "framework_ready": self.atomic_framework_ready
            },
            "execution_details": {
                "executed_techniques": self.attack_session["executed_techniques"],
                "failed_techniques": self.attack_session["failed_techniques"],
                "prerequisites_status": self.attack_session["prerequisites_checked"]
            },
            "framework_info": self.attack_session["framework_info"]
        }
        
        return summary
    
    def disconnect(self):
        """Close SSH connection and cleanup"""
        try:
            if self.sftp:
                self.sftp.close()
            if self.client:
                self.client.close()
            self.logger.info("🔌 SSH connection closed")
        except Exception as e:
            self.logger.error(f"Error during disconnect: {e}")


class RealAtomicVPLEConnection:
    """Context manager for VPLE connections using real Atomic Red Team"""
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.executor = RealAtomicRedTeamExecutor(hostname, username, password, port)
    
    def __enter__(self):
        if self.executor.connect():
            return self.executor
        else:
            raise ConnectionError("Failed to connect to VPLE VM or initialize Atomic Red Team framework")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Generate final report
        report = self.executor.get_session_report()
        print(f"\n📊 Attack session completed:")
        print(f"   Techniques executed: {report['session_overview']['techniques_executed']}")
        print(f"   Duration: {report['session_overview']['duration']:.2f}s")
        
        self.executor.disconnect()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test with VPLE VM
    vple_ip = "192.168.1.100"  # Replace with your VPLE IP
    
    try:
        with RealAtomicVPLEConnection(vple_ip) as vple:
            # Generate VPLE-optimized attack chain
            attack_chain = vple.generate_vple_attack_chain()
            
            print(f"🔗 Generated attack chain with {len(attack_chain)} techniques")
            for i, step in enumerate(attack_chain, 1):
                print(f"   {i}. {step['technique_id']} - {step['name']}")
            
            # Execute the attack chain
            print(f"\n🚀 Executing attack chain against VPLE VM...")
            result = vple.execute_attack_chain(attack_chain, dry_run=False)
            
            print(f"\n🏁 Attack chain execution completed:")
            print(f"   Success rate: {len(result['executed_steps'])}/{result['chain_length']}")
            print(f"   Total duration: {result['total_duration']:.2f}s")
            
    except Exception as e:
        print(f"❌ Attack execution failed: {e}")
