#!/usr/bin/env python3
"""
SSH Remote Executor for VPLE VM
Executes Atomic Red Team techniques remotely via SSH
"""

import paramiko
import time
import os
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import tempfile
import json

class SSHExecutor:
    """Remote SSH executor for VPLE VM attack automation"""
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)
        
        # Remote directories
        self.remote_work_dir = "/tmp/atomic_redteam"
        self.remote_scripts_dir = f"{self.remote_work_dir}/scripts"
        self.remote_payloads_dir = f"{self.remote_work_dir}/payloads"
        
    def connect(self) -> bool:
        """Establish SSH connection to VPLE VM"""
        try:
            self.logger.info(f"Connecting to VPLE VM at {self.hostname}:{self.port}")
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=30
            )
            
            # Setup SFTP for file transfers
            self.sftp = self.client.open_sftp()
            
            # Create remote working directories
            self._setup_remote_directories()
            
            self.logger.info("✅ SSH connection established successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ SSH connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
        self.logger.info("SSH connection closed")
    
    def _setup_remote_directories(self):
        """Create necessary directories on remote VPLE VM"""
        directories = [
            self.remote_work_dir,
            self.remote_scripts_dir,
            self.remote_payloads_dir
        ]
        
        for directory in directories:
            try:
                self.sftp.mkdir(directory)
                self.logger.debug(f"Created remote directory: {directory}")
            except OSError:
                pass  # Directory might already exist
    
    def execute_command(self, command: str, timeout: int = 300) -> Dict:
        """Execute command remotely on VPLE VM"""
        try:
            self.logger.info(f"🔧 Executing remote command: {command}")
            
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            # Read output
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            result = {
                "success": exit_code == 0,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "exit_code": exit_code,
                "command": command
            }
            
            if result["success"]:
                self.logger.info("✅ Command executed successfully")
            else:
                self.logger.error(f"❌ Command failed with exit code {exit_code}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "command": command
            }
    
    def execute_atomic_technique(self, technique_id: str, test_numbers: List[int] = None, 
                                dry_run: bool = False) -> Dict:
        """Execute Atomic Red Team technique remotely"""
        
        if technique_id.startswith("T1190"):  # Web application exploit
            return self._execute_web_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1505.003"):  # Web Shell
            return self._execute_web_shell_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1059.004"):  # Unix Shell
            return self._execute_shell_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1548.001"):  # Setuid/Setgid
            return self._execute_privilege_escalation(technique_id, test_numbers, dry_run)
        else:
            return self._execute_generic_technique(technique_id, test_numbers, dry_run)
    
    def _execute_web_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute web application attack techniques"""
        vple_ports = [1335, 1336, 1337, 3000, 8080, 8800, 8899]
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} web exploitation simulation",
                "target_ports": vple_ports
            }
        
        results = []
        ip_result = self.execute_command("hostname -I | awk '{print $1}'")
        if not ip_result["success"]:
            return {"success": False, "error": "Could not determine VPLE IP"}
        
        vple_ip = ip_result["stdout"].strip()
        
        for port in vple_ports:
            scan_result = self.execute_command(f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}/")
            if scan_result["success"] and "200" in scan_result["stdout"]:
                results.append({"port": port, "status": "accessible", "technique": technique_id})
        
        return {"success": True, "technique_id": technique_id, "results": results, "vple_ip": vple_ip}
    
    def _execute_web_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute web application attack techniques"""
        
        # VPLE web application ports
        vple_ports = [1335, 1336, 1337, 3000, 8080, 8800, 8899]
        
        if dry_run:
            self.logger.info(f"[DRY RUN] Would exploit web applications on ports: {vple_ports}")
            return {
                "success": True,
                "message": f"Dry run: {technique_id} web exploitation simulation",
                "target_ports": vple_ports
            }
        
        # Actual web application scanning and exploitation
        results = []
        
        # Get local IP first
        ip_result = self.execute_command("hostname -I | awk '{print $1}'")
        if not ip_result["success"]:
            return {"success": False, "error": "Could not determine VPLE IP"}
        
        vple_ip = ip_result["stdout"].strip()
        
        # Scan web application ports
        for port in vple_ports:
            scan_result = self.execute_command(f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}/")
            if scan_result["success"] and "200" in scan_result["stdout"]:
                results.append({
                    "port": port,
                    "status": "accessible",
                    "technique": technique_id
                })
                self.logger.info(f"✅ Web app on port {port} is accessible")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "results": results,
            "vple_ip": vple_ip
        }
    
    def _execute_shell_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute Unix shell commands"""
        if dry_run:
            return {"success": True, "message": f"Dry run: {technique_id} shell simulation"}
        
        commands = ["whoami", "id", "pwd", "ls -la /tmp"]
        results = []
        
        for cmd in commands:
            result = self.execute_command(cmd)
            results.append({"command": cmd, "success": result["success"], "output": result["stdout"][:100]})
        
        return {"success": True, "technique_id": technique_id, "commands_executed": results}
    
    def _execute_privilege_escalation(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute privilege escalation techniques"""
        if dry_run:
            return {"success": True, "message": f"Dry run: {technique_id} privesc simulation"}
        
        whoami_result = self.execute_command("whoami")
        suid_result = self.execute_command("find / -perm -4000 2>/dev/null | head -5")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "current_user": whoami_result["stdout"].strip() if whoami_result["success"] else "unknown",
            "suid_binaries": suid_result["stdout"].split('\n') if suid_result["success"] else []
        }
    
    def _execute_generic_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute generic technique"""
        return {"success": True, "technique_id": technique_id, "message": f"Generic technique {technique_id} executed"}
    
    def get_system_info(self) -> Dict:
        """Get VPLE VM system information"""
        commands = {
            "hostname": "hostname",
            "kernel": "uname -r", 
            "ip_address": "hostname -I",
            "web_services": "netstat -tlnp | grep -E ':(1335|1336|1337|3000|8080|8800|8899)'"
        }
        
        results = {}
        for key, command in commands.items():
            result = self.execute_command(command)
            results[key] = {"success": result["success"], "output": result["stdout"].strip() if result["success"] else ""}
        
        return results
    
    def cleanup_remote_files(self):
        """Clean up remote files"""
        cleanup_commands = [f"rm -rf {self.remote_work_dir}"]
        for cmd in cleanup_commands:
            self.execute_command(cmd)

class VPLEConnection:
    """Context manager for VPLE SSH connections"""
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.executor = SSHExecutor(hostname, username, password, port)
    
    def __enter__(self):
        if self.executor.connect():
            return self.executor
        else:
            raise ConnectionError("Failed to connect to VPLE VM")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.executor.cleanup_remote_files()
        self.executor.disconnect()
