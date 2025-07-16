#!/usr/bin/env python3
"""
Enhanced SSH Remote Executor for VPLE VM
Provides detailed analysis, artifact collection, and comprehensive reporting
"""

import paramiko
import time
import os
import logging
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
import subprocess
import base64

class EnhancedSSHExecutor:
    """Enhanced SSH executor with detailed analysis and reporting"""
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)
        
        # Enhanced tracking
        self.attack_session = {
            "start_time": datetime.now().isoformat(),
            "target": hostname,
            "phases": [],
            "artifacts": [],
            "system_changes": [],
            "evidence": []
        }
        
        # Remote directories
        self.remote_work_dir = "/tmp/atomic_redteam"
        self.remote_scripts_dir = f"{self.remote_work_dir}/scripts"
        self.remote_payloads_dir = f"{self.remote_work_dir}/payloads"
        self.remote_evidence_dir = f"{self.remote_work_dir}/evidence"
        
    def connect(self) -> bool:
        """Establish SSH connection with enhanced initial analysis"""
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
            
            # Setup SFTP
            self.sftp = self.client.open_sftp()
            
            # Create remote directories
            self._setup_remote_directories()
            
            # Perform initial system baseline
            self._capture_system_baseline()
            
            self.logger.info("✅ SSH connection established successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ SSH connection failed: {e}")
            return False
    
    def _setup_remote_directories(self):
        """Create necessary directories on remote VPLE VM"""
        directories = [
            self.remote_work_dir,
            self.remote_scripts_dir,
            self.remote_payloads_dir,
            self.remote_evidence_dir
        ]
        
        for directory in directories:
            try:
                self.sftp.mkdir(directory)
                self.logger.debug(f"Created remote directory: {directory}")
            except OSError:
                pass
    
    def _capture_system_baseline(self):
        """Capture initial system state for comparison"""
        self.logger.info("📋 Capturing system baseline...")
        
        baseline_commands = {
            "system_info": {
                "hostname": "hostname",
                "kernel": "uname -a",
                "os_release": "cat /etc/os-release",
                "uptime": "uptime",
                "load": "cat /proc/loadavg"
            },
            "network_info": {
                "interfaces": "ip addr show",
                "routes": "ip route show",
                "listening_ports": "netstat -tlnp",
                "connections": "netstat -tupln"
            },
            "process_info": {
                "processes": "ps aux",
                "process_tree": "pstree -p",
                "memory_usage": "free -h",
                "disk_usage": "df -h"
            },
            "security_info": {
                "users": "cat /etc/passwd",
                "groups": "cat /etc/group",
                "sudo_users": "cat /etc/sudoers 2>/dev/null || echo 'Access denied'",
                "suid_files": "find / -perm -4000 2>/dev/null",
                "sgid_files": "find / -perm -2000 2>/dev/null"
            },
            "web_services": {
                "apache_status": "systemctl status apache2 2>/dev/null || echo 'Not running'",
                "nginx_status": "systemctl status nginx 2>/dev/null || echo 'Not running'",
                "web_ports": "netstat -tlnp | grep -E ':(80|443|8080|8800|8899|1335|1336|1337|3000)'",
                "web_processes": "ps aux | grep -E '(apache|nginx|php|node|python)' | grep -v grep"
            }
        }
        
        baseline = {}
        for category, commands in baseline_commands.items():
            baseline[category] = {}
            self.logger.info(f"  Capturing {category}...")
            
            for key, command in commands.items():
                result = self.execute_command(command)
                baseline[category][key] = {
                    "command": command,
                    "success": result["success"],
                    "output": result["stdout"] if result["success"] else result["stderr"],
                    "timestamp": datetime.now().isoformat()
                }
        
        # Store baseline
        self.attack_session["baseline"] = baseline
        
        # Save baseline to remote system for comparison
        baseline_json = json.dumps(baseline, indent=2)
        self.execute_command(f"echo '{baseline_json}' > {self.remote_evidence_dir}/baseline.json")
        
        self.logger.info("✅ System baseline captured")
    
    def execute_command(self, command: str, timeout: int = 300) -> Dict:
        """Execute command with enhanced logging and artifact collection"""
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
            
            # Log command execution details
            if result["success"]:
                self.logger.info(f"✅ Command completed in {execution_time:.2f}s")
            else:
                self.logger.error(f"❌ Command failed (exit code {exit_code}) in {execution_time:.2f}s")
            
            # Store command in evidence
            self.attack_session["evidence"].append({
                "type": "command_execution",
                "details": result
            })
            
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
    
    def execute_atomic_technique(self, technique_id: str, test_numbers: List[int] = None, 
                                dry_run: bool = False) -> Dict:
        """Execute Atomic Red Team technique with detailed analysis"""
        
        phase_start = datetime.now()
        self.logger.info(f"🎯 Executing technique: {technique_id}")
        
        # Create phase tracking
        phase = {
            "technique_id": technique_id,
            "start_time": phase_start.isoformat(),
            "pre_execution_state": {},
            "execution_results": {},
            "post_execution_state": {},
            "artifacts_created": [],
            "system_changes": [],
            "analysis": {}
        }
        
        try:
            # Capture pre-execution state
            phase["pre_execution_state"] = self._capture_execution_state()
            
            # Execute technique based on ID
            if technique_id.startswith("T1190"):
                result = self._execute_web_technique_enhanced(technique_id, test_numbers, dry_run)
            elif technique_id.startswith("T1505.003"):
                result = self._execute_web_shell_technique_enhanced(technique_id, test_numbers, dry_run)
            elif technique_id.startswith("T1059.004"):
                result = self._execute_shell_technique_enhanced(technique_id, test_numbers, dry_run)
            elif technique_id.startswith("T1548.001"):
                result = self._execute_privilege_escalation_enhanced(technique_id, test_numbers, dry_run)
            else:
                result = self._execute_generic_technique_enhanced(technique_id, test_numbers, dry_run)
            
            phase["execution_results"] = result
            
            # Capture post-execution state
            phase["post_execution_state"] = self._capture_execution_state()
            
            # Analyze changes
            phase["analysis"] = self._analyze_technique_impact(
                phase["pre_execution_state"], 
                phase["post_execution_state"],
                technique_id
            )
            
            # Generate artifacts analysis
            phase["artifacts_created"] = self._detect_artifacts(technique_id)
            
            phase["end_time"] = datetime.now().isoformat()
            phase["duration"] = (datetime.now() - phase_start).total_seconds()
            
            # Store phase
            self.attack_session["phases"].append(phase)
            
            return result
            
        except Exception as e:
            phase["error"] = str(e)
            phase["end_time"] = datetime.now().isoformat()
            self.attack_session["phases"].append(phase)
            raise
    
    def _capture_execution_state(self) -> Dict:
        """Capture current system state for comparison"""
        state_commands = {
            "processes": "ps aux",
            "network_connections": "netstat -tupln",
            "file_system": f"find {self.remote_work_dir} -type f -exec ls -la {{}} + 2>/dev/null || echo 'No files'",
            "memory_usage": "free -m",
            "disk_usage": "df -h",
            "recent_files": "find /tmp -type f -mmin -5 2>/dev/null || echo 'No recent files'",
            "logged_in_users": "who",
            "system_load": "uptime"
        }
        
        state = {}
        for key, command in state_commands.items():
            result = self.execute_command(command)
            state[key] = {
                "output": result["stdout"] if result["success"] else result["stderr"],
                "timestamp": datetime.now().isoformat()
            }
        
        return state
    
    def _execute_web_technique_enhanced(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Enhanced web application attack with detailed analysis"""
        
        vple_web_apps = {
            1335: {"name": "DVWA", "path": "/", "technology": "PHP"},
            1336: {"name": "Mutillidae", "path": "/", "technology": "PHP"},
            1337: {"name": "WebGoat", "path": "/WebGoat", "technology": "Java"},
            3000: {"name": "Juice Shop", "path": "/", "technology": "Node.js"},
            8080: {"name": "bWAPP", "path": "/", "technology": "PHP"},
            8800: {"name": "WordPress", "path": "/", "technology": "PHP"},
            8899: {"name": "Security Ninjas", "path": "/", "technology": "PHP"}
        }
        
        if dry_run:
            return {
                "success": True,
                "message": f"Dry run: {technique_id} web exploitation simulation",
                "target_apps": vple_web_apps
            }
        
        # Get target IP
        ip_result = self.execute_command("hostname -I | awk '{print $1}'")
        if not ip_result["success"]:
            return {"success": False, "error": "Could not determine VPLE IP"}
        
        vple_ip = ip_result["stdout"].strip()
        
        # Detailed web application analysis
        web_analysis = {
            "target_ip": vple_ip,
            "applications": {},
            "vulnerabilities_found": [],
            "exploitation_attempts": [],
            "successful_exploits": []
        }
        
        for port, app_info in vple_web_apps.items():
            self.logger.info(f"  🌐 Analyzing {app_info['name']} on port {port}")
            
            app_analysis = {
                "name": app_info["name"],
                "port": port,
                "technology": app_info["technology"],
                "accessibility": "unknown",
                "response_analysis": {},
                "security_headers": {},
                "exploitation_results": []
            }
            
            # Check accessibility
            accessibility_result = self.execute_command(
                f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 http://localhost:{port}{app_info['path']}"
            )
            
            if accessibility_result["success"] and "200" in accessibility_result["stdout"]:
                app_analysis["accessibility"] = "accessible"
                
                # Get detailed response information
                response_result = self.execute_command(
                    f"curl -s -I --max-time 5 http://localhost:{port}{app_info['path']}"
                )
                
                if response_result["success"]:
                    app_analysis["response_analysis"] = {
                        "headers": response_result["stdout"],
                        "server_info": self._extract_server_info(response_result["stdout"])
                    }
                
                # Check for common vulnerabilities
                vuln_checks = self._perform_vulnerability_checks(port, app_info)
                app_analysis["exploitation_results"] = vuln_checks
                
                if vuln_checks:
                    web_analysis["successful_exploits"].append({
                        "app": app_info["name"],
                        "port": port,
                        "exploits": vuln_checks
                    })
            
            else:
                app_analysis["accessibility"] = "not_accessible"
                app_analysis["status_code"] = accessibility_result["stdout"]
            
            web_analysis["applications"][port] = app_analysis
        
        return {
            "success": True,
            "technique_id": technique_id,
            "detailed_analysis": web_analysis,
            "summary": {
                "total_apps": len(vple_web_apps),
                "accessible_apps": len([a for a in web_analysis["applications"].values() if a["accessibility"] == "accessible"]),
                "successful_exploits": len(web_analysis["successful_exploits"])
            }
        }
    
    def _perform_vulnerability_checks(self, port: int, app_info: Dict) -> List[Dict]:
        """Perform basic vulnerability checks on web applications"""
        checks = []
        
        # SQL Injection check
        sqli_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
        for payload in sqli_payloads:
            result = self.execute_command(
                f"curl -s --max-time 5 'http://localhost:{port}/?id={payload}' | grep -i 'sql\\|error\\|warning' | head -3"
            )
            if result["success"] and result["stdout"].strip():
                checks.append({
                    "vulnerability": "Potential SQL Injection",
                    "payload": payload,
                    "response": result["stdout"][:200]
                })
        
        # XSS check
        xss_payload = "<script>alert('XSS')</script>"
        result = self.execute_command(
            f"curl -s --max-time 5 'http://localhost:{port}/?search={xss_payload}' | grep -i 'script\\|alert'"
        )
        if result["success"] and "script" in result["stdout"]:
            checks.append({
                "vulnerability": "Potential XSS",
                "payload": xss_payload,
                "response": result["stdout"][:200]
            })
        
        # Directory traversal check
        traversal_payload = "../../../../etc/passwd"
        result = self.execute_command(
            f"curl -s --max-time 5 'http://localhost:{port}/?file={traversal_payload}' | grep -i 'root:\\|daemon:'"
        )
        if result["success"] and "root:" in result["stdout"]:
            checks.append({
                "vulnerability": "Directory Traversal",
                "payload": traversal_payload,
                "response": result["stdout"][:200]
            })
        
        return checks
    
    def _extract_server_info(self, headers: str) -> Dict:
        """Extract server information from HTTP headers"""
        info = {}
        for line in headers.split('\n'):
            if line.startswith('Server:'):
                info['server'] = line.split(':', 1)[1].strip()
            elif line.startswith('X-Powered-By:'):
                info['powered_by'] = line.split(':', 1)[1].strip()
            elif line.startswith('Set-Cookie:'):
                info['cookies'] = line.split(':', 1)[1].strip()
        return info
    
    def _execute_shell_technique_enhanced(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Enhanced shell technique with detailed command analysis"""
        
        if dry_run:
            return {"success": True, "message": f"Dry run: {technique_id} shell simulation"}
        
        # Comprehensive shell analysis
        shell_commands = {
            "identity": {
                "whoami": "whoami",
                "id": "id",
                "groups": "groups",
                "env": "env | head -20"
            },
            "system_info": {
                "hostname": "hostname",
                "uname": "uname -a",
                "distro": "lsb_release -a 2>/dev/null || cat /etc/os-release",
                "uptime": "uptime"
            },
            "file_system": {
                "pwd": "pwd",
                "home_dir": "ls -la ~",
                "tmp_dir": "ls -la /tmp",
                "var_log": "ls -la /var/log | head -10"
            },
            "network": {
                "ip_addr": "ip addr show",
                "routes": "ip route show",
                "dns": "cat /etc/resolv.conf"
            },
            "processes": {
                "ps": "ps aux | head -20",
                "pstree": "pstree -p | head -20",
                "top": "top -bn1 | head -20"
            }
        }
        
        analysis = {}
        
        for category, commands in shell_commands.items():
            self.logger.info(f"  🐚 Analyzing {category}")
            analysis[category] = {}
            
            for name, command in commands.items():
                result = self.execute_command(command)
                analysis[category][name] = {
                    "command": command,
                    "success": result["success"],
                    "output": result["stdout"] if result["success"] else result["stderr"],
                    "execution_time": result["execution_time"]
                }
        
        # Create evidence file
        evidence_file = f"{self.remote_evidence_dir}/shell_analysis_{int(time.time())}.json"
        evidence_json = json.dumps(analysis, indent=2)
        self.execute_command(f"echo '{evidence_json}' > {evidence_file}")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "detailed_analysis": analysis,
            "evidence_file": evidence_file,
            "summary": {
                "user": analysis["identity"]["whoami"]["output"].strip() if analysis["identity"]["whoami"]["success"] else "unknown",
                "system": analysis["system_info"]["hostname"]["output"].strip() if analysis["system_info"]["hostname"]["success"] else "unknown",
                "privileges": analysis["identity"]["id"]["output"].strip() if analysis["identity"]["id"]["success"] else "unknown"
            }
        }
    
    def _execute_privilege_escalation_enhanced(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Enhanced privilege escalation with detailed analysis"""
        
        if dry_run:
            return {"success": True, "message": f"Dry run: {technique_id} privesc simulation"}
        
        # Comprehensive privilege escalation analysis
        privesc_analysis = {
            "current_user": {},
            "system_info": {},
            "privilege_vectors": {},
            "file_permissions": {},
            "process_analysis": {},
            "network_analysis": {}
        }
        
        # Current user analysis
        user_commands = {
            "whoami": "whoami",
            "id": "id",
            "groups": "groups",
            "sudo_check": "sudo -l 2>/dev/null || echo 'No sudo access'",
            "history": "history | tail -20"
        }
        
        for name, command in user_commands.items():
            result = self.execute_command(command)
            privesc_analysis["current_user"][name] = {
                "output": result["stdout"] if result["success"] else result["stderr"],
                "success": result["success"]
            }
        
        # System privilege vectors
        privesc_commands = {
            "suid_files": "find / -perm -4000 2>/dev/null | head -20",
            "sgid_files": "find / -perm -2000 2>/dev/null | head -20",
            "world_writable": "find / -perm -002 -type f 2>/dev/null | head -20",
            "cron_jobs": "crontab -l 2>/dev/null || echo 'No cron jobs'",
            "system_cron": "ls -la /etc/cron* 2>/dev/null || echo 'No system cron'",
            "passwd_file": "cat /etc/passwd | head -20",
            "shadow_readable": "cat /etc/shadow 2>/dev/null || echo 'Not readable'",
            "kernel_version": "uname -r",
            "os_version": "cat /etc/os-release"
        }
        
        for name, command in privesc_commands.items():
            result = self.execute_command(command)
            privesc_analysis["privilege_vectors"][name] = {
                "output": result["stdout"] if result["success"] else result["stderr"],
                "success": result["success"]
            }
        
        # Process analysis
        process_commands = {
            "running_processes": "ps aux | grep -v grep",
            "listening_services": "netstat -tlnp",
            "running_services": "systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null"
        }
        
        for name, command in process_commands.items():
            result = self.execute_command(command)
            privesc_analysis["process_analysis"][name] = {
                "output": result["stdout"] if result["success"] else result["stderr"],
                "success": result["success"]
            }
        
        # Analyze findings
        findings = self._analyze_privilege_escalation_findings(privesc_analysis)
        
        # Save detailed analysis
        analysis_file = f"{self.remote_evidence_dir}/privesc_analysis_{int(time.time())}.json"
        analysis_json = json.dumps(privesc_analysis, indent=2)
        self.execute_command(f"echo '{analysis_json}' > {analysis_file}")
        
        return {
            "success": True,
            "technique_id": technique_id,
            "detailed_analysis": privesc_analysis,
            "findings": findings,
            "evidence_file": analysis_file,
            "summary": {
                "current_user": privesc_analysis["current_user"]["whoami"]["output"].strip() if privesc_analysis["current_user"]["whoami"]["success"] else "unknown",
                "suid_binaries_found": len(privesc_analysis["privilege_vectors"]["suid_files"]["output"].split('\n')) if privesc_analysis["privilege_vectors"]["suid_files"]["success"] else 0,
                "potential_vectors": len(findings["potential_vectors"]) if findings else 0
            }
        }
    
    def _analyze_privilege_escalation_findings(self, analysis: Dict) -> Dict:
        """Analyze privilege escalation findings"""
        findings = {
            "potential_vectors": [],
            "high_risk_items": [],
            "interesting_files": [],
            "recommendations": []
        }
        
        # Check for dangerous SUID binaries
        dangerous_suid = ["nmap", "vim", "less", "more", "nano", "cp", "mv", "find", "awk", "python", "perl", "ruby"]
        suid_output = analysis["privilege_vectors"]["suid_files"]["output"]
        
        for binary in dangerous_suid:
            if binary in suid_output:
                findings["potential_vectors"].append(f"Dangerous SUID binary found: {binary}")
        
        # Check for sudo access
        sudo_output = analysis["current_user"]["sudo_check"]["output"]
        if "NOPASSWD" in sudo_output:
            findings["potential_vectors"].append("Passwordless sudo access detected")
        
        # Check for world-writable files
        writable_output = analysis["privilege_vectors"]["world_writable"]["output"]
        if writable_output and "No such file" not in writable_output:
            findings["potential_vectors"].append("World-writable files found")
        
        return findings
    
    def _execute_generic_technique_enhanced(self, technique_id: str, test_numbers: List[int], dry_run: bool) -> Dict:
        """Enhanced generic technique execution"""
        return {
            "success": True,
            "technique_id": technique_id,
            "message": f"Generic technique {technique_id} executed with enhanced logging",
            "analysis": "Enhanced analysis would be implemented based on technique specifics"
        }
    
    def _analyze_technique_impact(self, pre_state: Dict, post_state: Dict, technique_id: str) -> Dict:
        """Analyze the impact of technique execution"""
        analysis = {
            "changes_detected": [],
            "new_processes": [],
            "new_files": [],
            "network_changes": [],
            "system_impact": "low"
        }
        
        # Compare process lists
        pre_processes = set(pre_state.get("processes", {}).get("output", "").split('\n'))
        post_processes = set(post_state.get("processes", {}).get("output", "").split('\n'))
        new_processes = post_processes - pre_processes
        
        if new_processes:
            analysis["new_processes"] = list(new_processes)
            analysis["changes_detected"].append(f"New processes detected: {len(new_processes)}")
        
        # Compare file system
        pre_files = set(pre_state.get("file_system", {}).get("output", "").split('\n'))
        post_files = set(post_state.get("file_system", {}).get("output", "").split('\n'))
        new_files = post_files - pre_files
        
        if new_files:
            analysis["new_files"] = list(new_files)
            analysis["changes_detected"].append(f"New files detected: {len(new_files)}")
        
        # Compare network connections
        pre_network = set(pre_state.get("network_connections", {}).get("output", "").split('\n'))
        post_network = set(post_state.get("network_connections", {}).get("output", "").split('\n'))
        new_connections = post_network - pre_network
        
        if new_connections:
            analysis["network_changes"] = list(new_connections)
            analysis["changes_detected"].append(f"New network connections: {len(new_connections)}")
        
        # Determine impact level
        if len(analysis["changes_detected"]) > 3:
            analysis["system_impact"] = "high"
        elif len(analysis["changes_detected"]) > 1:
            analysis["system_impact"] = "medium"
        
        return analysis
    
    def _detect_artifacts(self, technique_id: str) -> List[Dict]:
        """Detect artifacts created by technique execution"""
        artifacts = []
        
        # Check for files in work directory
        result = self.execute_command(f"find {self.remote_work_dir} -type f -exec ls -la {{}} +")
        if result["success"]:
            files = result["stdout"].strip().split('\n')
            for file_info in files:
                if file_info.strip():
                    artifacts.append({
                        "type": "file",
                        "location": file_info,
                        "technique": technique_id
                    })
        
        # Check for recent temporary files
        result = self.execute_command("find /tmp -type f -mmin -5 -exec ls -la {} +")
        if result["success"]:
            files = result["stdout"].strip().split('\n')
            for file_info in files:
                if file_info.strip() and "atomic" in file_info:
                    artifacts.append({
                        "type": "temporary_file",
                        "location": file_info,
                        "technique": technique_id
                    })
        
        return artifacts
    
    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive attack report"""
        self.attack_session["end_time"] = datetime.now().isoformat()
        self.attack_session["total_duration"] = (
            datetime.now() - datetime.fromisoformat(self.attack_session["start_time"])
        ).total_seconds()
        
        # Generate summary
        summary = {
            "attack_overview": {
                "target": self.attack_session["target"],
                "duration": self.attack_session["total_duration"],
                "techniques_executed": len(self.attack_session["phases"]),
                "successful_phases": len([p for p in self.attack_session["phases"] if p["execution_results"]["success"]]),
                "total_commands": len(self.attack_session["evidence"]),
                "artifacts_created": len(self.attack_session["artifacts"])
            },
            "phase_summary": [],
            "key_findings": [],
            "impact_assessment": {},
            "recommendations": []
        }
        
        # Phase summaries
        for phase in self.attack_session["phases"]:
            summary["phase_summary"].append({
                "technique": phase["technique_id"],
                "duration": phase.get("duration", 0),
                "success": phase["execution_results"]["success"],
                "changes_detected": len(phase.get("analysis", {}).get("changes_detected", [])),
                "system_impact": phase.get("analysis", {}).get("system_impact", "unknown")
            })
        
        # Key findings
        for phase in self.attack_session["phases"]:
            if "detailed_analysis" in phase["execution_results"]:
                analysis = phase["execution_results"]["detailed_analysis"]
                if "successful_exploits" in analysis:
                    for exploit in analysis["successful_exploits"]:
                        summary["key_findings"].append({
                            "type": "vulnerability",
                            "description": f"Exploitable vulnerability in {exploit['app']} on port {exploit['port']}",
                            "severity": "high"
                        })
        
        # Save report
        report_file = f"{self.remote_evidence_dir}/attack_report_{int(time.time())}.json"
        report_json = json.dumps({
            "summary": summary,
            "full_session": self.attack_session
        }, indent=2)
        self.execute_command(f"echo '{report_json}' > {report_file}")
        
        return {
            "summary": summary,
            "report_file": report_file,
            "evidence_directory": self.remote_evidence_dir
        }
    
    def cleanup_remote_files(self):
        """Clean up remote files with optional evidence preservation"""
        # Create evidence archive before cleanup
        archive_name = f"evidence_archive_{int(time.time())}.tar.gz"
        self.execute_command(f"cd {self.remote_work_dir} && tar -czf /tmp/{archive_name} evidence/")
        
        # Clean up work directory
        cleanup_commands = [f"rm -rf {self.remote_work_dir}"]
        for cmd in cleanup_commands:
            self.execute_command(cmd)
        
        self.logger.info(f"Evidence archived to: /tmp/{archive_name}")
    
    def disconnect(self):
        """Close SSH connection"""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
        self.logger.info("SSH connection closed")

class EnhancedVPLEConnection:
    """Enhanced context manager for VPLE SSH connections"""
    
    def __init__(self, hostname: str, username: str = "administrator", 
                 password: str = "password", port: int = 22):
        self.executor = EnhancedSSHExecutor(hostname, username, password, port)
    
    def __enter__(self):
        if self.executor.connect():
            return self.executor
        else:
            raise ConnectionError("Failed to connect to VPLE VM")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Generate final report
        report = self.executor.generate_comprehensive_report()
        print(f"\n📊 Comprehensive report generated: {report['report_file']}")
        
        self.executor.cleanup_remote_files()
        self.executor.disconnect()
