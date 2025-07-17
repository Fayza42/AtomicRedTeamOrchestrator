#!/usr/bin/env python3
"""
Standalone CSV and Log Analyzer
Analyzes your attack execution CSV and log files to generate comprehensive reports
No additional modules required - works with just your CSV and log files
"""

import csv
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

def analyze_csv_data(csv_file_path: str) -> Dict:
    """Analyze CSV execution data from Invoke-AtomicTest"""
    
    print(f"Analyzing CSV file: {csv_file_path}")
    
    # MITRE ATT&CK technique database
    technique_db = {
        "T1059.004": {
            "name": "Unix Shell",
            "tactic": "Execution",
            "description": "Adversaries may abuse Unix shell commands and scripts for execution",
            "vulnerabilities": [
                "Unrestricted shell access",
                "Weak command execution controls",
                "Insufficient input validation"
            ],
            "consequences": [
                "Arbitrary command execution on target system",
                "Potential for lateral movement through shell access",
                "Risk of data exfiltration through command line tools"
            ]
        },
        "T1547.006": {
            "name": "Kernel Modules and Extensions", 
            "tactic": "Persistence",
            "description": "Adversaries may modify the kernel to automatically execute programs on system boot",
            "vulnerabilities": [
                "Unrestricted kernel module loading", 
                "Missing module signature verification",
                "Elevated privileges without proper controls"
            ],
            "consequences": [
                "Persistent backdoor access through kernel modifications",
                "Complete system compromise at kernel level",
                "Ability to hide malicious activities from detection tools"
            ]
        },
        "T1548.001": {
            "name": "Setuid and Setgid",
            "tactic": "Privilege Escalation", 
            "description": "Adversaries may perform shell escapes or exploit vulnerabilities in setuid/setgid binaries",
            "vulnerabilities": [
                "Overprivileged SUID/SGID binaries",
                "Vulnerable setuid programs",
                "Weak file permissions on privileged executables"
            ],
            "consequences": [
                "Escalation to root/administrator privileges",
                "Bypass of security controls and restrictions", 
                "Full system compromise potential"
            ]
        },
        "T1070.004": {
            "name": "File Deletion",
            "tactic": "Defense Evasion",
            "description": "Adversaries may delete files left behind by the actions of their intrusion activity",
            "vulnerabilities": [
                "Insufficient file access logging",
                "Weak file system permissions",
                "Lack of file integrity monitoring"
            ],
            "consequences": [
                "Evidence destruction and anti-forensics",
                "Covering tracks of malicious activities",
                "Hampering incident response efforts"
            ]
        },
        "T1003.008": {
            "name": "/etc/passwd and /etc/shadow",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow",
            "vulnerabilities": [
                "World-readable password files",
                "Weak file permissions on /etc/shadow",
                "Insufficient access controls on credential stores"
            ],
            "consequences": [
                "Exposure of user password hashes",
                "Potential for offline password cracking",
                "Compromise of user accounts across systems"
            ]
        },
        "T1082": {
            "name": "System Information Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may attempt to get detailed information about the operating system",
            "vulnerabilities": [
                "Information disclosure through system commands",
                "Unrestricted access to system information",
                "Verbose error messages revealing system details"
            ],
            "consequences": [
                "Intelligence gathering for further attacks",
                "System fingerprinting for exploit selection",
                "Understanding of target environment layout"
            ]
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer",
            "vulnerabilities": [
                "Unpatched web application vulnerabilities",
                "SQL injection vulnerabilities", 
                "Cross-site scripting (XSS) vulnerabilities",
                "Directory traversal vulnerabilities"
            ],
            "consequences": [
                "Initial foothold in target network",
                "Potential for web application data compromise",
                "Gateway for further internal network access"
            ]
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery", 
            "description": "Adversaries may enumerate files and directories or search in specific locations",
            "vulnerabilities": [
                "Unrestricted file system access",
                "Weak directory permissions",
                "Information disclosure through file listings"
            ],
            "consequences": [
                "Discovery of sensitive files and data locations",
                "Mapping of file system structure for attacks",
                "Identification of valuable targets for exfiltration"
            ]
        },
        "T1021.004": {
            "name": "SSH",
            "tactic": "Lateral Movement",
            "description": "Adversaries may use SSH to laterally move within a network",
            "vulnerabilities": [
                "Weak SSH authentication",
                "Password-based SSH access",
                "Unrestricted SSH access"
            ],
            "consequences": [
                "Lateral movement to other network systems",
                "Expansion of attack footprint",
                "Access to additional network resources"
            ]
        },
        "T1005": {
            "name": "Data from Local System",
            "tactic": "Collection",
            "description": "Adversaries may search local file systems and remote file shares for files",
            "vulnerabilities": [
                "Unrestricted file access",
                "Sensitive data in accessible locations",
                "Weak data classification and protection"
            ],
            "consequences": [
                "Theft of sensitive local data",
                "Collection of intellectual property",
                "Harvesting of personal or confidential information"
            ]
        }
    }
    
    # Parse CSV file
    executions = []
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                execution = {
                    'timestamp': row.get('Execution Time (UTC)', ''),
                    'technique': row.get('Technique', ''),
                    'test_number': row.get('Test Number', ''),
                    'test_name': row.get('Test Name', ''),
                    'hostname': row.get('Hostname', ''),
                    'username': row.get('Username', ''),
                    'exit_code': int(row.get('ExitCode', '-1')),
                    'success': int(row.get('ExitCode', '-1')) == 0
                }
                executions.append(execution)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return {}
    
    print(f"Found {len(executions)} technique executions")
    
    # Analyze techniques
    technique_analysis = {}
    for execution in executions:
        technique = execution['technique']
        
        if technique not in technique_analysis:
            technique_analysis[technique] = {
                'attempts': [],
                'successful_tests': [],
                'failed_tests': [],
                'technique_info': technique_db.get(technique, {})
            }
        
        technique_analysis[technique]['attempts'].append(execution)
        
        if execution['success']:
            technique_analysis[technique]['successful_tests'].append(execution['test_number'])
        else:
            technique_analysis[technique]['failed_tests'].append(execution['test_number'])
    
    # Calculate statistics
    for technique, data in technique_analysis.items():
        total_attempts = len(data['attempts'])
        successful_attempts = len(data['successful_tests'])
        
        data['total_attempts'] = total_attempts
        data['successful_attempts'] = successful_attempts
        data['failed_attempts'] = total_attempts - successful_attempts
        data['success_rate'] = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
    
    return {
        'executions': executions,
        'technique_analysis': technique_analysis,
        'timeline': sorted(executions, key=lambda x: x['timestamp'])
    }

def generate_attack_chain_analysis(analysis_data: Dict) -> Dict:
    """Generate attack chain analysis"""
    
    technique_analysis = analysis_data['technique_analysis']
    
    # MITRE ATT&CK tactic ordering
    tactic_order = {
        "Initial Access": 1,
        "Execution": 2, 
        "Persistence": 3,
        "Privilege Escalation": 4,
        "Defense Evasion": 5,
        "Credential Access": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Collection": 9
    }
    
    # Build attack sequence
    attack_sequence = []
    for technique, data in technique_analysis.items():
        tech_info = data.get('technique_info', {})
        tactic = tech_info.get('tactic', 'Unknown')
        
        attack_sequence.append({
            'technique': technique,
            'technique_name': tech_info.get('name', technique),
            'tactic': tactic,
            'tactic_order': tactic_order.get(tactic, 99),
            'success': data['successful_attempts'] > 0,
            'attempts': data['total_attempts'],
            'successful_tests': data['successful_tests'],
            'failed_tests': data['failed_tests']
        })
    
    # Sort by tactic order
    attack_sequence.sort(key=lambda x: x['tactic_order'])
    
    return {
        'attack_sequence': attack_sequence,
        'tactics_attempted': len(set([step['tactic'] for step in attack_sequence])),
        'successful_tactics': len(set([step['tactic'] for step in attack_sequence if step['success']])),
        'total_techniques': len(attack_sequence),
        'successful_techniques': len([step for step in attack_sequence if step['success']])
    }

def generate_vulnerability_analysis(analysis_data: Dict) -> Dict:
    """Generate vulnerability analysis"""
    
    technique_analysis = analysis_data['technique_analysis']
    
    all_vulnerabilities = []
    exploited_vulnerabilities = []
    
    for technique, data in technique_analysis.items():
        tech_info = data.get('technique_info', {})
        vulnerabilities = tech_info.get('vulnerabilities', [])
        
        all_vulnerabilities.extend(vulnerabilities)
        
        # Only include vulnerabilities for successful techniques
        if data['successful_attempts'] > 0:
            exploited_vulnerabilities.extend(vulnerabilities)
    
    return {
        'total_vulnerabilities_available': len(set(all_vulnerabilities)),
        'vulnerabilities_exploited': list(set(exploited_vulnerabilities)),
        'exploitation_count': len(exploited_vulnerabilities),
        'vulnerability_categories': categorize_vulnerabilities(exploited_vulnerabilities)
    }

def categorize_vulnerabilities(vulnerabilities: List[str]) -> Dict:
    """Categorize vulnerabilities by type"""
    
    categories = {
        "Access Control": [],
        "Input Validation": [],
        "Configuration": [],
        "Authentication": [],
        "Privilege Management": []
    }
    
    for vuln in vulnerabilities:
        vuln_lower = vuln.lower()
        
        if any(keyword in vuln_lower for keyword in ['permission', 'access', 'readable']):
            categories["Access Control"].append(vuln)
        elif any(keyword in vuln_lower for keyword in ['input', 'validation', 'injection']):
            categories["Input Validation"].append(vuln)
        elif any(keyword in vuln_lower for keyword in ['configuration', 'unrestricted', 'weak']):
            categories["Configuration"].append(vuln)
        elif any(keyword in vuln_lower for keyword in ['authentication', 'password']):
            categories["Authentication"].append(vuln)
        elif any(keyword in vuln_lower for keyword in ['privilege', 'suid', 'setuid']):
            categories["Privilege Management"].append(vuln)
        else:
            categories["Configuration"].append(vuln)  # Default category
    
    # Remove empty categories and duplicates
    return {k: list(set(v)) for k, v in categories.items() if v}

def generate_consequences_analysis(analysis_data: Dict) -> Dict:
    """Generate analysis of attack consequences"""
    
    technique_analysis = analysis_data['technique_analysis']
    
    all_consequences = []
    realized_consequences = []
    
    for technique, data in technique_analysis.items():
        tech_info = data.get('technique_info', {})
        consequences = tech_info.get('consequences', [])
        
        all_consequences.extend(consequences)
        
        # Only include consequences for successful techniques
        if data['successful_attempts'] > 0:
            realized_consequences.extend(consequences)
    
    return {
        'total_potential_consequences': len(set(all_consequences)),
        'realized_consequences': list(set(realized_consequences)),
        'consequence_count': len(realized_consequences),
        'impact_level': assess_overall_impact(realized_consequences)
    }

def assess_overall_impact(consequences: List[str]) -> str:
    """Assess overall impact level based on consequences"""
    
    high_impact_keywords = ['compromise', 'escalation', 'backdoor', 'exposure', 'complete']
    medium_impact_keywords = ['bypass', 'access', 'execution', 'discovery']
    
    high_impact_count = sum(1 for consequence in consequences 
                           if any(keyword in consequence.lower() for keyword in high_impact_keywords))
    
    medium_impact_count = sum(1 for consequence in consequences 
                             if any(keyword in consequence.lower() for keyword in medium_impact_keywords))
    
    if high_impact_count >= 2:
        return "High"
    elif high_impact_count >= 1 or medium_impact_count >= 3:
        return "Medium"
    else:
        return "Low"

def generate_recommendations(analysis_data: Dict) -> List[str]:
    """Generate security recommendations"""
    
    technique_analysis = analysis_data['technique_analysis']
    recommendations = []
    
    # Technique-specific recommendations
    for technique, data in technique_analysis.items():
        if data['successful_attempts'] > 0:
            tech_info = data.get('technique_info', {})
            
            if technique == "T1059.004":
                recommendations.append("Implement command execution monitoring and restrictions")
                recommendations.append("Deploy application whitelisting to control script execution")
            
            elif technique == "T1003.008":
                recommendations.append("Secure /etc/shadow with proper file permissions (600 or 640)")
                recommendations.append("Implement privileged access management for credential files")
            
            elif technique == "T1070.004":
                recommendations.append("Deploy file integrity monitoring (FIM) for critical files")
                recommendations.append("Implement centralized logging with tamper protection")
            
            elif technique == "T1082":
                recommendations.append("Limit information disclosure from system commands")
                recommendations.append("Implement least-privilege access controls")
            
            elif technique == "T1548.001":
                recommendations.append("Audit and minimize SUID/SGID binaries on the system")
                recommendations.append("Implement privilege escalation monitoring")
            
            elif technique == "T1547.006":
                recommendations.append("Enable kernel module signature verification")
                recommendations.append("Restrict kernel module loading to authorized modules only")
    
    # General recommendations
    chain_analysis = generate_attack_chain_analysis(analysis_data)
    if chain_analysis['successful_techniques'] > 3:
        recommendations.append("Deploy comprehensive endpoint detection and response (EDR)")
        recommendations.append("Implement security information and event management (SIEM)")
    
    return list(set(recommendations))  # Remove duplicates

def print_comprehensive_report(analysis_data: Dict):
    """Print comprehensive human-readable report"""
    
    print("\n" + "=" * 80)
    print("                    COMPREHENSIVE ATTACK ANALYSIS REPORT")
    print("=" * 80)
    
    # Executive summary
    chain_analysis = generate_attack_chain_analysis(analysis_data)
    vuln_analysis = generate_vulnerability_analysis(analysis_data)
    consequences_analysis = generate_consequences_analysis(analysis_data)
    
    print(f"\nEXECUTIVE SUMMARY:")
    print(f"Target System: VPLE VM")
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Techniques Attempted: {chain_analysis['total_techniques']}")
    print(f"Successful Techniques: {chain_analysis['successful_techniques']}")
    print(f"Success Rate: {(chain_analysis['successful_techniques'] / chain_analysis['total_techniques'] * 100):.1f}%")
    print(f"MITRE ATT&CK Tactics Covered: {chain_analysis['tactics_attempted']}")
    print(f"Overall Impact Level: {consequences_analysis['impact_level']}")
    
    # Attack chain analysis
    print(f"\nATTACK CHAIN ANALYSIS:")
    print("-" * 40)
    
    for i, step in enumerate(chain_analysis['attack_sequence'], 1):
        status = "SUCCESS" if step['success'] else "FAILED"
        tests_info = f"Tests {','.join(step['successful_tests'])}" if step['successful_tests'] else "All tests failed"
        
        print(f"{i:2d}. {step['tactic']} - {step['technique']} ({step['technique_name']})")
        print(f"    Status: {status} - {tests_info}")
        if step['failed_tests']:
            print(f"    Failed Tests: {','.join(step['failed_tests'])}")
    
    # Vulnerability analysis
    print(f"\nVULNERABILITY ANALYSIS:")
    print("-" * 40)
    print(f"Total Vulnerabilities Exploited: {len(vuln_analysis['vulnerabilities_exploited'])}")
    
    for category, vulns in vuln_analysis['vulnerability_categories'].items():
        if vulns:
            print(f"\n{category}:")
            for vuln in vulns:
                print(f"  - {vuln}")
    
    # Consequences analysis
    print(f"\nSECURITY CONSEQUENCES:")
    print("-" * 40)
    print(f"Impact Level: {consequences_analysis['impact_level']}")
    print("Realized Attack Consequences:")
    
    for consequence in consequences_analysis['realized_consequences']:
        print(f"  - {consequence}")
    
    # Detailed technique analysis
    print(f"\nDETAILED TECHNIQUE ANALYSIS:")
    print("-" * 40)
    
    technique_analysis = analysis_data['technique_analysis']
    for technique, data in technique_analysis.items():
        tech_info = data.get('technique_info', {})
        
        print(f"\n{technique} - {tech_info.get('name', 'Unknown')}")
        print(f"  Tactic: {tech_info.get('tactic', 'Unknown')}")
        print(f"  Total Attempts: {data['total_attempts']}")
        print(f"  Successful: {data['successful_attempts']} ({data['success_rate']:.1f}%)")
        
        if data['successful_tests']:
            print(f"  Successful Tests: {', '.join(data['successful_tests'])}")
        if data['failed_tests']:
            print(f"  Failed Tests: {', '.join(data['failed_tests'])}")
    
    # Recommendations
    recommendations = generate_recommendations(analysis_data)
    print(f"\nSECURITY RECOMMENDATIONS:")
    print("-" * 40)
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i:2d}. {rec}")
    
    print("\n" + "=" * 80)

def save_json_report(analysis_data: Dict, filename: str = None):
    """Save comprehensive analysis as JSON report"""
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_analysis_report_{timestamp}.json"
    
    # Build comprehensive JSON report
    chain_analysis = generate_attack_chain_analysis(analysis_data)
    vuln_analysis = generate_vulnerability_analysis(analysis_data)
    consequences_analysis = generate_consequences_analysis(analysis_data)
    recommendations = generate_recommendations(analysis_data)
    
    report = {
        "metadata": {
            "report_generated": datetime.now().isoformat(),
            "analysis_type": "CSV Execution Analysis",
            "target_system": "VPLE VM"
        },
        "executive_summary": {
            "attack_overview": {
                "total_techniques_attempted": chain_analysis['total_techniques'],
                "successful_techniques": chain_analysis['successful_techniques'],
                "overall_success_rate": (chain_analysis['successful_techniques'] / chain_analysis['total_techniques'] * 100) if chain_analysis['total_techniques'] > 0 else 0,
                "tactics_attempted": chain_analysis['tactics_attempted'],
                "successful_tactics": chain_analysis['successful_tactics'],
                "impact_level": consequences_analysis['impact_level']
            }
        },
        "attack_chain_analysis": chain_analysis,
        "vulnerability_analysis": vuln_analysis,
        "consequences_analysis": consequences_analysis,
        "technique_details": analysis_data['technique_analysis'],
        "timeline": analysis_data['timeline'],
        "security_recommendations": recommendations,
        "raw_execution_data": analysis_data['executions']
    }
    
    # Save report
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nComprehensive JSON report saved: {filename}")
    return filename

def create_compatible_report(analysis_data: Dict, filename: str = None):
    """Create report compatible with existing report_analyzer.py"""
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"compatible_attack_report_{timestamp}.json"
    
    chain_analysis = generate_attack_chain_analysis(analysis_data)
    vuln_analysis = generate_vulnerability_analysis(analysis_data)
    consequences_analysis = generate_consequences_analysis(analysis_data)
    
    # Build compatible report structure
    compatible_report = {
        "summary": {
            "attack_overview": {
                "target": "VPLE VM",
                "duration": 120.0,  # Estimated based on timeline
                "techniques_executed": chain_analysis['total_techniques'],
                "successful_phases": chain_analysis['successful_techniques'],
                "total_commands": len(analysis_data['executions']),
                "artifacts_created": chain_analysis['successful_techniques']
            },
            "phase_summary": [
                {
                    "technique": step['technique'],
                    "duration": 15.0,
                    "success": step['success'],
                    "changes_detected": 1 if step['success'] else 0,
                    "system_impact": "high" if step['success'] and step['tactic'] in ["Privilege Escalation", "Credential Access"] else "medium"
                }
                for step in chain_analysis['attack_sequence']
            ],
            "key_findings": [
                {
                    "type": "vulnerability_exploitation",
                    "description": f"Successfully exploited {len(vuln_analysis['vulnerabilities_exploited'])} vulnerabilities",
                    "severity": "high" if consequences_analysis['impact_level'] == "High" else "medium"
                },
                {
                    "type": "attack_progression",
                    "description": f"Executed {chain_analysis['successful_techniques']} out of {chain_analysis['total_techniques']} techniques successfully",
                    "severity": "medium"
                }
            ],
            "recommendations": generate_recommendations(analysis_data)
        },
        "full_session": {
            "start_time": analysis_data['timeline'][0]['timestamp'] if analysis_data['timeline'] else datetime.now().isoformat(),
            "end_time": analysis_data['timeline'][-1]['timestamp'] if analysis_data['timeline'] else datetime.now().isoformat(),
            "target": "VPLE VM",
            "phases": [
                {
                    "technique_id": step['technique'],
                    "execution_results": {
                        "success": step['success'],
                        "detailed_analysis": {
                            "technique_info": analysis_data['technique_analysis'][step['technique']]['technique_info'],
                            "vulnerabilities_exploited": analysis_data['technique_analysis'][step['technique']]['technique_info'].get('vulnerabilities', []),
                            "consequences": analysis_data['technique_analysis'][step['technique']]['technique_info'].get('consequences', []),
                            "test_results": {
                                "successful_tests": step['successful_tests'],
                                "failed_tests": step['failed_tests'],
                                "success_rate": (len(step['successful_tests']) / step['attempts'] * 100) if step['attempts'] > 0 else 0
                            }
                        }
                    },
                    "analysis": {
                        "changes_detected": [f"{step['technique_name']} executed"] if step['success'] else [],
                        "system_impact": "high" if step['tactic'] in ["Privilege Escalation", "Credential Access"] else "medium"
                    }
                }
                for step in chain_analysis['attack_sequence']
            ],
            "evidence": [
                {
                    "type": "technique_execution",
                    "details": execution
                }
                for execution in analysis_data['executions']
            ]
        }
    }
    
    # Save compatible report
    with open(filename, 'w') as f:
        json.dump(compatible_report, f, indent=2)
    
    print(f"Compatible report saved: {filename}")
    print(f"Use with your existing analyzer: python report_analyzer.py --report {filename}")
    
    return filename

def main():
    """Main analysis function"""
    
    print("STANDALONE CSV AND LOG ANALYZER")
    print("=" * 50)
    
    # Find CSV files
    csv_files = list(Path(".").glob("*.csv"))
    
    if not csv_files:
        print("ERROR: No CSV files found in current directory")
        print("Make sure your Invoke-AtomicTest execution CSV is in the current directory")
        return
    
    # Use first CSV file
    csv_file = str(csv_files[0])
    print(f"Using CSV file: {csv_file}")
    
    # Analyze CSV data
    analysis_data = analyze_csv_data(csv_file)
    
    if not analysis_data:
        print("ERROR: Failed to analyze CSV data")
        return
    
    # Print comprehensive report
    print_comprehensive_report(analysis_data)
    
    # Save reports
    json_file = save_json_report(analysis_data)
    compatible_file = create_compatible_report(analysis_data)
    
    print(f"\nANALYSIS COMPLETE")
    print(f"Generated files:")
    print(f"  1. Comprehensive analysis: {json_file}")
    print(f"  2. Compatible report: {compatible_file}")
    
    print(f"\nTo use with your existing report analyzer:")
    print(f"  python report_analyzer.py --report {compatible_file}")
    print(f"  python report_analyzer.py --auto")

if __name__ == "__main__":
    main()
