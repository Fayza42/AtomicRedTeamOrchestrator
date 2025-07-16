#!/usr/bin/env python3
"""
Attack Report Analyzer
Analyzes attack reports and generates research documentation
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime
import argparse
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict, Counter

class AttackReportAnalyzer:
    """Analyzes attack reports and generates research insights"""
    
    def __init__(self, report_file: str = None, log_file: str = None):
        self.report_file = report_file
        self.log_file = log_file
        self.report_data = None
        self.analysis_results = {}
        
    def load_report(self, report_file: str = None):
        """Load attack report from JSON file"""
        file_to_load = report_file or self.report_file
        
        if not file_to_load or not os.path.exists(file_to_load):
            print(f"❌ Report file not found: {file_to_load}")
            return False
        
        try:
            with open(file_to_load, 'r') as f:
                self.report_data = json.load(f)
            print(f"✅ Loaded report: {file_to_load}")
            return True
        except Exception as e:
            print(f"❌ Failed to load report: {e}")
            return False
    
    def analyze_attack_timeline(self) -> Dict:
        """Analyze attack execution timeline"""
        if not self.report_data:
            return {}
        
        timeline_analysis = {
            "phases": [],
            "total_duration": 0,
            "phase_durations": {},
            "command_distribution": {},
            "critical_events": []
        }
        
        full_session = self.report_data.get("full_session", {})
        phases = full_session.get("phases", [])
        
        # Analyze phase timings
        for phase in phases:
            technique_id = phase.get("technique_id", "Unknown")
            duration = phase.get("duration", 0)
            start_time = phase.get("start_time", "")
            
            phase_info = {
                "technique": technique_id,
                "duration": duration,
                "start_time": start_time,
                "success": phase.get("execution_results", {}).get("success", False),
                "changes": len(phase.get("analysis", {}).get("changes_detected", [])),
                "impact": phase.get("analysis", {}).get("system_impact", "unknown")
            }
            
            timeline_analysis["phases"].append(phase_info)
            timeline_analysis["phase_durations"][technique_id] = duration
        
        # Calculate total duration
        if phases:
            start_times = [p.get("start_time") for p in phases if p.get("start_time")]
            end_times = [p.get("end_time") for p in phases if p.get("end_time")]
            if start_times and end_times:
                timeline_analysis["total_duration"] = full_session.get("total_duration", 0)
        
        # Analyze command distribution
        evidence = full_session.get("evidence", [])
        command_counts = Counter()
        
        for event in evidence:
            if event.get("type") == "command_execution":
                command = event.get("details", {}).get("command", "")
                command_type = command.split()[0] if command else "unknown"
                command_counts[command_type] += 1
        
        timeline_analysis["command_distribution"] = dict(command_counts)
        
        return timeline_analysis
    
    def analyze_vulnerabilities_found(self) -> Dict:
        """Analyze vulnerabilities discovered during attack"""
        if not self.report_data:
            return {}
        
        vuln_analysis = {
            "total_vulnerabilities": 0,
            "vulnerability_types": {},
            "affected_applications": [],
            "severity_distribution": {},
            "exploitation_success": {}
        }
        
        full_session = self.report_data.get("full_session", {})
        phases = full_session.get("phases", [])
        
        for phase in phases:
            execution_results = phase.get("execution_results", {})
            detailed_analysis = execution_results.get("detailed_analysis", {})
            
            # Web exploitation phase analysis
            if "applications" in detailed_analysis:
                apps = detailed_analysis["applications"]
                
                for port, app_data in apps.items():
                    if app_data.get("accessibility") == "accessible":
                        app_info = {
                            "name": app_data.get("name", "Unknown"),
                            "port": port,
                            "technology": app_data.get("technology", "Unknown"),
                            "vulnerabilities": app_data.get("exploitation_results", [])
                        }
                        
                        vuln_analysis["affected_applications"].append(app_info)
                        
                        # Count vulnerability types
                        for vuln in app_data.get("exploitation_results", []):
                            vuln_type = vuln.get("vulnerability", "Unknown")
                            if vuln_type not in vuln_analysis["vulnerability_types"]:
                                vuln_analysis["vulnerability_types"][vuln_type] = 0
                            vuln_analysis["vulnerability_types"][vuln_type] += 1
                            vuln_analysis["total_vulnerabilities"] += 1
        
        # Analyze severity (simplified classification)
        for vuln_type, count in vuln_analysis["vulnerability_types"].items():
            if "SQL" in vuln_type:
                vuln_analysis["severity_distribution"]["Critical"] = vuln_analysis["severity_distribution"].get("Critical", 0) + count
            elif "XSS" in vuln_type:
                vuln_analysis["severity_distribution"]["High"] = vuln_analysis["severity_distribution"].get("High", 0) + count
            elif "Directory Traversal" in vuln_type:
                vuln_analysis["severity_distribution"]["High"] = vuln_analysis["severity_distribution"].get("High", 0) + count
            else:
                vuln_analysis["severity_distribution"]["Medium"] = vuln_analysis["severity_distribution"].get("Medium", 0) + count
        
        return vuln_analysis
    
    def analyze_system_impact(self) -> Dict:
        """Analyze overall system impact"""
        if not self.report_data:
            return {}
        
        impact_analysis = {
            "total_changes": 0,
            "change_types": {},
            "affected_areas": {},
            "persistence_mechanisms": [],
            "artifacts_created": [],
            "risk_assessment": "Low"
        }
        
        full_session = self.report_data.get("full_session", {})
        phases = full_session.get("phases", [])
        
        for phase in phases:
            analysis = phase.get("analysis", {})
            
            # Count changes
            changes = analysis.get("changes_detected", [])
            impact_analysis["total_changes"] += len(changes)
            
            # Categorize changes
            for change in changes:
                if "process" in change.lower():
                    impact_analysis["change_types"]["Process"] = impact_analysis["change_types"].get("Process", 0) + 1
                elif "file" in change.lower():
                    impact_analysis["change_types"]["File System"] = impact_analysis["change_types"].get("File System", 0) + 1
                elif "network" in change.lower():
                    impact_analysis["change_types"]["Network"] = impact_analysis["change_types"].get("Network", 0) + 1
                else:
                    impact_analysis["change_types"]["Other"] = impact_analysis["change_types"].get("Other", 0) + 1
            
            # Track artifacts
            artifacts = phase.get("artifacts_created", [])
            for artifact in artifacts:
                impact_analysis["artifacts_created"].append({
                    "technique": phase.get("technique_id"),
                    "type": artifact.get("type"),
                    "location": artifact.get("location")
                })
            
            # Assess impact level
            system_impact = analysis.get("system_impact", "low")
            if system_impact == "high":
                impact_analysis["risk_assessment"] = "High"
            elif system_impact == "medium" and impact_analysis["risk_assessment"] != "High":
                impact_analysis["risk_assessment"] = "Medium"
        
        return impact_analysis
    
    def analyze_privilege_escalation(self) -> Dict:
        """Analyze privilege escalation attempts and success"""
        if not self.report_data:
            return {}
        
        privesc_analysis = {
            "vectors_identified": [],
            "suid_binaries": [],
            "sudo_access": "Unknown",
            "potential_exploits": [],
            "current_privileges": "Unknown"
        }
        
        full_session = self.report_data.get("full_session", {})
        phases = full_session.get("phases", [])
        
        for phase in phases:
            if phase.get("technique_id", "").startswith("T1548"):
                execution_results = phase.get("execution_results", {})
                detailed_analysis = execution_results.get("detailed_analysis", {})
                findings = execution_results.get("findings", {})
                
                # Extract privilege information
                current_user = execution_results.get("summary", {}).get("current_user", "Unknown")
                privesc_analysis["current_privileges"] = current_user
                
                # Extract SUID binaries
                privilege_vectors = detailed_analysis.get("privilege_vectors", {})
                suid_output = privilege_vectors.get("suid_files", {}).get("output", "")
                if suid_output:
                    privesc_analysis["suid_binaries"] = [
                        line.strip() for line in suid_output.split('\\n') 
                        if line.strip() and '/bin/' in line
                    ][:10]  # Limit to first 10
                
                # Extract sudo information
                sudo_output = detailed_analysis.get("current_user", {}).get("sudo_check", {}).get("output", "")
                if "NOPASSWD" in sudo_output:
                    privesc_analysis["sudo_access"] = "Passwordless sudo available"
                elif "may run" in sudo_output:
                    privesc_analysis["sudo_access"] = "Limited sudo access"
                else:
                    privesc_analysis["sudo_access"] = "No sudo access detected"
                
                # Extract potential vectors
                potential_vectors = findings.get("potential_vectors", [])
                privesc_analysis["vectors_identified"] = potential_vectors
        
        return privesc_analysis
    
    def generate_research_insights(self) -> Dict:
        """Generate research insights from attack data"""
        if not self.report_data:
            return {}
        
        insights = {
            "attack_effectiveness": {},
            "defensive_gaps": [],
            "technique_success_rates": {},
            "time_to_compromise": {},
            "recommendations": []
        }
        
        # Analyze technique success rates
        full_session = self.report_data.get("full_session", {})
        phases = full_session.get("phases", [])
        
        technique_stats = {}
        for phase in phases:
            technique = phase.get("technique_id", "Unknown")
            success = phase.get("execution_results", {}).get("success", False)
            duration = phase.get("duration", 0)
            
            if technique not in technique_stats:
                technique_stats[technique] = {"attempts": 0, "successes": 0, "total_time": 0}
            
            technique_stats[technique]["attempts"] += 1
            if success:
                technique_stats[technique]["successes"] += 1
            technique_stats[technique]["total_time"] += duration
        
        # Calculate success rates
        for technique, stats in technique_stats.items():
            success_rate = (stats["successes"] / stats["attempts"]) * 100 if stats["attempts"] > 0 else 0
            avg_time = stats["total_time"] / stats["attempts"] if stats["attempts"] > 0 else 0
            
            insights["technique_success_rates"][technique] = {
                "success_rate": success_rate,
                "average_time": avg_time,
                "attempts": stats["attempts"]
            }
        
        # Analyze defensive gaps
        vuln_analysis = self.analyze_vulnerabilities_found()
        if vuln_analysis["total_vulnerabilities"] > 0:
            insights["defensive_gaps"].append("Multiple web application vulnerabilities present")
        
        impact_analysis = self.analyze_system_impact()
        if impact_analysis["risk_assessment"] == "High":
            insights["defensive_gaps"].append("High system impact achieved")
        
        privesc_analysis = self.analyze_privilege_escalation()
        if privesc_analysis["vectors_identified"]:
            insights["defensive_gaps"].append("Privilege escalation vectors available")
        
        # Generate recommendations
        if vuln_analysis["total_vulnerabilities"] > 5:
            insights["recommendations"].append("Implement web application security scanning and remediation")
        
        if len(privesc_analysis["suid_binaries"]) > 10:
            insights["recommendations"].append("Review and minimize SUID binary permissions")
        
        if impact_analysis["total_changes"] > 10:
            insights["recommendations"].append("Implement comprehensive system monitoring")
        
        return insights
    
    def create_summary_report(self) -> str:
        """Create a comprehensive summary report"""
        if not self.report_data:
            return "No report data available"
        
        # Perform all analyses
        timeline = self.analyze_attack_timeline()
        vulnerabilities = self.analyze_vulnerabilities_found()
        impact = self.analyze_system_impact()
        privesc = self.analyze_privilege_escalation()
        insights = self.generate_research_insights()
        
        # Generate summary report
        summary = f"""
═══════════════════════════════════════════════════════════════
                    ATTACK ANALYSIS SUMMARY REPORT
═══════════════════════════════════════════════════════════════

📊 ATTACK OVERVIEW:
─────────────────────────────────────────────────────────────
• Target: {self.report_data.get('full_session', {}).get('target', 'Unknown')}
• Attack Duration: {timeline.get('total_duration', 0):.2f} seconds
• Phases Executed: {len(timeline.get('phases', []))}
• Total Commands: {len(self.report_data.get('full_session', {}).get('evidence', []))}
• Total System Changes: {impact.get('total_changes', 0)}

🌐 WEB APPLICATION ANALYSIS:
─────────────────────────────────────────────────────────────
• Total Vulnerabilities Found: {vulnerabilities.get('total_vulnerabilities', 0)}
• Affected Applications: {len(vulnerabilities.get('affected_applications', []))}
• Vulnerability Types: {', '.join(vulnerabilities.get('vulnerability_types', {}).keys())}

⬆️ PRIVILEGE ESCALATION ANALYSIS:
─────────────────────────────────────────────────────────────
• Current Privileges: {privesc.get('current_privileges', 'Unknown')}
• SUID Binaries Found: {len(privesc.get('suid_binaries', []))}
• Sudo Access: {privesc.get('sudo_access', 'Unknown')}
• Escalation Vectors: {len(privesc.get('vectors_identified', []))}

📈 SYSTEM IMPACT ANALYSIS:
─────────────────────────────────────────────────────────────
• Risk Assessment: {impact.get('risk_assessment', 'Unknown')}
• Change Categories: {', '.join(impact.get('change_types', {}).keys())}
• Artifacts Created: {len(impact.get('artifacts_created', []))}

🔍 RESEARCH INSIGHTS:
─────────────────────────────────────────────────────────────
• Defensive Gaps Identified: {len(insights.get('defensive_gaps', []))}
• Recommendations Generated: {len(insights.get('recommendations', []))}

🎯 TECHNIQUE SUCCESS RATES:
─────────────────────────────────────────────────────────────"""
        
        # Add technique success rates
        for technique, stats in insights.get('technique_success_rates', {}).items():
            summary += f"\\n• {technique}: {stats['success_rate']:.1f}% success rate ({stats['average_time']:.2f}s avg)"
        
        # Add detailed findings
        if vulnerabilities.get('vulnerability_types'):
            summary += "\\n\\n🚨 VULNERABILITIES DISCOVERED:\\n─────────────────────────────────────────────────────────────"
            for vuln_type, count in vulnerabilities['vulnerability_types'].items():
                summary += f"\\n• {vuln_type}: {count} instances"
        
        if privesc.get('vectors_identified'):
            summary += "\\n\\n⚠️ PRIVILEGE ESCALATION VECTORS:\\n─────────────────────────────────────────────────────────────"
            for vector in privesc['vectors_identified']:
                summary += f"\\n• {vector}"
        
        if insights.get('recommendations'):
            summary += "\\n\\n💡 SECURITY RECOMMENDATIONS:\\n─────────────────────────────────────────────────────────────"
            for rec in insights['recommendations']:
                summary += f"\\n• {rec}"
        
        summary += "\\n\\n═══════════════════════════════════════════════════════════════"
        
        return summary
    
    def export_to_markdown(self, output_file: str = None):
        """Export analysis to markdown format"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"attack_analysis_{timestamp}.md"
        
        summary = self.create_summary_report()
        
        # Convert to markdown format
        markdown_content = summary.replace('═', '=').replace('─', '-')
        markdown_content = f"# Attack Analysis Report\\n\\n{markdown_content}"
        
        try:
            with open(output_file, 'w') as f:
                f.write(markdown_content)
            print(f"✅ Markdown report exported: {output_file}")
            return output_file
        except Exception as e:
            print(f"❌ Failed to export markdown: {e}")
            return None

def find_latest_report(directory: str = ".") -> str:
    """Find the latest attack report in directory"""
    report_files = list(Path(directory).glob("*attack_report_*.json"))
    if not report_files:
        return None
    
    # Sort by modification time, newest first
    latest_file = max(report_files, key=lambda f: f.stat().st_mtime)
    return str(latest_file)

def main():
    parser = argparse.ArgumentParser(description="Analyze attack reports for research documentation")
    parser.add_argument("--report", help="Attack report JSON file path")
    parser.add_argument("--auto", action="store_true", help="Automatically find latest report")
    parser.add_argument("--output", help="Output file for markdown report")
    parser.add_argument("--summary", action="store_true", help="Show summary only")
    
    args = parser.parse_args()
    
    # Find report file
    report_file = args.report
    if args.auto or not report_file:
        report_file = find_latest_report()
        if not report_file:
            print("❌ No attack report files found")
            sys.exit(1)
        print(f"📁 Using latest report: {report_file}")
    
    # Initialize analyzer
    analyzer = AttackReportAnalyzer(report_file)
    
    if not analyzer.load_report():
        sys.exit(1)
    
    # Generate and display summary
    summary = analyzer.create_summary_report()
    print(summary)
    
    # Export to markdown if requested
    if not args.summary:
        output_file = analyzer.export_to_markdown(args.output)
        if output_file:
            print(f"\\n📄 Full analysis available in: {output_file}")

if __name__ == "__main__":
    main()
