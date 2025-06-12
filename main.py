#!/usr/bin/env python3
"""
Atomic Red Team Attack Orchestrator
Main entry point for intelligent attack automation
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
import time

# Rich for better terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
    from rich.syntax import Syntax
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("Install 'rich' for better output: pip install rich")

# Import our core modules
from core.technique_parser import TechniqueParser
from core.categorizer import AttackCategorizer
from core.dependency_mapper import DependencyMapper
from core.chain_builder import AttackChainBuilder, AttackObjective

class AtomicOrchestrator:
    """
    Main orchestrator for Atomic Red Team attack automation
    """
    
    def __init__(self, atomics_path: str, output_dir: str = "./output"):
        self.atomics_path = Path(atomics_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize console
        self.console = Console() if HAS_RICH else None
        
        # Initialize components
        self.parser = TechniqueParser(atomics_path)
        self.categorizer = AttackCategorizer()
        self.dependency_mapper = DependencyMapper()
        self.chain_builder = None  # Will be initialized after parsing
        
        # Data storage
        self.techniques = {}
        self.categorized_techniques = {}
        self.dependency_graph = None
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_file = self.output_dir / "orchestrator.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def initialize(self) -> bool:
        """Initialize the orchestrator by parsing techniques"""
        try:
            self._print_header("Initializing Atomic Red Team Orchestrator")
            
            # Parse techniques
            self._print_status("Parsing atomic techniques...")
            self.techniques = self.parser.parse_all_techniques()
            
            if not self.techniques:
                self._print_error("No techniques found. Check atomics path.")
                return False
            
            self._print_success(f"Parsed {len(self.techniques)} techniques")
            
            # Categorize techniques
            self._print_status("Categorizing techniques...")
            self.categorized_techniques = self.categorizer.categorize_techniques(self.techniques)
            
            # Build dependency graph
            self._print_status("Building dependency graph...")
            self.dependency_graph = self.dependency_mapper.build_dependency_graph(self.techniques)
            
            # Initialize chain builder
            self.chain_builder = AttackChainBuilder(self.dependency_mapper, self.categorizer)
            
            self._print_success("Initialization complete!")
            return True
            
        except Exception as e:
            self._print_error(f"Initialization failed: {e}")
            self.logger.exception("Initialization error")
            return False
    
    def analyze_target(self, platform: str = "windows") -> Dict[str, Any]:
        """Analyze available techniques for target platform"""
        platform_techniques = self.categorizer.filter_by_platform(
            self.categorized_techniques, platform
        )
        
        summary = self.categorizer.get_category_summary(platform_techniques)
        
        # Create analysis report
        analysis = {
            "platform": platform,
            "total_techniques": sum(cat["technique_count"] for cat in summary.values()),
            "categories": summary,
            "attack_surface": self._assess_attack_surface(platform_techniques),
            "recommended_chains": self._get_recommended_chains(platform)
        }
        
        return analysis
    
    def _assess_attack_surface(self, platform_techniques: Dict) -> Dict[str, Any]:
        """Assess attack surface for the target"""
        surface = {
            "initial_access_vectors": len(platform_techniques.get("initial_access", {}).get("techniques", [])),
            "execution_methods": len(platform_techniques.get("execution", {}).get("techniques", [])),
            "privilege_escalation_paths": len(platform_techniques.get("privilege_escalation", {}).get("techniques", [])),
            "persistence_mechanisms": len(platform_techniques.get("persistence", {}).get("techniques", [])),
            "evasion_techniques": len(platform_techniques.get("defense_evasion", {}).get("techniques", [])),
            "credential_access_methods": len(platform_techniques.get("credential_access", {}).get("techniques", [])),
            "lateral_movement_options": len(platform_techniques.get("lateral_movement", {}).get("techniques", []))
        }
        
        # Calculate risk score
        risk_score = sum(surface.values())
        if risk_score > 50:
            surface["risk_level"] = "high"
        elif risk_score > 25:
            surface["risk_level"] = "medium"
        else:
            surface["risk_level"] = "low"
        
        return surface
    
    def _get_recommended_chains(self, platform: str) -> List[Dict]:
        """Get recommended attack chains for platform"""
        recommendations = []
        
        # Web application chain
        if self._has_web_capabilities(platform):
            recommendations.append({
                "objective": "web_application",
                "name": "Web Application Compromise",
                "description": "Target web applications for initial access",
                "difficulty": "medium",
                "stealth": "medium"
            })
        
        # Privilege escalation chain
        recommendations.append({
            "objective": "privilege_escalation",
            "name": "Privilege Escalation",
            "description": "Focus on gaining elevated privileges",
            "difficulty": "high",
            "stealth": "low"
        })
        
        # Credential harvesting
        recommendations.append({
            "objective": "credential_harvesting",
            "name": "Credential Harvesting",
            "description": "Collect various types of credentials",
            "difficulty": "medium",
            "stealth": "low"
        })
        
        # Full compromise
        recommendations.append({
            "objective": "full_compromise",
            "name": "Full Kill Chain",
            "description": "Complete attack lifecycle",
            "difficulty": "high",
            "stealth": "low"
        })
        
        return recommendations
    
    def _has_web_capabilities(self, platform: str) -> bool:
        """Check if platform has web attack capabilities"""
        web_techniques = self.categorized_techniques.get("web_attacks", {}).get("techniques", [])
        return any(platform.lower() in [p.lower() for p in tech.get("platforms", [])] 
                  for tech in web_techniques)
    
    def build_attack_chain(self, objective: str, platform: str = "windows", 
                          constraints: Dict[str, Any] = None) -> Optional[Any]:
        """Build an attack chain for specific objective"""
        try:
            # Convert string objective to enum
            obj_enum = None
            for obj in AttackObjective:
                if obj.value == objective:
                    obj_enum = obj
                    break
            
            if not obj_enum:
                self._print_error(f"Unknown objective: {objective}")
                return None
            
            self._print_status(f"Building {objective} chain for {platform}...")
            
            chain = self.chain_builder.build_attack_chain(
                obj_enum, platform, self.categorized_techniques, constraints
            )
            
            self._print_success(f"Built chain with {len(chain.steps)} steps")
            return chain
            
        except Exception as e:
            self._print_error(f"Failed to build chain: {e}")
            self.logger.exception("Chain building error")
            return None
    
    def execute_chain(self, chain, dry_run: bool = True, interactive: bool = True) -> bool:
        """Execute an attack chain"""
        try:
            self._print_header(f"Executing Chain: {chain.name}")
            
            if dry_run:
                self._print_warning("DRY RUN MODE - No actual execution")
            
            # Display chain summary
            self._display_chain_summary(chain)
            
            if interactive and not self._confirm_execution(chain):
                self._print_info("Execution cancelled by user")
                return False
            
            # Execute each step
            success_count = 0
            for step in chain.steps:
                if self._execute_step(step, dry_run, interactive):
                    success_count += 1
                else:
                    if interactive:
                        if not Confirm.ask(f"Step {step.step_number} failed. Continue?"):
                            break
            
            self._print_success(f"Executed {success_count}/{len(chain.steps)} steps successfully")
            
            # Generate execution report
            self._generate_execution_report(chain, success_count)
            
            return success_count > 0
            
        except Exception as e:
            self._print_error(f"Execution failed: {e}")
            self.logger.exception("Execution error")
            return False
    
    def _execute_step(self, step, dry_run: bool, interactive: bool) -> bool:
        """Execute a single attack step"""
        try:
            self._print_info(f"Step {step.step_number}: {step.description}")
            self._print_info(f"  Technique: {step.technique_id} - {step.technique_name}")
            self._print_info(f"  Risk: {step.risk_level}, Detection: {step.detection_likelihood}")
            
            if interactive:
                self._print_info(f"  Expected: {step.expected_outcome}")
                if not Confirm.ask(f"Execute step {step.step_number}?"):
                    return False
            
            if dry_run:
                self._print_warning(f"  [DRY RUN] Would execute: Invoke-AtomicTest {step.technique_id}")
                time.sleep(1)  # Simulate execution time
                return True
            
            # Build Invoke-AtomicTest command
            cmd = ["powershell.exe", "-Command"]
            
            if step.test_numbers:
                test_param = ",".join(map(str, step.test_numbers))
                invoke_cmd = f"Invoke-AtomicTest {step.technique_id} -TestNumbers {test_param}"
            else:
                invoke_cmd = f"Invoke-AtomicTest {step.technique_id}"
            
            cmd.append(invoke_cmd)
            
            self._print_status(f"  Executing: {invoke_cmd}")
            
            # Execute command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self._print_success(f"  Step {step.step_number} completed successfully")
                return True
            else:
                self._print_error(f"  Step {step.step_number} failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self._print_error(f"  Step {step.step_number} timed out")
            return False
        except Exception as e:
            self._print_error(f"  Step {step.step_number} error: {e}")
            return False
    
    def _display_chain_summary(self, chain):
        """Display chain summary"""
        if not HAS_RICH:
            print(f"\nChain: {chain.name}")
            print(f"Objective: {chain.objective.value}")
            print(f"Platform: {chain.target_platform}")
            print(f"Steps: {len(chain.steps)}")
            print(f"Risk: {chain.overall_risk}")
            return
        
        # Rich table display
        table = Table(title=f"Attack Chain: {chain.name}")
        table.add_column("Step", style="cyan")
        table.add_column("Technique", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Risk", style="red")
        table.add_column("Detection", style="yellow")
        
        for step in chain.steps:
            table.add_row(
                str(step.step_number),
                f"{step.technique_id}\n{step.technique_name}",
                step.description,
                step.risk_level,
                step.detection_likelihood
            )
        
        self.console.print(table)
    
    def _confirm_execution(self, chain) -> bool:
        """Confirm execution with user"""
        if not HAS_RICH:
            return input(f"Execute chain '{chain.name}' with {len(chain.steps)} steps? (y/N): ").lower() == 'y'
        
        return Confirm.ask(f"Execute chain '{chain.name}' with {len(chain.steps)} steps?")
    
    def _generate_execution_report(self, chain, success_count: int):
        """Generate execution report"""
        report = {
            "chain_name": chain.name,
            "objective": chain.objective.value,
            "platform": chain.target_platform,
            "total_steps": len(chain.steps),
            "successful_steps": success_count,
            "success_rate": f"{(success_count/len(chain.steps)*100):.1f}%",
            "overall_risk": chain.overall_risk,
            "execution_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "steps": [
                {
                    "step_number": step.step_number,
                    "technique_id": step.technique_id,
                    "technique_name": step.technique_name,
                    "description": step.description,
                    "risk_level": step.risk_level,
                    "detection_likelihood": step.detection_likelihood
                }
                for step in chain.steps
            ]
        }
        
        report_file = self.output_dir / f"execution_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._print_success(f"Execution report saved: {report_file}")
    
    def export_chain(self, chain, format_type: str = "json") -> str:
        """Export attack chain in various formats"""
        timestamp = int(time.time())
        
        if format_type == "json":
            output_file = self.output_dir / f"chain_{chain.objective.value}_{timestamp}.json"
            content = self.chain_builder.export_chain_to_json(chain)
        elif format_type == "powershell":
            output_file = self.output_dir / f"chain_{chain.objective.value}_{timestamp}.ps1"
            content = self.chain_builder.export_chain_to_invoke_script(chain)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        with open(output_file, 'w') as f:
            f.write(content)
        
        self._print_success(f"Chain exported: {output_file}")
        return str(output_file)
    
    def list_techniques(self, platform: str = None, category: str = None) -> List[Dict]:
        """List available techniques with optional filtering"""
        techniques = self.techniques
        
        if platform:
            techniques = {
                tid: tdata for tid, tdata in techniques.items()
                if platform.lower() in [p.lower() for p in tdata.get("platforms", [])]
            }
        
        if category and category in self.categorized_techniques:
            category_techniques = {
                t["id"]: t for t in self.categorized_techniques[category]["techniques"]
            }
            techniques = {
                tid: tdata for tid, tdata in techniques.items()
                if tid in category_techniques
            }
        
        return list(techniques.values())
    
    def search_techniques(self, search_term: str) -> List[Dict]:
        """Search techniques by name or description"""
        return list(self.parser.search_techniques(search_term).values())
    
    # Output helper methods
    def _print_header(self, text: str):
        if HAS_RICH:
            self.console.print(Panel(text, style="bold blue"))
        else:
            print(f"\n=== {text} ===")
    
    def _print_status(self, text: str):
        if HAS_RICH:
            self.console.print(f"[blue]ℹ[/blue] {text}")
        else:
            print(f"[INFO] {text}")
    
    def _print_success(self, text: str):
        if HAS_RICH:
            self.console.print(f"[green]✓[/green] {text}")
        else:
            print(f"[SUCCESS] {text}")
    
    def _print_warning(self, text: str):
        if HAS_RICH:
            self.console.print(f"[yellow]⚠[/yellow] {text}")
        else:
            print(f"[WARNING] {text}")
    
    def _print_error(self, text: str):
        if HAS_RICH:
            self.console.print(f"[red]✗[/red] {text}")
        else:
            print(f"[ERROR] {text}")
    
    def _print_info(self, text: str):
        if HAS_RICH:
            self.console.print(text)
        else:
            print(text)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Atomic Red Team Attack Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize and analyze Windows target
  %(prog)s --atomics ./atomics --analyze --platform windows
  
  # Build web application attack chain
  %(prog)s --atomics ./atomics --build web_application --platform windows
  
  # Execute privilege escalation chain (dry run)
  %(prog)s --atomics ./atomics --build privilege_escalation --execute --dry-run
  
  # List available techniques for Linux
  %(prog)s --atomics ./atomics --list --platform linux
        """
    )
    
    # Required arguments
    parser.add_argument("--atomics", required=True, 
                       help="Path to Atomic Red Team atomics directory")
    
    # Actions
    parser.add_argument("--analyze", action="store_true",
                       help="Analyze target platform capabilities")
    parser.add_argument("--build", metavar="OBJECTIVE",
                       choices=[obj.value for obj in AttackObjective],
                       help="Build attack chain for objective")
    parser.add_argument("--execute", action="store_true",
                       help="Execute the built attack chain")
    parser.add_argument("--list", action="store_true",
                       help="List available techniques")
    parser.add_argument("--search", metavar="TERM",
                       help="Search techniques by name/description")
    
    # Options
    parser.add_argument("--platform", default="windows",
                       choices=["windows", "linux", "macos"],
                       help="Target platform (default: windows)")
    parser.add_argument("--category", 
                       help="Filter by category")
    parser.add_argument("--output", default="./output",
                       help="Output directory (default: ./output)")
    parser.add_argument("--dry-run", action="store_true",
                       help="Perform dry run (no actual execution)")
    parser.add_argument("--non-interactive", action="store_true",
                       help="Non-interactive mode")
    parser.add_argument("--export", choices=["json", "powershell"],
                       help="Export chain in specified format")
    parser.add_argument("--avoid-elevation", action="store_true",
                       help="Avoid techniques requiring elevation")
    
    args = parser.parse_args()
    
    # Initialize orchestrator
    orchestrator = AtomicOrchestrator(args.atomics, args.output)
    
    if not orchestrator.initialize():
        sys.exit(1)
    
    try:
        # Execute requested actions
        if args.analyze:
            analysis = orchestrator.analyze_target(args.platform)
            print(json.dumps(analysis, indent=2))
        
        elif args.list:
            techniques = orchestrator.list_techniques(args.platform, args.category)
            for tech in techniques[:10]:  # Limit output
                print(f"{tech['id']}: {tech['name']} ({', '.join(tech['platforms'])})")
            if len(techniques) > 10:
                print(f"... and {len(techniques) - 10} more")
        
        elif args.search:
            techniques = orchestrator.search_techniques(args.search)
            for tech in techniques:
                print(f"{tech['id']}: {tech['name']}")
        
        elif args.build:
            constraints = {
                "avoid_elevation": args.avoid_elevation,
                "single_test_per_technique": True
            }
            
            chain = orchestrator.build_attack_chain(args.build, args.platform, constraints)
            
            if chain:
                if args.export:
                    orchestrator.export_chain(chain, args.export)
                
                if args.execute:
                    orchestrator.execute_chain(
                        chain, 
                        dry_run=args.dry_run,
                        interactive=not args.non_interactive
                    )
                else:
                    orchestrator._display_chain_summary(chain)
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        orchestrator._print_warning("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        orchestrator._print_error(f"Unexpected error: {e}")
        logging.exception("Unexpected error")
        sys.exit(1)

if __name__ == "__main__":
    main()
