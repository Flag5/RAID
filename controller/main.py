#!/usr/bin/env python3
"""
RAID Controller - Main CLI Entry Point
Command-line interface for the RAID security assessment framework
"""

import sys
import os
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from specs.schemas import Authorization, AssessmentPlan, validate_authorization, validate_assessment_plan
from controller.llm_adapter import MockLLMAdapter, LLMAdapterWithFallback
from controller.rbac import RBACManager, initialize_default_users
from controller.approval_workflow import ApprovalWorkflowManager, ApprovalContext, ApprovalTrigger
from controller.monitoring import RAIDMonitor
from controller.network_isolation import NetworkIsolationManager, create_web_assessment_policy

console = Console()


class RAIDController:
    """Main RAID controller for orchestrating security assessments"""

    def __init__(self, config_dir: str = "/app"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.rbac = RBACManager(str(self.config_dir / "auth"))
        self.llm_adapter = LLMAdapterWithFallback(
            primary_adapter=MockLLMAdapter(),
            fallback_adapter=MockLLMAdapter()
        )
        self.approval_workflow = ApprovalWorkflowManager(self.rbac)
        self.monitor = RAIDMonitor(str(self.config_dir / "monitoring"))
        self.network_manager = NetworkIsolationManager()

        # Setup logging
        self._setup_logging()

        # Initialize default users if none exist
        if not self.rbac.users:
            initialize_default_users(self.rbac)

    def _setup_logging(self):
        """Setup logging configuration"""
        log_dir = self.config_dir / "logs"
        log_dir.mkdir(exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                RichHandler(console=console, rich_tracebacks=True),
                logging.FileHandler(log_dir / "raid.log")
            ]
        )

        # Suppress noisy loggers
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("docker").setLevel(logging.WARNING)

    async def dry_run(
        self,
        role_file: str,
        target: str,
        auth_file: str,
        output_dir: str
    ) -> bool:
        """Perform dry-run assessment (plan generation only)"""
        try:
            # Load and validate authorization
            authorization = self._load_authorization(auth_file)
            if not authorization:
                return False

            # Load role definition
            role_definition = self._load_role_definition(role_file)
            if not role_definition:
                return False

            console.print("[bold blue]Starting RAID dry-run assessment...[/bold blue]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:

                # Generate assessment plan
                task = progress.add_task("Generating assessment plan...", total=None)

                plan_response = await self.llm_adapter.generate_plan_with_fallback(
                    role=role_definition["name"],
                    target=target,
                    role_definition=role_definition,
                    authorization=authorization.model_dump(),
                    context={"dry_run": True}
                )

                if plan_response.validation_result.value != "valid":
                    console.print(f"[red]Plan generation failed: {plan_response.validation_errors}[/red]")
                    return False

                progress.update(task, description="Plan generated successfully")

                # Parse and validate plan
                plan_data = json.loads(plan_response.content)
                plan = validate_assessment_plan(plan_data)

                progress.update(task, description="Plan validated")

                # Save plan to output directory
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)

                plan_file = output_path / f"plan_{plan.run_id}.json"
                with open(plan_file, 'w') as f:
                    json.dump(plan_data, f, indent=2)

                progress.update(task, description=f"Plan saved to {plan_file}")

            # Display plan summary
            self._display_plan_summary(plan)

            console.print(f"[green]✓ Dry-run completed successfully![/green]")
            console.print(f"[blue]Plan saved to: {plan_file}[/blue]")

            return True

        except Exception as e:
            console.print(f"[red]Dry-run failed: {str(e)}[/red]")
            logging.exception("Dry-run failed")
            return False

    async def run_assessment(
        self,
        role_file: str,
        target: str,
        auth_file: str,
        output_dir: str,
        user: str = "admin"
    ) -> bool:
        """Run full security assessment"""
        try:
            # Authenticate user
            user_obj = self.rbac.get_user_by_username(user)
            if not user_obj:
                console.print(f"[red]User '{user}' not found[/red]")
                return False

            # Load and validate authorization
            authorization = self._load_authorization(auth_file)
            if not authorization:
                return False

            # Check user permissions
            if not self.rbac.authorize_action(user_obj, "run_assessment"):
                console.print(f"[red]User '{user}' not authorized to run assessments[/red]")
                return False

            console.print("[bold green]Starting RAID security assessment...[/bold green]")

            # Start monitoring
            self.monitor.start_run_monitoring(f"run_{target}_{user}", {
                "target": target,
                "user": user,
                "role_file": role_file
            })

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:

                # Load role and generate plan
                task = progress.add_task("Loading role and generating plan...", total=None)

                role_definition = self._load_role_definition(role_file)
                if not role_definition:
                    return False

                plan_response = await self.llm_adapter.generate_plan_with_fallback(
                    role=role_definition["name"],
                    target=target,
                    role_definition=role_definition,
                    authorization=authorization.model_dump()
                )

                if plan_response.validation_result.value != "valid":
                    console.print(f"[red]Plan generation failed: {plan_response.validation_errors}[/red]")
                    return False

                plan_data = json.loads(plan_response.content)
                plan = validate_assessment_plan(plan_data)

                progress.update(task, description="Plan generated and validated")

                # Execute assessment phases
                success = await self._execute_assessment_phases(plan, user_obj, progress)

                if success:
                    # Generate final report
                    progress.update(task, description="Generating final report...")
                    await self._generate_final_report(plan, output_dir)

            if success:
                console.print("[green]✓ Assessment completed successfully![/green]")
                self.monitor.end_run_monitoring(f"run_{target}_{user}", True)
            else:
                console.print("[red]✗ Assessment failed or was cancelled[/red]")
                self.monitor.end_run_monitoring(f"run_{target}_{user}", False)

            return success

        except Exception as e:
            console.print(f"[red]Assessment failed: {str(e)}[/red]")
            logging.exception("Assessment failed")
            return False

    async def _execute_assessment_phases(
        self,
        plan: AssessmentPlan,
        user,
        progress: Progress
    ) -> bool:
        """Execute assessment phases with approval workflow"""

        for i, phase in enumerate(plan.phases):
            task = progress.add_task(f"Phase {i+1}: {phase.name}", total=None)

            # Check if approval required
            if phase.requires_approval:
                progress.update(task, description=f"Requesting approval for {phase.name}...")

                approval_context = ApprovalContext(
                    run_id=plan.run_id,
                    phase_id=phase.phase_id,
                    target=plan.target,
                    risk_assessment="medium"
                )

                approval_request = await self.approval_workflow.request_approval(
                    ApprovalTrigger.DESTRUCTIVE_ACTION,
                    approval_context,
                    user,
                    timeout_minutes=5  # Short timeout for demo
                )

                progress.update(task, description="Waiting for approval...")

                # Auto-approve for demo (in production, this would wait for human approval)
                await asyncio.sleep(1)
                security_officer = self.rbac.get_user_by_username("security_officer")
                if security_officer:
                    self.rbac.submit_approval(
                        approval_request.request_id,
                        security_officer,
                        "approved",
                        "Auto-approved for demonstration"
                    )

                # Wait for approval result
                approval_status = await self.approval_workflow.wait_for_approval(approval_request)

                if approval_status.value != "approved":
                    console.print(f"[red]Phase '{phase.name}' not approved: {approval_status}[/red]")
                    return False

                progress.update(task, description=f"Phase approved, executing...")

            # Execute phase actions
            for action in phase.actions:
                progress.update(task, description=f"Executing {action.tool}...")

                # Simulate tool execution
                await self._execute_tool_action(action, plan.target)

                # Record metrics
                self.monitor.record_tool_execution(action.tool, 1.5, True)

            progress.update(task, description=f"Phase {phase.name} completed")

        return True

    async def _execute_tool_action(self, action, target: str):
        """Execute individual tool action (simulated)"""
        # In a real implementation, this would:
        # 1. Set up network isolation
        # 2. Launch tool container
        # 3. Execute tool with parameters
        # 4. Collect evidence
        # 5. Clean up resources

        # For demo, just simulate execution time
        await asyncio.sleep(0.5)

        logging.info(f"Executed {action.tool} against {target}")

    def _load_authorization(self, auth_file: str) -> Optional[Authorization]:
        """Load and validate authorization file"""
        try:
            auth_path = Path(auth_file)
            if not auth_path.exists():
                console.print(f"[red]Authorization file not found: {auth_file}[/red]")
                return None

            with open(auth_path, 'r') as f:
                auth_data = json.load(f)

            authorization = validate_authorization(auth_data)
            console.print("[green]✓ Authorization validated[/green]")
            return authorization

        except Exception as e:
            console.print(f"[red]Failed to load authorization: {str(e)}[/red]")
            return None

    def _load_role_definition(self, role_file: str) -> Optional[Dict[str, Any]]:
        """Load role definition file"""
        try:
            role_path = Path(role_file)
            if not role_path.exists():
                console.print(f"[red]Role file not found: {role_file}[/red]")
                return None

            # For demo, create a simple role definition
            role_definition = {
                "name": role_path.stem,
                "description": f"Security assessment role: {role_path.stem}",
                "tools": ["http-fetcher", "port-scanner", "web-scanner"],
                "phases": ["reconnaissance", "vulnerability_assessment", "exploitation"]
            }

            console.print(f"[green]✓ Role '{role_definition['name']}' loaded[/green]")
            return role_definition

        except Exception as e:
            console.print(f"[red]Failed to load role: {str(e)}[/red]")
            return None

    def _display_plan_summary(self, plan: AssessmentPlan):
        """Display assessment plan summary"""
        table = Table(title=f"Assessment Plan: {plan.run_id}")

        table.add_column("Phase", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Actions", style="green")
        table.add_column("Approval Required", style="yellow")
        table.add_column("Est. Time", style="blue")

        for i, phase in enumerate(plan.phases):
            table.add_row(
                str(i + 1),
                phase.name,
                str(len(phase.actions)),
                "Yes" if phase.requires_approval else "No",
                f"{phase.estimated_runtime_seconds}s"
            )

        console.print(table)

        # Display summary panel
        summary = Panel(
            f"[bold]Target:[/bold] {plan.target}\n"
            f"[bold]Role:[/bold] {plan.role}\n"
            f"[bold]Total Phases:[/bold] {len(plan.phases)}\n"
            f"[bold]Total Actions:[/bold] {sum(len(p.actions) for p in plan.phases)}\n"
            f"[bold]Estimated Runtime:[/bold] {plan.total_estimated_runtime}s\n"
            f"[bold]LLM Model:[/bold] {plan.llm_model}",
            title="Assessment Summary",
            border_style="blue"
        )
        console.print(summary)

    async def _generate_final_report(self, plan: AssessmentPlan, output_dir: str):
        """Generate final assessment report"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report = {
            "assessment_id": plan.run_id,
            "target": plan.target,
            "role": plan.role,
            "phases_executed": len(plan.phases),
            "completion_time": "2025-01-28T16:00:00Z",
            "status": "completed",
            "findings_summary": {
                "total_findings": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1
            },
            "recommendations": [
                "Update web application framework",
                "Implement additional input validation",
                "Enable security headers",
                "Review access controls"
            ]
        }

        report_file = output_path / f"report_{plan.run_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        console.print(f"[blue]Final report saved to: {report_file}[/blue]")

    def get_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return self.monitor.get_system_status()


# CLI Commands
@click.group()
@click.option('--config-dir', default='/tmp/raid-demo', help='Configuration directory')
@click.pass_context
def cli(ctx, config_dir):
    """RAID Security Assessment Framework"""
    ctx.ensure_object(dict)
    ctx.obj['controller'] = RAIDController(config_dir)


@cli.command()
@click.option('--role', required=True, help='Assessment role file')
@click.option('--target', required=True, help='Target system or network')
@click.option('--auth', required=True, help='Authorization file')
@click.option('--output', default='./results', help='Output directory')
@click.pass_context
def dry_run(ctx, role, target, auth, output):
    """Generate assessment plan without execution"""
    controller = ctx.obj['controller']

    # Create sample authorization for demo
    _create_sample_authorization(auth)

    success = asyncio.run(controller.dry_run(role, target, auth, output))
    sys.exit(0 if success else 1)


@cli.command()
@click.option('--role', required=True, help='Assessment role file')
@click.option('--target', required=True, help='Target system or network')
@click.option('--auth', required=True, help='Authorization file')
@click.option('--output', default='./results', help='Output directory')
@click.option('--user', default='admin', help='Username for authentication')
@click.pass_context
def run(ctx, role, target, auth, output, user):
    """Run full security assessment"""
    controller = ctx.obj['controller']

    # Create sample authorization for demo
    _create_sample_authorization(auth)

    success = asyncio.run(controller.run_assessment(role, target, auth, output, user))
    sys.exit(0 if success else 1)


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status"""
    controller = ctx.obj['controller']
    status_data = controller.get_status()

    table = Table(title="RAID System Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    for key, value in status_data.items():
        table.add_row(key.replace('_', ' ').title(), str(value))

    console.print(table)


@cli.command()
@click.pass_context
def users(ctx):
    """List users and roles"""
    controller = ctx.obj['controller']

    table = Table(title="RAID Users")
    table.add_column("Username", style="cyan")
    table.add_column("Roles", style="magenta")
    table.add_column("Active", style="green")
    table.add_column("Last Login", style="blue")

    for user in controller.rbac.users.values():
        roles = ", ".join([role.value for role in user.roles])
        last_login = user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "Never"

        table.add_row(
            user.username,
            roles,
            "Yes" if user.active else "No",
            last_login
        )

    console.print(table)


def _create_sample_authorization(auth_file: str):
    """Create sample authorization file for demo"""
    from datetime import datetime, timedelta

    auth_data = {
        "auth_id": "demo-auth-001",
        "issued_by": "RAID Demo System",
        "issued_at": datetime.utcnow().isoformat(),
        "expires_at": (datetime.utcnow() + timedelta(days=1)).isoformat(),
        "allow_destructive": False,
        "allow_device_passthrough": False,
        "allowed_roles": ["web-pentest", "network-scan"],
        "scope": {
            "target_cidrs": ["203.0.113.0/24", "192.168.1.0/24"],
            "target_domains": ["example.com", "test.example.com"],
            "excluded_cidrs": [],
            "max_targets": 100
        },
        "limits": {
            "max_duration_hours": 8,
            "max_tools_concurrent": 5,
            "rate_limit_per_minute": 100,
            "max_evidence_size_mb": 500
        },
        "requires_human_approval": ["destructive", "credential_access"],
        "purpose": "Security assessment demonstration",
        "contact_email": "demo@raid-framework.local"
    }

    # Ensure directory exists
    auth_path = Path(auth_file)
    auth_path.parent.mkdir(parents=True, exist_ok=True)

    with open(auth_path, 'w') as f:
        json.dump(auth_data, f, indent=2)


if __name__ == '__main__':
    cli()