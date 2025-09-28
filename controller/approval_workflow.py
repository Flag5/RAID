"""
RAID Approval Workflow Manager
Handles human-in-the-loop approval processes during assessment execution
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
import logging

from specs.schemas import ApprovalStatus, ApprovalRequiredEvent, ApprovalResultEvent
from controller.rbac import RBACManager, User, ApprovalRequest

logger = logging.getLogger(__name__)


class ApprovalTrigger(str, Enum):
    """Types of actions that trigger approval requests"""
    DESTRUCTIVE_ACTION = "destructive_action"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_MODIFICATION = "network_modification"
    TOOL_SYNTHESIS = "tool_synthesis"
    DEVICE_PASSTHROUGH = "device_passthrough"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"
    HIGH_VALUE_TARGET = "high_value_target"


@dataclass
class ApprovalContext:
    """Context information for approval decisions"""
    run_id: str
    phase_id: str
    action_id: Optional[str] = None
    target: Optional[str] = None
    tool_name: Optional[str] = None
    risk_assessment: str = "medium"
    estimated_impact: str = "low"
    additional_context: Dict[str, Any] = None

    def __post_init__(self):
        if self.additional_context is None:
            self.additional_context = {}


class ApprovalWorkflowManager:
    """Manages approval workflows during assessment execution"""

    def __init__(self, rbac_manager: RBACManager):
        self.rbac_manager = rbac_manager
        self.active_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_callbacks: Dict[str, Callable] = {}
        self.notification_handlers: List[Callable] = []

    async def request_approval(
        self,
        trigger: ApprovalTrigger,
        context: ApprovalContext,
        requester: User,
        timeout_minutes: int = 60,
        custom_prompt: Optional[str] = None
    ) -> ApprovalRequest:
        """Request approval for an action"""

        # Generate approval prompt
        prompt = custom_prompt or self._generate_approval_prompt(trigger, context)

        # Determine risk level
        risk_level = self._assess_risk_level(trigger, context)

        # Create approval request
        approval_request = self.rbac_manager.create_approval_request(
            requester=requester,
            action_type=trigger.value,
            description=prompt,
            run_id=context.run_id,
            target=context.target,
            estimated_risk=risk_level,
            timeout_minutes=timeout_minutes
        )

        # Track active approval
        self.active_approvals[approval_request.request_id] = approval_request

        # Generate approval event
        approval_event = ApprovalRequiredEvent(
            run_id=context.run_id,
            approval_id=approval_request.request_id,
            phase_id=context.phase_id,
            action_id=context.action_id,
            reason=f"{trigger.value}: {prompt}",
            prompt=prompt,
            timeout_seconds=timeout_minutes * 60
        )

        # Notify all handlers
        await self._notify_approval_required(approval_event)

        logger.info(f"Approval requested: {approval_request.request_id} for {trigger.value}")
        return approval_request

    async def wait_for_approval(
        self,
        approval_request: ApprovalRequest,
        check_interval: float = 5.0
    ) -> ApprovalStatus:
        """Wait for approval decision with periodic checks"""

        while not approval_request.is_expired():
            # Refresh approval status
            current_request = self.rbac_manager.approval_requests.get(approval_request.request_id)
            if current_request:
                approval_request.status = current_request.status
                approval_request.received_approvals = current_request.received_approvals
                approval_request.received_denials = current_request.received_denials

            # Check if resolved
            if approval_request.status != ApprovalStatus.PENDING:
                # Generate result event
                result_event = ApprovalResultEvent(
                    run_id=approval_request.run_id or "unknown",
                    approval_id=approval_request.request_id,
                    status=approval_request.status,
                    response=self._get_approval_response(approval_request),
                    approved_by=self._get_approver_names(approval_request)
                )

                await self._notify_approval_result(result_event)

                # Cleanup
                if approval_request.request_id in self.active_approvals:
                    del self.active_approvals[approval_request.request_id]

                return approval_request.status

            # Wait before next check
            await asyncio.sleep(check_interval)

        # Handle timeout
        approval_request.status = ApprovalStatus.TIMEOUT
        self.rbac_manager.approval_requests[approval_request.request_id].status = ApprovalStatus.TIMEOUT

        result_event = ApprovalResultEvent(
            run_id=approval_request.run_id or "unknown",
            approval_id=approval_request.request_id,
            status=ApprovalStatus.TIMEOUT,
            response="Approval request timed out"
        )

        await self._notify_approval_result(result_event)

        if approval_request.request_id in self.active_approvals:
            del self.active_approvals[approval_request.request_id]

        return ApprovalStatus.TIMEOUT

    def register_approval_callback(self, approval_id: str, callback: Callable):
        """Register callback for approval resolution"""
        self.approval_callbacks[approval_id] = callback

    def add_notification_handler(self, handler: Callable):
        """Add handler for approval notifications"""
        self.notification_handlers.append(handler)

    def get_pending_approvals_for_run(self, run_id: str) -> List[ApprovalRequest]:
        """Get all pending approvals for a specific run"""
        return [
            request for request in self.active_approvals.values()
            if request.run_id == run_id and request.status == ApprovalStatus.PENDING
        ]

    def emergency_approve_all(self, approver: User, reason: str = "Emergency approval") -> int:
        """Emergency approval of all pending requests (security officer only)"""
        if not approver.has_permission("emergency_approval"):
            logger.warning(f"User {approver.username} attempted emergency approval without permission")
            return 0

        approved_count = 0
        for request in self.active_approvals.values():
            if request.status == ApprovalStatus.PENDING:
                success = self.rbac_manager.submit_approval(
                    request.request_id,
                    approver,
                    ApprovalStatus.APPROVED,
                    f"EMERGENCY: {reason}"
                )
                if success:
                    approved_count += 1

        logger.critical(f"Emergency approval by {approver.username}: {approved_count} requests approved")
        return approved_count

    def _generate_approval_prompt(self, trigger: ApprovalTrigger, context: ApprovalContext) -> str:
        """Generate human-readable approval prompt"""

        base_prompts = {
            ApprovalTrigger.DESTRUCTIVE_ACTION: (
                f"DESTRUCTIVE ACTION APPROVAL REQUIRED\n\n"
                f"Target: {context.target}\n"
                f"Risk Level: {context.risk_assessment}\n"
                f"Estimated Impact: {context.estimated_impact}\n\n"
                f"A destructive action is about to be performed that could modify or damage the target system. "
                f"This action requires explicit human approval before proceeding.\n\n"
                f"Do you approve this destructive action?"
            ),

            ApprovalTrigger.CREDENTIAL_ACCESS: (
                f"CREDENTIAL ACCESS APPROVAL REQUIRED\n\n"
                f"Target: {context.target}\n"
                f"Tool: {context.tool_name}\n\n"
                f"The assessment is requesting access to stored credentials or attempting to extract "
                f"authentication information. This could provide access to sensitive systems.\n\n"
                f"Do you approve credential access for this assessment?"
            ),

            ApprovalTrigger.NETWORK_MODIFICATION: (
                f"NETWORK MODIFICATION APPROVAL REQUIRED\n\n"
                f"Target: {context.target}\n"
                f"Risk Level: {context.risk_assessment}\n\n"
                f"The assessment is requesting to modify network configurations, routing tables, "
                f"or firewall rules. This could affect network connectivity.\n\n"
                f"Do you approve network modifications for this assessment?"
            ),

            ApprovalTrigger.TOOL_SYNTHESIS: (
                f"TOOL SYNTHESIS APPROVAL REQUIRED\n\n"
                f"Tool Requirements: {context.additional_context.get('requirements', 'Not specified')}\n"
                f"Risk Level: {context.risk_assessment}\n\n"
                f"The system is requesting to synthesize a new security tool. This involves generating "
                f"and deploying custom code that will execute in the assessment environment.\n\n"
                f"Do you approve the synthesis of this custom tool?"
            ),

            ApprovalTrigger.DEVICE_PASSTHROUGH: (
                f"DEVICE PASSTHROUGH APPROVAL REQUIRED\n\n"
                f"Device: {context.additional_context.get('device_path', 'Not specified')}\n"
                f"Risk Level: {context.risk_assessment}\n\n"
                f"The assessment is requesting direct access to a hardware device. This provides "
                f"low-level system access and could potentially compromise host security.\n\n"
                f"Do you approve device passthrough for this assessment?"
            ),

            ApprovalTrigger.EMERGENCY_SHUTDOWN: (
                f"EMERGENCY SHUTDOWN APPROVAL REQUIRED\n\n"
                f"Trigger Reason: {context.additional_context.get('reason', 'Not specified')}\n\n"
                f"An emergency shutdown has been requested. This will immediately terminate all "
                f"running assessments and isolate the system for incident response.\n\n"
                f"Do you approve the emergency shutdown?"
            ),

            ApprovalTrigger.HIGH_VALUE_TARGET: (
                f"HIGH VALUE TARGET APPROVAL REQUIRED\n\n"
                f"Target: {context.target}\n"
                f"Target Classification: {context.additional_context.get('classification', 'Not specified')}\n\n"
                f"The target has been classified as high-value and requires additional approval "
                f"before assessment can proceed. High-value targets may include production systems, "
                f"critical infrastructure, or systems containing sensitive data.\n\n"
                f"Do you approve assessment of this high-value target?"
            )
        }

        prompt = base_prompts.get(trigger, f"Approval required for: {trigger.value}")

        # Add run context
        if context.run_id:
            prompt += f"\n\nRun ID: {context.run_id}"
        if context.phase_id:
            prompt += f"\nPhase ID: {context.phase_id}"
        if context.action_id:
            prompt += f"\nAction ID: {context.action_id}"

        return prompt

    def _assess_risk_level(self, trigger: ApprovalTrigger, context: ApprovalContext) -> str:
        """Assess risk level based on trigger and context"""

        # Base risk levels for different triggers
        risk_map = {
            ApprovalTrigger.DESTRUCTIVE_ACTION: "high",
            ApprovalTrigger.CREDENTIAL_ACCESS: "high",
            ApprovalTrigger.NETWORK_MODIFICATION: "medium",
            ApprovalTrigger.TOOL_SYNTHESIS: "medium",
            ApprovalTrigger.DEVICE_PASSTHROUGH: "high",
            ApprovalTrigger.EMERGENCY_SHUTDOWN: "critical",
            ApprovalTrigger.HIGH_VALUE_TARGET: "high"
        }

        base_risk = risk_map.get(trigger, "medium")

        # Adjust based on context
        if context.risk_assessment == "critical":
            return "critical"
        elif context.risk_assessment == "high" and base_risk in ["low", "medium"]:
            return "high"
        elif context.target and any(keyword in context.target.lower() for keyword in ["prod", "production", "critical"]):
            return "high" if base_risk == "medium" else base_risk

        return base_risk

    def _get_approval_response(self, approval_request: ApprovalRequest) -> Optional[str]:
        """Get approval response/comments"""
        if approval_request.comments:
            return approval_request.comments[-1].get("comment", "")
        return None

    def _get_approver_names(self, approval_request: ApprovalRequest) -> Optional[str]:
        """Get names of users who approved the request"""
        if approval_request.received_approvals:
            approver_ids = list(approval_request.received_approvals.keys())
            approver_names = []

            for approver_id in approver_ids:
                user = self.rbac_manager.users.get(approver_id)
                if user:
                    approver_names.append(user.username)

            return ", ".join(approver_names)

        return None

    async def _notify_approval_required(self, event: ApprovalRequiredEvent):
        """Notify handlers about approval requirement"""
        for handler in self.notification_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler("approval_required", event)
                else:
                    handler("approval_required", event)
            except Exception as e:
                logger.error(f"Error in approval notification handler: {e}")

    async def _notify_approval_result(self, event: ApprovalResultEvent):
        """Notify handlers about approval result"""
        for handler in self.notification_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler("approval_result", event)
                else:
                    handler("approval_result", event)
            except Exception as e:
                logger.error(f"Error in approval result handler: {e}")

        # Call registered callback if exists
        callback = self.approval_callbacks.get(event.approval_id)
        if callback:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in approval callback: {e}")


class ApprovalPolicy:
    """Defines approval policies for different scenarios"""

    @staticmethod
    def requires_approval(action: str, context: Dict[str, Any], authorization: Dict[str, Any]) -> bool:
        """Determine if action requires approval based on policy"""

        # Check authorization requirements
        requires_approval_actions = authorization.get("requires_human_approval", [])

        # Action-based requirements
        if action in requires_approval_actions:
            return True

        # Context-based requirements
        if context.get("destructive", False) and not authorization.get("allow_destructive", False):
            return True

        if context.get("device_access", False) and not authorization.get("allow_device_passthrough", False):
            return True

        # Target-based requirements
        target = context.get("target", "")
        if any(keyword in target.lower() for keyword in ["prod", "production", "critical"]):
            return True

        # Tool synthesis requirements
        if action == "synthesize_tool":
            return True

        return False

    @staticmethod
    def get_approval_trigger(action: str, context: Dict[str, Any]) -> ApprovalTrigger:
        """Determine appropriate approval trigger for action"""

        trigger_map = {
            "destructive": ApprovalTrigger.DESTRUCTIVE_ACTION,
            "credential_access": ApprovalTrigger.CREDENTIAL_ACCESS,
            "network_modification": ApprovalTrigger.NETWORK_MODIFICATION,
            "synthesize_tool": ApprovalTrigger.TOOL_SYNTHESIS,
            "device_passthrough": ApprovalTrigger.DEVICE_PASSTHROUGH,
            "emergency_shutdown": ApprovalTrigger.EMERGENCY_SHUTDOWN
        }

        # Check for high-value target
        target = context.get("target", "")
        if any(keyword in target.lower() for keyword in ["prod", "production", "critical"]):
            return ApprovalTrigger.HIGH_VALUE_TARGET

        return trigger_map.get(action, ApprovalTrigger.DESTRUCTIVE_ACTION)


# Example approval handler implementations
class ConsoleApprovalHandler:
    """Simple console-based approval handler for development"""

    def __init__(self):
        self.pending_approvals = {}

    async def handle_approval_required(self, event_type: str, event: ApprovalRequiredEvent):
        """Handle approval required notification"""
        if event_type == "approval_required":
            print(f"\n{'='*60}")
            print(f"APPROVAL REQUIRED: {event.approval_id}")
            print(f"{'='*60}")
            print(f"Run ID: {event.run_id}")
            print(f"Reason: {event.reason}")
            print(f"Prompt: {event.prompt}")
            print(f"Timeout: {event.timeout_seconds} seconds")
            print(f"{'='*60}")

            self.pending_approvals[event.approval_id] = event

    async def handle_approval_result(self, event_type: str, event: ApprovalResultEvent):
        """Handle approval result notification"""
        if event_type == "approval_result":
            print(f"\nAPPROVAL RESOLVED: {event.approval_id}")
            print(f"Status: {event.status}")
            print(f"Approved by: {event.approved_by}")
            print(f"Response: {event.response}")

            if event.approval_id in self.pending_approvals:
                del self.pending_approvals[event.approval_id]


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    from controller.rbac import RBACManager, initialize_default_users

    async def test_approval_workflow():
        # Setup
        rbac = RBACManager(tempfile.mkdtemp())
        initialize_default_users(rbac)

        workflow = ApprovalWorkflowManager(rbac)
        console_handler = ConsoleApprovalHandler()
        workflow.add_notification_handler(console_handler.handle_approval_required)
        workflow.add_notification_handler(console_handler.handle_approval_result)

        # Test approval request
        analyst = rbac.get_user_by_username("analyst")
        context = ApprovalContext(
            run_id="test-run-001",
            phase_id="destructive-phase",
            target="production.example.com",
            risk_assessment="high"
        )

        approval_request = await workflow.request_approval(
            ApprovalTrigger.DESTRUCTIVE_ACTION,
            context,
            analyst,
            timeout_minutes=1  # Short timeout for testing
        )

        print(f"Created approval request: {approval_request.request_id}")

        # Simulate approval in background
        async def auto_approve():
            await asyncio.sleep(2)  # Wait 2 seconds
            security_officer = rbac.get_user_by_username("security_officer")
            rbac.submit_approval(
                approval_request.request_id,
                security_officer,
                ApprovalStatus.APPROVED,
                "Approved for testing"
            )

        # Start auto-approval task
        asyncio.create_task(auto_approve())

        # Wait for approval
        result = await workflow.wait_for_approval(approval_request)
        print(f"Final approval status: {result}")

    # Run test
    asyncio.run(test_approval_workflow())