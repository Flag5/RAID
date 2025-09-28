"""
RAID Framework - Machine-Readable Schemas
Pydantic models for all data structures and API interfaces
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, validator


# =============================================================================
# Core Enums
# =============================================================================

class EventType(str, Enum):
    """NDJSON event types"""
    PLAN = "plan"
    PHASE_START = "phase_start"
    PHASE_END = "phase_end"
    TOOL_START = "tool_start"
    TOOL_OUTPUT = "tool_output"
    TOOL_END = "tool_end"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_RESULT = "approval_result"
    ERROR = "error"
    FINAL_REPORT = "final_report"


class ToolStatus(str, Enum):
    """Tool execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ApprovalStatus(str, Enum):
    """Approval request status"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"


class RunStatus(str, Enum):
    """Assessment run status"""
    CREATED = "created"
    VALIDATING = "validating"
    PLANNING = "planning"
    EXECUTING = "executing"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# =============================================================================
# Authorization Schema
# =============================================================================

class AuthorizationScope(BaseModel):
    """Network and target scope definition"""
    target_cidrs: List[str] = Field(..., description="Allowed target CIDR blocks")
    target_domains: List[str] = Field(default=[], description="Allowed target domains")
    excluded_cidrs: List[str] = Field(default=[], description="Explicitly excluded CIDRs")
    max_targets: int = Field(default=1000, description="Maximum number of targets")


class AuthorizationLimits(BaseModel):
    """Rate limits and resource constraints"""
    max_duration_hours: int = Field(default=24, description="Maximum assessment duration")
    max_tools_concurrent: int = Field(default=10, description="Max concurrent tools")
    rate_limit_per_minute: int = Field(default=100, description="API calls per minute")
    max_evidence_size_mb: int = Field(default=1000, description="Max evidence size")


class Authorization(BaseModel):
    """Signed authorization for security assessments"""
    auth_id: str = Field(..., description="Unique authorization ID")
    issued_by: str = Field(..., description="Issuer identity")
    issued_at: datetime = Field(..., description="Issue timestamp")
    expires_at: datetime = Field(..., description="Expiration timestamp")

    # Permissions
    allow_destructive: bool = Field(default=False, description="Allow destructive actions")
    allow_device_passthrough: bool = Field(default=False, description="Allow USB device access")
    allowed_roles: List[str] = Field(..., description="Permitted assessment roles")

    # Scope and limits
    scope: AuthorizationScope = Field(..., description="Target and network scope")
    limits: AuthorizationLimits = Field(..., description="Resource limits")

    # Approval requirements
    requires_human_approval: List[str] = Field(
        default=["destructive", "credential_access", "network_modification"],
        description="Actions requiring human approval"
    )

    # Metadata
    purpose: str = Field(..., description="Assessment purpose")
    contact_email: str = Field(..., description="Contact for issues")

    # Signature (added by signing process)
    signature: Optional[str] = Field(None, description="Ed25519 signature")
    signing_key_id: Optional[str] = Field(None, description="Signing key identifier")

    @validator('expires_at')
    def expires_after_issued(cls, v, values):
        if 'issued_at' in values and v <= values['issued_at']:
            raise ValueError('expires_at must be after issued_at')
        return v


# =============================================================================
# Plan Schema
# =============================================================================

class ToolAction(BaseModel):
    """Individual tool action within a phase"""
    action_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique action ID")
    tool: str = Field(..., description="Tool identifier")
    params: Dict[str, Any] = Field(..., description="Tool parameters")
    timeout_seconds: int = Field(default=300, description="Action timeout")
    retry_count: int = Field(default=0, description="Number of retries on failure")
    depends_on: List[str] = Field(default=[], description="Dependent action IDs")


class AssessmentPhase(BaseModel):
    """Individual phase of security assessment"""
    phase_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique phase ID")
    name: str = Field(..., description="Human-readable phase name")
    intent: str = Field(..., description="Phase purpose and goals")

    # Tool constraints
    allowed_tools: List[str] = Field(..., description="Tools allowed in this phase")
    forbidden_tools: List[str] = Field(default=[], description="Explicitly forbidden tools")

    # Actions and execution
    actions: List[ToolAction] = Field(..., description="Tool actions to execute")
    requires_approval: bool = Field(default=False, description="Human approval required")
    estimated_runtime_seconds: int = Field(..., description="Estimated execution time")

    # Dependencies
    depends_on_phases: List[str] = Field(default=[], description="Dependent phase IDs")


class AssessmentPlan(BaseModel):
    """Complete security assessment plan"""
    run_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique run ID")
    plan_version: str = Field(default="1.0", description="Plan schema version")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Plan creation time")

    # Assessment metadata
    role: str = Field(..., description="Assessment role name")
    target: str = Field(..., description="Primary target")
    assessment_type: str = Field(..., description="Type of assessment")

    # Execution plan
    phases: List[AssessmentPhase] = Field(..., description="Ordered assessment phases")
    total_estimated_runtime: int = Field(..., description="Total estimated runtime seconds")

    # LLM metadata
    llm_model: str = Field(..., description="LLM model used for planning")
    llm_request_id: Optional[str] = Field(None, description="LLM request identifier")
    llm_token_usage: Optional[Dict[str, int]] = Field(None, description="Token usage stats")

    # Validation
    validated_at: Optional[datetime] = Field(None, description="Plan validation timestamp")
    validation_errors: List[str] = Field(default=[], description="Validation error messages")


# =============================================================================
# Tool Runner API Schema
# =============================================================================

class ToolRunContext(BaseModel):
    """Runtime context for tool execution"""
    run_id: str = Field(..., description="Assessment run ID")
    phase_id: str = Field(..., description="Current phase ID")
    action_id: str = Field(..., description="Current action ID")

    # Authorization context
    authorized: bool = Field(..., description="Tool execution authorized")
    scope: AuthorizationScope = Field(..., description="Authorized scope")

    # Runtime environment
    evidence_path: str = Field(..., description="Evidence collection path")
    temp_path: str = Field(..., description="Temporary file path")
    max_runtime_seconds: int = Field(default=300, description="Maximum execution time")

    # Network and resource constraints
    network_allowed: bool = Field(default=True, description="Network access allowed")
    allowed_egress_cidrs: List[str] = Field(default=[], description="Allowed egress destinations")
    max_memory_mb: int = Field(default=512, description="Memory limit")
    max_cpu_percent: int = Field(default=50, description="CPU limit percentage")


class ToolRunRequest(BaseModel):
    """Standard tool runner execution request"""
    action: str = Field(..., description="Tool action to perform")
    params: Dict[str, Any] = Field(..., description="Action parameters")
    run_context: ToolRunContext = Field(..., description="Execution context")

    # Request metadata
    request_id: str = Field(default_factory=lambda: str(uuid4()), description="Request ID")
    submitted_at: datetime = Field(default_factory=datetime.utcnow, description="Submission time")


class EvidenceReference(BaseModel):
    """Reference to collected evidence"""
    evidence_id: str = Field(..., description="Evidence identifier")
    file_path: str = Field(..., description="Evidence file path")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(..., description="File size in bytes")
    sha256_hash: str = Field(..., description="SHA256 hash of evidence")
    collected_at: datetime = Field(default_factory=datetime.utcnow, description="Collection time")
    metadata: Dict[str, Any] = Field(default={}, description="Additional metadata")


class ToolRunResult(BaseModel):
    """Tool execution result"""
    status: ToolStatus = Field(..., description="Execution status")
    result: Dict[str, Any] = Field(default={}, description="Tool output data")

    # Evidence and artifacts
    evidence_refs: List[EvidenceReference] = Field(default=[], description="Collected evidence")

    # Execution metadata
    execution_time_seconds: float = Field(..., description="Actual execution time")
    exit_code: Optional[int] = Field(None, description="Process exit code")
    stdout: Optional[str] = Field(None, description="Standard output")
    stderr: Optional[str] = Field(None, description="Standard error")

    # Error information
    error_message: Optional[str] = Field(None, description="Error description")
    error_details: Dict[str, Any] = Field(default={}, description="Detailed error info")

    # Resource usage
    peak_memory_mb: Optional[float] = Field(None, description="Peak memory usage")
    cpu_time_seconds: Optional[float] = Field(None, description="CPU time used")

    # Completed timestamp
    completed_at: datetime = Field(default_factory=datetime.utcnow, description="Completion time")


# =============================================================================
# NDJSON Event Schema
# =============================================================================

class BaseEvent(BaseModel):
    """Base class for all NDJSON events"""
    event_type: EventType = Field(..., description="Event type identifier")
    event_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique event ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    run_id: str = Field(..., description="Assessment run ID")


class PlanEvent(BaseEvent):
    """Plan generation event"""
    event_type: EventType = Field(EventType.PLAN, description="Event type")
    plan: AssessmentPlan = Field(..., description="Generated assessment plan")


class PhaseStartEvent(BaseEvent):
    """Phase start event"""
    event_type: EventType = Field(EventType.PHASE_START, description="Event type")
    phase: AssessmentPhase = Field(..., description="Starting phase")


class PhaseEndEvent(BaseEvent):
    """Phase completion event"""
    event_type: EventType = Field(EventType.PHASE_END, description="Event type")
    phase_id: str = Field(..., description="Completed phase ID")
    status: ToolStatus = Field(..., description="Phase completion status")
    duration_seconds: float = Field(..., description="Phase execution time")


class ToolStartEvent(BaseEvent):
    """Tool execution start event"""
    event_type: EventType = Field(EventType.TOOL_START, description="Event type")
    tool: str = Field(..., description="Tool identifier")
    action: ToolAction = Field(..., description="Tool action being executed")


class ToolOutputEvent(BaseEvent):
    """Tool output/progress event"""
    event_type: EventType = Field(EventType.TOOL_OUTPUT, description="Event type")
    action_id: str = Field(..., description="Tool action ID")
    output_type: str = Field(..., description="Output type (stdout, stderr, progress)")
    content: str = Field(..., description="Output content")


class ToolEndEvent(BaseEvent):
    """Tool execution completion event"""
    event_type: EventType = Field(EventType.TOOL_END, description="Event type")
    action_id: str = Field(..., description="Tool action ID")
    result: ToolRunResult = Field(..., description="Tool execution result")


class ApprovalRequiredEvent(BaseEvent):
    """Human approval required event"""
    event_type: EventType = Field(EventType.APPROVAL_REQUIRED, description="Event type")
    approval_id: str = Field(default_factory=lambda: str(uuid4()), description="Approval request ID")
    phase_id: str = Field(..., description="Phase requiring approval")
    action_id: Optional[str] = Field(None, description="Specific action requiring approval")
    reason: str = Field(..., description="Reason approval is required")
    prompt: str = Field(..., description="Approval prompt for human")
    timeout_seconds: int = Field(default=3600, description="Approval timeout")


class ApprovalResultEvent(BaseEvent):
    """Approval decision event"""
    event_type: EventType = Field(EventType.APPROVAL_RESULT, description="Event type")
    approval_id: str = Field(..., description="Approval request ID")
    status: ApprovalStatus = Field(..., description="Approval decision")
    response: Optional[str] = Field(None, description="Human response/instructions")
    approved_by: Optional[str] = Field(None, description="Approver identity")
    approved_at: datetime = Field(default_factory=datetime.utcnow, description="Decision timestamp")


class ErrorEvent(BaseEvent):
    """Error event"""
    event_type: EventType = Field(EventType.ERROR, description="Event type")
    error_type: str = Field(..., description="Error type/category")
    error_message: str = Field(..., description="Error description")
    error_details: Dict[str, Any] = Field(default={}, description="Detailed error information")
    phase_id: Optional[str] = Field(None, description="Phase where error occurred")
    action_id: Optional[str] = Field(None, description="Action where error occurred")


class FinalReportEvent(BaseEvent):
    """Final assessment report event"""
    event_type: EventType = Field(EventType.FINAL_REPORT, description="Event type")
    status: RunStatus = Field(..., description="Final run status")

    # Execution summary
    start_time: datetime = Field(..., description="Assessment start time")
    end_time: datetime = Field(..., description="Assessment end time")
    total_duration_seconds: float = Field(..., description="Total execution time")

    # Phase summary
    phases_completed: int = Field(..., description="Number of phases completed")
    phases_failed: int = Field(default=0, description="Number of phases failed")

    # Tool summary
    tools_executed: int = Field(..., description="Total tools executed")
    tools_succeeded: int = Field(..., description="Successful tool executions")
    tools_failed: int = Field(default=0, description="Failed tool executions")

    # Evidence summary
    evidence_collected: int = Field(..., description="Number of evidence items")
    total_evidence_size_mb: float = Field(..., description="Total evidence size")

    # Findings summary
    findings: Dict[str, Any] = Field(default={}, description="Assessment findings summary")
    recommendations: List[str] = Field(default=[], description="Security recommendations")


# =============================================================================
# Union Types for Event Processing
# =============================================================================

NDJSONEvent = Union[
    PlanEvent,
    PhaseStartEvent,
    PhaseEndEvent,
    ToolStartEvent,
    ToolOutputEvent,
    ToolEndEvent,
    ApprovalRequiredEvent,
    ApprovalResultEvent,
    ErrorEvent,
    FinalReportEvent
]


# =============================================================================
# Run Manifest Schema
# =============================================================================

class RunManifest(BaseModel):
    """Final run manifest with metadata and signatures"""
    manifest_version: str = Field(default="1.0", description="Manifest schema version")
    run_id: str = Field(..., description="Assessment run ID")

    # Authorization
    authorization_fingerprint: str = Field(..., description="SHA256 of authorization")
    authorization_signer: str = Field(..., description="Authorization signer identity")

    # Plan metadata
    role_name: str = Field(..., description="Assessment role")
    role_digest: str = Field(..., description="SHA256 of role definition")
    plan_digest: str = Field(..., description="SHA256 of generated plan")

    # Execution metadata
    start_time: datetime = Field(..., description="Run start time")
    end_time: datetime = Field(..., description="Run end time")
    final_status: RunStatus = Field(..., description="Final run status")

    # Tool and image metadata
    tools_used: List[str] = Field(..., description="List of tools executed")
    image_digests: Dict[str, str] = Field(..., description="Container image digests")
    synthesized_tools: List[str] = Field(default=[], description="Synthesized tool IDs")

    # LLM metadata
    llm_model: str = Field(..., description="LLM model used")
    llm_requests: List[str] = Field(default=[], description="LLM request IDs")
    total_tokens_used: Optional[int] = Field(None, description="Total token usage")

    # Registry and environment
    registry_snapshot: Dict[str, Any] = Field(..., description="Tool registry state")
    environment_info: Dict[str, str] = Field(..., description="Runtime environment")

    # Artifacts
    ndjson_file: str = Field(..., description="NDJSON log file path")
    evidence_archive: str = Field(..., description="Evidence archive path")

    # Signatures
    manifest_signature: Optional[str] = Field(None, description="Manifest signature")
    ndjson_signature: Optional[str] = Field(None, description="NDJSON file signature")
    evidence_signature: Optional[str] = Field(None, description="Evidence archive signature")
    signing_key_id: Optional[str] = Field(None, description="Signing key identifier")
    signed_at: Optional[datetime] = Field(None, description="Signing timestamp")


# =============================================================================
# API Response Models
# =============================================================================

class APIResponse(BaseModel):
    """Standard API response wrapper"""
    success: bool = Field(..., description="Request success status")
    message: str = Field(..., description="Response message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    errors: List[str] = Field(default=[], description="Error messages")
    request_id: str = Field(default_factory=lambda: str(uuid4()), description="Request ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class RunStatusResponse(BaseModel):
    """Run status API response"""
    run_id: str = Field(..., description="Assessment run ID")
    status: RunStatus = Field(..., description="Current run status")
    current_phase: Optional[str] = Field(None, description="Current phase name")
    progress_percent: float = Field(..., description="Completion percentage")
    start_time: datetime = Field(..., description="Run start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion")
    pending_approvals: List[str] = Field(default=[], description="Pending approval IDs")


# =============================================================================
# Schema Validation Utilities
# =============================================================================

def validate_ndjson_event(event_data: Dict[str, Any]) -> NDJSONEvent:
    """Validate and parse NDJSON event data"""
    event_type = event_data.get("event_type")

    event_map = {
        EventType.PLAN: PlanEvent,
        EventType.PHASE_START: PhaseStartEvent,
        EventType.PHASE_END: PhaseEndEvent,
        EventType.TOOL_START: ToolStartEvent,
        EventType.TOOL_OUTPUT: ToolOutputEvent,
        EventType.TOOL_END: ToolEndEvent,
        EventType.APPROVAL_REQUIRED: ApprovalRequiredEvent,
        EventType.APPROVAL_RESULT: ApprovalResultEvent,
        EventType.ERROR: ErrorEvent,
        EventType.FINAL_REPORT: FinalReportEvent,
    }

    if event_type not in event_map:
        raise ValueError(f"Unknown event type: {event_type}")

    return event_map[event_type](**event_data)


def validate_tool_run_request(request_data: Dict[str, Any]) -> ToolRunRequest:
    """Validate tool runner request"""
    return ToolRunRequest(**request_data)


def validate_authorization(auth_data: Dict[str, Any]) -> Authorization:
    """Validate authorization structure"""
    return Authorization(**auth_data)


def validate_assessment_plan(plan_data: Dict[str, Any]) -> AssessmentPlan:
    """Validate assessment plan"""
    return AssessmentPlan(**plan_data)