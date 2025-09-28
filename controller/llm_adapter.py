"""
RAID LLM Adapter Interface
Robust adapter for LLM integration with validation and fallback mechanisms
"""

import json
import time
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import logging

from specs.schemas import AssessmentPlan, validate_assessment_plan


logger = logging.getLogger(__name__)


class LLMProvider(str, Enum):
    """Supported LLM providers"""
    MOCK = "mock"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    GOOGLE = "google"
    LOCAL = "local"


class ValidationResult(str, Enum):
    """LLM response validation results"""
    VALID = "valid"
    INVALID_JSON = "invalid_json"
    INVALID_SCHEMA = "invalid_schema"
    MISSING_REQUIRED = "missing_required"
    SECURITY_VIOLATION = "security_violation"


@dataclass
class LLMRequest:
    """LLM request metadata"""
    request_id: str
    timestamp: datetime
    model: str
    prompt: str
    parameters: Dict[str, Any]
    context_size: int
    estimated_tokens: int


@dataclass
class LLMResponse:
    """LLM response with metadata"""
    request_id: str
    response_id: str
    timestamp: datetime
    content: str
    model: str

    # Token usage
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    # Quality metrics
    response_time_seconds: float = 0.0
    confidence_score: Optional[float] = None

    # Validation
    validation_result: ValidationResult = ValidationResult.VALID
    validation_errors: List[str] = None

    def __post_init__(self):
        if self.validation_errors is None:
            self.validation_errors = []


class LLMAdapter(ABC):
    """Abstract base class for LLM adapters"""

    def __init__(self, provider: LLMProvider, config: Dict[str, Any]):
        self.provider = provider
        self.config = config
        self.request_history: List[LLMRequest] = []
        self.response_history: List[LLMResponse] = []

    @abstractmethod
    async def generate_plan(
        self,
        role: str,
        target: str,
        role_definition: Dict[str, Any],
        authorization: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> LLMResponse:
        """Generate assessment plan"""
        pass

    @abstractmethod
    async def replan(
        self,
        original_plan: AssessmentPlan,
        execution_context: Dict[str, Any],
        human_feedback: Optional[str] = None
    ) -> LLMResponse:
        """Re-plan based on execution context and feedback"""
        pass

    @abstractmethod
    async def synthesize_tool(
        self,
        requirements: str,
        context: Dict[str, Any]
    ) -> LLMResponse:
        """Generate tool synthesis instructions"""
        pass

    def _log_request(self, request: LLMRequest):
        """Log LLM request"""
        self.request_history.append(request)
        logger.info(f"LLM request {request.request_id}: {request.model}")

    def _log_response(self, response: LLMResponse):
        """Log LLM response"""
        self.response_history.append(response)
        logger.info(
            f"LLM response {response.response_id}: "
            f"tokens={response.total_tokens}, "
            f"time={response.response_time_seconds:.2f}s, "
            f"validation={response.validation_result}"
        )


class PlanValidator:
    """Validates LLM-generated assessment plans"""

    @staticmethod
    def validate_plan_response(content: str, context: Dict[str, Any]) -> LLMResponse:
        """Validate plan generation response"""
        response = LLMResponse(
            request_id=context.get("request_id", "unknown"),
            response_id=f"resp_{int(time.time())}",
            timestamp=datetime.utcnow(),
            content=content,
            model=context.get("model", "unknown")
        )

        # Step 1: JSON parsing
        try:
            plan_data = json.loads(content)
        except json.JSONDecodeError as e:
            response.validation_result = ValidationResult.INVALID_JSON
            response.validation_errors = [f"JSON parsing failed: {str(e)}"]
            return response

        # Step 2: Schema validation
        try:
            plan = validate_assessment_plan(plan_data)
        except Exception as e:
            response.validation_result = ValidationResult.INVALID_SCHEMA
            response.validation_errors = [f"Schema validation failed: {str(e)}"]
            return response

        # Step 3: Security validation
        security_errors = PlanValidator._validate_plan_security(plan, context)
        if security_errors:
            response.validation_result = ValidationResult.SECURITY_VIOLATION
            response.validation_errors = security_errors
            return response

        # Step 4: Completeness validation
        completeness_errors = PlanValidator._validate_plan_completeness(plan, context)
        if completeness_errors:
            response.validation_result = ValidationResult.MISSING_REQUIRED
            response.validation_errors = completeness_errors
            return response

        response.validation_result = ValidationResult.VALID
        return response

    @staticmethod
    def _validate_plan_security(plan: AssessmentPlan, context: Dict[str, Any]) -> List[str]:
        """Validate plan against security constraints"""
        errors = []
        authorization = context.get("authorization", {})

        # Check tool authorization
        allowed_tools = authorization.get("allowed_tools", [])
        forbidden_tools = authorization.get("forbidden_tools", [])

        for phase in plan.phases:
            for action in phase.actions:
                if allowed_tools and action.tool not in allowed_tools:
                    errors.append(f"Tool '{action.tool}' not in allowed tools list")

                if action.tool in forbidden_tools:
                    errors.append(f"Tool '{action.tool}' is explicitly forbidden")

        # Check destructive actions
        if not authorization.get("allow_destructive", False):
            destructive_patterns = ["delete", "modify", "exploit", "attack"]
            for phase in plan.phases:
                for pattern in destructive_patterns:
                    if pattern.lower() in phase.intent.lower():
                        errors.append(f"Destructive action detected in phase: {phase.name}")

        # Check target scope
        scope = authorization.get("scope", {})
        target_cidrs = scope.get("target_cidrs", [])
        target_domains = scope.get("target_domains", [])
        plan_target = context.get("target", "")

        if (target_cidrs or target_domains) and plan_target:
            # Check against CIDR blocks (for IP addresses)
            cidr_authorized = any(
                plan_target in cidr or "0.0.0.0/0" in target_cidrs
                for cidr in target_cidrs
            )

            # Check against domain allowlist
            domain_authorized = any(
                plan_target == domain or plan_target.endswith('.' + domain)
                for domain in target_domains
            )

            if not (cidr_authorized or domain_authorized):
                errors.append(f"Target '{plan_target}' not in authorized scope")

        return errors

    @staticmethod
    def _validate_plan_completeness(plan: AssessmentPlan, context: Dict[str, Any]) -> List[str]:
        """Validate plan completeness"""
        errors = []

        # Required fields
        if not plan.run_id:
            errors.append("Missing run_id")

        if not plan.phases:
            errors.append("Plan must contain at least one phase")

        # Phase validation
        for i, phase in enumerate(plan.phases):
            if not phase.phase_id:
                errors.append(f"Phase {i} missing phase_id")

            if not phase.actions:
                errors.append(f"Phase '{phase.name}' must contain at least one action")

            # Action validation
            for j, action in enumerate(phase.actions):
                if not action.tool:
                    errors.append(f"Action {j} in phase '{phase.name}' missing tool")

                if not action.params:
                    errors.append(f"Action {j} in phase '{phase.name}' missing params")

        # Dependency validation
        phase_ids = {phase.phase_id for phase in plan.phases}
        for phase in plan.phases:
            for dep_id in phase.depends_on_phases:
                if dep_id not in phase_ids:
                    errors.append(f"Phase '{phase.name}' depends on unknown phase '{dep_id}'")

        return errors


class MockLLMAdapter(LLMAdapter):
    """Mock LLM adapter for testing"""

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(LLMProvider.MOCK, config or {})
        self.responses = config.get("responses", {}) if config else {}
        self.should_fail = config.get("should_fail", False) if config else False
        self.response_delay = config.get("response_delay", 0.1) if config else 0.1

    async def generate_plan(
        self,
        role: str,
        target: str,
        role_definition: Dict[str, Any],
        authorization: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> LLMResponse:
        """Generate mock assessment plan"""
        request_id = f"req_{int(time.time())}"

        request = LLMRequest(
            request_id=request_id,
            timestamp=datetime.utcnow(),
            model="mock-planner-v1",
            prompt=f"Generate plan for {role} targeting {target}",
            parameters={"temperature": 0.1, "max_tokens": 2000},
            context_size=len(str(role_definition)) + len(str(authorization)),
            estimated_tokens=500
        )
        self._log_request(request)

        # Simulate processing time
        import asyncio
        await asyncio.sleep(self.response_delay)

        if self.should_fail:
            content = '{"error": "Mock LLM failure"}'
        else:
            # Generate deterministic mock plan
            content = self._generate_mock_plan(role, target, role_definition, authorization)

        response = PlanValidator.validate_plan_response(
            content=content,
            context={
                "request_id": request_id,
                "model": "mock-planner-v1",
                "authorization": authorization,
                "target": target
            }
        )

        response.prompt_tokens = 100
        response.completion_tokens = 400
        response.total_tokens = 500
        response.response_time_seconds = self.response_delay

        self._log_response(response)
        return response

    async def replan(
        self,
        original_plan: AssessmentPlan,
        execution_context: Dict[str, Any],
        human_feedback: Optional[str] = None
    ) -> LLMResponse:
        """Generate mock replan"""
        request_id = f"req_{int(time.time())}"

        request = LLMRequest(
            request_id=request_id,
            timestamp=datetime.utcnow(),
            model="mock-planner-v1",
            prompt=f"Replan assessment {original_plan.run_id}",
            parameters={"temperature": 0.1, "max_tokens": 2000},
            context_size=len(str(original_plan)),
            estimated_tokens=600
        )
        self._log_request(request)

        await asyncio.sleep(self.response_delay)

        # Mock replan - just modify original
        new_plan = original_plan.model_copy()
        new_plan.run_id = f"replan_{original_plan.run_id}"
        if human_feedback:
            # Add feedback as new phase
            new_phase = {
                "phase_id": f"feedback_phase_{int(time.time())}",
                "name": "Human Feedback Integration",
                "intent": f"Address feedback: {human_feedback}",
                "allowed_tools": ["http-fetcher"],
                "actions": [{
                    "action_id": f"action_{int(time.time())}",
                    "tool": "http-fetcher",
                    "params": {"action": "feedback_integration", "feedback": human_feedback},
                    "timeout_seconds": 300
                }],
                "requires_approval": False,
                "estimated_runtime_seconds": 300
            }
            new_plan.phases.append(new_phase)

        content = new_plan.model_dump_json()

        response = PlanValidator.validate_plan_response(
            content=content,
            context={
                "request_id": request_id,
                "model": "mock-planner-v1",
                "authorization": execution_context.get("authorization", {}),
                "target": execution_context.get("target", "")
            }
        )

        response.prompt_tokens = 200
        response.completion_tokens = 500
        response.total_tokens = 700
        response.response_time_seconds = self.response_delay

        self._log_response(response)
        return response

    async def synthesize_tool(
        self,
        requirements: str,
        context: Dict[str, Any]
    ) -> LLMResponse:
        """Generate mock tool synthesis"""
        request_id = f"req_{int(time.time())}"

        request = LLMRequest(
            request_id=request_id,
            timestamp=datetime.utcnow(),
            model="mock-synthesizer-v1",
            prompt=f"Synthesize tool: {requirements}",
            parameters={"temperature": 0.2, "max_tokens": 3000},
            context_size=len(requirements) + len(str(context)),
            estimated_tokens=800
        )
        self._log_request(request)

        await asyncio.sleep(self.response_delay * 2)  # Synthesis takes longer

        tool_spec = {
            "tool_name": "custom_tool",
            "description": requirements,
            "code": self._generate_mock_tool_code(requirements),
            "dockerfile": self._generate_mock_dockerfile(),
            "requirements": ["requests", "pydantic"],
            "security_level": "standard"
        }

        content = json.dumps(tool_spec, indent=2)

        response = LLMResponse(
            request_id=request_id,
            response_id=f"resp_{int(time.time())}",
            timestamp=datetime.utcnow(),
            content=content,
            model="mock-synthesizer-v1",
            prompt_tokens=300,
            completion_tokens=700,
            total_tokens=1000,
            response_time_seconds=self.response_delay * 2,
            validation_result=ValidationResult.VALID
        )

        self._log_response(response)
        return response

    def _generate_mock_plan(
        self,
        role: str,
        target: str,
        role_definition: Dict[str, Any],
        authorization: Dict[str, Any]
    ) -> str:
        """Generate deterministic mock plan"""
        plan = {
            "run_id": f"mock_run_{hashlib.md5(f'{role}_{target}'.encode()).hexdigest()[:8]}",
            "plan_version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "role": role,
            "target": target,
            "assessment_type": "security_assessment",
            "phases": [
                {
                    "phase_id": "phase_reconnaissance",
                    "name": "Reconnaissance",
                    "intent": f"Gather information about target {target}",
                    "allowed_tools": ["http-fetcher", "dns-lookup"],
                    "actions": [
                        {
                            "action_id": "action_http_probe",
                            "tool": "http-fetcher",
                            "params": {
                                "action": "fetch",
                                "url": f"http://{target}",
                                "method": "GET"
                            },
                            "timeout_seconds": 30
                        }
                    ],
                    "requires_approval": False,
                    "estimated_runtime_seconds": 60
                }
            ],
            "total_estimated_runtime": 60,
            "llm_model": "mock-planner-v1",
            "llm_request_id": f"req_{int(time.time())}"
        }

        return json.dumps(plan, indent=2)

    def _generate_mock_tool_code(self, requirements: str) -> str:
        """Generate mock tool code"""
        return f'''
"""
Generated tool: {requirements}
"""

import logging
from typing import Dict, Any
from specs.schemas import ToolRunRequest, ToolRunResult

logger = logging.getLogger(__name__)

def execute_tool(request: ToolRunRequest) -> ToolRunResult:
    """Execute custom tool based on requirements"""
    logger.info(f"Executing tool for: {requirements}")

    # Mock implementation
    result = {{
        "status": "completed",
        "message": "Tool executed successfully",
        "requirements": "{requirements}"
    }}

    return ToolRunResult(
        status="completed",
        result=result,
        execution_time_seconds=1.0
    )
'''

    def _generate_mock_dockerfile(self) -> str:
        """Generate mock Dockerfile"""
        return '''
FROM python:3.11-alpine

RUN addgroup -g 1000 tooluser && \\
    adduser -D -s /bin/sh -u 1000 -G tooluser tooluser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R tooluser:tooluser /app

USER tooluser
ENTRYPOINT ["python", "tool.py"]
'''


class LLMAdapterFactory:
    """Factory for creating LLM adapters"""

    @staticmethod
    def create_adapter(provider: LLMProvider, config: Dict[str, Any]) -> LLMAdapter:
        """Create appropriate LLM adapter"""
        if provider == LLMProvider.MOCK:
            return MockLLMAdapter(config)
        elif provider == LLMProvider.OPENAI:
            # TODO: Implement OpenAI adapter
            raise NotImplementedError("OpenAI adapter not yet implemented")
        elif provider == LLMProvider.ANTHROPIC:
            # TODO: Implement Anthropic adapter
            raise NotImplementedError("Anthropic adapter not yet implemented")
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")


class LLMAdapterWithFallback:
    """LLM adapter with validation and fallback mechanisms"""

    def __init__(self, primary_adapter: LLMAdapter, fallback_adapter: Optional[LLMAdapter] = None):
        self.primary_adapter = primary_adapter
        self.fallback_adapter = fallback_adapter or MockLLMAdapter()
        self.max_retries = 3
        self.retry_delay = 1.0

    async def generate_plan_with_fallback(
        self,
        role: str,
        target: str,
        role_definition: Dict[str, Any],
        authorization: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> LLMResponse:
        """Generate plan with validation and fallback"""

        for attempt in range(self.max_retries):
            try:
                # Try primary adapter
                response = await self.primary_adapter.generate_plan(
                    role, target, role_definition, authorization, context
                )

                if response.validation_result == ValidationResult.VALID:
                    return response

                logger.warning(
                    f"Primary adapter validation failed (attempt {attempt + 1}): "
                    f"{response.validation_result}, errors: {response.validation_errors}"
                )

            except Exception as e:
                logger.error(f"Primary adapter failed (attempt {attempt + 1}): {str(e)}")

            # Wait before retry
            if attempt < self.max_retries - 1:
                import asyncio
                await asyncio.sleep(self.retry_delay * (attempt + 1))

        # Fallback to mock adapter
        logger.warning("Primary adapter failed, using fallback")
        return await self.fallback_adapter.generate_plan(
            role, target, role_definition, authorization, context
        )