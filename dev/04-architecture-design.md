# RAID Architecture Design

## System Overview

RAID is a containerized, agentic security assessment framework built around an MCP (Model Context Protocol) server architecture. The system provides authorized, auditable security assessments with human-in-the-loop controls and real-time streaming capabilities.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                RAID Framework                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐ │
│  │   Controller    │    │   MCP Server    │    │      Tool Runners           │ │
│  │                 │    │                 │    │                             │ │
│  │ • CLI Interface │────│ • Tool Registry │────│ • HTTP Fetcher              │ │
│  │ • Executor      │    │ • Tool Discovery│    │ • Playwright Browser        │ │
│  │ • Planner       │    │ • Synthesis API │    │ • Security Scanner          │ │
│  │ • Synthesizer   │    │ • Event Stream  │    │ • Custom Synthesized Tools  │ │
│  │ • Role Loader   │    │ • FastMCP Core  │    │ • Hardware Tools (USB)      │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────────┘ │
│           │                       │                          │                  │
│           │                       │                          │                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐ │
│  │   Streaming UI  │    │ Security Layer  │    │     Artifact Storage        │ │
│  │                 │    │                 │    │                             │ │
│  │ • Terminal TUI  │    │ • Authorization │    │ • NDJSON Logs               │ │
│  │ • Web Interface │    │ • Signing       │    │ • Evidence Files            │ │
│  │ • WebSocket/SSE │    │ • Audit Trail   │    │ • Run Manifests             │ │
│  │ • Approval UI   │    │ • Network Isol  │    │ • Cryptographic Signatures  │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────────┘ │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Controller Layer

The Controller layer is the main orchestration engine that manages the entire assessment lifecycle.

#### 1.1 CLI Interface (`controller/cli.py`)
```python
# Command Structure
raid dry-run --role web-pentest --target example.com --auth auth.json
raid run --role web-pentest --target example.com --auth auth.json
raid pause --run-id <uuid>
raid resume --run-id <uuid>
raid approve --run-id <uuid> --approval "Continue with scan"
raid replay --artifact results/run-123.tar.gz
raid verify --artifact results/run-123.tar.gz
```

**Responsibilities**:
- Parse command-line arguments
- Validate inputs and configurations
- Route commands to appropriate controller functions
- Handle user interactions and approvals

#### 1.2 Executor (`controller/executor.py`)
```python
class ExecutionEngine:
    async def execute_plan(self, plan: Plan, auth: Authorization) -> RunResult:
        # Main execution loop
        # - Phase management
        # - Tool orchestration
        # - Streaming coordination
        # - Approval handling
```

**Responsibilities**:
- Orchestrate plan execution across phases
- Manage tool lifecycle (start, monitor, stop)
- Handle pause/resume operations
- Coordinate streaming events
- Implement approval workflows
- Generate run artifacts

#### 1.3 Planner (`controller/planner.py`)
```python
class AssessmentPlanner:
    def generate_plan(self, role: Role, target: str, auth: Authorization) -> Plan:
        # LLM-based plan generation
        # - Role analysis
        # - Target scoping
        # - Tool selection
        # - Phase sequencing
```

**Responsibilities**:
- Generate assessment plans using LLM
- Validate plans against role constraints
- Optimize tool usage and sequencing
- Handle plan modifications and re-planning

#### 1.4 Synthesizer (`controller/synthesizer.py`)
```python
class ToolSynthesizer:
    async def synthesize_tool(self, requirements: str) -> SynthesizedTool:
        # Tool synthesis pipeline
        # - Code generation
        # - Dockerfile creation
        # - Sandbox validation
        # - Registration
```

**Responsibilities**:
- Generate custom tools based on requirements
- Create Docker containers for tools
- Validate tools in sandbox environment
- Register validated tools in MCP registry

### 2. MCP Server Layer

The MCP Server layer provides the capability hub and tool registry using FastMCP 2.0.

#### 2.1 MCP Server (`mcp/server.py`)
```python
from fastmcp import FastMCP

mcp = FastMCP("raid-security-assessment")

@mcp.tool
async def discover_tools(category: str) -> List[ToolMetadata]:
    """Discover available tools by category"""

@mcp.tool
async def execute_tool(tool_id: str, params: dict) -> ToolResult:
    """Execute a tool with given parameters"""

@mcp.tool
async def synthesize_tool(requirements: str) -> str:
    """Create a new tool based on requirements"""
```

**Responsibilities**:
- Expose tool discovery and execution via MCP protocol
- Handle tool synthesis requests
- Manage tool lifecycle and state
- Stream execution events and logs
- Provide authentication and authorization

#### 2.2 Registry Store (`mcp/registry_store.py`)
```python
class ToolRegistry:
    def __init__(self, persistence_path: str):
        # In-memory registry with disk persistence

    async def register_tool(self, tool: ToolMetadata) -> str:
        # Register new tool

    async def discover_tools(self, filters: dict) -> List[ToolMetadata]:
        # Discover tools by filters

    async def get_tool(self, tool_id: str) -> ToolMetadata:
        # Get specific tool metadata
```

**Responsibilities**:
- Maintain tool registry with persistence
- Handle tool discovery and filtering
- Manage tool metadata and versions
- Provide tool availability and status

### 3. Tool Runner Layer

The Tool Runner layer contains containerized tools that perform specific security assessment tasks.

#### 3.1 HTTP Fetcher (`tool-runners/http_fetcher/app.py`)
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/run', methods=['POST'])
def run_tool():
    # Validate inputs against run context
    # Execute HTTP requests with security controls
    # Collect evidence and write to mounted path
    # Return structured results
```

**Base Tool Runner Interface**:
- POST /run endpoint for execution
- Input validation against run context
- Evidence collection to mounted volumes
- Structured JSON response format
- Logging to stdout for streaming

#### 3.2 Playwright Browser Tool
```python
# Integration with Microsoft Playwright MCP
from playwright import async_playwright

class PlaywrightSecurityTool:
    async def scan_web_app(self, url: str, scan_types: List[str]) -> ScanResult:
        # Browser-based security scanning
        # XSS detection
        # SQL injection testing
        # Screenshot evidence collection
```

#### 3.3 Synthesized Tools
```python
# Dynamically generated tools follow standard interface
class SynthesizedTool:
    def __init__(self, requirements: str, template: str):
        # Generated from requirements and templates

    async def execute(self, params: dict) -> ToolResult:
        # Custom implementation based on synthesis
```

### 4. Streaming UI Layer

The Streaming UI layer provides real-time monitoring and interaction capabilities.

#### 4.1 Terminal UI (`ui/terminal_ui.py`)
```python
class TerminalStreamer:
    def __init__(self, run_id: str):
        # Connect to event stream

    async def start_streaming(self):
        # Display real-time logs and events
        # Handle keyboard input for controls
        # Show approval prompts
```

**Features**:
- Real-time log streaming
- Interactive controls (p=pause, r=resume, a=approve, q=quit)
- Status indicators and progress bars
- Color-coded event types

#### 4.2 Web UI (`ui/web_ui.py`)
```python
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles

app = FastAPI()

@app.websocket("/ws/{run_id}")
async def websocket_endpoint(websocket: WebSocket, run_id: str):
    # Handle WebSocket connections for streaming

@app.post("/api/approve/{run_id}")
async def submit_approval(run_id: str, approval: ApprovalRequest):
    # Handle approval submissions
```

**Features**:
- WebSocket-based real-time streaming
- Minimal HTML/JS client interface
- Approval form and chat interface
- Event history and replay

### 5. Security Layer

The Security layer provides comprehensive security controls and audit capabilities.

#### 5.1 Authorization (`controller/auth.py`)
```python
class AuthorizationManager:
    def validate_auth(self, auth_file: str) -> Authorization:
        # Validate signed authorization files

    def check_permissions(self, action: str, context: RunContext) -> bool:
        # Check action permissions against auth

    def require_approval(self, action: str) -> bool:
        # Determine if action requires human approval
```

#### 5.2 Signing (`controller/signing.py`)
```python
from cryptography.hazmat.primitives.asymmetric import ed25519

class ArtifactSigner:
    def __init__(self, private_key_path: str):
        # Load Ed25519 private key

    def sign_artifact(self, artifact_path: str) -> str:
        # Sign artifact and return signature

    def verify_signature(self, artifact_path: str, signature: str) -> bool:
        # Verify artifact signature
```

#### 5.3 Network Isolation
```python
class NetworkPolicy:
    def __init__(self, allowed_cidrs: List[str]):
        # Configure network restrictions

    def validate_request(self, target: str) -> bool:
        # Validate target against allowed CIDRs
```

### 6. Artifact Storage Layer

The Artifact Storage layer handles evidence collection, logging, and audit trail generation.

#### 6.1 NDJSON Streaming (`controller/artifacts.py`)
```python
class NDJSONStreamer:
    def __init__(self, output_path: str):
        # Initialize streaming NDJSON writer

    async def append_event(self, event: Event):
        # Append event to NDJSON file

    async def finalize_run(self, manifest: RunManifest):
        # Complete run and generate final artifacts
```

#### 6.2 Evidence Collection
```python
class EvidenceCollector:
    def __init__(self, evidence_dir: str):
        # Initialize evidence collection

    async def collect_file(self, source: str, metadata: dict):
        # Collect file evidence with metadata

    async def collect_screenshot(self, image_data: bytes, context: dict):
        # Collect screenshot evidence
```

## Data Flow Architecture

### 1. Assessment Execution Flow
```
1. CLI Command → Controller → Authorization Validation
2. Controller → Role Loader → Load Assessment Role
3. Controller → Planner → Generate Assessment Plan
4. Controller → Executor → Begin Phase Execution
5. Executor → MCP Server → Discover Required Tools
6. MCP Server → Tool Registry → Find or Synthesize Tools
7. Executor → Tool Runners → Execute Assessment Tools
8. Tool Runners → Evidence Collector → Collect Results
9. Executor → Streaming UI → Stream Real-time Events
10. Executor → Artifact Generator → Create Signed Artifacts
```

### 2. Streaming Event Flow
```
Tool Execution → Event Generation → NDJSON Append → UI Updates
      ↓                ↓               ↓            ↓
   stdout logs     event objects   file writes   WebSocket/SSE
```

### 3. Approval Flow
```
Executor → Approval Required → UI Notification → Human Decision → Approval API → Continue/Stop
```

## Container Architecture

### 1. Service Composition
```yaml
# docker-compose.dev.yaml
services:
  controller:
    build: ./controller
    volumes:
      - ./results:/app/results
      - ./auth:/app/auth
    depends_on:
      - mcp-server

  mcp-server:
    build: ./mcp
    ports:
      - "8000:8000"
    volumes:
      - ./tool-registry:/app/registry

  tool-runner-http:
    build: ./tool-runners/http_fetcher
    volumes:
      - ./evidence:/app/evidence
    network_mode: "service:controller"

  tool-runner-playwright:
    build: ./tool-runners/playwright
    volumes:
      - ./evidence:/app/evidence
    # Device passthrough example (commented)
    # devices:
    #   - "/dev/bus/usb/001/004:/dev/bus/usb/001/004"
```

### 2. Security Isolation
- Each tool runner in separate container
- Network policies restrict tool access
- Volume mounts limit file access
- Resource limits prevent resource exhaustion
- AppArmor/SELinux profiles for additional isolation

### 3. Device Passthrough
```bash
# USB Wi-Fi adapter passthrough example
docker run --device=/dev/bus/usb/001/004 raid-wifi-tool
```

## API Specifications

### 1. MCP Server API (FastMCP)
```python
# Tool Discovery
GET /tools?category=security&target_type=web

# Tool Execution
POST /tools/{tool_id}/execute
{
  "params": {...},
  "run_context": {...}
}

# Tool Synthesis
POST /tools/synthesize
{
  "requirements": "Create a tool to check HTTP headers",
  "template": "flask-tool"
}

# Event Streaming
WebSocket /events/{run_id}
```

### 2. Controller API
```python
# Run Management
POST /api/runs
GET /api/runs/{run_id}
POST /api/runs/{run_id}/pause
POST /api/runs/{run_id}/resume

# Approval Management
POST /api/runs/{run_id}/approve
GET /api/runs/{run_id}/approvals

# Artifact Management
GET /api/runs/{run_id}/artifacts
GET /api/runs/{run_id}/evidence
```

### 3. Tool Runner API
```python
# Standard interface for all tool runners
POST /run
{
  "action": "fetch",
  "params": {...},
  "run_context": {
    "authorized": true,
    "scope": ["192.168.1.0/24"],
    "evidence_path": "/app/evidence"
  }
}

Response:
{
  "status": "success",
  "result": {...},
  "evidence_refs": ["evidence/screenshot-123.png"],
  "execution_time": 5.2
}
```

## Security Architecture

### 1. Defense in Depth
- **Authorization Layer**: Signed auth files, role-based permissions
- **Network Layer**: CIDR restrictions, isolated containers
- **Container Layer**: Resource limits, security profiles
- **Application Layer**: Input validation, output sanitization
- **Cryptographic Layer**: Ed25519 signing, artifact verification

### 2. Threat Model
- **Malicious Tools**: Sandbox validation, static analysis
- **Network Attacks**: Network isolation, target validation
- **Container Escape**: Security profiles, privilege dropping
- **Data Exfiltration**: Evidence encryption, audit trails
- **Privilege Escalation**: Non-root containers, capability restrictions

### 3. Audit and Compliance
- **Complete Audit Trail**: Every action logged and signed
- **Evidence Chain**: Cryptographic verification of evidence
- **Regulatory Compliance**: Structured reporting for compliance
- **Incident Response**: Kill switches and emergency procedures

This architecture provides a robust, secure, and scalable foundation for the RAID security assessment framework while maintaining simplicity and ease of use.