# Requirements Analysis

## High-Level Requirements

### 1. MCP Server as Capability Hub
- **Requirement**: MCP server runs as service inside container environment
- **Purpose**: Acts as capability hub and registry for tools
- **Implementation**: FastAPI-based server with tool discovery, synthesis, and execution endpoints

### 2. Real-time Streaming UI
- **Terminal UI**: Claude Code style streaming of planner output, tool logs, NDJSON events
- **Web UI**: WebSocket/SSE for streaming events from controller
- **Requirements**: Live updates, interactive controls, pause/resume/approve

### 3. Human-in-the-Loop Controls
- **Checkpoints**: Controller pauses at approval points
- **Approval Flow**: CLI accepts approvals and ad-hoc instructions
- **Integration**: Instructions inserted into ongoing plan and trigger replanning

### 4. Device Passthrough Support
- **USB Device Support**: Wi-Fi adapter passthrough via docker compose
- **Security**: No host-root requirement for container
- **Documentation**: Safe host steps with strong warnings

### 5. Streaming Logs & Persistent Artifacts
- **NDJSON Format**: Plan + sequential records, evidence files
- **Live Updates**: Streaming data appended as events occur
- **Artifacts**: Run manifest and signatures for each execution

### 6. Tool Synthesis Pipeline
- **On-Demand Creation**: Small tools created as needed
- **Validation**: Offline sandbox validation before registration
- **Safety**: Static checks and unit tests required

### 7. Simple CLI Interface
- **Commands**: `raid run`, `raid dry-run`, `raid pause`, `raid resume`, `raid approve`, `raid replay`, `raid verify`
- **User Experience**: Intuitive and consistent

## Safety Requirements (MUST HAVE)

### 1. Authorization Framework
- **Explicit Auth**: Destructive actions require explicit authorization
- **Manual Confirmation**: Human approval step during run
- **Validation**: `allow_destructive: true` in auth configuration

### 2. Tool Validation Pipeline
- **Static Analysis**: Synthesized tools pass static checks
- **Unit Testing**: Tools tested in offline sandbox
- **Approval Gate**: Only validated tools touch live targets

### 3. Device Security
- **Explicit Passthrough**: Manual operator device attachment
- **Documentation**: Host prerequisites and permissions documented
- **Privilege Warnings**: Clear warnings about host-level privileges

### 4. Network Isolation
- **CIDR Restrictions**: Tool containers restricted to target CIDRs
- **Controller Enforcement**: Network isolation enforced by controller
- **Egress Control**: No unauthorized network access

### 5. Emergency Controls
- **Kill Switch**: Always available emergency stop
- **Heartbeat Monitoring**: Lost heartbeat triggers container kill
- **Evidence Snapshot**: Evidence preserved on emergency stop

### 6. Code Security
- **No Remote Fetching**: Generated tools cannot fetch remote code at runtime
- **Local Code Only**: All code present locally or synthesized locally
- **Runtime Isolation**: No dynamic code loading from external sources

## Acceptance Criteria

### 1. Build System
- **Makefile Targets**: build, up, test, lint, clean
- **Container Support**: Docker compose environment
- **Development Workflow**: Complete dev-to-test pipeline

### 2. CLI Functionality
- **Dry-run Mode**: Produces signed NDJSON plan file
- **Full Run Mode**: Executes plan while streaming events
- **Command Set**: All specified commands functional

### 3. MCP Server Implementation
- **Tool Discovery**: Endpoint for finding available tools
- **Synthesis Requests**: Tool creation and validation
- **Run-tool Proxy**: Execute tools and stream results
- **Event Streaming**: Real-time event distribution

### 4. Tool Runner Example
- **HTTP Fetcher**: POST /run endpoint with input validation
- **Evidence Writing**: Structured output to mounted evidence path
- **Security Validation**: URL validation against run context scope

### 5. Interactive UI Requirements
- **Terminal Streaming**: Live plan, LLM messages, tool outputs
- **Web UI**: WebSocket/SSE streaming with chat interface
- **Approval Interface**: Request and handle approvals

### 6. Device Passthrough Example
- **USB Wi-Fi Example**: Complete docker compose example
- **Documentation**: Safe host operations guide
- **Security Emphasis**: No privileged access required for normal operations

### 7. Synthesis Pipeline
- **Python Tool Runners**: Build Python tool-runner images
- **Offline Testing**: Linters and unit tests in sandbox
- **Registration**: Only validated tools registered

### 8. Artifact Generation
- **NDJSON Output**: Incremental appends during run
- **Signed Manifest**: Final signed manifest with run metadata
- **Evidence Chain**: Complete audit trail

### 9. Testing Requirements
- **Unit Tests**: pytest for role validation, controller dry-run, tool-runner API
- **Integration Tests**: Pause/approve flow with mock UI signals
- **Mock LLM**: Test-friendly LLM adapter

### 10. LLM Integration
- **Minimal Adapter**: MockLLM for tests, swappable for real providers
- **Provider Agnostic**: Easy to switch between LLM providers

## Technical Constraints

### Language & Framework
- **Python**: Primary language for controller and tools
- **FastAPI**: Web framework for MCP server and APIs
- **Docker**: Containerization platform
- **WebSockets**: Real-time communication

### Security Constraints
- **No Root**: Containers don't require host root privileges
- **Sandbox Testing**: All synthesis in isolated environment
- **Network Restrictions**: Configurable network policies
- **Signed Artifacts**: Cryptographic verification of all outputs

### Performance Constraints
- **Real-time Streaming**: Sub-second latency for UI updates
- **Scalability**: Handle multiple concurrent tool executions
- **Resource Limits**: Configurable limits for tool containers

### Integration Constraints
- **MCP Compatibility**: Follow MCP specification exactly
- **Docker Integration**: Standard docker compose workflow
- **CLI Standards**: Follow Unix CLI conventions