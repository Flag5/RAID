# RAID Project Overview

## Project Name
**RAID**: Agentic, Containerized Security Assessment Framework

## Core Mission
Build a minimal, well-structured prototype that uses an MCP server plus tool-runners to perform authorized, auditable security assessments with human-in-the-loop controls.

## Key Capabilities (Delta Class)
1. **Planner** → Tool Discovery → Tool Synthesis → Tool Execution → Evidence Collection → Signed Artifact
2. **Interactive Controls** - Human-in-the-loop approvals and runtime steering
3. **Real-time Streaming** - Terminal and Web UI for live monitoring
4. **Device Passthrough** - USB Wi-Fi adapter support with host protection
5. **Tool Synthesis** - Create and validate tools on-demand in sandbox

## Safety-First Design
- ✅ Explicit authorization required for all runs
- ✅ Human approval for destructive actions
- ✅ Containerized tool isolation
- ✅ Network egress restrictions
- ✅ Static analysis and sandbox testing for synthesized tools
- ✅ Kill switch and heartbeat monitoring
- ✅ Signed audit trails

## Architecture Overview
```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Controller        │    │   MCP Server        │    │   Tool Runners      │
│   - CLI Interface   │────│   - Tool Registry   │────│   - HTTP Fetcher    │
│   - Executor        │    │   - Tool Discovery  │    │   - Synthesized     │
│   - Planner         │    │   - Event Streaming │    │   - Hardware Tools  │
│   - Synthesizer     │    │                     │    │                     │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
          │                          │                          │
          │                          │                          │
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Streaming UI      │    │   Device Support    │    │   Security Layer    │
│   - Terminal TUI    │    │   - USB Passthrough │    │   - Signing         │
│   - Web Interface   │    │   - Host Protection │    │   - Authorization   │
│   - Real-time Logs  │    │                     │    │   - Evidence Chain  │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

## Repository Status
- **Current Phase**: Planning and Documentation
- **Next Phase**: Core Implementation
- **Target**: Functional prototype with all safety measures

## Documentation Structure
- `dev/` - Development documentation and planning
- `specs/` - Technical specifications
- `docs/` - User documentation
- `examples/` - Usage examples and tutorials

## Development Approach
1. **Safety First** - All security measures implemented from start
2. **Incremental** - Build and test each component independently
3. **Well Documented** - Every decision and design choice recorded
4. **Claude-Friendly** - Structured for easy AI assistance and context