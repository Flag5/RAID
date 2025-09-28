#!/usr/bin/env python3
"""
RAID MCP Server
FastMCP-based server for tool discovery, synthesis, and execution
"""

import json
import asyncio
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Import RAID components
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from specs.schemas import ToolRunRequest, ToolRunResult, ToolRunContext, EvidenceReference
from controller.rbac import RBACManager, initialize_default_users
from controller.monitoring import RAIDMonitor

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Simple tool registry for MCP server"""

    def __init__(self, storage_path: str = "/tmp/raid-tools"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.tools: Dict[str, Dict[str, Any]] = {}
        self._load_default_tools()

    def _load_default_tools(self):
        """Load default tools into registry"""
        self.tools = {
            "http-fetcher": {
                "tool_id": "http-fetcher",
                "name": "HTTP Fetcher",
                "description": "Fetch HTTP resources and analyze responses",
                "version": "1.0.0",
                "category": "web",
                "capabilities": ["http_get", "http_post", "header_analysis"],
                "parameters": {
                    "url": {"type": "string", "required": True},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "default": {}},
                    "timeout": {"type": "integer", "default": 30}
                },
                "container_image": "raid/http-fetcher:latest",
                "network_requirements": ["egress_http", "egress_https"],
                "evidence_types": ["http_response", "headers", "screenshot"]
            },
            "port-scanner": {
                "tool_id": "port-scanner",
                "name": "Port Scanner",
                "description": "Network port scanning and service enumeration",
                "version": "1.0.0",
                "category": "network",
                "capabilities": ["tcp_scan", "udp_scan", "service_detection"],
                "parameters": {
                    "target": {"type": "string", "required": True},
                    "ports": {"type": "string", "default": "1-1000"},
                    "scan_type": {"type": "string", "default": "tcp"},
                    "timing": {"type": "string", "default": "normal"}
                },
                "container_image": "raid/port-scanner:latest",
                "network_requirements": ["egress_tcp", "egress_udp"],
                "evidence_types": ["port_scan", "service_info"]
            },
            "web-scanner": {
                "tool_id": "web-scanner",
                "name": "Web Application Scanner",
                "description": "Comprehensive web application security scanning",
                "version": "1.0.0",
                "category": "web",
                "capabilities": ["vuln_scan", "crawler", "auth_test"],
                "parameters": {
                    "base_url": {"type": "string", "required": True},
                    "scan_depth": {"type": "integer", "default": 3},
                    "include_paths": {"type": "array", "default": []},
                    "exclude_paths": {"type": "array", "default": []}
                },
                "container_image": "raid/web-scanner:latest",
                "network_requirements": ["egress_http", "egress_https"],
                "evidence_types": ["vulnerability_report", "crawl_data", "screenshots"]
            }
        }

    def discover_tools(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discover available tools"""
        tools = list(self.tools.values())

        if category:
            tools = [tool for tool in tools if tool.get("category") == category]

        return tools

    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """Get specific tool information"""
        return self.tools.get(tool_id)

    def register_tool(self, tool_metadata: Dict[str, Any]) -> bool:
        """Register a new tool"""
        tool_id = tool_metadata.get("tool_id")
        if not tool_id:
            return False

        self.tools[tool_id] = tool_metadata
        return True


class ConnectionManager:
    """Manage WebSocket connections for real-time updates"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        if self.active_connections:
            message_json = json.dumps(message)
            disconnected = []

            for connection in self.active_connections:
                try:
                    await connection.send_text(message_json)
                except:
                    disconnected.append(connection)

            # Remove disconnected clients
            for connection in disconnected:
                self.disconnect(connection)


class RAIDMCPServer:
    """RAID MCP Server implementation"""

    def __init__(self, config_dir: str = "/tmp/raid-mcp"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.tool_registry = ToolRegistry(str(self.config_dir / "tools"))
        self.rbac = RBACManager(str(self.config_dir / "auth"))
        self.monitor = RAIDMonitor(str(self.config_dir / "monitoring"))
        self.connection_manager = ConnectionManager()

        # Initialize default users
        if not self.rbac.users:
            initialize_default_users(self.rbac)

        # Setup FastAPI app
        self.app = FastAPI(
            title="RAID MCP Server",
            description="Model Context Protocol server for RAID security assessments",
            version="1.0.0"
        )

        self._setup_middleware()
        self._setup_routes()

    def _setup_middleware(self):
        """Setup FastAPI middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def _setup_routes(self):
        """Setup API routes"""

        @self.app.get("/")
        async def root():
            return {
                "service": "RAID MCP Server",
                "version": "1.0.0",
                "status": "running",
                "capabilities": ["tool_discovery", "tool_execution", "tool_synthesis"]
            }

        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "services": {
                    "tool_registry": "up",
                    "rbac": "up",
                    "monitoring": "up"
                }
            }

        @self.app.get("/tools")
        async def discover_tools(category: Optional[str] = None):
            """Discover available tools"""
            tools = self.tool_registry.discover_tools(category)
            return {"tools": tools}

        @self.app.get("/tools/{tool_id}")
        async def get_tool(tool_id: str):
            """Get specific tool information"""
            tool = self.tool_registry.get_tool(tool_id)
            if not tool:
                raise HTTPException(status_code=404, detail="Tool not found")
            return tool

        @self.app.post("/tools/{tool_id}/execute")
        async def execute_tool(tool_id: str, request: ToolRunRequest):
            """Execute a tool"""
            try:
                # Get tool metadata
                tool = self.tool_registry.get_tool(tool_id)
                if not tool:
                    raise HTTPException(status_code=404, detail="Tool not found")

                # Validate authorization
                if not request.run_context.authorized:
                    raise HTTPException(status_code=403, detail="Execution not authorized")

                # Simulate tool execution
                result = await self._simulate_tool_execution(tool_id, request)

                # Record metrics
                self.monitor.record_tool_execution(tool_id, result.execution_time_seconds, True)

                # Broadcast execution event
                await self.connection_manager.broadcast({
                    "event": "tool_execution",
                    "tool_id": tool_id,
                    "request_id": request.request_id,
                    "status": result.status,
                    "timestamp": datetime.utcnow().isoformat()
                })

                return result.model_dump()

            except Exception as e:
                logger.error(f"Tool execution failed: {e}")
                self.monitor.record_tool_execution(tool_id, 0, False)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/tools/synthesize")
        async def synthesize_tool(synthesis_request: Dict[str, Any]):
            """Synthesize a new tool"""
            try:
                requirements = synthesis_request.get("requirements", "")
                context = synthesis_request.get("context", {})

                # Simulate tool synthesis
                synthesized_tool = await self._simulate_tool_synthesis(requirements, context)

                # Register the synthesized tool
                self.tool_registry.register_tool(synthesized_tool)

                # Record metrics
                self.monitor.record_security_event("tool_synthesis", "medium", {
                    "requirements": requirements,
                    "tool_id": synthesized_tool["tool_id"]
                })

                return {
                    "status": "success",
                    "tool_id": synthesized_tool["tool_id"],
                    "message": "Tool synthesized and registered successfully"
                }

            except Exception as e:
                logger.error(f"Tool synthesis failed: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.websocket("/ws/events")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time events"""
            await self.connection_manager.connect(websocket)
            try:
                while True:
                    # Keep connection alive
                    await websocket.receive_text()
            except WebSocketDisconnect:
                self.connection_manager.disconnect(websocket)

        @self.app.get("/status")
        async def get_status():
            """Get system status"""
            return self.monitor.get_system_status()

        @self.app.get("/metrics")
        async def get_metrics():
            """Get performance metrics"""
            return self.monitor.get_performance_metrics()

    async def _simulate_tool_execution(self, tool_id: str, request: ToolRunRequest) -> ToolRunResult:
        """Simulate tool execution (replace with real implementation)"""
        # Simulate execution time
        await asyncio.sleep(0.5)

        # Create mock evidence
        evidence = EvidenceReference(
            evidence_id=f"evidence_{request.request_id}",
            file_path=f"/evidence/{tool_id}_{request.request_id}.json",
            content_type="application/json",
            size_bytes=1024,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            metadata={
                "tool": tool_id,
                "target": request.params.get("target", "unknown")
            }
        )

        # Create result
        result = ToolRunResult(
            status="completed",
            result={
                "tool": tool_id,
                "action": request.action,
                "parameters": request.params,
                "output": f"Mock output from {tool_id}",
                "success": True
            },
            evidence_refs=[evidence],
            execution_time_seconds=0.5,
            stdout=f"Executing {tool_id} with action {request.action}",
            stderr=""
        )

        return result

    async def _simulate_tool_synthesis(self, requirements: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate tool synthesis (replace with real implementation)"""
        # Simulate synthesis time
        await asyncio.sleep(1.0)

        # Generate tool metadata
        tool_id = f"synthesized_{int(datetime.utcnow().timestamp())}"

        synthesized_tool = {
            "tool_id": tool_id,
            "name": f"Synthesized Tool: {requirements[:50]}",
            "description": f"Custom tool created for: {requirements}",
            "version": "1.0.0",
            "category": "custom",
            "capabilities": ["custom_action"],
            "parameters": {
                "target": {"type": "string", "required": True},
                "options": {"type": "object", "default": {}}
            },
            "container_image": f"raid/synthesized:{tool_id}",
            "network_requirements": ["egress_http"],
            "evidence_types": ["custom_output"],
            "synthesis_metadata": {
                "requirements": requirements,
                "context": context,
                "created_at": datetime.utcnow().isoformat(),
                "validation_status": "passed"
            }
        }

        return synthesized_tool

    def run(self, host: str = "0.0.0.0", port: int = 8000, debug: bool = False):
        """Run the MCP server"""
        logger.info(f"Starting RAID MCP Server on {host}:{port}")

        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info" if not debug else "debug",
            reload=debug
        )


# CLI for running the server
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RAID MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--config-dir", default="/tmp/raid-mcp", help="Configuration directory")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create and run server
    server = RAIDMCPServer(args.config_dir)
    server.run(host=args.host, port=args.port, debug=args.debug)