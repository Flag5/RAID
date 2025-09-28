#!/usr/bin/env python3
"""
RAID HTTP Fetcher Tool Runner
Simple HTTP fetching tool with security validation and evidence collection
"""

import json
import time
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Tool configuration
TOOL_NAME = "http-fetcher"
TOOL_VERSION = "1.0.0"
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_TIMEOUT = 30
EVIDENCE_PATH = Path("/tmp/raid_evidence")

app = Flask(__name__)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(TOOL_NAME)

# Ensure evidence directory exists
EVIDENCE_PATH.mkdir(parents=True, exist_ok=True)


class HTTPFetcher:
    """HTTP fetching tool with security controls"""

    def __init__(self):
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Default headers
        self.session.headers.update({
            'User-Agent': f'RAID-{TOOL_NAME}/{TOOL_VERSION}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def validate_url(self, url: str, authorized_scope: list) -> bool:
        """Validate URL against authorized scope"""
        try:
            parsed = urlparse(url)

            if not parsed.scheme or not parsed.netloc:
                return False

            # Check against authorized scope (simplified validation)
            if authorized_scope:
                # In production, this would do proper CIDR checking
                return any(scope in url for scope in authorized_scope)

            return True

        except Exception as e:
            logger.error(f"URL validation failed: {e}")
            return False

    def fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT
    ) -> Dict[str, Any]:
        """Fetch URL and return response data"""

        start_time = time.time()

        try:
            # Prepare request
            req_headers = headers or {}

            # Make request
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                data=data,
                timeout=timeout,
                stream=True,  # Stream to check content length
                allow_redirects=True
            )

            # Check response size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > MAX_RESPONSE_SIZE:
                raise ValueError(f"Response too large: {content_length} bytes")

            # Read response content with size limit
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > MAX_RESPONSE_SIZE:
                    raise ValueError(f"Response too large: {len(content)} bytes")

            # Decode content
            try:
                text_content = content.decode('utf-8', errors='replace')
            except:
                text_content = content.decode('latin-1', errors='replace')

            execution_time = time.time() - start_time

            result = {
                "url": url,
                "method": method,
                "status_code": response.status_code,
                "status_text": response.reason,
                "headers": dict(response.headers),
                "content": text_content,
                "content_length": len(content),
                "execution_time": execution_time,
                "redirects": [resp.url for resp in response.history],
                "final_url": response.url,
                "encoding": response.encoding,
                "timestamp": datetime.utcnow().isoformat()
            }

            return result

        except requests.exceptions.Timeout:
            raise ValueError(f"Request timeout after {timeout} seconds")
        except requests.exceptions.ConnectionError as e:
            raise ValueError(f"Connection error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Request failed: {str(e)}")

    def save_evidence(self, response_data: Dict[str, Any], evidence_id: str) -> str:
        """Save response data as evidence"""

        evidence_file = EVIDENCE_PATH / f"{evidence_id}.json"

        # Create evidence metadata
        evidence = {
            "evidence_id": evidence_id,
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "collected_at": datetime.utcnow().isoformat(),
            "evidence_type": "http_response",
            "data": response_data,
            "metadata": {
                "url": response_data.get("url"),
                "status_code": response_data.get("status_code"),
                "content_type": response_data.get("headers", {}).get("content-type"),
                "content_length": response_data.get("content_length")
            }
        }

        # Calculate hash
        evidence_json = json.dumps(evidence, sort_keys=True)
        evidence_hash = hashlib.sha256(evidence_json.encode()).hexdigest()
        evidence["sha256_hash"] = evidence_hash

        # Save to file
        with open(evidence_file, 'w') as f:
            json.dump(evidence, f, indent=2)

        logger.info(f"Evidence saved: {evidence_file}")
        return str(evidence_file)


# Flask routes
@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route('/run', methods=['POST'])
def run_tool():
    """Main tool execution endpoint"""

    try:
        # Parse request
        request_data = request.get_json()
        if not request_data:
            return jsonify({"error": "No JSON data provided"}), 400

        # Extract parameters
        action = request_data.get("action")
        params = request_data.get("params", {})
        run_context = request_data.get("run_context", {})

        # Validate action
        if action != "fetch":
            return jsonify({"error": f"Unsupported action: {action}"}), 400

        # Validate authorization
        if not run_context.get("authorized", False):
            return jsonify({"error": "Tool execution not authorized"}), 403

        # Extract parameters
        url = params.get("url")
        if not url:
            return jsonify({"error": "URL parameter required"}), 400

        method = params.get("method", "GET")
        headers = params.get("headers", {})
        data = params.get("data")
        timeout = params.get("timeout", DEFAULT_TIMEOUT)

        # Validate URL against scope
        fetcher = HTTPFetcher()
        authorized_scope = run_context.get("scope", {}).get("target_cidrs", [])

        if not fetcher.validate_url(url, authorized_scope):
            return jsonify({"error": "URL not in authorized scope"}), 403

        logger.info(f"Fetching URL: {url} (method: {method})")

        # Execute fetch
        response_data = fetcher.fetch_url(
            url=url,
            method=method,
            headers=headers,
            data=data,
            timeout=timeout
        )

        # Save evidence
        evidence_id = f"http_fetch_{int(time.time())}"
        evidence_file = fetcher.save_evidence(response_data, evidence_id)

        # Prepare result
        result = {
            "status": "completed",
            "result": {
                "url": response_data["url"],
                "status_code": response_data["status_code"],
                "content_length": response_data["content_length"],
                "final_url": response_data["final_url"],
                "redirects": len(response_data["redirects"]),
                "execution_time": response_data["execution_time"]
            },
            "evidence_refs": [
                {
                    "evidence_id": evidence_id,
                    "file_path": evidence_file,
                    "content_type": "application/json",
                    "size_bytes": Path(evidence_file).stat().st_size,
                    "sha256_hash": response_data.get("sha256_hash", ""),
                    "collected_at": datetime.utcnow().isoformat()
                }
            ],
            "execution_time_seconds": response_data["execution_time"],
            "stdout": f"Successfully fetched {url}",
            "stderr": "",
            "completed_at": datetime.utcnow().isoformat()
        }

        return jsonify(result)

    except ValueError as e:
        error_msg = str(e)
        logger.error(f"Validation error: {error_msg}")
        return jsonify({
            "status": "failed",
            "error_message": error_msg,
            "error_type": "validation_error",
            "completed_at": datetime.utcnow().isoformat()
        }), 400

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Tool execution failed: {error_msg}", exc_info=True)
        return jsonify({
            "status": "failed",
            "error_message": error_msg,
            "error_type": "execution_error",
            "completed_at": datetime.utcnow().isoformat()
        }), 500


@app.route('/info', methods=['GET'])
def tool_info():
    """Tool information endpoint"""
    return jsonify({
        "tool_id": TOOL_NAME,
        "name": "HTTP Fetcher",
        "version": TOOL_VERSION,
        "description": "Fetch HTTP resources and analyze responses",
        "category": "web",
        "capabilities": ["http_get", "http_post", "header_analysis"],
        "parameters": {
            "url": {"type": "string", "required": True, "description": "Target URL to fetch"},
            "method": {"type": "string", "default": "GET", "description": "HTTP method"},
            "headers": {"type": "object", "default": {}, "description": "Custom headers"},
            "data": {"type": "string", "default": None, "description": "Request body data"},
            "timeout": {"type": "integer", "default": DEFAULT_TIMEOUT, "description": "Request timeout"}
        },
        "evidence_types": ["http_response", "headers"],
        "network_requirements": ["egress_http", "egress_https"],
        "resource_limits": {
            "max_response_size": MAX_RESPONSE_SIZE,
            "max_timeout": 300
        }
    })


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="RAID HTTP Fetcher Tool")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    logger.info(f"Starting {TOOL_NAME} v{TOOL_VERSION} on {args.host}:{args.port}")

    app.run(host=args.host, port=args.port, debug=args.debug)