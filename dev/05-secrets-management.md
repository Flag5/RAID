# Secrets and Token Management for RAID

## Overview
Security assessment tools often require API tokens, credentials, and other sensitive configuration. RAID needs a secure, auditable system for managing these secrets while maintaining the principle of least privilege.

## Requirements

### 1. Secret Types
- **API Tokens**: Shodan, VirusTotal, Have I Been Pwned, Censys
- **MCP Server Credentials**: Authentication for third-party MCP servers
- **Target Credentials**: When authorized for authenticated scanning
- **Signing Keys**: Ed25519 keys for artifact signing
- **Infrastructure Secrets**: Database connections, service tokens

### 2. Security Requirements
- ✅ **Never in Code**: No secrets hardcoded or in version control
- ✅ **Encrypted at Rest**: All secrets encrypted when stored
- ✅ **Audit Trail**: All secret access logged and auditable
- ✅ **Least Privilege**: Tools only get secrets they need
- ✅ **Rotation Support**: Ability to rotate secrets without downtime
- ✅ **Emergency Revocation**: Immediate secret revocation capability

## Architecture Design

### 1. Secrets Store Structure
```
secrets/
├── config/
│   ├── secrets.yaml.enc      # Encrypted secrets configuration
│   └── secrets.schema.yaml   # Secrets validation schema
├── keys/
│   ├── signing/
│   │   ├── private.key.enc   # Encrypted Ed25519 private key
│   │   └── public.key        # Public key (not secret)
│   └── encryption/
│       └── master.key        # Master encryption key (external)
└── runtime/
    └── .env.runtime          # Runtime secrets (memory only)
```

### 2. Secrets Configuration Format
```yaml
# secrets.yaml (before encryption)
api_tokens:
  # ADEO MCP Server - Combined Shodan + VirusTotal
  adeo_shodan_vt:
    shodan_token: "${SHODAN_API_KEY}"
    virustotal_token: "${VT_API_KEY}"
    server_url: "http://localhost:3001"
    scopes: ["host_lookup", "dns_ops", "network_scan", "vuln_analysis", "url_scan", "file_hash", "ip_reputation"]
    rate_limit: 100

  # Individual API access (fallback)
  shodan:
    token: "${SHODAN_API_KEY}"
    scopes: ["search", "scan"]
    rate_limit: 100

  virustotal:
    token: "${VT_API_KEY}"
    scopes: ["file_scan", "url_scan"]
    rate_limit: 1000

  hibp:
    token: "${HIBP_API_KEY}"
    scopes: ["breach_search"]
    rate_limit: 10

mcp_servers:
  external_security_scanner:
    auth_type: "bearer"
    token: "${EXTERNAL_SCANNER_TOKEN}"
    endpoint: "https://api.example-scanner.com"

target_credentials:
  # Only when explicitly authorized for authenticated scanning
  web_app_admin:
    username: "${WEB_ADMIN_USER}"
    password: "${WEB_ADMIN_PASS}"
    scope: "example.com"
    authorized_actions: ["authenticated_scan"]

signing:
  ed25519_private_key: "${SIGNING_PRIVATE_KEY}"
  key_id: "raid-signing-key-001"
```

### 3. Secrets Manager Implementation
```python
# controller/secrets.py
from cryptography.fernet import Fernet
from typing import Dict, Optional
import yaml
import os

class SecretsManager:
    def __init__(self, secrets_dir: str, master_key: Optional[str] = None):
        self.secrets_dir = secrets_dir
        self.master_key = master_key or os.getenv('RAID_MASTER_KEY')
        self.fernet = Fernet(self.master_key.encode()) if self.master_key else None
        self._secrets_cache = {}

    def load_secrets(self) -> Dict:
        """Load and decrypt secrets configuration"""
        encrypted_path = os.path.join(self.secrets_dir, 'config/secrets.yaml.enc')

        if not os.path.exists(encrypted_path):
            raise FileNotFoundError("Secrets file not found")

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self.fernet.decrypt(encrypted_data)
        return yaml.safe_load(decrypted_data.decode())

    def get_secret(self, key_path: str, tool_context: str) -> Optional[str]:
        """Get specific secret with audit logging"""
        self._audit_secret_access(key_path, tool_context)

        keys = key_path.split('.')
        secrets = self._get_cached_secrets()

        value = secrets
        for key in keys:
            value = value.get(key) if isinstance(value, dict) else None
            if value is None:
                return None

        # Resolve environment variable if needed
        if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
            env_var = value[2:-1]
            return os.getenv(env_var)

        return value

    def encrypt_secrets_file(self, plain_file: str) -> str:
        """Encrypt a plain secrets file"""
        with open(plain_file, 'r') as f:
            plain_data = f.read()

        encrypted_data = self.fernet.encrypt(plain_data.encode())

        encrypted_path = plain_file + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        # Remove plain file
        os.remove(plain_file)
        return encrypted_path

    def _audit_secret_access(self, key_path: str, context: str):
        """Log secret access for audit trail"""
        # Implementation for audit logging
        pass
```

### 4. Tool Secret Injection
```python
# controller/tool_context.py
class ToolContext:
    def __init__(self, tool_id: str, secrets_manager: SecretsManager):
        self.tool_id = tool_id
        self.secrets_manager = secrets_manager

    def get_runtime_env(self) -> Dict[str, str]:
        """Get environment variables for tool execution"""
        tool_secrets = self._get_tool_secrets()

        env_vars = {}
        for secret_key, secret_value in tool_secrets.items():
            env_var_name = f"RAID_{secret_key.upper()}"
            env_vars[env_var_name] = secret_value

        return env_vars

    def _get_tool_secrets(self) -> Dict[str, str]:
        """Get secrets authorized for this specific tool"""
        # Tool-specific secret mapping based on tool requirements
        tool_secret_map = {
            'web_scanner': ['api_tokens.shodan', 'api_tokens.virustotal'],
            'breach_checker': ['api_tokens.hibp'],
            'network_scanner': ['api_tokens.shodan', 'api_tokens.censys'],
        }

        secrets = {}
        for secret_path in tool_secret_map.get(self.tool_id, []):
            secret_value = self.secrets_manager.get_secret(secret_path, self.tool_id)
            if secret_value:
                secret_key = secret_path.split('.')[-1]
                secrets[secret_key] = secret_value

        return secrets
```

## Integration with RAID Components

### 1. MCP Server Integration
```python
# mcp/server.py
from fastmcp import FastMCP
from controller.secrets import SecretsManager

mcp = FastMCP("raid-security-assessment")
secrets_manager = SecretsManager("/app/secrets")

@mcp.tool
async def execute_tool_with_secrets(tool_id: str, params: dict) -> ToolResult:
    """Execute tool with appropriate secrets injected"""
    tool_context = ToolContext(tool_id, secrets_manager)
    env_vars = tool_context.get_runtime_env()

    # Inject secrets as environment variables for tool execution
    return await execute_tool_container(tool_id, params, env_vars)
```

### 2. Docker Container Secret Injection
```python
# controller/executor.py
def execute_tool_container(tool_id: str, params: dict, secrets_env: dict):
    """Execute tool container with secrets as environment variables"""
    docker_client = docker.from_env()

    container = docker_client.containers.run(
        image=f"raid-tool-{tool_id}",
        environment=secrets_env,  # Secrets injected as env vars
        volumes={
            'evidence_volume': {'bind': '/app/evidence', 'mode': 'rw'}
        },
        network_mode='none',  # Network isolation
        remove=True,
        detach=False
    )

    return parse_tool_output(container.logs())
```

### 3. CLI Secret Management
```bash
# Set up secrets (one-time)
raid secrets init --master-key-file ~/.raid/master.key
raid secrets set api_tokens.shodan --from-env SHODAN_API_KEY
raid secrets set api_tokens.virustotal --from-file vt_token.txt
raid secrets encrypt-all

# Runtime (master key from secure source)
export RAID_MASTER_KEY=$(cat ~/.raid/master.key)
raid run --role web-pentest --target example.com --auth auth.json
```

## Security Best Practices

### 1. Key Management
- **Master Key**: Stored outside repository (KMS, HSM, or secure file)
- **Signing Keys**: Separate from API tokens
- **Key Rotation**: Regular rotation with zero-downtime
- **Key Backup**: Secure backup and recovery procedures

### 2. Access Control
- **Tool-Specific**: Each tool only gets secrets it needs
- **Audit Logging**: All secret access logged with context
- **Time-Limited**: Secrets can have expiration times
- **Scope-Limited**: Secrets tied to specific targets/scopes

### 3. Runtime Security
- **Memory Only**: Secrets never written to disk in plain text
- **Container Isolation**: Secrets injected only to authorized containers
- **Network Isolation**: Prevent secret exfiltration
- **Emergency Revocation**: Immediate secret invalidation

## Implementation Priority

### Phase 1: Basic Secrets Management
- [ ] SecretsManager implementation
- [ ] Encryption/decryption of secrets files
- [ ] Environment variable injection
- [ ] Basic audit logging

### Phase 2: Advanced Features
- [ ] Tool-specific secret mapping
- [ ] Runtime secret injection for containers
- [ ] Secret rotation capabilities
- [ ] Enhanced audit and monitoring

### Phase 3: Production Hardening
- [ ] KMS/HSM integration
- [ ] Advanced access controls
- [ ] Secret scanning and validation
- [ ] Compliance reporting

## Directory Structure Update
```
secrets/                    # Secrets management (gitignored)
├── config/
│   ├── secrets.yaml.enc    # Encrypted secrets
│   ├── secrets.schema.yaml # Validation schema
│   └── tool-secrets.yaml   # Tool-to-secret mapping
├── keys/
│   ├── signing/
│   └── encryption/
└── scripts/
    ├── setup-secrets.py    # Initial secrets setup
    ├── rotate-keys.py      # Key rotation utilities
    └── audit-secrets.py    # Secret access auditing
```

This provides a secure, auditable foundation for managing the various tokens and credentials that security assessment tools will need.