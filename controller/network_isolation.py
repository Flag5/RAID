"""
RAID Network Isolation Manager
Programmatic network isolation enforcement for tool containers
"""

import json
import subprocess
import ipaddress
import logging
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class NetworkPolicy:
    """Network access policy for tool execution"""
    network_id: str
    allowed_cidrs: List[str]
    blocked_cidrs: List[str]
    allow_dns: bool = True
    allow_localhost: bool = False
    max_connections: int = 10
    rate_limit_per_minute: int = 100


@dataclass
class IsolatedNetwork:
    """Isolated network configuration"""
    network_id: str
    network_name: str
    subnet: str
    gateway: str
    isolation_rules: List[str]
    created_at: str


class NetworkIsolationManager:
    """Manages network isolation for RAID tool containers"""

    def __init__(self):
        self.active_networks: Dict[str, IsolatedNetwork] = {}
        self.network_policies: Dict[str, NetworkPolicy] = {}

    @contextmanager
    def isolated_network(self, policy: NetworkPolicy):
        """Context manager for isolated network lifecycle"""
        network = None
        try:
            network = self.create_isolated_network(policy)
            yield network
        finally:
            if network:
                self.cleanup_network(network.network_id)

    def create_isolated_network(self, policy: NetworkPolicy) -> IsolatedNetwork:
        """Create isolated Docker network with firewall rules"""
        network_name = f"raid-isolated-{policy.network_id}"
        subnet = self._allocate_subnet()

        try:
            # Create Docker network
            self._create_docker_network(network_name, subnet)

            # Create iptables rules for isolation
            rules = self._create_firewall_rules(network_name, subnet, policy)

            network = IsolatedNetwork(
                network_id=policy.network_id,
                network_name=network_name,
                subnet=subnet,
                gateway=self._get_gateway_ip(subnet),
                isolation_rules=rules,
                created_at=self._get_timestamp()
            )

            self.active_networks[policy.network_id] = network
            self.network_policies[policy.network_id] = policy

            logger.info(f"Created isolated network: {network_name} ({subnet})")
            return network

        except Exception as e:
            logger.error(f"Failed to create isolated network: {e}")
            # Cleanup on failure
            self._cleanup_docker_network(network_name)
            raise

    def cleanup_network(self, network_id: str):
        """Clean up isolated network and firewall rules"""
        if network_id not in self.active_networks:
            logger.warning(f"Network {network_id} not found for cleanup")
            return

        network = self.active_networks[network_id]

        try:
            # Remove firewall rules
            self._remove_firewall_rules(network.isolation_rules)

            # Remove Docker network
            self._cleanup_docker_network(network.network_name)

            # Remove from tracking
            del self.active_networks[network_id]
            del self.network_policies[network_id]

            logger.info(f"Cleaned up isolated network: {network.network_name}")

        except Exception as e:
            logger.error(f"Error cleaning up network {network_id}: {e}")

    def get_container_run_args(self, network_id: str) -> List[str]:
        """Get Docker run arguments for network isolation"""
        if network_id not in self.active_networks:
            raise ValueError(f"Network {network_id} not found")

        network = self.active_networks[network_id]
        policy = self.network_policies[network_id]

        args = [
            f"--network={network.network_name}",
            "--network-alias=tool-container"
        ]

        # Add DNS configuration
        if policy.allow_dns:
            args.extend(["--dns=8.8.8.8", "--dns=8.8.4.4"])
        else:
            args.append("--dns=127.0.0.1")  # Non-functional DNS

        return args

    def validate_network_access(self, network_id: str, target: str) -> bool:
        """Validate if target is allowed by network policy"""
        if network_id not in self.network_policies:
            return False

        policy = self.network_policies[network_id]

        try:
            target_ip = ipaddress.ip_address(target)
        except ValueError:
            # Handle hostnames - simplified validation
            return self._validate_hostname_access(policy, target)

        # Check against allowed CIDRs
        for cidr in policy.allowed_cidrs:
            if target_ip in ipaddress.ip_network(cidr, strict=False):
                # Check if it's explicitly blocked
                for blocked_cidr in policy.blocked_cidrs:
                    if target_ip in ipaddress.ip_network(blocked_cidr, strict=False):
                        return False
                return True

        return False

    def _create_docker_network(self, network_name: str, subnet: str):
        """Create Docker network"""
        cmd = [
            "docker", "network", "create",
            "--driver=bridge",
            f"--subnet={subnet}",
            "--internal",  # No external connectivity by default
            network_name
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create Docker network: {result.stderr}")

    def _cleanup_docker_network(self, network_name: str):
        """Remove Docker network"""
        cmd = ["docker", "network", "rm", network_name]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            logger.warning(f"Failed to remove Docker network {network_name}: {result.stderr}")

    def _create_firewall_rules(self, network_name: str, subnet: str, policy: NetworkPolicy) -> List[str]:
        """Create iptables rules for network isolation"""
        rules = []
        chain_name = f"RAID-{policy.network_id}"

        try:
            # Create custom chain
            self._run_iptables(["-t", "filter", "-N", chain_name])
            rules.append(f"chain:{chain_name}")

            # Jump to custom chain for this subnet
            self._run_iptables([
                "-t", "filter", "-A", "FORWARD",
                "-s", subnet, "-j", chain_name
            ])
            rules.append(f"forward:{subnet}")

            # Allow localhost if permitted
            if policy.allow_localhost:
                self._run_iptables([
                    "-t", "filter", "-A", chain_name,
                    "-d", "127.0.0.0/8", "-j", "ACCEPT"
                ])
                rules.append("allow:localhost")

            # Allow DNS if permitted
            if policy.allow_dns:
                self._run_iptables([
                    "-t", "filter", "-A", chain_name,
                    "-p", "udp", "--dport", "53", "-j", "ACCEPT"
                ])
                self._run_iptables([
                    "-t", "filter", "-A", chain_name,
                    "-p", "tcp", "--dport", "53", "-j", "ACCEPT"
                ])
                rules.extend(["allow:dns-udp", "allow:dns-tcp"])

            # Block explicitly forbidden CIDRs
            for blocked_cidr in policy.blocked_cidrs:
                self._run_iptables([
                    "-t", "filter", "-A", chain_name,
                    "-d", blocked_cidr, "-j", "DROP"
                ])
                rules.append(f"block:{blocked_cidr}")

            # Allow permitted CIDRs
            for allowed_cidr in policy.allowed_cidrs:
                self._run_iptables([
                    "-t", "filter", "-A", chain_name,
                    "-d", allowed_cidr, "-j", "ACCEPT"
                ])
                rules.append(f"allow:{allowed_cidr}")

            # Connection limit
            self._run_iptables([
                "-t", "filter", "-A", chain_name,
                "-m", "connlimit",
                "--connlimit-above", str(policy.max_connections),
                "-j", "DROP"
            ])
            rules.append(f"connlimit:{policy.max_connections}")

            # Rate limiting
            self._run_iptables([
                "-t", "filter", "-A", chain_name,
                "-m", "limit",
                "--limit", f"{policy.rate_limit_per_minute}/min",
                "-j", "ACCEPT"
            ])
            rules.append(f"ratelimit:{policy.rate_limit_per_minute}")

            # Default deny
            self._run_iptables([
                "-t", "filter", "-A", chain_name,
                "-j", "DROP"
            ])
            rules.append("default:drop")

            return rules

        except Exception as e:
            # Cleanup on failure
            self._remove_firewall_rules(rules)
            raise RuntimeError(f"Failed to create firewall rules: {e}")

    def _remove_firewall_rules(self, rules: List[str]):
        """Remove iptables rules"""
        for rule in reversed(rules):  # Remove in reverse order
            try:
                if rule.startswith("chain:"):
                    chain_name = rule.split(":", 1)[1]
                    # Flush and delete chain
                    self._run_iptables(["-t", "filter", "-F", chain_name], check=False)
                    self._run_iptables(["-t", "filter", "-X", chain_name], check=False)

                elif rule.startswith("forward:"):
                    subnet = rule.split(":", 1)[1]
                    # Remove forward rule
                    self._run_iptables([
                        "-t", "filter", "-D", "FORWARD",
                        "-s", subnet, "-j", f"RAID-{self._get_network_id_from_subnet(subnet)}"
                    ], check=False)

            except Exception as e:
                logger.warning(f"Failed to remove firewall rule {rule}: {e}")

    def _run_iptables(self, args: List[str], check: bool = True):
        """Run iptables command"""
        cmd = ["iptables"] + args
        result = subprocess.run(cmd, capture_output=True, text=True)

        if check and result.returncode != 0:
            raise RuntimeError(f"iptables command failed: {' '.join(cmd)}\nError: {result.stderr}")

    def _allocate_subnet(self) -> str:
        """Allocate available subnet for isolated network"""
        # Simple subnet allocation - production should use proper IPAM
        base_network = ipaddress.ip_network("172.30.0.0/16")

        used_subnets = set()
        for network in self.active_networks.values():
            used_subnets.add(network.subnet)

        # Find available /24 subnet
        for subnet in base_network.subnets(new_prefix=24):
            if str(subnet) not in used_subnets:
                return str(subnet)

        raise RuntimeError("No available subnets for network isolation")

    def _get_gateway_ip(self, subnet: str) -> str:
        """Get gateway IP for subnet"""
        network = ipaddress.ip_network(subnet)
        return str(list(network.hosts())[0])

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def _validate_hostname_access(self, policy: NetworkPolicy, hostname: str) -> bool:
        """Validate hostname against policy (simplified)"""
        # In production, resolve hostname and check against IP policies
        # For now, use simple whitelist approach
        allowed_domains = [
            "httpbin.org", "example.com", "github.com", "pypi.org"
        ]

        # Check if hostname ends with allowed domain
        for domain in allowed_domains:
            if hostname.endswith(domain):
                return True

        return False

    def _get_network_id_from_subnet(self, subnet: str) -> str:
        """Get network ID from subnet (helper for cleanup)"""
        for network_id, network in self.active_networks.items():
            if network.subnet == subnet:
                return network_id
        return "unknown"

    def get_network_stats(self) -> Dict[str, any]:
        """Get statistics about active networks"""
        return {
            "active_networks": len(self.active_networks),
            "networks": {
                network_id: {
                    "name": network.network_name,
                    "subnet": network.subnet,
                    "created_at": network.created_at,
                    "rules_count": len(network.isolation_rules)
                }
                for network_id, network in self.active_networks.items()
            }
        }


class NetworkPolicyBuilder:
    """Builder for network policies"""

    def __init__(self, network_id: str):
        self.policy = NetworkPolicy(
            network_id=network_id,
            allowed_cidrs=[],
            blocked_cidrs=[]
        )

    def allow_cidr(self, cidr: str) -> 'NetworkPolicyBuilder':
        """Allow access to CIDR block"""
        self.policy.allowed_cidrs.append(cidr)
        return self

    def block_cidr(self, cidr: str) -> 'NetworkPolicyBuilder':
        """Block access to CIDR block"""
        self.policy.blocked_cidrs.append(cidr)
        return self

    def allow_internet(self) -> 'NetworkPolicyBuilder':
        """Allow general internet access"""
        self.policy.allowed_cidrs.append("0.0.0.0/0")
        return self

    def block_private_networks(self) -> 'NetworkPolicyBuilder':
        """Block access to private network ranges"""
        private_cidrs = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16"  # Link-local
        ]
        self.policy.blocked_cidrs.extend(private_cidrs)
        return self

    def allow_dns(self, enabled: bool = True) -> 'NetworkPolicyBuilder':
        """Configure DNS access"""
        self.policy.allow_dns = enabled
        return self

    def set_rate_limit(self, requests_per_minute: int) -> 'NetworkPolicyBuilder':
        """Set rate limiting"""
        self.policy.rate_limit_per_minute = requests_per_minute
        return self

    def set_connection_limit(self, max_connections: int) -> 'NetworkPolicyBuilder':
        """Set maximum concurrent connections"""
        self.policy.max_connections = max_connections
        return self

    def build(self) -> NetworkPolicy:
        """Build the network policy"""
        return self.policy


# Pre-defined policy templates
def create_web_assessment_policy(network_id: str, target_cidrs: List[str]) -> NetworkPolicy:
    """Create policy for web application assessment"""
    builder = NetworkPolicyBuilder(network_id)

    for cidr in target_cidrs:
        builder.allow_cidr(cidr)

    return (builder
            .allow_dns(True)
            .block_private_networks()
            .set_rate_limit(200)
            .set_connection_limit(20)
            .build())


def create_network_scan_policy(network_id: str, target_cidrs: List[str]) -> NetworkPolicy:
    """Create policy for network scanning"""
    builder = NetworkPolicyBuilder(network_id)

    for cidr in target_cidrs:
        builder.allow_cidr(cidr)

    return (builder
            .allow_dns(True)
            .set_rate_limit(1000)  # Higher rate for scanning
            .set_connection_limit(50)
            .build())


def create_isolated_policy(network_id: str) -> NetworkPolicy:
    """Create completely isolated policy (no network access)"""
    return NetworkPolicyBuilder(network_id).allow_dns(False).build()


# Example usage and testing
if __name__ == "__main__":
    # Example: Create isolated network for web assessment
    manager = NetworkIsolationManager()

    policy = create_web_assessment_policy(
        network_id="web-test-001",
        target_cidrs=["203.0.113.0/24"]  # Example target network
    )

    with manager.isolated_network(policy) as network:
        print(f"Created isolated network: {network.network_name}")
        print(f"Docker args: {manager.get_container_run_args(network.network_id)}")

        # Test access validation
        print(f"Access to 203.0.113.100: {manager.validate_network_access(network.network_id, '203.0.113.100')}")
        print(f"Access to 10.0.0.1: {manager.validate_network_access(network.network_id, '10.0.0.1')}")

    print("Network cleaned up")