#!/usr/bin/env python3
"""
RAID Device Passthrough Security Check
Pre-deployment validation script for USB device passthrough security
"""

import os
import sys
import json
import subprocess
import logging
import platform
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DeviceInfo:
    """USB device information"""
    device_path: str
    vendor_id: str
    product_id: str
    manufacturer: str
    product: str
    serial: Optional[str]
    device_class: str
    interfaces: List[str]


@dataclass
class SecurityCheckResult:
    """Security check result"""
    check_name: str
    passed: bool
    message: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    details: Dict = None


class DeviceSecurityChecker:
    """Validates host security for USB device passthrough"""

    def __init__(self, output_dir: str = "/tmp/raid-device-checks"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[SecurityCheckResult] = []

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'device_security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_complete_security_check(self, device_path: str) -> bool:
        """Run complete security validation for device passthrough"""
        self.logger.info(f"Starting security check for device: {device_path}")

        # Core security checks
        checks = [
            self.check_host_environment,
            self.check_user_permissions,
            self.check_device_validity,
            self.check_device_security,
            self.check_container_security,
            self.check_network_isolation,
            self.check_monitoring_capabilities,
            self.check_incident_response
        ]

        for check in checks:
            try:
                if device_path:
                    result = check(device_path)
                else:
                    result = check()

                self.results.append(result)

                if result.severity == "CRITICAL" and not result.passed:
                    self.logger.critical(f"CRITICAL security check failed: {result.check_name}")
                    return False

            except Exception as e:
                self.logger.error(f"Security check failed: {check.__name__}: {e}")
                self.results.append(SecurityCheckResult(
                    check_name=check.__name__,
                    passed=False,
                    message=f"Check failed with exception: {str(e)}",
                    severity="CRITICAL"
                ))
                return False

        # Generate security report
        self.generate_security_report()

        # Check overall pass/fail
        critical_failures = [r for r in self.results if r.severity == "CRITICAL" and not r.passed]
        high_failures = [r for r in self.results if r.severity == "HIGH" and not r.passed]

        if critical_failures:
            self.logger.error(f"CRITICAL security failures detected: {len(critical_failures)}")
            return False

        if len(high_failures) > 2:
            self.logger.error(f"Too many HIGH severity failures: {len(high_failures)}")
            return False

        self.logger.info("Device passthrough security validation PASSED")
        return True

    def check_host_environment(self) -> SecurityCheckResult:
        """Check host environment security"""
        issues = []

        # Check if running as root (should not be)
        if os.geteuid() == 0:
            issues.append("Running as root user - use dedicated non-root user")

        # Check OS and version
        if platform.system() != "Linux":
            issues.append("Device passthrough only supported on Linux")

        # Check for dedicated assessment host
        hostname = platform.node()
        if not any(keyword in hostname.lower() for keyword in ["assessment", "pentest", "security", "isolated"]):
            issues.append("Host does not appear to be dedicated assessment system")

        # Check for security tools
        required_tools = ["iptables", "docker", "apparmor_parser"]
        missing_tools = []

        for tool in required_tools:
            if not self._command_exists(tool):
                missing_tools.append(tool)

        if missing_tools:
            issues.append(f"Missing required security tools: {missing_tools}")

        return SecurityCheckResult(
            check_name="Host Environment Security",
            passed=len(issues) == 0,
            message="Host environment validated" if len(issues) == 0 else f"Issues found: {'; '.join(issues)}",
            severity="CRITICAL" if issues else "LOW",
            details={"issues": issues, "hostname": hostname}
        )

    def check_user_permissions(self) -> SecurityCheckResult:
        """Check user permissions and group memberships"""
        issues = []
        username = os.getenv("USER", "unknown")

        # Check required group memberships
        required_groups = ["docker", "dialout"]
        user_groups = self._get_user_groups()

        missing_groups = [group for group in required_groups if group not in user_groups]
        if missing_groups:
            issues.append(f"User not in required groups: {missing_groups}")

        # Check sudo configuration
        if not self._can_run_sudo():
            issues.append("User cannot run sudo (required for device setup)")

        # Check home directory permissions
        home_dir = Path.home()
        if home_dir.stat().st_mode & 0o077:
            issues.append("Home directory has overly permissive permissions")

        return SecurityCheckResult(
            check_name="User Permissions",
            passed=len(issues) == 0,
            message="User permissions validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="HIGH" if issues else "LOW",
            details={"username": username, "groups": user_groups, "issues": issues}
        )

    def check_device_validity(self, device_path: str) -> SecurityCheckResult:
        """Check if device path is valid and secure"""
        issues = []

        if not device_path:
            return SecurityCheckResult(
                check_name="Device Validity",
                passed=False,
                message="No device path provided",
                severity="CRITICAL"
            )

        device_path_obj = Path(device_path)

        # Check if device exists
        if not device_path_obj.exists():
            issues.append(f"Device path does not exist: {device_path}")

        # Check if it's actually a device
        if not device_path_obj.is_char_device() and not device_path_obj.is_block_device():
            issues.append(f"Path is not a device: {device_path}")

        # Check device permissions
        try:
            stat_info = device_path_obj.stat()
            if stat_info.st_mode & 0o002:  # World writable
                issues.append("Device is world-writable (security risk)")
        except OSError:
            issues.append("Cannot read device permissions")

        # Validate device path format
        if not device_path.startswith("/dev/"):
            issues.append("Device path should start with /dev/")

        # Check for USB device pattern
        if "/dev/bus/usb/" not in device_path:
            issues.append("Device path should follow USB device pattern (/dev/bus/usb/)")

        return SecurityCheckResult(
            check_name="Device Validity",
            passed=len(issues) == 0,
            message="Device path validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="CRITICAL" if issues else "LOW",
            details={"device_path": device_path, "issues": issues}
        )

    def check_device_security(self, device_path: str) -> SecurityCheckResult:
        """Check device-specific security properties"""
        issues = []
        device_info = None

        try:
            device_info = self._get_device_info(device_path)

            # Check device class - some classes are higher risk
            high_risk_classes = ["hub", "hid", "mass_storage", "wireless"]
            if any(risk_class in device_info.device_class.lower() for risk_class in high_risk_classes):
                issues.append(f"Device class '{device_info.device_class}' requires additional security measures")

            # Check for known problematic vendors/products
            problematic_patterns = ["BadUSB", "unknown", "0x0000"]
            device_desc = f"{device_info.manufacturer} {device_info.product}".lower()

            for pattern in problematic_patterns:
                if pattern.lower() in device_desc:
                    issues.append(f"Device description contains suspicious pattern: {pattern}")

            # Check if device has been seen before
            if not self._is_device_whitelisted(device_info):
                issues.append("Device not in whitelist - manual approval required")

        except Exception as e:
            issues.append(f"Could not retrieve device information: {e}")

        return SecurityCheckResult(
            check_name="Device Security",
            passed=len(issues) == 0,
            message="Device security validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="HIGH" if issues else "LOW",
            details={"device_info": device_info.__dict__ if device_info else None, "issues": issues}
        )

    def check_container_security(self) -> SecurityCheckResult:
        """Check container security configuration"""
        issues = []

        # Check if Docker is running
        if not self._is_docker_running():
            issues.append("Docker daemon is not running")

        # Check AppArmor status
        if not self._is_apparmor_enabled():
            issues.append("AppArmor is not enabled")

        # Check seccomp support
        if not self._is_seccomp_supported():
            issues.append("Seccomp filtering not supported")

        # Check for user namespaces
        if not self._are_user_namespaces_enabled():
            issues.append("User namespaces not enabled")

        # Check Docker security options
        docker_info = self._get_docker_info()
        if docker_info:
            if not docker_info.get("SecurityOptions"):
                issues.append("Docker missing security options")

        return SecurityCheckResult(
            check_name="Container Security",
            passed=len(issues) == 0,
            message="Container security validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="HIGH" if issues else "LOW",
            details={"docker_info": docker_info, "issues": issues}
        )

    def check_network_isolation(self) -> SecurityCheckResult:
        """Check network isolation capabilities"""
        issues = []

        # Check iptables functionality
        if not self._can_run_iptables():
            issues.append("Cannot run iptables (required for network isolation)")

        # Check for bridge networking
        if not self._is_bridge_networking_available():
            issues.append("Bridge networking not available")

        # Check for existing firewall rules
        existing_rules = self._get_iptables_rules()
        if len(existing_rules) > 100:  # Arbitrary threshold
            issues.append("Large number of existing iptables rules - may conflict")

        # Check for network monitoring tools
        network_tools = ["tcpdump", "netstat", "ss"]
        missing_tools = [tool for tool in network_tools if not self._command_exists(tool)]
        if missing_tools:
            issues.append(f"Missing network monitoring tools: {missing_tools}")

        return SecurityCheckResult(
            check_name="Network Isolation",
            passed=len(issues) == 0,
            message="Network isolation validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="MEDIUM" if issues else "LOW",
            details={"existing_rules_count": len(existing_rules), "issues": issues}
        )

    def check_monitoring_capabilities(self) -> SecurityCheckResult:
        """Check monitoring and logging capabilities"""
        issues = []

        # Check system logging
        if not Path("/var/log").exists():
            issues.append("System logging directory not accessible")

        # Check for audit framework
        if not self._command_exists("auditctl"):
            issues.append("Linux audit framework not available")

        # Check disk space for logs
        disk_space = self._get_available_disk_space("/var/log")
        if disk_space < 1000:  # Less than 1GB
            issues.append(f"Low disk space for logging: {disk_space}MB")

        # Check for system monitoring tools
        monitoring_tools = ["ps", "top", "iotop", "lsof"]
        missing_tools = [tool for tool in monitoring_tools if not self._command_exists(tool)]
        if missing_tools:
            issues.append(f"Missing monitoring tools: {missing_tools}")

        return SecurityCheckResult(
            check_name="Monitoring Capabilities",
            passed=len(issues) == 0,
            message="Monitoring capabilities validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="MEDIUM" if issues else "LOW",
            details={"disk_space_mb": disk_space, "issues": issues}
        )

    def check_incident_response(self) -> SecurityCheckResult:
        """Check incident response preparedness"""
        issues = []

        # Check for emergency shutdown script
        shutdown_script = Path("/usr/local/bin/raid-emergency-shutdown")
        if not shutdown_script.exists():
            issues.append("Emergency shutdown script not found")

        # Check for backup/snapshot capabilities
        backup_tools = ["rsync", "tar"]
        missing_backup_tools = [tool for tool in backup_tools if not self._command_exists(tool)]
        if missing_backup_tools:
            issues.append(f"Missing backup tools: {missing_backup_tools}")

        # Check network isolation script
        isolation_script = Path("/usr/local/bin/raid-network-isolate")
        if not isolation_script.exists():
            issues.append("Network isolation script not found")

        return SecurityCheckResult(
            check_name="Incident Response",
            passed=len(issues) == 0,
            message="Incident response validated" if len(issues) == 0 else f"Issues: {'; '.join(issues)}",
            severity="MEDIUM" if issues else "LOW",
            details={"issues": issues}
        )

    def generate_security_report(self):
        """Generate comprehensive security report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "overall_status": "PASS" if all(r.passed or r.severity in ["LOW", "MEDIUM"] for r in self.results) else "FAIL",
            "checks": [
                {
                    "name": result.check_name,
                    "passed": result.passed,
                    "message": result.message,
                    "severity": result.severity,
                    "details": result.details
                }
                for result in self.results
            ],
            "summary": {
                "total_checks": len(self.results),
                "passed": len([r for r in self.results if r.passed]),
                "failed": len([r for r in self.results if not r.passed]),
                "critical_failures": len([r for r in self.results if r.severity == "CRITICAL" and not r.passed]),
                "high_failures": len([r for r in self.results if r.severity == "HIGH" and not r.passed])
            }
        }

        # Save report
        report_file = self.output_dir / "security_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        self.logger.info(f"Security report saved to: {report_file}")

        # Generate human-readable summary
        self._generate_summary_report(report)

    def _generate_summary_report(self, report: Dict):
        """Generate human-readable summary"""
        summary_file = self.output_dir / "security_summary.txt"

        with open(summary_file, 'w') as f:
            f.write("RAID Device Passthrough Security Check Summary\n")
            f.write("=" * 50 + "\n\n")

            f.write(f"Overall Status: {report['overall_status']}\n")
            f.write(f"Timestamp: {report['timestamp']}\n")
            f.write(f"Host: {report['hostname']}\n\n")

            f.write("Check Results:\n")
            f.write("-" * 20 + "\n")

            for check in report['checks']:
                status = "PASS" if check['passed'] else "FAIL"
                f.write(f"{check['name']}: {status} ({check['severity']})\n")
                f.write(f"  {check['message']}\n\n")

            f.write("Summary:\n")
            f.write("-" * 10 + "\n")
            summary = report['summary']
            f.write(f"Total Checks: {summary['total_checks']}\n")
            f.write(f"Passed: {summary['passed']}\n")
            f.write(f"Failed: {summary['failed']}\n")
            f.write(f"Critical Failures: {summary['critical_failures']}\n")
            f.write(f"High Severity Failures: {summary['high_failures']}\n")

        self.logger.info(f"Summary report saved to: {summary_file}")

    # Helper methods
    def _command_exists(self, command: str) -> bool:
        """Check if command exists in PATH"""
        return subprocess.run(["which", command], capture_output=True).returncode == 0

    def _get_user_groups(self) -> List[str]:
        """Get current user's group memberships"""
        try:
            result = subprocess.run(["groups"], capture_output=True, text=True)
            return result.stdout.strip().split()
        except:
            return []

    def _can_run_sudo(self) -> bool:
        """Check if user can run sudo"""
        try:
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def _get_device_info(self, device_path: str) -> DeviceInfo:
        """Get detailed device information"""
        # Simplified device info extraction
        # Production should use proper USB device enumeration
        return DeviceInfo(
            device_path=device_path,
            vendor_id="unknown",
            product_id="unknown",
            manufacturer="unknown",
            product="unknown",
            serial=None,
            device_class="unknown",
            interfaces=[]
        )

    def _is_device_whitelisted(self, device_info: DeviceInfo) -> bool:
        """Check if device is in whitelist"""
        # Simplified whitelist check
        return False  # Require manual approval for all devices

    def _is_docker_running(self) -> bool:
        """Check if Docker daemon is running"""
        try:
            result = subprocess.run(["docker", "info"], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def _is_apparmor_enabled(self) -> bool:
        """Check if AppArmor is enabled"""
        try:
            result = subprocess.run(["aa-status"], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def _is_seccomp_supported(self) -> bool:
        """Check if seccomp is supported"""
        return Path("/proc/sys/kernel/seccomp").exists()

    def _are_user_namespaces_enabled(self) -> bool:
        """Check if user namespaces are enabled"""
        try:
            with open("/proc/sys/user/max_user_namespaces", 'r') as f:
                return int(f.read().strip()) > 0
        except:
            return False

    def _get_docker_info(self) -> Optional[Dict]:
        """Get Docker system information"""
        try:
            result = subprocess.run(["docker", "info", "--format", "{{json .}}"],
                                  capture_output=True, text=True)
            return json.loads(result.stdout)
        except:
            return None

    def _can_run_iptables(self) -> bool:
        """Check if iptables can be run"""
        try:
            result = subprocess.run(["sudo", "-n", "iptables", "-L"], capture_output=True)
            return result.returncode == 0
        except:
            return False

    def _is_bridge_networking_available(self) -> bool:
        """Check if bridge networking is available"""
        return Path("/sys/class/net/docker0").exists()

    def _get_iptables_rules(self) -> List[str]:
        """Get current iptables rules"""
        try:
            result = subprocess.run(["sudo", "-n", "iptables", "-S"],
                                  capture_output=True, text=True)
            return result.stdout.strip().split('\n')
        except:
            return []

    def _get_available_disk_space(self, path: str) -> int:
        """Get available disk space in MB"""
        try:
            stat = os.statvfs(path)
            return (stat.f_bavail * stat.f_frsize) // (1024 * 1024)
        except:
            return 0


def main():
    """Main function for command-line usage"""
    if len(sys.argv) != 2:
        print("Usage: device_security_check.py <device_path>")
        print("Example: device_security_check.py /dev/bus/usb/001/004")
        sys.exit(1)

    device_path = sys.argv[1]
    checker = DeviceSecurityChecker()

    print("RAID Device Passthrough Security Check")
    print("=" * 40)
    print(f"Checking device: {device_path}")
    print()

    success = checker.run_complete_security_check(device_path)

    if success:
        print("✅ SECURITY CHECK PASSED")
        print("Device passthrough is approved for use")
        sys.exit(0)
    else:
        print("❌ SECURITY CHECK FAILED")
        print("Device passthrough is NOT approved")
        print("Review security report for details")
        sys.exit(1)


if __name__ == "__main__":
    main()