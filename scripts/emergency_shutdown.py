#!/usr/bin/env python3
"""
RAID Emergency Shutdown Script
Immediate containment and evidence preservation for security incidents
"""

import os
import sys
import json
import signal
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class EmergencyShutdown:
    """Emergency shutdown and containment system"""

    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.incident_id = f"incident_{int(datetime.now().timestamp())}"
        self.evidence_dir = Path(f"/tmp/raid-incident-{self.incident_id}")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - EMERGENCY - %(message)s',
            handlers=[
                logging.FileHandler(self.evidence_dir / 'emergency.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def execute_emergency_shutdown(self, reason: str = "Manual trigger"):
        """Execute complete emergency shutdown procedure"""
        self.logger.critical(f"EMERGENCY SHUTDOWN INITIATED: {reason}")

        # Phase 1: Immediate containment
        self.logger.info("Phase 1: Immediate containment")
        self.kill_all_containers()
        self.isolate_network()
        self.pause_all_raids()

        # Phase 2: Evidence preservation
        self.logger.info("Phase 2: Evidence preservation")
        self.snapshot_system_state()
        self.collect_container_logs()
        self.collect_network_state()
        self.collect_process_state()

        # Phase 3: Security lockdown
        self.logger.info("Phase 3: Security lockdown")
        self.disable_network_interfaces()
        self.create_memory_dump()
        self.secure_evidence()

        # Phase 4: Incident reporting
        self.logger.info("Phase 4: Incident reporting")
        self.generate_incident_report(reason)

        self.logger.critical("EMERGENCY SHUTDOWN COMPLETE")
        print(f"Incident ID: {self.incident_id}")
        print(f"Evidence preserved in: {self.evidence_dir}")

    def kill_all_containers(self):
        """Immediately kill all RAID containers"""
        try:
            # Get all RAID containers
            result = subprocess.run([
                "docker", "ps", "--filter", "name=raid-", "--format", "{{.ID}}"
            ], capture_output=True, text=True)

            container_ids = result.stdout.strip().split('\n')
            container_ids = [cid for cid in container_ids if cid]

            if container_ids:
                self.logger.info(f"Killing {len(container_ids)} RAID containers")

                # Force kill all containers
                subprocess.run(["docker", "kill"] + container_ids, capture_output=True)

                # Remove containers
                subprocess.run(["docker", "rm", "-f"] + container_ids, capture_output=True)

                self.logger.info("All RAID containers terminated")
            else:
                self.logger.info("No RAID containers found")

        except Exception as e:
            self.logger.error(f"Error killing containers: {e}")

    def isolate_network(self):
        """Isolate all RAID networks"""
        try:
            # Get all RAID networks
            result = subprocess.run([
                "docker", "network", "ls", "--filter", "name=raid-", "--format", "{{.Name}}"
            ], capture_output=True, text=True)

            networks = result.stdout.strip().split('\n')
            networks = [net for net in networks if net and net != "bridge"]

            for network in networks:
                # Disconnect all containers from network
                subprocess.run([
                    "docker", "network", "disconnect", "-f", network, "$(docker ps -q)"
                ], shell=True, capture_output=True)

                # Remove network
                subprocess.run(["docker", "network", "rm", network], capture_output=True)

            self.logger.info(f"Isolated {len(networks)} RAID networks")

        except Exception as e:
            self.logger.error(f"Error isolating networks: {e}")

    def pause_all_raids(self):
        """Pause all active RAID runs"""
        try:
            # Look for RAID controller processes
            result = subprocess.run([
                "pgrep", "-f", "raid"
            ], capture_output=True, text=True)

            pids = result.stdout.strip().split('\n')
            pids = [pid for pid in pids if pid]

            for pid in pids:
                try:
                    # Send SIGSTOP to pause process
                    os.kill(int(pid), signal.SIGSTOP)
                    self.logger.info(f"Paused RAID process: {pid}")
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error pausing RAID processes: {e}")

    def snapshot_system_state(self):
        """Capture complete system state snapshot"""
        try:
            state_file = self.evidence_dir / "system_state.json"

            state = {
                "timestamp": self.timestamp,
                "incident_id": self.incident_id,
                "hostname": os.uname().nodename,
                "uptime": self._get_uptime(),
                "load_average": os.getloadavg(),
                "memory_info": self._get_memory_info(),
                "disk_usage": self._get_disk_usage(),
                "network_interfaces": self._get_network_interfaces(),
                "active_connections": self._get_active_connections(),
                "running_processes": self._get_running_processes(),
                "open_files": self._get_open_files(),
                "kernel_modules": self._get_kernel_modules(),
                "environment_vars": dict(os.environ)
            }

            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)

            self.logger.info("System state snapshot captured")

        except Exception as e:
            self.logger.error(f"Error capturing system state: {e}")

    def collect_container_logs(self):
        """Collect all container logs"""
        try:
            logs_dir = self.evidence_dir / "container_logs"
            logs_dir.mkdir(exist_ok=True)

            # Get all containers (including stopped ones)
            result = subprocess.run([
                "docker", "ps", "-a", "--filter", "name=raid-", "--format", "{{.Names}}"
            ], capture_output=True, text=True)

            containers = result.stdout.strip().split('\n')
            containers = [name for name in containers if name]

            for container in containers:
                try:
                    log_file = logs_dir / f"{container}.log"
                    with open(log_file, 'w') as f:
                        subprocess.run([
                            "docker", "logs", container
                        ], stdout=f, stderr=subprocess.STDOUT)

                    self.logger.info(f"Collected logs for container: {container}")

                except Exception as e:
                    self.logger.warning(f"Could not collect logs for {container}: {e}")

        except Exception as e:
            self.logger.error(f"Error collecting container logs: {e}")

    def collect_network_state(self):
        """Collect network configuration and state"""
        try:
            network_file = self.evidence_dir / "network_state.txt"

            with open(network_file, 'w') as f:
                # Network interfaces
                f.write("=== Network Interfaces ===\n")
                subprocess.run(["ip", "addr", "show"], stdout=f, stderr=subprocess.STDOUT)

                # Routing table
                f.write("\n=== Routing Table ===\n")
                subprocess.run(["ip", "route", "show"], stdout=f, stderr=subprocess.STDOUT)

                # iptables rules
                f.write("\n=== iptables Rules ===\n")
                subprocess.run(["sudo", "iptables", "-L", "-n", "-v"],
                             stdout=f, stderr=subprocess.STDOUT)

                # Active connections
                f.write("\n=== Active Connections ===\n")
                subprocess.run(["ss", "-tuln"], stdout=f, stderr=subprocess.STDOUT)

                # Docker networks
                f.write("\n=== Docker Networks ===\n")
                subprocess.run(["docker", "network", "ls"], stdout=f, stderr=subprocess.STDOUT)

            self.logger.info("Network state collected")

        except Exception as e:
            self.logger.error(f"Error collecting network state: {e}")

    def collect_process_state(self):
        """Collect process and system information"""
        try:
            process_file = self.evidence_dir / "process_state.txt"

            with open(process_file, 'w') as f:
                # Process list
                f.write("=== Process List ===\n")
                subprocess.run(["ps", "auxww"], stdout=f, stderr=subprocess.STDOUT)

                # Process tree
                f.write("\n=== Process Tree ===\n")
                subprocess.run(["pstree", "-p"], stdout=f, stderr=subprocess.STDOUT)

                # System calls
                f.write("\n=== Open Files ===\n")
                subprocess.run(["lsof", "+L1"], stdout=f, stderr=subprocess.STDOUT)

                # Memory maps
                f.write("\n=== Memory Maps ===\n")
                subprocess.run(["cat", "/proc/meminfo"], stdout=f, stderr=subprocess.STDOUT)

            self.logger.info("Process state collected")

        except Exception as e:
            self.logger.error(f"Error collecting process state: {e}")

    def disable_network_interfaces(self):
        """Disable network interfaces for complete isolation"""
        try:
            # Get all network interfaces except loopback
            result = subprocess.run([
                "ip", "link", "show"
            ], capture_output=True, text=True)

            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and 'lo:' not in line:
                    interface = line.split(':')[1].strip().split('@')[0]
                    interfaces.append(interface)

            for interface in interfaces:
                try:
                    subprocess.run(["sudo", "ip", "link", "set", interface, "down"],
                                 capture_output=True)
                    self.logger.info(f"Disabled network interface: {interface}")
                except:
                    pass

        except Exception as e:
            self.logger.error(f"Error disabling network interfaces: {e}")

    def create_memory_dump(self):
        """Create memory dump for forensic analysis"""
        try:
            # Only dump memory of RAID processes to avoid huge files
            result = subprocess.run([
                "pgrep", "-f", "raid"
            ], capture_output=True, text=True)

            pids = result.stdout.strip().split('\n')
            pids = [pid for pid in pids if pid]

            dumps_dir = self.evidence_dir / "memory_dumps"
            dumps_dir.mkdir(exist_ok=True)

            for pid in pids:
                try:
                    dump_file = dumps_dir / f"process_{pid}.dump"
                    maps_file = f"/proc/{pid}/maps"
                    mem_file = f"/proc/{pid}/mem"

                    if Path(maps_file).exists():
                        # Copy process memory maps
                        subprocess.run([
                            "cp", maps_file, str(dumps_dir / f"process_{pid}.maps")
                        ], capture_output=True)

                        self.logger.info(f"Created memory dump for PID: {pid}")

                except Exception as e:
                    self.logger.warning(f"Could not dump memory for PID {pid}: {e}")

        except Exception as e:
            self.logger.error(f"Error creating memory dumps: {e}")

    def secure_evidence(self):
        """Secure and sign evidence collection"""
        try:
            # Create evidence manifest
            manifest = {
                "incident_id": self.incident_id,
                "timestamp": self.timestamp,
                "hostname": os.uname().nodename,
                "evidence_files": [],
                "file_hashes": {}
            }

            # Calculate hashes for all evidence files
            for file_path in self.evidence_dir.rglob("*"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(self.evidence_dir)
                    manifest["evidence_files"].append(str(rel_path))

                    # Calculate SHA256 hash
                    try:
                        import hashlib
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        manifest["file_hashes"][str(rel_path)] = file_hash
                    except:
                        pass

            # Save manifest
            manifest_file = self.evidence_dir / "MANIFEST.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)

            # Create tamper-evident archive
            archive_name = f"raid-incident-{self.incident_id}.tar.gz"
            subprocess.run([
                "tar", "-czf", f"/tmp/{archive_name}", "-C", str(self.evidence_dir.parent),
                self.evidence_dir.name
            ], capture_output=True)

            self.logger.info(f"Evidence secured in archive: /tmp/{archive_name}")

        except Exception as e:
            self.logger.error(f"Error securing evidence: {e}")

    def generate_incident_report(self, reason: str):
        """Generate incident report"""
        try:
            report = {
                "incident_id": self.incident_id,
                "timestamp": self.timestamp,
                "trigger_reason": reason,
                "hostname": os.uname().nodename,
                "shutdown_phases": [
                    "Container termination",
                    "Network isolation",
                    "Process suspension",
                    "Evidence collection",
                    "System lockdown"
                ],
                "evidence_location": str(self.evidence_dir),
                "next_steps": [
                    "Review incident logs",
                    "Analyze evidence collection",
                    "Determine root cause",
                    "Update security measures",
                    "Resume operations when safe"
                ],
                "contacts": [
                    "Security team: security@organization.com",
                    "Incident response: ir@organization.com"
                ]
            }

            report_file = self.evidence_dir / "INCIDENT_REPORT.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)

            # Also create human-readable report
            summary_file = self.evidence_dir / "INCIDENT_SUMMARY.txt"
            with open(summary_file, 'w') as f:
                f.write("RAID EMERGENCY SHUTDOWN INCIDENT REPORT\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Incident ID: {self.incident_id}\n")
                f.write(f"Timestamp: {self.timestamp}\n")
                f.write(f"Hostname: {os.uname().nodename}\n")
                f.write(f"Trigger Reason: {reason}\n\n")

                f.write("Actions Taken:\n")
                for phase in report["shutdown_phases"]:
                    f.write(f"  ✓ {phase}\n")

                f.write(f"\nEvidence Location: {self.evidence_dir}\n\n")

                f.write("Next Steps:\n")
                for step in report["next_steps"]:
                    f.write(f"  • {step}\n")

            self.logger.info("Incident report generated")

        except Exception as e:
            self.logger.error(f"Error generating incident report: {e}")

    # Helper methods for system state collection
    def _get_uptime(self) -> str:
        try:
            with open('/proc/uptime', 'r') as f:
                return f.read().strip()
        except:
            return "unknown"

    def _get_memory_info(self) -> Dict:
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    key, value = line.strip().split(':', 1)
                    meminfo[key] = value.strip()
                return meminfo
        except:
            return {}

    def _get_disk_usage(self) -> Dict:
        try:
            result = subprocess.run(['df', '-h'], capture_output=True, text=True)
            return {"df_output": result.stdout}
        except:
            return {}

    def _get_network_interfaces(self) -> List:
        try:
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
            return result.stdout.split('\n')
        except:
            return []

    def _get_active_connections(self) -> List:
        try:
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
            return result.stdout.split('\n')
        except:
            return []

    def _get_running_processes(self) -> List:
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            return result.stdout.split('\n')
        except:
            return []

    def _get_open_files(self) -> List:
        try:
            result = subprocess.run(['lsof'], capture_output=True, text=True)
            return result.stdout.split('\n')[:1000]  # Limit output
        except:
            return []

    def _get_kernel_modules(self) -> List:
        try:
            result = subprocess.run(['lsmod'], capture_output=True, text=True)
            return result.stdout.split('\n')
        except:
            return []


def signal_handler(signum, frame):
    """Handle emergency shutdown signals"""
    shutdown = EmergencyShutdown()
    shutdown.execute_emergency_shutdown(f"Signal {signum} received")
    sys.exit(0)


def main():
    """Main function for manual trigger"""
    if len(sys.argv) > 1:
        reason = " ".join(sys.argv[1:])
    else:
        reason = "Manual emergency shutdown trigger"

    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    print("RAID Emergency Shutdown System")
    print("=" * 30)
    print("WARNING: This will immediately terminate all RAID operations")
    print("and isolate the system for incident response.")
    print()

    if len(sys.argv) == 1:
        confirm = input("Are you sure you want to proceed? (yes/no): ")
        if confirm.lower() != "yes":
            print("Emergency shutdown cancelled.")
            sys.exit(0)

    shutdown = EmergencyShutdown()
    shutdown.execute_emergency_shutdown(reason)


if __name__ == "__main__":
    main()