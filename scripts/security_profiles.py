#!/usr/bin/env python3
"""
RAID Security Profiles Generator
Creates seccomp, AppArmor, and other security profiles for container hardening
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any


class SecurityProfileGenerator:
    """Generate security profiles for RAID containers"""

    def __init__(self, output_dir: str = "docker/security"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_all_profiles(self):
        """Generate all security profiles"""
        print("Generating security profiles...")

        # Seccomp profiles
        self.generate_controller_seccomp()
        self.generate_tool_runner_seccomp()
        self.generate_synthesized_tool_seccomp()

        # AppArmor profiles
        self.generate_controller_apparmor()
        self.generate_tool_runner_apparmor()
        self.generate_synthesized_tool_apparmor()

        # eBPF monitoring scripts
        self.generate_syscall_monitor()

        print(f"Security profiles generated in {self.output_dir}")

    def generate_controller_seccomp(self):
        """Generate seccomp profile for controller container"""
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            "syscalls": [
                # Essential syscalls
                {
                    "names": [
                        "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
                        "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
                        "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
                        "readv", "writev", "access", "pipe", "select", "sched_yield",
                        "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Process management (limited)
                {
                    "names": ["getpid", "getppid", "getuid", "geteuid", "getgid", "getegid"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # File system (restricted)
                {
                    "names": ["getcwd", "chdir", "rename", "mkdir", "rmdir", "creat", "unlink"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Networking (controlled)
                {
                    "names": ["socket", "connect", "accept", "bind", "listen", "socketpair"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [
                        {
                            "index": 0,
                            "value": 2,  # AF_INET
                            "op": "SCMP_CMP_EQ"
                        }
                    ]
                },
                # Time
                {
                    "names": ["gettimeofday", "time", "clock_gettime"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Memory management
                {
                    "names": ["mlock", "munlock", "mlockall", "munlockall"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Docker API calls
                {
                    "names": ["sendto", "recvfrom", "sendmsg", "recvmsg"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Denied syscalls (security-critical)
                {
                    "names": [
                        "clone", "fork", "vfork", "execve", "execveat",
                        "ptrace", "process_vm_readv", "process_vm_writev",
                        "mount", "umount", "umount2", "pivot_root", "chroot",
                        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid",
                        "capget", "capset", "prctl", "arch_prctl",
                        "reboot", "kexec_load", "kexec_file_load"
                    ],
                    "action": "SCMP_ACT_ERRNO"
                }
            ]
        }

        with open(self.output_dir / "controller-seccomp.json", 'w') as f:
            json.dump(profile, f, indent=2)

    def generate_tool_runner_seccomp(self):
        """Generate seccomp profile for tool runner containers"""
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            "syscalls": [
                # Basic syscalls
                {
                    "names": [
                        "read", "write", "open", "openat", "close", "stat", "fstat",
                        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
                        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                        "readv", "writev", "pread64", "pwrite64"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Process info (read-only)
                {
                    "names": ["getpid", "getppid", "getuid", "geteuid", "getgid", "getegid"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Limited file operations
                {
                    "names": ["access", "getcwd", "readlink", "readlinkat"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Networking (very restricted)
                {
                    "names": ["socket", "connect"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [
                        {
                            "index": 0,
                            "value": 2,  # AF_INET only
                            "op": "SCMP_CMP_EQ"
                        }
                    ]
                },
                # Time
                {
                    "names": ["gettimeofday", "time", "clock_gettime"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Strictly forbidden
                {
                    "names": [
                        "clone", "fork", "vfork", "execve", "execveat",
                        "ptrace", "mount", "umount", "umount2", "chroot", "pivot_root",
                        "setuid", "setgid", "setreuid", "setregid",
                        "bind", "listen", "accept",  # No server capabilities
                        "kill", "tkill", "tgkill",  # No process killing
                        "reboot", "syslog", "kexec_load"
                    ],
                    "action": "SCMP_ACT_ERRNO"
                }
            ]
        }

        with open(self.output_dir / "tool-runner-seccomp.json", 'w') as f:
            json.dump(profile, f, indent=2)

    def generate_synthesized_tool_seccomp(self):
        """Generate ultra-restrictive seccomp for synthesized tools"""
        profile = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
                # Absolute minimum syscalls
                {
                    "names": [
                        "read", "write", "close", "stat", "fstat",
                        "mmap", "munmap", "brk", "rt_sigreturn",
                        "readv", "writev"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Process info (minimal)
                {
                    "names": ["getpid", "getuid", "getgid"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Time (limited)
                {
                    "names": ["gettimeofday", "time"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # File access (evidence directory only - enforced by AppArmor)
                {
                    "names": ["open", "openat"],
                    "action": "SCMP_ACT_ALLOW"
                },
                # Everything else denied
                {
                    "names": ["*"],
                    "action": "SCMP_ACT_ERRNO"
                }
            ]
        }

        with open(self.output_dir / "synthesized-tool-seccomp.json", 'w') as f:
            json.dump(profile, f, indent=2)

    def generate_controller_apparmor(self):
        """Generate AppArmor profile for controller"""
        profile = """
#include <tunables/global>

profile raid-controller flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/ssl_certs>

  # Network access
  network inet stream,
  network inet dgram,
  network unix stream,
  network unix dgram,

  # File access
  /app/** rw,
  /tmp/** rw,
  /var/tmp/** rw,
  /results/** rw,
  /evidence/** rw,
  /auth/** r,
  /roles/** r,
  /secrets/** r,

  # Python and system libraries
  /usr/bin/python3* ix,
  /usr/lib/python*/** r,
  /lib/x86_64-linux-gnu/** rm,
  /usr/lib/x86_64-linux-gnu/** rm,

  # Docker socket (for container management)
  /var/run/docker.sock rw,

  # System information
  /proc/*/stat r,
  /proc/*/status r,
  /proc/meminfo r,
  /proc/cpuinfo r,
  /sys/fs/cgroup/** r,

  # Denied paths
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /root/** rw,
  deny /home/** rw,
  deny /boot/** rw,
  deny /sys/** w,
  deny /proc/sys/** w,

  # Capabilities
  capability net_bind_service,
  capability dac_override,
  capability fowner,

  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_ptrace,
}
"""

        with open(self.output_dir / "raid-controller", 'w') as f:
            f.write(profile)

    def generate_tool_runner_apparmor(self):
        """Generate AppArmor profile for tool runners"""
        profile = """
#include <tunables/global>

profile raid-tool-runner flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  #include <abstractions/python>

  # Limited network access
  network inet stream,
  network inet dgram,

  # Restricted file access
  /app/** r,
  /app/tool/** rw,
  /app/evidence/** rw,
  /tmp/** rw,

  # Python runtime
  /usr/bin/python3* ix,
  /usr/lib/python*/** r,
  /lib/x86_64-linux-gnu/** rm,

  # System information (read-only)
  /proc/*/stat r,
  /proc/meminfo r,

  # Denied paths (extensive)
  deny /etc/shadow r,
  deny /etc/gshadow r,
  deny /etc/passwd w,
  deny /etc/group w,
  deny /root/** rw,
  deny /home/** rw,
  deny /boot/** rw,
  deny /sys/** w,
  deny /proc/sys/** w,
  deny /var/run/docker.sock rw,
  deny /dev/** rw,

  # No capabilities
  deny capability,
}
"""

        with open(self.output_dir / "raid-tool-runner", 'w') as f:
            f.write(profile)

    def generate_synthesized_tool_apparmor(self):
        """Generate ultra-restrictive AppArmor for synthesized tools"""
        profile = """
#include <tunables/global>

profile raid-synthesized-tool flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Minimal file access
  /app/tool.py r,
  /app/evidence/** rw,
  /tmp/** rw,

  # Python (minimal)
  /usr/bin/python3 ix,
  /usr/lib/python*/site-packages/** r,
  /lib/x86_64-linux-gnu/libc.so.* rm,
  /lib/x86_64-linux-gnu/libpthread.so.* rm,

  # No network access
  deny network,

  # Deny everything else
  deny /** w,
  deny /proc/** w,
  deny /sys/** rw,
  deny /dev/** rw,
  deny /etc/** w,
  deny /usr/** w,
  deny /var/** rw,
  deny /home/** rw,
  deny /root/** rw,

  # No capabilities
  deny capability,
}
"""

        with open(self.output_dir / "raid-synthesized-tool", 'w') as f:
            f.write(profile)

    def generate_syscall_monitor(self):
        """Generate eBPF-based syscall monitoring script"""
        monitor_script = """#!/usr/bin/env python3
'''
RAID Syscall Monitor
eBPF-based monitoring for suspicious syscall patterns in containers
'''

import sys
import signal
import time
from datetime import datetime
try:
    from bcc import BPF
except ImportError:
    print("WARNING: BCC not available, syscall monitoring disabled")
    sys.exit(0)

# eBPF program
bpf_program = '''
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Suspicious syscalls to monitor
BPF_HASH(suspicious_syscalls, u32, u64);

// Track container processes
BPF_HASH(container_pids, u32, u64);

int trace_syscall_enter(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 syscall_id = ctx->orig_ax;

    // Check if this is a container process
    u64 *container_flag = container_pids.lookup(&pid);
    if (!container_flag) {
        return 0;
    }

    // Monitor dangerous syscalls
    if (syscall_id == 56 ||   // clone
        syscall_id == 57 ||   // fork
        syscall_id == 58 ||   // vfork
        syscall_id == 59 ||   // execve
        syscall_id == 165 ||  // mount
        syscall_id == 166 ||  // umount2
        syscall_id == 105 ||  // setuid
        syscall_id == 106 ||  // setgid
        syscall_id == 101 ||  // ptrace
        syscall_id == 155) {  // pivot_root

        u64 *count = suspicious_syscalls.lookup(&syscall_id);
        if (count) {
            (*count)++;
        } else {
            u64 initial = 1;
            suspicious_syscalls.update(&syscall_id, &initial);
        }

        // Print alert
        bpf_trace_printk("ALERT: PID %d attempted syscall %d\\n", pid, syscall_id);
    }

    return 0;
}
'''

class SyscallMonitor:
    def __init__(self):
        self.bpf = None
        self.running = False
        self.alerts = []

    def start_monitoring(self, container_pids):
        '''Start monitoring specified container PIDs'''
        try:
            self.bpf = BPF(text=bpf_program)
            self.bpf.attach_kprobe(event="sys_enter", fn_name="trace_syscall_enter")

            # Register container PIDs
            container_map = self.bpf["container_pids"]
            for pid in container_pids:
                container_map[pid] = 1

            self.running = True
            print(f"Started syscall monitoring for PIDs: {container_pids}")

        except Exception as e:
            print(f"Failed to start syscall monitoring: {e}")
            return False

        return True

    def check_alerts(self):
        '''Check for new alerts'''
        if not self.bpf:
            return []

        alerts = []
        try:
            suspicious_map = self.bpf["suspicious_syscalls"]
            for syscall_id, count in suspicious_map.items():
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "syscall_id": syscall_id.value,
                    "count": count.value,
                    "severity": "HIGH" if count.value > 5 else "MEDIUM"
                })
        except Exception as e:
            print(f"Error checking alerts: {e}")

        return alerts

    def stop_monitoring(self):
        '''Stop monitoring'''
        self.running = False
        if self.bpf:
            self.bpf.cleanup()

def signal_handler(sig, frame):
    print("\\nStopping syscall monitor...")
    sys.exit(0)

def main():
    if len(sys.argv) < 2:
        print("Usage: syscall_monitor.py <container_pid1> [container_pid2] ...")
        sys.exit(1)

    container_pids = [int(pid) for pid in sys.argv[1:]]

    monitor = SyscallMonitor()
    signal.signal(signal.SIGINT, signal_handler)

    if monitor.start_monitoring(container_pids):
        print("Syscall monitoring active. Press Ctrl+C to stop.")

        try:
            while True:
                time.sleep(5)
                alerts = monitor.check_alerts()
                for alert in alerts:
                    print(f"SECURITY ALERT: {alert}")

        except KeyboardInterrupt:
            pass
        finally:
            monitor.stop_monitoring()

if __name__ == "__main__":
    main()
"""

        monitor_file = self.output_dir / "syscall_monitor.py"
        with open(monitor_file, 'w') as f:
            f.write(monitor_script)

        # Make executable
        monitor_file.chmod(0o755)

    def generate_docker_security_opts(self):
        """Generate Docker security options for compose files"""
        security_opts = {
            "controller": [
                "--security-opt=seccomp:docker/security/controller-seccomp.json",
                "--security-opt=apparmor:raid-controller",
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--cap-add=NET_BIND_SERVICE",
                "--cap-add=DAC_OVERRIDE"
            ],
            "tool_runner": [
                "--security-opt=seccomp:docker/security/tool-runner-seccomp.json",
                "--security-opt=apparmor:raid-tool-runner",
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--read-only",
                "--tmpfs=/tmp:noexec,nosuid,size=100m"
            ],
            "synthesized_tool": [
                "--security-opt=seccomp:docker/security/synthesized-tool-seccomp.json",
                "--security-opt=apparmor:raid-synthesized-tool",
                "--security-opt=no-new-privileges",
                "--cap-drop=ALL",
                "--read-only",
                "--tmpfs=/tmp:noexec,nosuid,size=50m",
                "--memory=128m",
                "--cpus=0.25",
                "--network=none"
            ]
        }

        with open(self.output_dir / "docker-security-opts.json", 'w') as f:
            json.dump(security_opts, f, indent=2)


if __name__ == "__main__":
    generator = SecurityProfileGenerator()
    generator.generate_all_profiles()
    generator.generate_docker_security_opts()
    print("Security profiles generation complete!")
"""