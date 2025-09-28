"""
RAID Operational Monitoring and Alerting System
Real-time monitoring, metrics collection, and alerting for security assessments
"""

import time
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MetricType(str, Enum):
    """Types of metrics collected"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Alert:
    """Alert definition and state"""
    alert_id: str
    name: str
    description: str
    severity: AlertSeverity
    condition: str
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    escalation_count: int = 0
    max_escalations: int = 3


@dataclass
class Metric:
    """Metric data point"""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collects and stores system metrics"""

    def __init__(self, max_history: int = 10000):
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()

    def counter(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Increment counter metric"""
        with self.lock:
            metric_key = self._get_metric_key(name, labels or {})
            self.counters[metric_key] += value

            metric = Metric(
                name=name,
                value=self.counters[metric_key],
                metric_type=MetricType.COUNTER,
                labels=labels or {}
            )
            self.metrics[metric_key].append(metric)

    def gauge(self, name: str, value: Union[int, float], labels: Dict[str, str] = None):
        """Set gauge metric value"""
        with self.lock:
            metric_key = self._get_metric_key(name, labels or {})
            self.gauges[metric_key] = float(value)

            metric = Metric(
                name=name,
                value=value,
                metric_type=MetricType.GAUGE,
                labels=labels or {}
            )
            self.metrics[metric_key].append(metric)

    def histogram(self, name: str, value: Union[int, float], labels: Dict[str, str] = None):
        """Record histogram value"""
        with self.lock:
            metric_key = self._get_metric_key(name, labels or {})

            metric = Metric(
                name=name,
                value=value,
                metric_type=MetricType.HISTOGRAM,
                labels=labels or {}
            )
            self.metrics[metric_key].append(metric)

    def timer(self, name: str, labels: Dict[str, str] = None):
        """Context manager for timing operations"""
        return TimerContext(self, name, labels or {})

    def get_metric_value(self, name: str, labels: Dict[str, str] = None) -> Optional[Union[int, float]]:
        """Get current value of a metric"""
        metric_key = self._get_metric_key(name, labels or {})

        if metric_key in self.counters:
            return self.counters[metric_key]
        elif metric_key in self.gauges:
            return self.gauges[metric_key]
        elif metric_key in self.metrics:
            recent_metrics = list(self.metrics[metric_key])
            if recent_metrics:
                return recent_metrics[-1].value

        return None

    def get_metric_history(self, name: str, labels: Dict[str, str] = None, limit: int = 100) -> List[Metric]:
        """Get metric history"""
        metric_key = self._get_metric_key(name, labels or {})
        if metric_key in self.metrics:
            return list(self.metrics[metric_key])[-limit:]
        return []

    def _get_metric_key(self, name: str, labels: Dict[str, str]) -> str:
        """Generate unique key for metric with labels"""
        if not labels:
            return name

        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"


class TimerContext:
    """Context manager for timing operations"""

    def __init__(self, collector: MetricsCollector, name: str, labels: Dict[str, str]):
        self.collector = collector
        self.name = name
        self.labels = labels
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.collector.histogram(self.name, duration, self.labels)


class AlertManager:
    """Manages alerts and notifications"""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_rules: List[Callable] = []
        self.notification_handlers: List[Callable] = []
        self.running = False
        self.check_interval = 10  # seconds

    def add_alert_rule(self, rule_func: Callable[[MetricsCollector], Optional[Alert]]):
        """Add alert rule function"""
        self.alert_rules.append(rule_func)

    def add_notification_handler(self, handler: Callable[[Alert], None]):
        """Add notification handler"""
        self.notification_handlers.append(handler)

    async def start_monitoring(self):
        """Start alert monitoring loop"""
        self.running = True
        logger.info("Starting alert monitoring")

        while self.running:
            try:
                await self._check_alerts()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in alert monitoring: {e}")
                await asyncio.sleep(self.check_interval)

    def stop_monitoring(self):
        """Stop alert monitoring"""
        self.running = False
        logger.info("Stopping alert monitoring")

    async def _check_alerts(self):
        """Check all alert rules"""
        for rule_func in self.alert_rules:
            try:
                alert = rule_func(self.metrics)
                if alert:
                    await self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error checking alert rule: {e}")

        # Check for resolved alerts
        await self._check_resolved_alerts()

    async def _handle_alert(self, alert: Alert):
        """Handle triggered alert"""
        if alert.alert_id in self.active_alerts:
            # Update existing alert
            existing = self.active_alerts[alert.alert_id]
            existing.escalation_count += 1
            existing.metadata.update(alert.metadata)

            if existing.escalation_count <= existing.max_escalations:
                await self._notify_alert(existing, is_escalation=True)
        else:
            # New alert
            self.active_alerts[alert.alert_id] = alert
            await self._notify_alert(alert, is_escalation=False)
            logger.warning(f"Alert triggered: {alert.name} ({alert.severity})")

    async def _check_resolved_alerts(self):
        """Check if any alerts should be resolved"""
        resolved_alerts = []

        for alert_id, alert in self.active_alerts.items():
            # Check if alert condition is no longer met
            if self._is_alert_resolved(alert):
                alert.resolved_at = datetime.utcnow()
                resolved_alerts.append(alert_id)
                await self._notify_alert_resolved(alert)

        # Remove resolved alerts
        for alert_id in resolved_alerts:
            del self.active_alerts[alert_id]

    def _is_alert_resolved(self, alert: Alert) -> bool:
        """Check if alert condition is resolved"""
        # Simplified resolution check - production should have proper logic
        return False

    async def _notify_alert(self, alert: Alert, is_escalation: bool = False):
        """Send alert notifications"""
        for handler in self.notification_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Error in notification handler: {e}")

    async def _notify_alert_resolved(self, alert: Alert):
        """Send alert resolution notifications"""
        logger.info(f"Alert resolved: {alert.name}")
        # Implementation for resolution notifications


class RAIDMonitor:
    """Main monitoring system for RAID framework"""

    def __init__(self, config_dir: str = "/app/monitoring"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.metrics = MetricsCollector()
        self.alerts = AlertManager(self.metrics)

        # System state tracking
        self.active_runs: Dict[str, Dict] = {}
        self.tool_performance: Dict[str, List[float]] = defaultdict(list)

        # Setup standard alert rules
        self._setup_default_alerts()

    def start_run_monitoring(self, run_id: str, run_context: Dict[str, Any]):
        """Start monitoring a specific run"""
        self.active_runs[run_id] = {
            "start_time": datetime.utcnow(),
            "context": run_context,
            "phases_completed": 0,
            "tools_executed": 0,
            "errors": 0
        }

        self.metrics.counter("raid.runs.started", labels={"run_id": run_id})
        self.metrics.gauge("raid.runs.active", len(self.active_runs))

    def end_run_monitoring(self, run_id: str, success: bool = True):
        """End monitoring for a specific run"""
        if run_id in self.active_runs:
            run_data = self.active_runs[run_id]
            duration = (datetime.utcnow() - run_data["start_time"]).total_seconds()

            self.metrics.histogram("raid.run.duration", duration, labels={"run_id": run_id})
            self.metrics.counter("raid.runs.completed", labels={
                "run_id": run_id,
                "success": str(success)
            })

            del self.active_runs[run_id]
            self.metrics.gauge("raid.runs.active", len(self.active_runs))

    def record_tool_execution(self, tool_name: str, duration: float, success: bool):
        """Record tool execution metrics"""
        self.metrics.histogram("raid.tool.execution_time", duration, labels={
            "tool": tool_name,
            "success": str(success)
        })

        self.metrics.counter("raid.tool.executions", labels={
            "tool": tool_name,
            "success": str(success)
        })

        # Track performance history
        self.tool_performance[tool_name].append(duration)
        if len(self.tool_performance[tool_name]) > 100:
            self.tool_performance[tool_name] = self.tool_performance[tool_name][-100:]

    def record_approval_request(self, approval_type: str, response_time: Optional[float] = None):
        """Record approval request metrics"""
        self.metrics.counter("raid.approvals.requested", labels={"type": approval_type})

        if response_time:
            self.metrics.histogram("raid.approval.response_time", response_time, labels={
                "type": approval_type
            })

    def record_security_event(self, event_type: str, severity: str, details: Dict[str, Any] = None):
        """Record security-related events"""
        self.metrics.counter("raid.security.events", labels={
            "type": event_type,
            "severity": severity
        })

        # Create alert for high-severity security events
        if severity in ["high", "critical"]:
            alert = Alert(
                alert_id=f"security_{event_type}_{int(time.time())}",
                name=f"Security Event: {event_type}",
                description=f"High-severity security event detected: {event_type}",
                severity=AlertSeverity.HIGH if severity == "high" else AlertSeverity.CRITICAL,
                condition=f"security_event.{event_type}",
                triggered_at=datetime.utcnow(),
                metadata=details or {}
            )

            asyncio.create_task(self.alerts._handle_alert(alert))

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "active_runs": len(self.active_runs),
            "active_alerts": len(self.alerts.active_alerts),
            "total_runs_started": self.metrics.get_metric_value("raid.runs.started") or 0,
            "total_tools_executed": self.metrics.get_metric_value("raid.tool.executions") or 0,
            "system_health": self._assess_system_health()
        }

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        metrics = {}

        # Run performance
        run_durations = self.metrics.get_metric_history("raid.run.duration", limit=50)
        if run_durations:
            durations = [m.value for m in run_durations]
            metrics["run_performance"] = {
                "avg_duration": sum(durations) / len(durations),
                "min_duration": min(durations),
                "max_duration": max(durations),
                "total_runs": len(durations)
            }

        # Tool performance
        metrics["tool_performance"] = {}
        for tool_name, times in self.tool_performance.items():
            if times:
                metrics["tool_performance"][tool_name] = {
                    "avg_time": sum(times) / len(times),
                    "min_time": min(times),
                    "max_time": max(times),
                    "executions": len(times)
                }

        return metrics

    def _setup_default_alerts(self):
        """Setup default alert rules"""

        def high_failure_rate_alert(metrics: MetricsCollector) -> Optional[Alert]:
            """Alert on high tool failure rate"""
            total_executions = metrics.get_metric_value("raid.tool.executions") or 0

            if total_executions > 10:  # Only check if we have enough data
                # Calculate failure rate from recent metrics
                recent_executions = metrics.get_metric_history("raid.tool.executions", limit=20)
                failures = sum(1 for m in recent_executions if m.labels.get("success") == "False")

                if len(recent_executions) > 0:
                    failure_rate = failures / len(recent_executions)

                    if failure_rate > 0.3:  # 30% failure rate
                        return Alert(
                            alert_id="high_failure_rate",
                            name="High Tool Failure Rate",
                            description=f"Tool failure rate is {failure_rate:.1%}",
                            severity=AlertSeverity.HIGH,
                            condition="failure_rate > 0.3",
                            triggered_at=datetime.utcnow(),
                            metadata={"failure_rate": failure_rate}
                        )
            return None

        def long_running_assessment_alert(metrics: MetricsCollector) -> Optional[Alert]:
            """Alert on long-running assessments"""
            for run_id, run_data in self.active_runs.items():
                duration = (datetime.utcnow() - run_data["start_time"]).total_seconds()

                if duration > 3600:  # 1 hour
                    return Alert(
                        alert_id=f"long_running_{run_id}",
                        name="Long Running Assessment",
                        description=f"Assessment {run_id} has been running for {duration/3600:.1f} hours",
                        severity=AlertSeverity.MEDIUM,
                        condition="run_duration > 3600",
                        triggered_at=datetime.utcnow(),
                        metadata={"run_id": run_id, "duration": duration}
                    )
            return None

        def security_event_alert(metrics: MetricsCollector) -> Optional[Alert]:
            """Alert on suspicious security events"""
            security_events = metrics.get_metric_history("raid.security.events", limit=10)

            # Check for rapid security events
            recent_events = [e for e in security_events
                           if (datetime.utcnow() - e.timestamp).total_seconds() < 300]  # Last 5 minutes

            if len(recent_events) > 5:
                return Alert(
                    alert_id="rapid_security_events",
                    name="Rapid Security Events",
                    description=f"{len(recent_events)} security events in last 5 minutes",
                    severity=AlertSeverity.HIGH,
                    condition="security_events > 5 in 5min",
                    triggered_at=datetime.utcnow(),
                    metadata={"event_count": len(recent_events)}
                )
            return None

        # Register alert rules
        self.alerts.add_alert_rule(high_failure_rate_alert)
        self.alerts.add_alert_rule(long_running_assessment_alert)
        self.alerts.add_alert_rule(security_event_alert)

    def _assess_system_health(self) -> str:
        """Assess overall system health"""
        if len(self.alerts.active_alerts) == 0:
            return "healthy"

        critical_alerts = [a for a in self.alerts.active_alerts.values()
                          if a.severity == AlertSeverity.CRITICAL]
        high_alerts = [a for a in self.alerts.active_alerts.values()
                      if a.severity == AlertSeverity.HIGH]

        if critical_alerts:
            return "critical"
        elif len(high_alerts) > 2:
            return "degraded"
        elif len(self.alerts.active_alerts) > 5:
            return "warning"
        else:
            return "healthy"


# Notification handlers
class ConsoleNotificationHandler:
    """Console-based notification handler"""

    def __call__(self, alert: Alert):
        print(f"\n🚨 ALERT: {alert.name}")
        print(f"Severity: {alert.severity.upper()}")
        print(f"Description: {alert.description}")
        print(f"Time: {alert.triggered_at}")
        if alert.metadata:
            print(f"Details: {alert.metadata}")
        print("-" * 50)


class LogNotificationHandler:
    """Log-based notification handler"""

    def __init__(self):
        self.logger = logging.getLogger("raid.alerts")

    def __call__(self, alert: Alert):
        self.logger.warning(f"Alert: {alert.name} - {alert.description}", extra={
            "alert_id": alert.alert_id,
            "severity": alert.severity,
            "metadata": alert.metadata
        })


class MetricsExporter:
    """Export metrics in Prometheus format"""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []

        # Export counters
        for metric_key, value in self.metrics.counters.items():
            name, labels = self._parse_metric_key(metric_key)
            labels_str = self._format_labels(labels)
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name}{labels_str} {value}")

        # Export gauges
        for metric_key, value in self.metrics.gauges.items():
            name, labels = self._parse_metric_key(metric_key)
            labels_str = self._format_labels(labels)
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{labels_str} {value}")

        return "\n".join(lines)

    def _parse_metric_key(self, metric_key: str) -> tuple:
        """Parse metric key into name and labels"""
        if "{" in metric_key:
            name, labels_part = metric_key.split("{", 1)
            labels_part = labels_part.rstrip("}")
            labels = dict(item.split("=") for item in labels_part.split(",") if "=" in item)
            return name, labels
        return metric_key, {}

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus"""
        if not labels:
            return ""

        label_pairs = [f'{k}="{v}"' for k, v in labels.items()]
        return "{" + ",".join(label_pairs) + "}"


# Example usage
if __name__ == "__main__":
    import asyncio

    async def test_monitoring():
        monitor = RAIDMonitor("/tmp/raid-monitoring-test")

        # Add notification handlers
        monitor.alerts.add_notification_handler(ConsoleNotificationHandler())
        monitor.alerts.add_notification_handler(LogNotificationHandler())

        # Start monitoring
        monitoring_task = asyncio.create_task(monitor.alerts.start_monitoring())

        # Simulate some activity
        monitor.start_run_monitoring("test-run-001", {"target": "example.com"})

        # Simulate tool executions
        for i in range(10):
            success = i < 7  # 70% success rate
            monitor.record_tool_execution("http-fetcher", 1.5 + i * 0.1, success)
            await asyncio.sleep(0.1)

        # Simulate security events
        monitor.record_security_event("suspicious_network_access", "high", {
            "target": "192.168.1.1",
            "tool": "nmap"
        })

        # Wait for monitoring
        await asyncio.sleep(15)

        # Stop monitoring
        monitor.alerts.stop_monitoring()
        await monitoring_task

        # Print status
        print("\nSystem Status:")
        print(json.dumps(monitor.get_system_status(), indent=2))

        print("\nPerformance Metrics:")
        print(json.dumps(monitor.get_performance_metrics(), indent=2))

    asyncio.run(test_monitoring())