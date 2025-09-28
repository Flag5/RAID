"""
RAID Role-Based Access Control (RBAC) System
Manages user roles, permissions, and approval workflows
"""

import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging

from specs.schemas import Authorization, AssessmentPlan, ApprovalStatus

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    """System permissions"""
    # Assessment permissions
    RUN_ASSESSMENT = "run_assessment"
    RUN_DESTRUCTIVE = "run_destructive"
    RUN_AUTHENTICATED = "run_authenticated"

    # Tool permissions
    SYNTHESIZE_TOOLS = "synthesize_tools"
    APPROVE_TOOLS = "approve_tools"
    MANAGE_TOOLS = "manage_tools"

    # Device permissions
    USE_DEVICES = "use_devices"
    APPROVE_DEVICES = "approve_devices"

    # Administrative permissions
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"

    # Approval permissions
    APPROVE_ASSESSMENTS = "approve_assessments"
    APPROVE_DESTRUCTIVE = "approve_destructive"
    APPROVE_EMERGENCY = "approve_emergency"


class Role(str, Enum):
    """Predefined system roles"""
    # Operator roles
    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    TEAM_LEAD = "team_lead"

    # Administrative roles
    ADMINISTRATOR = "administrator"
    SECURITY_OFFICER = "security_officer"

    # Special roles
    EMERGENCY_RESPONDER = "emergency_responder"
    AUDIT_VIEWER = "audit_viewer"
    TOOL_DEVELOPER = "tool_developer"


@dataclass
class User:
    """User account with RBAC properties"""
    user_id: str
    username: str
    email: str
    roles: Set[Role]
    permissions: Set[Permission] = field(default_factory=set)

    # Account status
    active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

    # Security settings
    mfa_enabled: bool = False
    session_timeout_minutes: int = 480  # 8 hours

    # Approval limits
    max_approval_value: float = 0.0  # Monetary value limit
    approval_timeout_minutes: int = 60

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        if not self.active:
            return False

        # Direct permission grant
        if permission in self.permissions:
            return True

        # Permission from roles
        for role in self.roles:
            if permission in ROLE_PERMISSIONS.get(role, set()):
                return True

        return False

    def can_approve(self, action_type: str, value: float = 0.0) -> bool:
        """Check if user can approve specific action"""
        if not self.active:
            return False

        # Check value limits
        if value > self.max_approval_value:
            return False

        # Check action-specific permissions
        approval_map = {
            "destructive": Permission.APPROVE_DESTRUCTIVE,
            "assessment": Permission.APPROVE_ASSESSMENTS,
            "emergency": Permission.APPROVE_EMERGENCY,
            "tool_synthesis": Permission.APPROVE_TOOLS,
            "device_passthrough": Permission.APPROVE_DEVICES
        }

        required_permission = approval_map.get(action_type)
        return required_permission and self.has_permission(required_permission)


@dataclass
class ApprovalRequest:
    """Approval request with audit trail"""
    request_id: str
    requester_id: str
    action_type: str
    action_description: str

    # Request context
    run_id: Optional[str] = None
    target: Optional[str] = None
    estimated_risk: str = "medium"  # low, medium, high, critical
    estimated_value: float = 0.0

    # Approval workflow
    status: ApprovalStatus = ApprovalStatus.PENDING
    required_approvers: Set[str] = field(default_factory=set)
    received_approvals: Dict[str, datetime] = field(default_factory=dict)
    received_denials: Dict[str, datetime] = field(default_factory=dict)

    # Timing
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Audit trail
    comments: List[Dict[str, str]] = field(default_factory=list)

    def is_expired(self) -> bool:
        """Check if approval request has expired"""
        return self.expires_at and datetime.utcnow() > self.expires_at

    def is_fully_approved(self) -> bool:
        """Check if request has all required approvals"""
        return len(self.received_approvals) >= len(self.required_approvers)

    def has_denial(self) -> bool:
        """Check if request has been denied"""
        return len(self.received_denials) > 0


# Role-Permission Mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ANALYST: {
        Permission.RUN_ASSESSMENT,
        Permission.USE_DEVICES
    },

    Role.SENIOR_ANALYST: {
        Permission.RUN_ASSESSMENT,
        Permission.RUN_AUTHENTICATED,
        Permission.USE_DEVICES,
        Permission.SYNTHESIZE_TOOLS
    },

    Role.TEAM_LEAD: {
        Permission.RUN_ASSESSMENT,
        Permission.RUN_AUTHENTICATED,
        Permission.RUN_DESTRUCTIVE,
        Permission.USE_DEVICES,
        Permission.SYNTHESIZE_TOOLS,
        Permission.APPROVE_ASSESSMENTS,
        Permission.APPROVE_TOOLS,
        Permission.VIEW_AUDIT_LOGS
    },

    Role.ADMINISTRATOR: {
        Permission.RUN_ASSESSMENT,
        Permission.RUN_AUTHENTICATED,
        Permission.RUN_DESTRUCTIVE,
        Permission.USE_DEVICES,
        Permission.SYNTHESIZE_TOOLS,
        Permission.MANAGE_TOOLS,
        Permission.APPROVE_ASSESSMENTS,
        Permission.APPROVE_TOOLS,
        Permission.APPROVE_DEVICES,
        Permission.MANAGE_USERS,
        Permission.MANAGE_ROLES,
        Permission.VIEW_AUDIT_LOGS
    },

    Role.SECURITY_OFFICER: {
        Permission.APPROVE_ASSESSMENTS,
        Permission.APPROVE_DESTRUCTIVE,
        Permission.APPROVE_DEVICES,
        Permission.VIEW_AUDIT_LOGS,
        Permission.EMERGENCY_SHUTDOWN
    },

    Role.EMERGENCY_RESPONDER: {
        Permission.EMERGENCY_SHUTDOWN,
        Permission.APPROVE_EMERGENCY,
        Permission.VIEW_AUDIT_LOGS
    },

    Role.AUDIT_VIEWER: {
        Permission.VIEW_AUDIT_LOGS
    },

    Role.TOOL_DEVELOPER: {
        Permission.SYNTHESIZE_TOOLS,
        Permission.MANAGE_TOOLS,
        Permission.APPROVE_TOOLS
    }
}


class RBACManager:
    """Role-Based Access Control Manager"""

    def __init__(self, config_dir: str = "/app/auth"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.users: Dict[str, User] = {}
        self.approval_requests: Dict[str, ApprovalRequest] = {}
        self.audit_log: List[Dict] = []

        self._load_configuration()

    def authenticate_user(self, username: str, credentials: Dict[str, str]) -> Optional[User]:
        """Authenticate user and return user object"""
        # Simplified authentication - production should use proper auth
        user = self.get_user_by_username(username)
        if not user or not user.active:
            self._audit_log("authentication_failed", username)
            return None

        # Update last login
        user.last_login = datetime.utcnow()
        self._save_users()

        self._audit_log("authentication_success", username)
        return user

    def authorize_action(self, user: User, action: str, context: Dict = None) -> bool:
        """Authorize user action based on RBAC"""
        if not user.active:
            return False

        # Map actions to permissions
        action_permissions = {
            "run_assessment": Permission.RUN_ASSESSMENT,
            "run_destructive": Permission.RUN_DESTRUCTIVE,
            "run_authenticated": Permission.RUN_AUTHENTICATED,
            "synthesize_tools": Permission.SYNTHESIZE_TOOLS,
            "use_devices": Permission.USE_DEVICES,
            "manage_users": Permission.MANAGE_USERS,
            "emergency_shutdown": Permission.EMERGENCY_SHUTDOWN
        }

        required_permission = action_permissions.get(action)
        if not required_permission:
            return False

        authorized = user.has_permission(required_permission)

        self._audit_log(
            "authorization_check",
            user.username,
            {
                "action": action,
                "authorized": authorized,
                "context": context
            }
        )

        return authorized

    def create_approval_request(
        self,
        requester: User,
        action_type: str,
        description: str,
        **kwargs
    ) -> ApprovalRequest:
        """Create new approval request"""

        request_id = f"approval_{int(time.time())}_{hash(description) % 10000:04d}"

        # Determine required approvers based on action type and risk
        required_approvers = self._get_required_approvers(action_type, kwargs.get("estimated_risk", "medium"))

        # Set expiration time
        timeout_minutes = kwargs.get("timeout_minutes", 60)
        expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)

        request = ApprovalRequest(
            request_id=request_id,
            requester_id=requester.user_id,
            action_type=action_type,
            action_description=description,
            required_approvers=required_approvers,
            expires_at=expires_at,
            **{k: v for k, v in kwargs.items() if k in ApprovalRequest.__dataclass_fields__}
        )

        self.approval_requests[request_id] = request
        self._save_approval_requests()

        self._audit_log(
            "approval_request_created",
            requester.username,
            {
                "request_id": request_id,
                "action_type": action_type,
                "required_approvers": list(required_approvers)
            }
        )

        return request

    def submit_approval(
        self,
        request_id: str,
        approver: User,
        decision: ApprovalStatus,
        comment: str = ""
    ) -> bool:
        """Submit approval decision"""

        if request_id not in self.approval_requests:
            return False

        request = self.approval_requests[request_id]

        # Check if user can approve this request
        if not approver.can_approve(request.action_type, request.estimated_value):
            self._audit_log(
                "approval_unauthorized",
                approver.username,
                {"request_id": request_id, "reason": "insufficient_permissions"}
            )
            return False

        # Check if request is still valid
        if request.is_expired():
            request.status = ApprovalStatus.TIMEOUT
            self._audit_log(
                "approval_timeout",
                approver.username,
                {"request_id": request_id}
            )
            return False

        # Record decision
        if decision == ApprovalStatus.APPROVED:
            request.received_approvals[approver.user_id] = datetime.utcnow()
        elif decision == ApprovalStatus.DENIED:
            request.received_denials[approver.user_id] = datetime.utcnow()
            request.status = ApprovalStatus.DENIED

        # Add comment
        if comment:
            request.comments.append({
                "approver": approver.username,
                "timestamp": datetime.utcnow().isoformat(),
                "comment": comment,
                "decision": decision.value
            })

        # Check if fully approved
        if request.is_fully_approved() and not request.has_denial():
            request.status = ApprovalStatus.APPROVED
            request.resolved_at = datetime.utcnow()

        self._save_approval_requests()

        self._audit_log(
            "approval_submitted",
            approver.username,
            {
                "request_id": request_id,
                "decision": decision.value,
                "final_status": request.status.value
            }
        )

        return True

    def get_pending_approvals(self, approver: User) -> List[ApprovalRequest]:
        """Get pending approval requests for user"""
        pending = []

        for request in self.approval_requests.values():
            if (request.status == ApprovalStatus.PENDING and
                not request.is_expired() and
                approver.user_id in request.required_approvers and
                approver.user_id not in request.received_approvals and
                approver.can_approve(request.action_type, request.estimated_value)):

                pending.append(request)

        return sorted(pending, key=lambda r: r.created_at)

    def create_user(
        self,
        username: str,
        email: str,
        roles: List[Role],
        creator: User,
        **kwargs
    ) -> Optional[User]:
        """Create new user account"""

        if not creator.has_permission(Permission.MANAGE_USERS):
            return None

        if any(user.username == username for user in self.users.values()):
            return None  # Username already exists

        user_id = f"user_{int(time.time())}_{hash(username) % 10000:04d}"

        user = User(
            user_id=user_id,
            username=username,
            email=email,
            roles=set(roles),
            **kwargs
        )

        self.users[user_id] = user
        self._save_users()

        self._audit_log(
            "user_created",
            creator.username,
            {
                "new_user": username,
                "roles": [r.value for r in roles]
            }
        )

        return user

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def _get_required_approvers(self, action_type: str, risk_level: str) -> Set[str]:
        """Determine required approvers based on action type and risk"""

        # Get users with appropriate approval permissions
        eligible_approvers = []

        for user in self.users.values():
            if user.active and user.can_approve(action_type):
                eligible_approvers.append(user.user_id)

        # Determine number of approvers needed based on risk
        approval_counts = {
            "low": 1,
            "medium": 1,
            "high": 2,
            "critical": 3
        }

        required_count = approval_counts.get(risk_level, 1)

        # For critical actions, require specific roles
        if risk_level == "critical":
            # Require at least one security officer
            security_officers = [
                user.user_id for user in self.users.values()
                if user.active and Role.SECURITY_OFFICER in user.roles
            ]
            if security_officers:
                return set(security_officers[:1] + eligible_approvers[:required_count-1])

        return set(eligible_approvers[:required_count])

    def _load_configuration(self):
        """Load RBAC configuration from files"""
        # Load users
        users_file = self.config_dir / "users.json"
        if users_file.exists():
            try:
                with open(users_file, 'r') as f:
                    users_data = json.load(f)

                for user_data in users_data.values():
                    user = User(
                        user_id=user_data["user_id"],
                        username=user_data["username"],
                        email=user_data["email"],
                        roles={Role(r) for r in user_data["roles"]},
                        permissions={Permission(p) for p in user_data.get("permissions", [])},
                        active=user_data.get("active", True),
                        mfa_enabled=user_data.get("mfa_enabled", False),
                        max_approval_value=user_data.get("max_approval_value", 0.0)
                    )
                    self.users[user.user_id] = user
            except Exception as e:
                logger.error(f"Failed to load users: {e}")

        # Load approval requests
        approvals_file = self.config_dir / "approval_requests.json"
        if approvals_file.exists():
            try:
                with open(approvals_file, 'r') as f:
                    approvals_data = json.load(f)

                for request_data in approvals_data.values():
                    request = ApprovalRequest(
                        request_id=request_data["request_id"],
                        requester_id=request_data["requester_id"],
                        action_type=request_data["action_type"],
                        action_description=request_data["action_description"],
                        status=ApprovalStatus(request_data["status"]),
                        required_approvers=set(request_data["required_approvers"]),
                        received_approvals={
                            k: datetime.fromisoformat(v)
                            for k, v in request_data.get("received_approvals", {}).items()
                        }
                    )
                    self.approval_requests[request.request_id] = request
            except Exception as e:
                logger.error(f"Failed to load approval requests: {e}")

    def _save_users(self):
        """Save users to file"""
        users_file = self.config_dir / "users.json"

        users_data = {}
        for user in self.users.values():
            users_data[user.user_id] = {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "roles": [r.value for r in user.roles],
                "permissions": [p.value for p in user.permissions],
                "active": user.active,
                "mfa_enabled": user.mfa_enabled,
                "max_approval_value": user.max_approval_value,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None
            }

        with open(users_file, 'w') as f:
            json.dump(users_data, f, indent=2)

    def _save_approval_requests(self):
        """Save approval requests to file"""
        approvals_file = self.config_dir / "approval_requests.json"

        approvals_data = {}
        for request in self.approval_requests.values():
            approvals_data[request.request_id] = {
                "request_id": request.request_id,
                "requester_id": request.requester_id,
                "action_type": request.action_type,
                "action_description": request.action_description,
                "status": request.status.value,
                "required_approvers": list(request.required_approvers),
                "received_approvals": {
                    k: v.isoformat() for k, v in request.received_approvals.items()
                },
                "received_denials": {
                    k: v.isoformat() for k, v in request.received_denials.items()
                },
                "created_at": request.created_at.isoformat(),
                "expires_at": request.expires_at.isoformat() if request.expires_at else None,
                "comments": request.comments
            }

        with open(approvals_file, 'w') as f:
            json.dump(approvals_data, f, indent=2)

    def _audit_log(self, action: str, username: str, details: Dict = None):
        """Add entry to audit log"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "username": username,
            "details": details or {}
        }

        self.audit_log.append(entry)

        # Save to file
        audit_file = self.config_dir / "audit.log"
        with open(audit_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')


def initialize_default_users(rbac_manager: RBACManager):
    """Initialize default users for development"""

    # Create admin user
    admin = User(
        user_id="admin_001",
        username="admin",
        email="admin@raid-framework.local",
        roles={Role.ADMINISTRATOR},
        max_approval_value=1000000.0  # High approval limit
    )

    # Create security officer
    security_officer = User(
        user_id="security_001",
        username="security_officer",
        email="security@raid-framework.local",
        roles={Role.SECURITY_OFFICER},
        max_approval_value=500000.0
    )

    # Create team lead
    team_lead = User(
        user_id="lead_001",
        username="team_lead",
        email="lead@raid-framework.local",
        roles={Role.TEAM_LEAD},
        max_approval_value=100000.0
    )

    # Create analyst
    analyst = User(
        user_id="analyst_001",
        username="analyst",
        email="analyst@raid-framework.local",
        roles={Role.ANALYST}
    )

    rbac_manager.users.update({
        admin.user_id: admin,
        security_officer.user_id: security_officer,
        team_lead.user_id: team_lead,
        analyst.user_id: analyst
    })

    rbac_manager._save_users()


# Example usage and testing functions
if __name__ == "__main__":
    rbac = RBACManager("/tmp/raid-rbac-test")
    initialize_default_users(rbac)

    # Test authentication
    admin = rbac.get_user_by_username("admin")
    print(f"Admin permissions: {[p.value for p in ROLE_PERMISSIONS[Role.ADMINISTRATOR]]}")

    # Test authorization
    print(f"Admin can run destructive: {rbac.authorize_action(admin, 'run_destructive')}")

    # Test approval workflow
    analyst = rbac.get_user_by_username("analyst")
    approval_request = rbac.create_approval_request(
        analyst,
        "destructive",
        "Delete test files from target system",
        estimated_risk="high"
    )

    print(f"Created approval request: {approval_request.request_id}")

    # Test approval
    security_officer = rbac.get_user_by_username("security_officer")
    rbac.submit_approval(approval_request.request_id, security_officer, ApprovalStatus.APPROVED, "Approved for testing")

    print(f"Approval status: {approval_request.status}")