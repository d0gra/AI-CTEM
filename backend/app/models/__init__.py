"""All ORM models. Importing this package registers every table on Base.metadata."""

from app.models.ai import AIAgent, AIAssessment, AIAssessmentTest, AIAsset, AIIntegration, AIModel, AIUsage, MCPServer
from app.models.assessment import Assessment, AssessmentRun, AssessmentTarget, Job
from app.models.asset import Asset, AssetDiscoveryEvent, AssetRelationship, ScopeTarget
from app.models.finding import (
    AIFinding,
    Evidence,
    Finding,
    FindingEvent,
    RemediationTask,
    RiskAcceptance,
    RiskScore,
    Vulnerability,
)
from app.models.governance import (
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
    IntelSyncState,
    Policy,
    PolicyEvaluation,
    PolicyException,
    ThreatIntelligence,
)
from app.models.identity import (
    Organization,
    Permission,
    Role,
    RolePermission,
    Team,
    TeamMember,
    User,
    UserSession,
    UserToken,
)
from app.models.ops import (
    AuditEvent,
    Integration,
    Notification,
    NotificationDelivery,
    NotificationRead,
    NotificationRule,
    Report,
)

__all__ = [
    "AIAgent", "AIAssessment", "AIAssessmentTest", "AIAsset", "AIFinding", "AIIntegration", "AIModel", "AIUsage",
    "Assessment", "AssessmentRun", "AssessmentTarget", "Asset", "AssetDiscoveryEvent", "AssetRelationship",
    "AttackPath", "AttackPathEdge", "AttackPathNode", "AuditEvent", "Evidence", "Finding", "FindingEvent",
    "Integration", "IntelSyncState", "Job", "MCPServer", "Notification", "NotificationDelivery",
    "NotificationRead", "NotificationRule", "Organization", "Permission", "Policy", "PolicyEvaluation",
    "PolicyException", "RemediationTask", "Report", "RiskAcceptance", "RiskScore", "Role", "RolePermission",
    "ScopeTarget", "Team", "TeamMember", "ThreatIntelligence", "User", "UserSession", "UserToken", "Vulnerability",
]
