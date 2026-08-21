from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import Role, Severity


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    organization: str = Field(default="Independent learner", max_length=180)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(ORMModel):
    id: str
    email: str
    full_name: str
    organization: str
    role: Role
    is_active: bool


class ProjectCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=3000)
    scope: str = Field(default="127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16", max_length=2000)
    start_date: date | None = None
    end_date: date | None = None


class ProjectOut(ORMModel):
    id: str
    name: str
    description: str
    scope: str
    status: str
    owner_id: str
    start_date: date | None
    end_date: date | None
    created_at: Any


class ScanValidateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    project_id: str | None = None


class ScanCreate(BaseModel):
    project_id: str
    target: str = Field(min_length=1, max_length=255)
    profile: Literal["basic_discovery", "common_services", "web_security", "tls_configuration", "full_authorized"]
    purpose: str = Field(min_length=10, max_length=1000)
    approved_scope: str = Field(min_length=3, max_length=2000)
    authorization_confirmed: bool
    policy_accepted: bool
    custom_ports: list[int] = Field(default_factory=list, max_length=256)
    demo: bool = False
    rate_limit: int = Field(default=20, ge=1, le=100)
    timeout_seconds: float = Field(default=1.5, ge=0.25, le=5)

    @field_validator("custom_ports")
    @classmethod
    def valid_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("Ports must be between 1 and 65535")
        return sorted(set(value))


class FindingUpdate(BaseModel):
    status: Literal["open", "acknowledged", "in_progress", "resolved", "accepted_risk"] | None = None
    assigned_user_id: str | None = None
    analyst_notes: str | None = Field(default=None, max_length=5000)


class RuleCreate(BaseModel):
    project_id: str
    name: str = Field(min_length=3, max_length=140)
    description: str = Field(min_length=5, max_length=1000)
    severity: Severity
    rule_type: Literal["connection_count", "byte_threshold", "port_match", "protocol_match", "external_destination"]
    conditions: dict[str, Any]
    enabled: bool = True


class AssessmentCreate(BaseModel):
    project_id: str
    template_id: str
    name: str = Field(min_length=3, max_length=180)


class ResponseUpdate(BaseModel):
    control_id: str
    category: str
    response: Literal["implemented", "partially_implemented", "not_implemented", "not_applicable", "not_reviewed"]
    notes: str = Field(default="", max_length=5000)
    evidence_reference: str = Field(default="", max_length=500)
    owner: str = Field(default="", max_length=120)
    target_date: date | None = None
    remediation_plan: str = Field(default="", max_length=5000)


class ResponsesUpdate(BaseModel):
    responses: list[ResponseUpdate] = Field(max_length=300)
    complete: bool = False


class ReportCreate(BaseModel):
    project_id: str
    report_type: Literal["executive", "technical"]
    format: Literal["json", "csv", "pdf"] = "json"


class TrafficDemoCreate(BaseModel):
    project_id: str
    anonymize: bool = True
