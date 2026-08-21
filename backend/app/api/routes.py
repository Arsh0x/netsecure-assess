from __future__ import annotations

import asyncio
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..models import (
    Alert, Assessment, AssessmentResponse, AssessmentTemplate, Asset, AuditLog,
    AuthorizationRecord, DetectionRule, Finding, Project, ProjectMember, Report,
    Role, Scan, Service, Severity, TrafficRecord, User,
)
from ..schemas import (
    AssessmentCreate, FindingUpdate, LoginRequest, ProjectCreate, ProjectOut,
    RefreshRequest, RegisterRequest, ReportCreate, ResponsesUpdate, RuleCreate,
    ScanCreate, ScanValidateRequest, TokenResponse, TrafficDemoCreate, UserOut,
)
from ..security import create_token, decode_token, get_current_user, hash_password, require_roles, verify_password
from ..services.audit import record_audit
from ..services.risk import assessment_scores, risk_rating
from ..services.safety import UnsafeTarget, validate_target, within_scope
from ..services.scanner import execute_scan
from ..services.pcap import CaptureError, parse_capture

router = APIRouter(prefix="/api")
settings = get_settings()


def project_query(db: Session, user: User):
    query = db.query(Project).filter(Project.deleted_at.is_(None))
    if user.role == Role.administrator:
        return query
    member_ids = db.query(ProjectMember.project_id).filter(ProjectMember.user_id == user.id)
    if user.role == Role.researcher:
        return query.filter((Project.owner_id == user.id) | (Project.id.in_(member_ids)))
    return query.filter((Project.owner_id == user.id) | (Project.id.in_(member_ids)))


def require_project(db: Session, user: User, project_id: str) -> Project:
    project = project_query(db, user).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or unavailable")
    return project


def finding_json(item: Finding, db: Session) -> dict:
    asset = db.get(Asset, item.asset_id) if item.asset_id else None
    return {
        "id": item.id, "project_id": item.project_id, "asset_id": item.asset_id,
        "asset": asset.hostname or asset.ip_address if asset else "Project-wide", "asset_ip": asset.ip_address if asset else None,
        "title": item.title, "description": item.description, "port": item.port, "service": item.service,
        "severity": item.severity.value, "confidence": item.confidence, "evidence": item.evidence,
        "remediation": item.remediation, "references": item.references, "status": item.status,
        "assigned_user_id": item.assigned_user_id, "analyst_notes": item.analyst_notes,
        "risk_score": item.risk_score, "created_at": item.created_at,
    }


@router.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "demo_mode": settings.demo_mode, "live_capture": settings.enable_live_capture}


@router.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(func.lower(User.email) == payload.email.lower()).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=payload.email.lower(), full_name=payload.full_name, organization=payload.organization, password_hash=hash_password(payload.password), role=Role.student)
    db.add(user)
    db.commit()
    db.refresh(user)
    record_audit(db, "account.registered", user, "user", user.id, source_ip=request.client.host if request.client else None)
    return user


@router.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(func.lower(User.email) == payload.email.lower()).first()
    source_ip = request.client.host if request.client else None
    if user and user.locked_until:
        locked_until = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(timezone.utc):
            record_audit(db, "login.locked", user, details={}, source_ip=source_ip)
            raise HTTPException(status_code=423, detail="Account temporarily locked after repeated failures")
    if not user or not verify_password(payload.password, user.password_hash):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.commit()
        record_audit(db, "login.failed", user, details={"email": payload.email[:120]}, source_ip=source_ip)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    user.failed_logins, user.locked_until = 0, None
    db.commit()
    record_audit(db, "login.succeeded", user, source_ip=source_ip)
    return TokenResponse(access_token=create_token(user, "access"), refresh_token=create_token(user, "refresh"))


@router.post("/auth/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    token = decode_token(payload.refresh_token, "refresh")
    user = db.get(User, token["sub"])
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Account is unavailable")
    return TokenResponse(access_token=create_token(user, "access"), refresh_token=create_token(user, "refresh"))


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/dashboard")
def dashboard(project_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    projects = project_query(db, user)
    ids = [project.id for project in projects.all()]
    if project_id:
        require_project(db, user, project_id)
        ids = [project_id]
    if not ids:
        return {"metrics": {"assets":0,"active_assets":0,"open_findings":0,"critical_high":0,"assessment_score":0,"alerts":0}, "severity":[], "risk_trend":[], "protocols":[], "top_assets":[], "remediation":[]}
    assets = db.query(Asset).filter(Asset.project_id.in_(ids), Asset.deleted_at.is_(None)).all()
    findings = db.query(Finding).filter(Finding.project_id.in_(ids)).all()
    alerts = db.query(Alert).filter(Alert.project_id.in_(ids)).all()
    assessments = db.query(Assessment).filter(Assessment.project_id.in_(ids)).all()
    traffic = db.query(TrafficRecord).filter(TrafficRecord.project_id.in_(ids)).all()
    sev = Counter(f.severity.value for f in findings if f.status != "resolved")
    protocols = defaultdict(lambda: {"packets":0,"bytes":0})
    for record in traffic:
        protocols[record.protocol]["packets"] += record.packets
        protocols[record.protocol]["bytes"] += record.bytes
    avg_assessment = round(sum(a.score for a in assessments) / len(assessments), 1) if assessments else 0
    return {
        "metrics": {"assets":len(assets), "active_assets":sum(a.status=="active" for a in assets), "open_findings":sum(f.status!="resolved" for f in findings), "critical_high":sev["critical"]+sev["high"], "assessment_score":avg_assessment, "alerts":len(alerts)},
        "severity": [{"name": key.title(), "value": sev[key]} for key in ["critical","high","medium","low","informational"]],
        "risk_trend": [{"date": (datetime.now()-timedelta(days=days)).strftime("%b %d"), "risk": value} for days,value in [(35,72),(28,69),(21,66),(14,62),(7,58),(0,54)]],
        "protocols": [{"name":key,"packets":value["packets"],"bytes":value["bytes"]} for key,value in protocols.items()],
        "top_assets": [{"id":a.id,"name":a.hostname or a.ip_address,"ip":a.ip_address,"risk":a.risk_score,"ports":db.query(Service).filter(Service.asset_id==a.id).count()} for a in sorted(assets,key=lambda item:item.risk_score,reverse=True)[:5]],
        "remediation": [{"name":"Resolved","value":sum(f.status=="resolved" for f in findings)},{"name":"In progress","value":sum(f.status=="in_progress" for f in findings)},{"name":"Open","value":sum(f.status in {"open","acknowledged"} for f in findings)}],
    }


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return project_query(db, user).order_by(Project.updated_at.desc()).all()


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = Project(**payload.model_dump(), owner_id=user.id)
    db.add(project); db.commit(); db.refresh(project)
    record_audit(db, "project.created", user, "project", project.id, {"name": project.name, "scope": project.scope})
    return project


@router.get("/projects/{project_id}")
def get_project(project_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = require_project(db, user, project_id)
    return {"project": ProjectOut.model_validate(project), "counts": {"assets":db.query(Asset).filter(Asset.project_id==project.id).count(), "scans":db.query(Scan).filter(Scan.project_id==project.id).count(), "findings":db.query(Finding).filter(Finding.project_id==project.id).count(), "alerts":db.query(Alert).filter(Alert.project_id==project.id).count()}}


@router.get("/assets")
def list_assets(project_id: str | None = None, search: str = "", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    ids = [p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    query = db.query(Asset).filter(Asset.project_id.in_(ids), Asset.deleted_at.is_(None))
    if search: query=query.filter((Asset.ip_address.contains(search)) | (Asset.hostname.contains(search)))
    return [{"id":a.id,"project_id":a.project_id,"ip_address":a.ip_address,"hostname":a.hostname,"status":a.status,"probable_os":a.probable_os,"criticality":a.criticality,"risk_score":a.risk_score,"first_seen":a.first_seen,"last_seen":a.last_seen,"open_ports":db.query(Service).filter(Service.asset_id==a.id).count()} for a in query.order_by(Asset.risk_score.desc()).all()]


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    asset=db.get(Asset,asset_id)
    if not asset: raise HTTPException(404,"Asset not found")
    require_project(db,user,asset.project_id)
    services=db.query(Service).filter(Service.asset_id==asset.id).order_by(Service.port).all()
    findings=db.query(Finding).filter(Finding.asset_id==asset.id).all()
    return {"asset":{"id":asset.id,"ip_address":asset.ip_address,"hostname":asset.hostname,"probable_os":asset.probable_os,"status":asset.status,"criticality":asset.criticality,"risk_score":asset.risk_score},"services":[{"id":s.id,"port":s.port,"protocol":s.protocol,"name":s.name,"product":s.product,"version":s.version,"tls":s.tls} for s in services],"findings":[finding_json(f,db) for f in findings]}


@router.post("/scans/validate")
def validate_scan_target(payload: ScanValidateRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    try: target=validate_target(payload.target)
    except UnsafeTarget as exc: raise HTTPException(422,detail=str(exc)) from exc
    in_scope=True
    if payload.project_id:
        project=require_project(db,user,payload.project_id)
        in_scope=within_scope(target.addresses,project.scope)
    return {"valid":in_scope,"normalized":target.normalized,"kind":target.kind,"host_count":len(target.addresses),"addresses":target.addresses,"message":"Target is private and within the project scope." if in_scope else "Target is private but outside this project's approved scope."}


@router.post("/scans", status_code=201)
async def create_scan(payload: ScanCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project=require_project(db,user,payload.project_id)
    if not payload.authorization_confirmed or not payload.policy_accepted:
        raise HTTPException(422,"Ownership/authorization and policy acceptance are mandatory")
    try: target=validate_target(payload.target)
    except UnsafeTarget as exc: raise HTTPException(422,detail=str(exc)) from exc
    if not payload.demo and not within_scope(target.addresses,project.scope):
        raise HTTPException(422,"Target is outside the project's authorized scope")
    if len(payload.custom_ports)>settings.max_ports: raise HTTPException(422,"Selected port count exceeds the administrator limit")
    auth=AuthorizationRecord(project_id=project.id,user_id=user.id,target=target.normalized,purpose=payload.purpose,approved_scope=payload.approved_scope,policy_accepted=True,source_ip=request.client.host if request.client else None)
    db.add(auth); db.flush()
    scan=Scan(project_id=project.id,user_id=user.id,authorization_id=auth.id,name=f"{payload.profile.replace('_',' ').title()} · {target.normalized}",target=target.normalized,profile=payload.profile,ports=",".join(map(str,payload.custom_ports)),status="queued")
    db.add(scan); db.commit(); db.refresh(scan)
    record_audit(db,"scan.created",user,"scan",scan.id,{"target":target.normalized,"profile":payload.profile,"demo":payload.demo,"authorization_id":auth.id})
    asyncio.create_task(execute_scan(scan.id,target.addresses,payload.custom_ports,payload.timeout_seconds,payload.demo))
    return {"id":scan.id,"status":scan.status,"target":scan.target,"authorization_id":auth.id}


@router.get("/scans")
def list_scans(project_id: str | None=None, db: Session=Depends(get_db), user: User=Depends(get_current_user)):
    ids=[p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    scans=db.query(Scan).filter(Scan.project_id.in_(ids)).order_by(Scan.created_at.desc()).all()
    return [{"id":s.id,"project_id":s.project_id,"name":s.name,"target":s.target,"profile":s.profile,"status":s.status,"progress":s.progress,"hosts_found":s.hosts_found,"services_found":s.services_found,"findings_found":s.findings_found,"created_at":s.created_at,"completed_at":s.completed_at,"error":s.error} for s in scans]


@router.get("/scans/{scan_id}")
def get_scan(scan_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    require_project(db,user,scan.project_id)
    return {"id":scan.id,"project_id":scan.project_id,"name":scan.name,"target":scan.target,"profile":scan.profile,"status":scan.status,"progress":scan.progress,"hosts_found":scan.hosts_found,"services_found":scan.services_found,"findings_found":scan.findings_found,"created_at":scan.created_at,"started_at":scan.started_at,"completed_at":scan.completed_at,"error":scan.error,"findings":[finding_json(f,db) for f in db.query(Finding).filter(Finding.scan_id==scan.id).all()]}


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    scan=db.get(Scan,scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    require_project(db,user,scan.project_id)
    if scan.status not in {"queued","running"}: raise HTTPException(409,"Only active scans can be cancelled")
    scan.status="cancelled"; db.commit(); record_audit(db,"scan.cancelled",user,"scan",scan.id)
    return {"status":"cancelled"}


@router.get("/findings")
def list_findings(project_id:str|None=None,severity:str|None=None,status_filter:str|None=Query(None,alias="status"),db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    ids=[p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    query=db.query(Finding).filter(Finding.project_id.in_(ids))
    if severity: query=query.filter(Finding.severity==severity)
    if status_filter: query=query.filter(Finding.status==status_filter)
    return [finding_json(f,db) for f in query.order_by(Finding.risk_score.desc()).all()]


@router.get("/findings/{finding_id}")
def get_finding(finding_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    finding=db.get(Finding,finding_id)
    if not finding: raise HTTPException(404,"Finding not found")
    require_project(db,user,finding.project_id)
    data=finding_json(finding,db); data["risk_explanation"]={"score":finding.risk_score,"rating":risk_rating(finding.risk_score),"factors":{"technical_severity":"30%","confidence":"10%","asset_criticality":"15%","exposure":"10%","likelihood":"10%","business_impact":"15%","controls_and_status":"reductions"}}
    data["validation_warning"]="Version and configuration findings can produce false positives. Human validation is required."
    return data


@router.patch("/findings/{finding_id}")
def update_finding(finding_id:str,payload:FindingUpdate,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    finding=db.get(Finding,finding_id)
    if not finding: raise HTTPException(404,"Finding not found")
    require_project(db,user,finding.project_id)
    for key,value in payload.model_dump(exclude_unset=True).items(): setattr(finding,key,value)
    db.commit(); record_audit(db,"finding.updated",user,"finding",finding.id,payload.model_dump(exclude_unset=True))
    return finding_json(finding,db)


@router.get("/traffic/summary")
def traffic_summary(project_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    require_project(db,user,project_id); rows=db.query(TrafficRecord).filter(TrafficRecord.project_id==project_id).all()
    protocols=defaultdict(lambda:{"packets":0,"bytes":0,"connections":0}); talkers=defaultdict(lambda:{"packets":0,"bytes":0})
    for row in rows:
        protocols[row.protocol]["packets"]+=row.packets; protocols[row.protocol]["bytes"]+=row.bytes; protocols[row.protocol]["connections"]+=1
        talkers[row.source]["packets"]+=row.packets; talkers[row.source]["bytes"]+=row.bytes
    return {"totals":{"records":len(rows),"packets":sum(r.packets for r in rows),"bytes":sum(r.bytes for r in rows)},"protocols":[{"name":k,**v} for k,v in protocols.items()],"top_talkers":[{"address":k,**v} for k,v in sorted(talkers.items(),key=lambda item:item[1]["bytes"],reverse=True)[:8]],"recent":[{"source":r.source,"destination":r.destination,"source_port":r.source_port,"destination_port":r.destination_port,"protocol":r.protocol,"packets":r.packets,"bytes":r.bytes,"observed_at":r.observed_at} for r in rows[:20]],"privacy":"Metadata and aggregates only; packet payloads are not retained."}


@router.post("/traffic/demo",status_code=201)
def generate_demo_traffic(payload:TrafficDemoCreate,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    require_project(db,user,payload.project_id)
    samples=[("10.20.0.12","10.20.0.1",51522,53,"DNS",420,44000),("10.20.0.42","10.20.0.51",40112,23,"TCP",180,122000),("10.20.0.24","10.20.0.12",5432,51220,"TCP",720,860000)]
    for source,dest,sport,dport,protocol,packets,byte_count in samples: db.add(TrafficRecord(project_id=payload.project_id,source=source,destination=dest,source_port=sport,destination_port=dport,protocol=protocol,packets=packets,bytes=byte_count,metadata_json={"demo":True,"anonymized":payload.anonymize}))
    db.commit(); record_audit(db,"traffic.demo_imported",user,"project",payload.project_id,{"records":len(samples),"payload_retained":False})
    return {"records_created":len(samples),"payload_retained":False}


@router.post("/traffic/import", status_code=201)
async def import_capture(
    project_id: str = Form(...), anonymize: bool = Form(True), file: UploadFile = File(...),
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    require_project(db,user,project_id)
    filename=(file.filename or "").lower()
    if not filename.endswith((".pcap",".pcapng")):
        raise HTTPException(422,"Only .pcap and .pcapng files are accepted")
    data=await file.read(25*1024*1024+1)
    if len(data)>25*1024*1024:
        raise HTTPException(413,"Capture exceeds the 25 MB educational import limit")
    try:
        summaries=parse_capture(data,anonymize=anonymize)
    except CaptureError as exc:
        raise HTTPException(422,detail=str(exc)) from exc
    for item in summaries:
        db.add(TrafficRecord(project_id=project_id,**item,metadata_json={"source":"pcap_import","anonymized":anonymize,"payload_retained":False}))
    db.commit()
    record_audit(db,"traffic.capture_imported",user,"project",project_id,{"filename":filename[-120:],"summaries":len(summaries),"anonymized":anonymize,"payload_retained":False})
    return {"records_created":len(summaries),"packets_summarized":sum(item["packets"] for item in summaries),"payload_retained":False,"anonymized":anonymize}


@router.get("/alerts")
def list_alerts(project_id:str|None=None,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    ids=[p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    rows=db.query(Alert).filter(Alert.project_id.in_(ids)).order_by(Alert.created_at.desc()).all()
    return [{"id":a.id,"project_id":a.project_id,"rule_name":a.rule_name,"description":a.description,"severity":a.severity.value,"source":a.source,"destination":a.destination,"evidence":a.evidence,"investigation":a.investigation,"status":a.status,"created_at":a.created_at} for a in rows]


@router.get("/rules")
def list_rules(project_id:str|None=None,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    query=db.query(DetectionRule)
    if project_id: require_project(db,user,project_id); query=query.filter((DetectionRule.project_id==project_id)|(DetectionRule.project_id.is_(None)))
    return [{"id":r.id,"project_id":r.project_id,"name":r.name,"description":r.description,"severity":r.severity.value,"rule_type":r.rule_type,"conditions":r.conditions,"enabled":r.enabled,"built_in":r.built_in} for r in query.all()]


@router.post("/rules",status_code=201)
def create_rule(payload:RuleCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(Role.researcher,Role.administrator))):
    require_project(db,user,payload.project_id)
    allowed={"threshold","window_seconds","ports","protocol","destinations"}
    if not payload.conditions or set(payload.conditions)-allowed: raise HTTPException(422,"Rule conditions contain unsupported fields")
    serialized=str(payload.conditions)
    if len(serialized)>2000: raise HTTPException(422,"Rule is too large")
    rule=DetectionRule(**payload.model_dump()); db.add(rule); db.commit(); db.refresh(rule); record_audit(db,"rule.created",user,"rule",rule.id,{"rule_type":rule.rule_type})
    return {"id":rule.id,"name":rule.name,"rule_type":rule.rule_type,"conditions":rule.conditions}


@router.get("/assessments/templates")
def templates(db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    return [{"id":t.id,"name":t.name,"description":t.description,"framework":t.framework,"controls":t.controls} for t in db.query(AssessmentTemplate).filter(AssessmentTemplate.active.is_(True)).all()]


@router.get("/assessments")
def list_assessments(project_id:str|None=None,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    ids=[p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    return [{"id":a.id,"project_id":a.project_id,"template_id":a.template_id,"name":a.name,"status":a.status,"score":a.score,"maturity_score":a.maturity_score,"residual_risk":a.residual_risk,"updated_at":a.updated_at} for a in db.query(Assessment).filter(Assessment.project_id.in_(ids)).order_by(Assessment.updated_at.desc()).all()]


@router.post("/assessments",status_code=201)
def create_assessment(payload:AssessmentCreate,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    require_project(db,user,payload.project_id); template=db.get(AssessmentTemplate,payload.template_id)
    if not template: raise HTTPException(404,"Assessment template not found")
    assessment=Assessment(project_id=payload.project_id,template_id=payload.template_id,user_id=user.id,name=payload.name)
    db.add(assessment); db.flush()
    for control in template.controls: db.add(AssessmentResponse(assessment_id=assessment.id,control_id=control["id"],category=control["category"],response="not_reviewed"))
    db.commit(); record_audit(db,"assessment.created",user,"assessment",assessment.id)
    return {"id":assessment.id,"status":assessment.status}


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    assessment=db.get(Assessment,assessment_id)
    if not assessment: raise HTTPException(404,"Assessment not found")
    require_project(db,user,assessment.project_id); template=db.get(AssessmentTemplate,assessment.template_id); rows=db.query(AssessmentResponse).filter(AssessmentResponse.assessment_id==assessment.id).all()
    by_category=defaultdict(list)
    for row in rows: by_category[row.category].append(row.response)
    category_scores={category:assessment_scores(values)["score"] for category,values in by_category.items()}
    controls={c["id"]:c for c in template.controls}
    return {"id":assessment.id,"project_id":assessment.project_id,"name":assessment.name,"status":assessment.status,"score":assessment.score,"maturity_score":assessment.maturity_score,"residual_risk":assessment.residual_risk,"category_scores":category_scores,"formula":assessment_scores([r.response for r in rows])["formula"],"responses":[{"id":r.id,"control_id":r.control_id,"category":r.category,"prompt":controls.get(r.control_id,{}).get("prompt",""),"response":r.response,"notes":r.notes,"evidence_reference":r.evidence_reference,"owner":r.owner,"target_date":r.target_date,"remediation_plan":r.remediation_plan} for r in rows]}


@router.put("/assessments/{assessment_id}/responses")
def update_responses(assessment_id:str,payload:ResponsesUpdate,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    assessment=db.get(Assessment,assessment_id)
    if not assessment: raise HTTPException(404,"Assessment not found")
    require_project(db,user,assessment.project_id); existing={r.control_id:r for r in db.query(AssessmentResponse).filter(AssessmentResponse.assessment_id==assessment.id).all()}
    for item in payload.responses:
        row=existing.get(item.control_id)
        if row:
            for key,value in item.model_dump().items(): setattr(row,key,value)
    values=[r.response for r in existing.values()]; scores=assessment_scores(values)
    assessment.score=scores["score"]; assessment.maturity_score=scores["maturity_score"]; assessment.residual_risk=scores["residual_risk"]; assessment.status="completed" if payload.complete else "in_progress"
    db.commit(); record_audit(db,"assessment.updated",user,"assessment",assessment.id,{"complete":payload.complete,"score":assessment.score})
    return {**scores,"status":assessment.status}


def build_report(db:Session,project:Project,kind:str)->dict:
    assets=db.query(Asset).filter(Asset.project_id==project.id).all(); findings=db.query(Finding).filter(Finding.project_id==project.id).all(); assessments=db.query(Assessment).filter(Assessment.project_id==project.id).all()
    score=round(sum(a.risk_score for a in assets)/len(assets),1) if assets else 0
    summary={"project":project.name,"scope":project.scope,"generated_at":datetime.now(timezone.utc).isoformat(),"overall_risk_score":score,"overall_risk_rating":risk_rating(score),"security_score":round(sum(a.score for a in assessments)/len(assessments),1) if assessments else 0,"asset_count":len(assets),"open_findings":sum(f.status!="resolved" for f in findings),"human_validation_required":True}
    top=sorted(findings,key=lambda f:f.risk_score,reverse=True)[:10]
    if kind=="executive": return {**summary,"executive_summary":f"The authorized assessment recorded {len(assets)} assets and {summary['open_findings']} open findings.","key_concerns":[f.title for f in top[:5]],"top_recommendations":[f.remediation for f in top[:5]],"limitations":"Automated observations and version matches can produce false positives."}
    return {**summary,"methodology":"Bounded TCP connect checks, metadata analysis and structured control review. No exploitation was performed.","assets":[{"ip":a.ip_address,"hostname":a.hostname,"os":a.probable_os,"risk":a.risk_score} for a in assets],"findings":[finding_json(f,db) for f in findings],"limitations":"Results are point-in-time observations and require human validation.","audit_note":"Authorization and report-generation events are retained in the immutable audit log."}


@router.post("/reports",status_code=201)
def create_report(payload:ReportCreate,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    project=require_project(db,user,payload.project_id); content=build_report(db,project,payload.report_type); report=Report(project_id=project.id,user_id=user.id,report_type=payload.report_type,format=payload.format,title=f"{project.name} · {payload.report_type.title()} report",content=content)
    db.add(report); db.commit(); db.refresh(report); record_audit(db,"report.generated",user,"report",report.id,{"type":payload.report_type,"format":payload.format})
    return {"id":report.id,"title":report.title,"format":report.format,"content":content}


@router.get("/reports")
def list_reports(project_id:str|None=None,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    ids=[p.id for p in project_query(db,user).all()]
    if project_id: require_project(db,user,project_id); ids=[project_id]
    return [{"id":r.id,"project_id":r.project_id,"title":r.title,"report_type":r.report_type,"format":r.format,"created_at":r.created_at,"human_validation_required":r.human_validation_required} for r in db.query(Report).filter(Report.project_id.in_(ids)).order_by(Report.created_at.desc()).all()]


@router.get("/reports/{report_id}/download")
def download_report(report_id:str,db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    report=db.get(Report,report_id)
    if not report: raise HTTPException(404,"Report not found")
    require_project(db,user,report.project_id)
    if report.format=="json":
        import json
        return Response(json.dumps(report.content,indent=2,default=str),media_type="application/json",headers={"Content-Disposition":f'attachment; filename="{report.report_type}-report.json"'})
    if report.format=="pdf":
        from fpdf import FPDF
        pdf=FPDF(); pdf.set_title(report.title); pdf.add_page(); pdf.set_font("Helvetica","B",18)
        pdf.cell(0,12,report.title,new_x="LMARGIN",new_y="NEXT")
        pdf.set_font("Helvetica","",9)
        pdf.multi_cell(0,6,"Authorized defensive assessment. All automated findings require human validation.",new_x="LMARGIN",new_y="NEXT"); pdf.ln(3)
        for key,value in report.content.items():
            safe=str(value).encode("latin-1","replace").decode("latin-1")
            pdf.set_font("Helvetica","B",10); pdf.multi_cell(0,6,key.replace("_"," ").title(),new_x="LMARGIN",new_y="NEXT")
            pdf.set_font("Helvetica","",8); pdf.multi_cell(0,5,safe,new_x="LMARGIN",new_y="NEXT"); pdf.ln(1)
        return Response(bytes(pdf.output()),media_type="application/pdf",headers={"Content-Disposition":f'attachment; filename="{report.report_type}-report.pdf"'})
    output=io.StringIO(); writer=csv.writer(output); writer.writerow(["field","value"])
    for key,value in report.content.items(): writer.writerow([key,str(value).replace("=","'=") if isinstance(value,str) and value.startswith(("=","+","-","@")) else value])
    return Response(output.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{report.report_type}-report.csv"'})


@router.get("/audit-logs")
def audit_logs(limit:int=Query(100,ge=1,le=500),db:Session=Depends(get_db),user:User=Depends(require_roles(Role.administrator))):
    rows=db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [{"id":r.id,"user_id":r.user_id,"action":r.action,"entity_type":r.entity_type,"entity_id":r.entity_id,"details":r.details,"source_ip":r.source_ip,"created_at":r.created_at} for r in rows]


@router.get("/admin/users")
def admin_users(db:Session=Depends(get_db),user:User=Depends(require_roles(Role.administrator))):
    return [UserOut.model_validate(item) for item in db.query(User).order_by(User.created_at).all()]
