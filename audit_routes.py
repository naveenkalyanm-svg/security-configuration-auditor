from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from datetime import datetime
import os

from database import SessionLocal
from models.models import Audit, Finding

from reports.pdf_generator import generate_pdf_report
from services.ai_service import analyze_finding


router = APIRouter(
    prefix="/audit",
    tags=["Audit"]
)


# =========================================================
# UPLOAD AND ANALYZE CONFIGURATION
# =========================================================

@router.post("/upload")
async def upload_config(file: UploadFile = File(...)):

    filename = file.filename.lower() if file.filename else ""

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )

    # Identify configuration type
    if "sshd_config" in filename:
        configuration_type = "SSH"

    elif "nginx" in filename:
        configuration_type = "NGINX"

    elif "dockerfile" in filename:
        configuration_type = "DOCKER"

    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported configuration file"
        )

    # Read uploaded file
    content = await file.read()

    try:
        text_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Configuration file must be UTF-8 text"
        )

    findings = []

    # =====================================================
    # SSH
    # =====================================================

    if configuration_type == "SSH":

        from parsers.ssh_parser import parse_ssh_config
        from security.rule_engine import run_rules
        from security.risk_engine import calculate_risk

        parsed_config = parse_ssh_config(text_content)

        findings = run_rules(parsed_config)

        for finding in findings:

            risk_result = calculate_risk(finding)

            finding["risk_score"] = risk_result["score"]
            finding["risk"] = risk_result["risk"]

    # =====================================================
    # DOCKER
    # =====================================================

    elif configuration_type == "DOCKER":

        from parsers.docker_parser import parse_dockerfile
        from security.rule_engine import run_rules
        from security.risk_engine import calculate_risk

        parsed_config = parse_dockerfile(text_content)

        findings = run_rules(parsed_config)

        for finding in findings:

            risk_result = calculate_risk(finding)

            finding["risk_score"] = risk_result["score"]
            finding["risk"] = risk_result["risk"]

    # =====================================================
    # NGINX
    # =====================================================

    elif configuration_type == "NGINX":

        from parsers.nginx_parser import parse_nginx_config
        from security.rule_engine import run_rules
        from security.risk_engine import calculate_risk

        parsed_config = parse_nginx_config(text_content)

        findings = run_rules(parsed_config)

        for finding in findings:

            risk_result = calculate_risk(finding)

            finding["risk_score"] = risk_result["score"]
            finding["risk"] = risk_result["risk"]

    # =====================================================
    # AI / THREAT INTELLIGENCE BRIDGE
    # =====================================================

    for finding in findings:

        ai_result = analyze_finding(finding)

        finding["ai_explanation"] = ai_result["ai_explanation"]

        finding["threat_context"] = ai_result["threat_context"]

        finding["remediation"] = ai_result["remediation"]

        finding["ai_status"] = ai_result["ai_status"]

    # =====================================================
    # SAVE TO DATABASE
    # =====================================================

    db = SessionLocal()

    try:

        audit = Audit(
            file_name=file.filename,
            configuration_type=configuration_type,
            scan_date=datetime.utcnow(),
            total_findings=len(findings),
            status="completed"
        )

        db.add(audit)

        db.commit()

        db.refresh(audit)

        # Save findings
        for finding in findings:

            db_finding = Finding(
                audit_id=audit.id,
                rule_id=finding["rule_id"],
                title=finding["title"],
                setting=finding["setting"],
                current_value=finding["current_value"],
                severity=finding["severity"],
                risk=finding["risk"],
                explanation=finding["ai_explanation"],
                threat_context=finding["threat_context"],
                recommendation=finding["remediation"]
            )

            db.add(db_finding)

        db.commit()

        # =================================================
        # RETURN RESULT
        # =================================================

        return {
            "message": "Configuration analyzed successfully",

            "audit_id": audit.id,

            "file_name": file.filename,

            "configuration_type": configuration_type,

            "total_findings": len(findings),

            "findings": findings
        }

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Error processing configuration: {str(e)}"
        )

    finally:

        db.close()


# =========================================================
# AUDIT HISTORY
# =========================================================

@router.get("/history")
def get_audit_history():

    db = SessionLocal()

    try:

        audits = (
            db.query(Audit)
            .order_by(Audit.id.desc())
            .all()
        )

        return [
            {
                "audit_id": audit.id,
                "file_name": audit.file_name,
                "configuration_type": audit.configuration_type,
                "scan_date": audit.scan_date,
                "total_findings": audit.total_findings,
                "status": audit.status
            }

            for audit in audits
        ]

    finally:

        db.close()


# =========================================================
# FINDINGS FOR ONE AUDIT
# =========================================================

@router.get("/{audit_id}/findings")
def get_audit_findings(audit_id: int):

    db = SessionLocal()

    try:

        audit = (
            db.query(Audit)
            .filter(Audit.id == audit_id)
            .first()
        )

        if not audit:

            raise HTTPException(
                status_code=404,
                detail="Audit not found"
            )

        findings = (
            db.query(Finding)
            .filter(Finding.audit_id == audit_id)
            .all()
        )

        return {
            "audit_id": audit.id,

            "file_name": audit.file_name,

            "configuration_type": audit.configuration_type,

            "total_findings": len(findings),

            "findings": [

                {
                    "finding_id": finding.id,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "setting": finding.setting,
                    "current_value": finding.current_value,
                    "severity": finding.severity,
                    "risk": finding.risk,
                    "explanation": finding.explanation,
                    "threat_context": finding.threat_context,
                    "recommendation": finding.recommendation
                }

                for finding in findings
            ]
        }

    finally:

        db.close()


# =========================================================
# GENERATE PDF REPORT
# =========================================================

@router.get("/{audit_id}/report")
def generate_audit_report(audit_id: int):

    db = SessionLocal()

    try:

        audit = (
            db.query(Audit)
            .filter(Audit.id == audit_id)
            .first()
        )

        if not audit:

            raise HTTPException(
                status_code=404,
                detail="Audit not found"
            )

        findings = (
            db.query(Finding)
            .filter(Finding.audit_id == audit_id)
            .all()
        )

        os.makedirs(
            "reports/generated",
            exist_ok=True
        )

        file_path = (
            f"reports/generated/"
            f"audit_report_{audit_id}.pdf"
        )

        generate_pdf_report(
            file_path,
            audit,
            findings
        )

        return FileResponse(
            path=file_path,
            media_type="application/pdf",
            filename=f"audit_report_{audit_id}.pdf"
        )

    finally:

        db.close()