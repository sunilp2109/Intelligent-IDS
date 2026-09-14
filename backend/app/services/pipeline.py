from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.models import AttackLog
from app.services.analysis import analyze_from_payload, persist_analysis
from app.services.detection import run_detection
from app.services.explain import run_explanation
from app.services.features import extract_features_from_db
from app.services.ingestion import IngestOutcome, ingest_event
from app.services.realtime_service import (
    broadcast_detection_created,
    broadcast_risk_assessed,
    broadcast_security_event,
    broadcast_system_status,
    build_security_event_payload,
    utc_now_iso,
)
from app.services.risk import assess_from_payload, persist_risk_assessment
from honeypot.parser.log_parser import NormalizedEvent
from ml.explainability.shap_explainer import ExplanationError, ExplanationUnavailableError
from ml.models.predict import InvalidFeatureInputError, ModelNotFoundError

logger = logging.getLogger("intelligent_ids.pipeline")

PipelineStatus = Literal[
    "duplicate",
    "complete",
    "model_unavailable",
    "feature_unavailable",
    "invalid_features",
    "error",
]


@dataclass
class ProcessResult:
    ingest: IngestOutcome
    status: PipelineStatus
    detection_id: int | None = None
    analysis_id: int | None = None
    risk_id: int | None = None
    xai_status: str = "unavailable"
    payload: dict[str, Any] | None = None


def process_security_event(db: Session, event: NormalizedEvent) -> ProcessResult:
    """Ingest one honeypot event, reuse Modules 3–7, then broadcast a complete result."""
    outcome = ingest_event(db, event)
    if outcome.result == "duplicate":
        return ProcessResult(ingest=outcome, status="duplicate")
    return run_session_pipeline(db, outcome.attack_log_id, ingest=outcome)


def run_session_pipeline(
    db: Session,
    attack_log_id: int,
    *,
    ingest: IngestOutcome | None = None,
) -> ProcessResult:
    dummy_ingest = ingest or IngestOutcome("inserted", "", attack_log_id)
    attack_log = db.get(AttackLog, attack_log_id)
    source_ip = attack_log.ip_address if attack_log is not None else "unknown"
    envelope_ts = utc_now_iso()

    try:
        records = extract_features_from_db(db, log_id=attack_log_id)
        if not records:
            logger.warning("Pipeline skipped log_id=%s reason=feature_unavailable", attack_log_id)
            broadcast_system_status(
                "pipeline_incomplete",
                reason="feature_unavailable",
                log_id=attack_log_id,
                source_ip=source_ip,
            )
            return ProcessResult(ingest=dummy_ingest, status="feature_unavailable")

        features = records[0]["features"]
        try:
            prediction, detection = run_detection(db, features, log_id=attack_log_id)
        except ModelNotFoundError:
            logger.info("Pipeline stored event only log_id=%s reason=model_unavailable", attack_log_id)
            broadcast_system_status(
                "pipeline_incomplete",
                reason="model_unavailable",
                log_id=attack_log_id,
                source_ip=source_ip,
            )
            return ProcessResult(ingest=dummy_ingest, status="model_unavailable")
        except InvalidFeatureInputError as exc:
            logger.warning("Pipeline invalid features log_id=%s detail=%s", attack_log_id, exc)
            broadcast_system_status(
                "pipeline_incomplete",
                reason="invalid_features",
                log_id=attack_log_id,
                source_ip=source_ip,
            )
            return ProcessResult(ingest=dummy_ingest, status="invalid_features")

        detection_id = detection.id if detection is not None else None
        broadcast_detection_created(
            {
                "log_id": attack_log_id,
                "detection_id": detection_id,
                "source_ip": source_ip,
                "classification": prediction["classification"],
                "confidence_score": prediction["confidence_score"],
            },
            timestamp=envelope_ts,
        )

        analysis = analyze_from_payload(
            features,
            classification=prediction["classification"],
            confidence_score=prediction["confidence_score"],
        )
        saved_analysis = persist_analysis(db, analysis, detection_id=detection_id)
        analysis_id = saved_analysis.id

        xai_status = "unavailable"
        if detection_id is not None:
            try:
                run_explanation(db, features, detection_id=detection_id)
                xai_status = "stored"
            except (ExplanationUnavailableError, ExplanationError, ModelNotFoundError, InvalidFeatureInputError) as exc:
                logger.info("XAI skipped log_id=%s detection_id=%s reason=%s", attack_log_id, detection_id, exc)

        risk = assess_from_payload(
            classification=prediction["classification"],
            confidence_score=prediction["confidence_score"],
            attack_category=analysis["attack_category"],
            evidence_strength=analysis["evidence_strength"],
            features=features,
            indicators=analysis.get("indicators"),
        )
        saved_risk = persist_risk_assessment(db, risk, detection_id=detection_id)

        broadcast_risk_assessed(
            {
                "log_id": attack_log_id,
                "detection_id": detection_id,
                "source_ip": source_ip,
                "risk_score": saved_risk.risk_score,
                "risk_level": saved_risk.risk_level,
                "recommended_action": saved_risk.recommended_action,
            },
            timestamp=envelope_ts,
        )

        payload = build_security_event_payload(
            log_id=attack_log_id,
            detection_id=detection_id,
            source_ip=source_ip,
            classification=prediction["classification"],
            confidence_score=prediction["confidence_score"],
            attack_category=analysis["attack_category"],
            risk_score=saved_risk.risk_score,
            risk_level=saved_risk.risk_level,
            recommended_action=saved_risk.recommended_action,
            xai_status=xai_status,
            timestamp=envelope_ts,
        )
        broadcast_security_event(payload)
        return ProcessResult(
            ingest=dummy_ingest,
            status="complete",
            detection_id=detection_id,
            analysis_id=analysis_id,
            risk_id=saved_risk.id,
            xai_status=xai_status,
            payload=payload,
        )
    except Exception:
        logger.exception("Pipeline failed log_id=%s", attack_log_id)
        broadcast_system_status(
            "pipeline_incomplete",
            reason="processing_error",
            log_id=attack_log_id,
            source_ip=source_ip,
        )
        return ProcessResult(ingest=dummy_ingest, status="error")
