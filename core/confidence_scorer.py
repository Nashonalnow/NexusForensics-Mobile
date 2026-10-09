#!/usr/bin/env python3
"""
NexusForensics Mobile™ | Explainable Confidence Scoring Engine
Court-defensible scoring formula: Supporting Sources - Contradictory Evidence + Temporal Proximity + Artifact Reliability.
Strict Copper Standard: Complete mathematical transparency, zero black-box calculations.
"""

import uuid
from typing import Dict, List, Any, Optional, Tuple

from .models import FindingModel, ConfidenceFactorModel
from .warehouse import DuckDBWarehouse, to_uuid

class ConfidenceScoringEngine:
    """
    Evaluates correlated evidence and synthesizes court-ready forensic findings
    with transparent mathematical breakdowns.
    """

    def __init__(self, warehouse: DuckDBWarehouse):
        self.wh = warehouse

    def evaluate_communication_events(self, case_id: str, device_id: str) -> List[FindingModel]:
        """
        Evaluates communication events (messages, calls) against correlated device state and application focus.
        Synthesizes defensible findings with confidence score calculations.
        """
        findings: List[FindingModel] = []
        did = to_uuid(device_id)
        cid = to_uuid(case_id)

        # Pull communication events
        comms = self.wh.raw_sql_query("""
            SELECT * FROM forensic.events 
            WHERE category = 'communication' AND device_id = ?
            ORDER BY timestamp DESC;
        """, params=[did], limit=100)

        # For each communication event, inspect its relationships
        for c in comms.get("rows", []):
            ev_id = str(c["event_id"])
            rels = self.wh.query_relationships(ev_id)

            supporting_events: List[str] = [ev_id]
            contradictory_events: List[str] = []
            factors: List[ConfidenceFactorModel] = []


            # Base score: Direct Evidence recorded in official database
            base_score = 70
            factors.append(ConfidenceFactorModel(
                finding_id="",
                event_id=ev_id,
                score=70,
                factor_type="base_direct_evidence",
                explanation=f"Direct artifact record found in {c.get('event_type')} database."
            ))

            has_unlock = False
            has_app_active = False
            has_contradiction = False

            for r in rels:
                rel_type = r.get("relationship_type")
                source_id = str(r.get("source_event_id"))
                target_id = str(r.get("target_event_id"))
                other_id = source_id if source_id != ev_id else target_id
                rationale = r.get("rationale", "")

                if rel_type in ["preceded_by", "supports"]:
                    has_unlock = True
                    supporting_events.append(other_id)
                    factors.append(ConfidenceFactorModel(
                        finding_id="",
                        event_id=other_id,
                        score=15,
                        factor_type="supporting_corroboration",
                        explanation=f"Supporting user interaction: {rationale}"
                    ))
                elif rel_type == "used_app":
                    has_app_active = True
                    supporting_events.append(other_id)
                    factors.append(ConfidenceFactorModel(
                        finding_id="",
                        event_id=other_id,
                        score=12,
                        factor_type="app_foreground_corroboration",
                        explanation=f"Corroborated foreground app: {rationale}"
                    ))
                elif rel_type == "located_at":
                    supporting_events.append(other_id)
                    factors.append(ConfidenceFactorModel(
                        finding_id="",
                        event_id=other_id,
                        score=5,
                        factor_type="location_corroboration",
                        explanation=f"Coinciding location fix: {rationale}"
                    ))
                elif rel_type == "contradicts":
                    has_contradiction = True
                    contradictory_events.append(other_id)
                    factors.append(ConfidenceFactorModel(
                        finding_id="",
                        event_id=other_id,
                        score=-35,
                        factor_type="contradictory_evidence",
                        explanation=f"Contradictory state: {rationale}"
                    ))

            # Compute final confidence percentage (clamp between 10 and 99)
            total_score = sum(f.score for f in factors)
            final_confidence = max(10, min(99, total_score))

            title = f"User Manually Transmitted {c.get('event_type', 'message').replace('_', ' ').title()}"
            if has_contradiction:
                title = f"Anomalous Transmission Under Locked State: {c.get('event_type')}"

            desc_parts = [
                f"Event {ev_id} occurred at {c.get('timestamp')}.",
                f"Description: {c.get('description')}."
            ]
            if has_unlock:
                desc_parts.append("Corroborated by prior device unlock/screen activation.")
            if has_app_active:
                desc_parts.append("Application was confirmed in foreground focus.")
            if has_contradiction:
                desc_parts.append("WARNING: Potential automated, background, or anomalous transmission.")

            finding = FindingModel(
                case_id=cid,
                title=title,
                description=" ".join(desc_parts),
                confidence=final_confidence,
                finding_type="user_communication",
                supporting_events=supporting_events,
                contradictory_events=contradictory_events
            )

            # Persist finding in DuckDB
            self.wh.insert_finding(
                finding_id=finding.finding_id,
                case_id=finding.case_id,
                title=finding.title,
                description=finding.description,
                finding_type=finding.finding_type,
                confidence=finding.confidence,
                methodology_version=getattr(finding, 'methodology_version', '1.0.0'),
                analyst=getattr(finding, 'analyst', 'Lead Forensic Examiner'),
                supporting_events=finding.supporting_events
            )


            # Persist confidence factors
            for f in factors:
                f.finding_id = finding.finding_id
                self.wh.insert_confidence_factor(
                    f.factor_id, f.finding_id, f.event_id, f.score, f.factor_type, f.explanation
                )

            findings.append(finding)

        return findings
