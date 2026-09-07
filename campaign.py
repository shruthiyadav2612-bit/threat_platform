"""
This is the "network effect" layer:
  - seen_before(): has this IOC appeared in a prior case? how many times?
  - link_campaigns(): if the new case shares an IOC with existing case(s),
    cluster them into a Campaign (creating one if needed, merging into an
    existing one if the IOC is already part of a campaign).
"""

from sqlalchemy.orm import Session
from sqlalchemy import func

from . import models


def seen_before(db: Session, ioc_type: str, value: str, exclude_case_id: int = None) -> dict:
    q = db.query(models.IOC).filter(models.IOC.ioc_type == ioc_type, models.IOC.value == value)
    if exclude_case_id:
        q = q.filter(models.IOC.case_id != exclude_case_id)
    rows = q.all()
    if not rows:
        return {"known": False, "times_seen": 0, "case_ids": []}
    return {
        "known": True,
        "times_seen": len(rows),
        "case_ids": [r.case_id for r in rows],
    }


def link_campaigns(db: Session, case: models.Case, ioc_values: list) -> list:
    """
    Given the IOC values (ip/domain) just extracted for `case`, find other
    cases that share any of them and cluster into a campaign.
    Returns the list of Campaign objects this case now belongs to.
    """
    if not ioc_values:
        return []

    matched_campaigns = []

    for value in ioc_values:
        other_case_ids = (
            db.query(models.IOC.case_id)
            .filter(models.IOC.value == value, models.IOC.case_id != case.id)
            .distinct()
            .all()
        )
        other_case_ids = [c[0] for c in other_case_ids]
        if not other_case_ids:
            continue

        # Does an existing campaign already track this IOC?
        existing_campaign = (
            db.query(models.Campaign)
            .filter(models.Campaign.shared_ioc == value)
            .first()
        )

        if existing_campaign:
            if case not in existing_campaign.cases:
                existing_campaign.cases.append(case)
            matched_campaigns.append(existing_campaign)
        else:
            # Create a new campaign linking this case + the other case(s)
            campaign = models.Campaign(
                name=f"Campaign — shared IOC {value}",
                shared_ioc=value,
            )
            db.add(campaign)
            db.flush()  # get campaign.id before appending relationships
            campaign.cases.append(case)
            other_cases = db.query(models.Case).filter(models.Case.id.in_(other_case_ids)).all()
            for oc in other_cases:
                if oc not in campaign.cases:
                    campaign.cases.append(oc)
            matched_campaigns.append(campaign)

    db.commit()
    return matched_campaigns


def campaign_graph_data(db: Session, campaign_id: int) -> dict:
    """Node/edge JSON for the frontend graph (vis-network format)."""
    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        return {"nodes": [], "edges": []}

    nodes = []
    edges = []
    seen_node_ids = set()

    ioc_node_id = f"ioc_{campaign.shared_ioc}"
    nodes.append({"id": ioc_node_id, "label": campaign.shared_ioc, "group": "ioc", "shape": "diamond"})
    seen_node_ids.add(ioc_node_id)

    for c in campaign.cases:
        case_node_id = f"case_{c.id}"
        if case_node_id not in seen_node_ids:
            nodes.append({
                "id": case_node_id,
                "label": f"Case {c.id}\n{c.subject[:30]}",
                "group": "case",
                "shape": "box",
            })
            seen_node_ids.add(case_node_id)
        edges.append({"from": case_node_id, "to": ioc_node_id})

        # also show this case's other IOCs as satellite nodes for context
        for ioc in c.iocs:
            if ioc.value == campaign.shared_ioc:
                continue
            other_id = f"ioc_{ioc.value}"
            if other_id not in seen_node_ids:
                nodes.append({"id": other_id, "label": ioc.value, "group": "ioc_other", "shape": "dot"})
                seen_node_ids.add(other_id)
            edges.append({"from": case_node_id, "to": other_id})

    return {"nodes": nodes, "edges": edges, "campaign_name": campaign.name}


def ioc_intelligence(db: Session, value: str) -> dict:
    """Full profile for one IOC value: first seen, times seen, related cases/campaigns."""
    rows = (
        db.query(models.IOC)
        .filter(models.IOC.value == value)
        .order_by(models.IOC.first_seen.asc())
        .all()
    )
    if not rows:
        return {"value": value, "known": False}

    case_ids = sorted(set(r.case_id for r in rows))
    campaigns = db.query(models.Campaign).filter(models.Campaign.shared_ioc == value).all()

    risk = "HIGH" if len(case_ids) >= 3 else ("MEDIUM" if len(case_ids) == 2 else "LOW")

    return {
        "value": value,
        "known": True,
        "ioc_type": rows[0].ioc_type,
        "first_seen": rows[0].first_seen.isoformat(),
        "times_seen": len(rows),
        "related_case_ids": case_ids,
        "related_campaigns": [{"id": c.id, "name": c.name} for c in campaigns],
        "risk": risk,
    }


def campaign_detail(db: Session, campaign_id: int) -> dict:
    """Stats + timeline for one campaign, for the Attack Campaigns view."""
    campaign = db.query(models.Campaign).filter(models.Campaign.id == campaign_id).first()
    if not campaign:
        return {}

    cases_sorted = sorted(campaign.cases, key=lambda c: c.upload_date)
    all_ioc_values = set()
    for c in cases_sorted:
        for ioc in c.iocs:
            all_ioc_values.add(ioc.value)

    timeline = [
        {
            "case_id": c.id,
            "date": c.upload_date.isoformat(),
            "subject": c.subject,
            "verdict": c.verdict,
        }
        for c in cases_sorted
    ]

    return {
        "id": campaign.id,
        "name": campaign.name,
        "shared_ioc": campaign.shared_ioc,
        "case_count": len(cases_sorted),
        "shared_ioc_count": len(all_ioc_values),
        "first_observed": cases_sorted[0].upload_date.isoformat() if cases_sorted else None,
        "last_observed": cases_sorted[-1].upload_date.isoformat() if cases_sorted else None,
        "timeline": timeline,
    }


def all_campaigns(db: Session) -> list:
    campaigns = db.query(models.Campaign).all()
    return [
        {
            "id": c.id,
            "name": c.name,
            "shared_ioc": c.shared_ioc,
            "case_count": len(c.cases),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in campaigns
    ]
