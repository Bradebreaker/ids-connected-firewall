"""
api/routes_report.py — Security Report Generation Endpoints.

Provides real data-driven reporting across multiple formats and time intervals:
    - GET /api/report/data  : Structured JSON payload for live UI report preview
    - GET /api/report/html  : Printable, standalone HTML security report
    - GET /api/report/csv   : CSV export of alerts for analysis
    - GET /api/report/json  : Complete raw JSON security archive export
    - GET /api/report       : Default HTML report (backward compatible)
"""

import io
import csv
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from db.models import Alert, BlockedIP, FirewallRule, User
from api.dependencies import get_db, get_current_user
from sniffer.packet_event import get_current_packet_count

router = APIRouter(prefix="/api/report", tags=["Report"])


async def _fetch_report_data(period: str, db: AsyncSession) -> Dict[str, Any]:
    """Fetch and aggregate real database metrics for the specified period."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    time_filter = None
    period_label = "All Recorded Security History"

    if period == "hour":
        time_filter = Alert.timestamp >= now - timedelta(hours=1)
        period_label = "Last 1 Hour"
    elif period == "today":
        time_filter = Alert.timestamp >= today_start
        period_label = f"Today ({today_start.strftime('%Y-%m-%d')} UTC to Present)"
    elif period in ["24h", "day"]:
        time_filter = Alert.timestamp >= now - timedelta(hours=24)
        period_label = "Last 24 Hours"
    elif period in ["7d", "week"]:
        time_filter = Alert.timestamp >= now - timedelta(days=7)
        period_label = "Last 7 Days"

    # Query filtered alerts
    query = select(Alert).order_by(desc(Alert.timestamp))
    if time_filter is not None:
        query = query.where(time_filter)
    alerts_result = await db.execute(query)
    alerts: List[Alert] = alerts_result.scalars().all()

    total_alerts = len(alerts)
    auto_blocked_count = sum(1 for a in alerts if a.auto_blocked)

    # Severity distribution
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for a in alerts:
        if a.severity in severity_counts:
            severity_counts[a.severity] += 1

    # Attack types distribution
    type_counts: Dict[str, int] = {}
    for a in alerts:
        atype = a.alert_type or "unknown"
        type_counts[atype] = type_counts.get(atype, 0) + 1

    # Top attackers for period
    attacker_counts: Dict[str, int] = {}
    for a in alerts:
        attacker_counts[a.source_ip] = attacker_counts.get(a.source_ip, 0) + 1
    sorted_attackers = sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_attackers = [{"ip": ip, "count": count} for ip, count in sorted_attackers]

    # Top targeted services/ports
    port_counts: Dict[int, int] = {}
    for a in alerts:
        if a.dest_port:
            port_counts[a.dest_port] = port_counts.get(a.dest_port, 0) + 1
    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_ports = [{"port": p, "count": count} for p, count in sorted_ports]

    # Blocked IPs
    blocks_result = await db.execute(select(BlockedIP).order_by(desc(BlockedIP.blocked_at)))
    blocked_ips: List[BlockedIP] = blocks_result.scalars().all()

    # Active Firewall Rules
    rules_result = await db.execute(select(FirewallRule).where(FirewallRule.is_active == True).order_by(FirewallRule.priority))
    firewall_rules: List[FirewallRule] = rules_result.scalars().all()

    # Recommendations generation
    recommendations = []
    if severity_counts["high"] > 0:
        recommendations.append("Immediate review of High-Severity attack incidents (SQLi, Log4Shell, RCE) and confirm source IP quarantines.")
    if "port_scan" in type_counts and type_counts["port_scan"] > 5:
        recommendations.append("Persistent network reconnaissance detected. Consider deploying fail2ban / rate-limiting upstream ingress ports.")
    if "brute_force" in type_counts and type_counts["brute_force"] > 0:
        recommendations.append("SSH / Telnet brute force detected. Enforce multi-factor authentication (MFA) and disable password-based root SSH.")
    if not recommendations:
        recommendations.append("System operating under normal traffic parameters. Continue standard continuous security monitoring.")

    # Convert alerts to serializable dicts
    alerts_data = []
    for a in alerts[:100]:
        alerts_data.append({
            "id": a.id,
            "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "—",
            "source_ip": a.source_ip,
            "dest_ip": a.dest_ip or "—",
            "dest_port": a.dest_port or 0,
            "protocol": a.protocol or "—",
            "alert_type": a.alert_type,
            "severity": a.severity,
            "description": a.description,
            "auto_blocked": a.auto_blocked,
        })

    blocks_data = []
    for b in blocked_ips:
        blocks_data.append({
            "id": b.id,
            "ip_address": b.ip_address,
            "reason": b.reason or "—",
            "blocked_at": b.blocked_at.strftime("%Y-%m-%d %H:%M:%S") if b.blocked_at else "—",
            "expires_at": b.expires_at.strftime("%Y-%m-%d %H:%M:%S") if b.expires_at else "Permanent",
            "is_permanent": b.is_permanent,
        })

    rules_data = []
    for r in firewall_rules:
        rules_data.append({
            "id": r.id,
            "priority": r.priority,
            "source_ip": r.source_ip,
            "dest_port": r.dest_port or "*",
            "protocol": r.protocol or "ALL",
            "action": r.action,
            "rule_type": r.rule_type,
            "is_active": r.is_active,
        })

    return {
        "report_id": f"REP-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "period": period,
        "period_label": period_label,
        "executive_summary": {
            "total_alerts": total_alerts,
            "auto_blocked_count": auto_blocked_count,
            "active_blocks_count": len(blocked_ips),
            "active_rules_count": len(firewall_rules),
            "packets_processed": get_current_packet_count(),
            "overall_status": "CRITICAL THREATS" if severity_counts["high"] > 0 else ("ELEVATED" if severity_counts["medium"] > 0 else "NOMINAL"),
        },
        "severity_analysis": severity_counts,
        "attack_types": type_counts,
        "top_attackers": top_attackers,
        "top_ports": top_ports,
        "blocked_ips": blocks_data,
        "firewall_rules": rules_data,
        "recent_alerts": alerts_data,
        "recommendations": recommendations,
    }


@router.get("/data")
async def get_report_data(
    period: str = Query("24h", regex="^(hour|today|24h|7d|all)$"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return JSON payload of report data for interactive preview."""
    data = await _fetch_report_data(period, db)
    return data


@router.get("/html", response_class=HTMLResponse)
@router.get("", response_class=HTMLResponse)
async def get_report_html(
    period: str = Query("24h", regex="^(hour|today|24h|7d|all)$"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Generate standalone printable HTML security report."""
    data = await _fetch_report_data(period, db)

    # Build alerts table rows
    alert_rows = ""
    for a in data["recent_alerts"][:50]:
        sev_color = "#ef4444" if a["severity"] == "high" else ("#f59e0b" if a["severity"] == "medium" else "#10b981")
        action_badge = "<span style='color:#ef4444;font-weight:600;'>BLOCKED</span>" if a["auto_blocked"] else "<span style='color:#64748b;'>ALERTED</span>"
        alert_rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-family:monospace;">{a['timestamp']}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-family:monospace;color:#38bdf8;">{a['source_ip']}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;">{a['alert_type'].replace('_', ' ').title()}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;color:{sev_color};font-weight:700;">{a['severity'].upper()}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;">{action_badge}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-size:0.85rem;color:#cbd5e1;">{a['description'][:100]}</td>
        </tr>
        """
    if not data["recent_alerts"]:
        alert_rows = "<tr><td colspan='6' style='padding:20px;text-align:center;color:#64748b;'>No security events recorded for this period.</td></tr>"

    # Build blocked rows
    blocked_rows = ""
    for b in data["blocked_ips"]:
        blocked_rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-family:monospace;color:#f43f5e;">{b['ip_address']}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;">{b['reason']}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-family:monospace;">{b['blocked_at']}</td>
            <td style="padding:8px;border-bottom:1px solid #1e293b;font-family:monospace;">{b['expires_at']}</td>
        </tr>
        """
    if not data["blocked_ips"]:
        blocked_rows = "<tr><td colspan='4' style='padding:15px;text-align:center;color:#64748b;'>No active host blocks recorded.</td></tr>"

    # Top attackers rows
    top_rows = ""
    for atk in data["top_attackers"]:
        top_rows += f"<tr><td style='padding:6px 8px;font-family:monospace;color:#38bdf8;'>{atk['ip']}</td><td style='padding:6px 8px;font-weight:700;text-align:right;'>{atk['count']} incidents</td></tr>"
    if not data["top_attackers"]:
        top_rows = "<tr><td colspan='2' style='padding:10px;text-align:center;color:#64748b;'>No attacker data for this period.</td></tr>"

    recs_html = "".join(f"<li style='margin-bottom:8px;color:#e2e8f0;'>{r}</li>" for r in data["recommendations"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IDS Security Report — {data['report_id']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b1120; color: #f8fafc; margin: 0; padding: 30px; }}
        .report-box {{ max-width: 1000px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 40px; }}
        h1, h2, h3 {{ color: #ffffff; margin-top: 0; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 30px; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; font-weight: 700; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; }}
        .stat-val {{ font-size: 1.8rem; font-weight: 800; color: #38bdf8; }}
        .stat-lbl {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; margin-bottom: 25px; }}
        th {{ background: #1e293b; padding: 10px 8px; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; border-bottom: 1px solid #334155; }}
        @media print {{ body {{ background: #ffffff; color: #000000; padding: 0; }} .report-box {{ border: none; padding: 0; background: #ffffff; }} th {{ background: #f1f5f9; color: #000; }} .stat-card {{ background: #f8fafc; border-color: #cbd5e1; color: #000; }} .stat-val {{ color: #0284c7; }} }}
    </style>
</head>
<body>
    <div class="report-box">
        <div class="header">
            <div>
                <h1>🛡️ IDS Security Operations Report</h1>
                <div style="color:#94a3b8; font-size:0.9rem;">Period: <strong style="color:#f8fafc;">{data['period_label']}</strong> | Report ID: {data['report_id']}</div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:0.85rem; color:#94a3b8;">Generated: {data['generated_at']}</div>
                <div style="margin-top:8px;"><span class="badge" style="background:#0284c7; color:#fff;">Status: {data['executive_summary']['overall_status']}</span></div>
            </div>
        </div>

        <div class="grid">
            <div class="stat-card"><div class="stat-val">{data['executive_summary']['total_alerts']}</div><div class="stat-lbl">Total Alerts</div></div>
            <div class="stat-card"><div class="stat-val" style="color:#ef4444;">{data['executive_summary']['auto_blocked_count']}</div><div class="stat-lbl">Auto-Blocked Attacks</div></div>
            <div class="stat-card"><div class="stat-val" style="color:#f59e0b;">{data['executive_summary']['active_blocks_count']}</div><div class="stat-lbl">Quarantined Hosts</div></div>
            <div class="stat-card"><div class="stat-val" style="color:#10b981;">{data['executive_summary']['packets_processed']}</div><div class="stat-lbl">Processed Packets</div></div>
        </div>

        <h2>Executive Threat Overview</h2>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 25px;">
            <div style="background:#1e293b; padding:15px; border-radius:8px;">
                <h3 style="font-size:0.95rem; color:#94a3b8;">Severity Distribution</h3>
                <div style="display:flex; justify-content:space-around; margin-top:15px;">
                    <div style="text-align:center;"><div style="font-size:1.4rem; font-weight:700; color:#ef4444;">{data['severity_analysis']['high']}</div><div style="font-size:0.75rem; color:#94a3b8;">HIGH</div></div>
                    <div style="text-align:center;"><div style="font-size:1.4rem; font-weight:700; color:#f59e0b;">{data['severity_analysis']['medium']}</div><div style="font-size:0.75rem; color:#94a3b8;">MEDIUM</div></div>
                    <div style="text-align:center;"><div style="font-size:1.4rem; font-weight:700; color:#10b981;">{data['severity_analysis']['low']}</div><div style="font-size:0.75rem; color:#94a3b8;">LOW</div></div>
                </div>
            </div>
            <div style="background:#1e293b; padding:15px; border-radius:8px;">
                <h3 style="font-size:0.95rem; color:#94a3b8;">Top Threat Actors</h3>
                <table style="margin-bottom:0;">
                    {top_rows}
                </table>
            </div>
        </div>

        <h2>Critical Incident Ledger</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Attack Vector</th>
                    <th>Severity</th>
                    <th>Mitigation</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {alert_rows}
            </tbody>
        </table>

        <h2>Active Host Quarantine (Firewall Blocks)</h2>
        <table>
            <thead>
                <tr>
                    <th>Quarantined IP</th>
                    <th>Enforcement Reason</th>
                    <th>Blocked At</th>
                    <th>Expiration</th>
                </tr>
            </thead>
            <tbody>
                {blocked_rows}
            </tbody>
        </table>

        <h2>Defensive Recommendations</h2>
        <ul style="background:#1e293b; padding:20px 30px; border-radius:8px; line-height:1.6;">
            {recs_html}
        </ul>
    </div>
</body>
</html>"""
    filename = f"IDS_Security_Report_{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}.html"
    return HTMLResponse(content=html, headers={"Content-Disposition": f'inline; filename="{filename}"'})


@router.get("/csv")
async def get_report_csv(
    period: str = Query("24h", regex="^(hour|today|24h|7d|all)$"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Export alerts as CSV spreadsheet for the specified period."""
    data = await _fetch_report_data(period, db)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Alert ID", "Timestamp", "Source IP", "Destination IP", "Port", "Protocol", "Attack Type", "Severity", "Auto Blocked", "Description"])

    for a in data["recent_alerts"]:
        writer.writerow([
            a["id"],
            a["timestamp"],
            a["source_ip"],
            a["dest_ip"],
            a["dest_port"],
            a["protocol"],
            a["alert_type"],
            a["severity"],
            "TRUE" if a["auto_blocked"] else "FALSE",
            a["description"],
        ])

    filename = f"IDS_Alerts_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/json")
async def get_report_json(
    period: str = Query("24h", regex="^(hour|today|24h|7d|all)$"),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Download complete raw JSON security data archive."""
    data = await _fetch_report_data(period, db)
    filename = f"IDS_Traffic_{datetime.utcnow().strftime('%Y-%m-%d')}.json"
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
