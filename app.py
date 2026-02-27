"""
Cloud-Sentinel: Automated Website Health & Security Monitor
Flask Dashboard — app.py
Region : ap-south-2

★ Lambda logic is now built-in:
  A background thread runs every 5 minutes, checks all monitored sites,
  writes results to DynamoDB, and publishes SNS alerts automatically —
  no separate AWS Lambda function needed.
"""

import hashlib
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from decimal import Decimal
from functools import wraps

import boto3
from boto3.dynamodb.conditions import Attr
from flask import (Flask, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ══════════════════════════════════════════════════════════════
# APP CONFIG
# ══════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = "cloud-sentinel-super-secret-key-change-in-prod"

AWS_REGION           = "ap-south-2"
MONITOR_INTERVAL_SEC = 300   # ★ Check every 5 minutes (same cadence as Lambda schedule)

# Sites to monitor — same list the Lambda function used
MONITORED_SITES = [
    {"url": "https://www.amazon.com",        "expected_checksum": None},
    {"url": "https://www.flipkart.com",      "expected_checksum": None},
    {"url": "https://www.github.com",        "expected_checksum": None},
    {"url": "https://www.stackoverflow.com", "expected_checksum": None},
    {"url": "https://www.wikipedia.org",     "expected_checksum": None},
]

# ══════════════════════════════════════════════════════════════
# AWS CLIENTS
# ══════════════════════════════════════════════════════════════
dynamodb    = boto3.resource("dynamodb", region_name=AWS_REGION)
logs_table  = dynamodb.Table("CloudSentinelLogs")
users_table = dynamodb.Table("CloudSentinelUsers")
sns_client  = boto3.client("sns", region_name=AWS_REGION)
sts_client  = boto3.client("sts", region_name=AWS_REGION)


# ══════════════════════════════════════════════════════════════
# SNS TOPIC ARN — AUTO RESOLVED VIA STS
# ══════════════════════════════════════════════════════════════
def get_sns_topic_arn():
    try:
        account_id = sts_client.get_caller_identity()["Account"]
        arn = f"arn:aws:sns:{AWS_REGION}:{account_id}:CloudSentinelAlerts"
        print(f"[sns] Topic ARN resolved → {arn}")
        return arn
    except Exception as ex:
        print(f"[sns] WARNING: STS failed — {ex}")
        return ""


SNS_TOPIC_ARN = get_sns_topic_arn()


# ══════════════════════════════════════════════════════════════
# ★ LAMBDA LOGIC — SITE CHECKER (now runs in-process)
# ══════════════════════════════════════════════════════════════

def _s3_snapshot_key(url: str, ts: str) -> str:
    """
    Build a deterministic S3 key from the site URL and timestamp.
    e.g. snapshots/www.flipkart.com/flipkart_20250714_0942.html
    """
    from urllib.parse import urlparse
    host    = urlparse(url).netloc.lstrip("www.")          # flipkart.com
    dt      = ts[:16].replace("-", "").replace("T", "_").replace(":", "")  # 20250714_0942
    slug    = host.split(".")[0]                           # flipkart
    return f"snapshots/{urlparse(url).netloc}/{slug}_{dt}.html"


def _upload_snapshot_to_s3(url: str, body: bytes, key: str) -> None:
    """
    ★ Upload the raw HTML body to the cloud-sentinel-snapshots S3 bucket.
    Called on every failed (non-200) check — provides forensic archive
    for diff, SLA reporting, and site recovery (Slide 7 of walkthrough).
    """
    try:
        from botocore.exceptions import ClientError as _BCE
        acct      = sts_client.get_caller_identity()["Account"]
        bucket    = "cloud-sentinel-snapshots"
        s3_client = boto3.client("s3", region_name=AWS_REGION)

        def _put():
            s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                ContentType="text/html",
                Metadata={"source-url": url},
            )

        try:
            _put()
        except _BCE as be:
            if be.response["Error"]["Code"] == "NoSuchBucket":
                # Bucket missing — create it then retry once
                print(f"[s3] Bucket {bucket} missing — creating before upload …")
                try:
                    if AWS_REGION == "us-east-1":
                        s3_client.create_bucket(Bucket=bucket)
                    else:
                        s3_client.create_bucket(
                            Bucket=bucket,
                            CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
                        )
                    s3_client.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls":       True,
                            "IgnorePublicAcls":      True,
                            "BlockPublicPolicy":     True,
                            "RestrictPublicBuckets": True,
                        },
                    )
                    _put()   # retry upload after creation
                except Exception as create_ex:
                    print(f"[s3] Could not create bucket or retry upload: {create_ex}")
                    return
            else:
                raise

        print(f"[s3] ✅ Snapshot saved → s3://{bucket}/{key}")
    except Exception as ex:
        print(f"[s3] WARNING: snapshot upload failed: {ex}")


def check_site(site: dict) -> dict:
    """
    Perform an HTTP GET on a monitored site and return a result dict
    ready to be written to DynamoDB.  Mirrors what the Lambda did.

    ★ On any non-200 / failed check the raw HTML body is uploaded to
      the cloud-sentinel-snapshots S3 bucket for forensic comparison
      (shown in Slide 7 of the output walkthrough).
    """
    url  = site["url"]
    ts   = datetime.utcnow().isoformat()
    body = b""
    try:
        req   = urllib.request.Request(
            url, headers={"User-Agent": "CloudSentinel/1.0"}
        )
        start = datetime.utcnow()
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed   = (datetime.utcnow() - start).total_seconds() * 1000
            body      = resp.read()
            status    = resp.status
            checksum  = hashlib.md5(body).hexdigest()
            expected  = site.get("expected_checksum")
            chk_match = (expected is None) or (checksum == expected)
    except Exception as exc:
        elapsed   = 0.0
        status    = 0
        checksum  = ""
        chk_match = False
        print(f"[monitor] ERROR fetching {url}: {exc}")

    # ★ Build S3 snapshot key for every check (stored in DynamoDB row)
    snap_key = _s3_snapshot_key(url, ts)

    # ★ Upload snapshot to S3 on EVERY check so the History page
    #   can always show a snapshot filename (Slide 4 shows filenames
    #   even for 200-OK rows like wikipedia/amazon).
    #   Only actually write to S3 if we have a body (status != 0).
    if body:
        _upload_snapshot_to_s3(url, body, snap_key)

    return {
        "SiteURL":          url,
        "Timestamp":        ts,
        "status_code":      status,
        "latency":          Decimal(str(round(elapsed, 2))),
        "checksum":         checksum,
        "checksum_match":   chk_match,
        "s3_snapshot_key":  snap_key,   # ★ stored in every DynamoDB row (Slide 8)
    }


def classify_severity(result: dict):
    """Return 'critical', 'warning', or None."""
    sc  = result["status_code"]
    chk = result["checksum_match"]
    if sc == 0 or sc >= 500:
        return "critical"
    if sc >= 400 or not chk:
        return "warning"
    return None


def _http_reason_label(code: int) -> str:
    """
    Human-readable reason for an HTTP status code.
    Matches the alert condition descriptions shown in Slide 6 of the walkthrough.
    """
    labels = {
        0:   "HTTP 0 · Connection refused / timeout",
        301: "HTTP 301 · Permanent redirect",
        302: "HTTP 302 · Temporary redirect",
        400: "HTTP 400 · Bad request",
        401: "HTTP 401 · Unauthorized",
        403: "HTTP 403 · Forbidden",
        404: "HTTP 404 · Resource not found",
        429: "HTTP 429 · Too many requests",
        500: "HTTP 500 · Internal Server Error",
        502: "HTTP 502 · Bad Gateway",
        503: "HTTP 503 · Service unavailable",
        504: "HTTP 504 · Gateway timeout",
    }
    if code in labels:
        return labels[code]
    if code >= 500:
        return f"HTTP {code} · Server-side failure"
    if code >= 400:
        return f"HTTP {code} · Client error"
    return f"HTTP {code}"


def build_alert_reasons(result: dict) -> str:
    """
    Build the reason string that appears in both the SNS email body
    and the alert card REASON tag (Slides 5 & 6 of walkthrough).
    """
    reasons = []
    if result["status_code"] != 200:
        reasons.append(_http_reason_label(result["status_code"]))
    if not result["checksum_match"]:
        reasons.append("Checksum mismatch · Content may have been tampered or changed")
    return " · ".join(reasons) if reasons else "Unknown"


def publish_single_alert(result: dict, severity: str) -> None:
    """
    ★ Publish an SNS alert for one check result immediately after detection.
    All confirmed subscribers on CloudSentinelAlerts receive the email.
    """
    if not SNS_TOPIC_ARN:
        print("[sns] SNS_TOPIC_ARN not resolved — skipping single alert.")
        return

    reasons  = build_alert_reasons(result)
    lat      = float(result.get("latency", 0))
    snap_key = result.get("s3_snapshot_key", "")
    # ── Email body exactly matching Slide 6 of the output walkthrough ──
    lines   = [
        "=" * 60,
        f"  CLOUD-SENTINEL — {severity.upper()} ALERT",
        f"  Region : {AWS_REGION}",
        f"  Time   : {result['Timestamp'][:19]} UTC",
        "=" * 60,
        "",
        f"  Site     : {result['SiteURL']}",
        f"  HTTP     : {result['status_code']}",
        f"  Latency  : {lat:.1f} ms",
        f"  Checksum : {'MATCH' if result['checksum_match'] else 'MISMATCH'}",
        f"  Reason   : {reasons}",
        "",
    ]
    if snap_key:
        lines += [
            f"  Snapshot : s3://cloud-sentinel-snapshots/{snap_key}",
            "             (HTML archive stored for forensic comparison & recovery)",
            "",
        ]
    lines += [
        "=" * 60,
        "  Cloud-Sentinel Monitoring System",
        "  This is an automated notification — do not reply.",
        "=" * 60,
    ]
    # Subject format: [Cloud-Sentinel] CRITICAL: flipkart.com — ap-south-2
    from urllib.parse import urlparse
    short_host = urlparse(result["SiteURL"]).netloc
    subject = (
        f"[Cloud-Sentinel] {severity.upper()}: "
        f"{short_host} — {AWS_REGION}"
    )
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message="\n".join(lines),
        )
        print(f"[sns] ✅ Alert sent for {result['SiteURL']} ({severity})")
    except Exception as ex:
        print(f"[sns] ERROR publishing single alert: {ex}")


def run_monitor_cycle() -> list:
    """
    ★ Core monitor logic (was the Lambda handler).
    Checks all MONITORED_SITES, writes each result to DynamoDB, and
    immediately publishes an SNS alert for any critical/warning result.
    Returns a list of result summaries.
    """
    print(f"[monitor] ── Starting check cycle {datetime.utcnow().isoformat()} ──")
    summaries = []

    for site in MONITORED_SITES:
        result   = check_site(site)
        severity = classify_severity(result)

        # Persist to DynamoDB
        try:
            logs_table.put_item(Item=result)
            print(
                f"[monitor] Saved  {result['SiteURL']:<38} "
                f"HTTP {result['status_code']}  "
                f"{float(result['latency']):.0f} ms"
            )
        except Exception as ex:
            print(f"[monitor] ERROR saving {result['SiteURL']}: {ex}")

        # ★ Fire SNS alert immediately on critical / warning
        if severity:
            publish_single_alert(result, severity)

        summaries.append({
            "url":      result["SiteURL"],
            "status":   result["status_code"],
            "latency":  float(result["latency"]),
            "severity": severity or "ok",
        })

    print(f"[monitor] ── Cycle complete — {len(summaries)} sites checked ──")
    return summaries


def _background_monitor():
    """
    Daemon thread: runs run_monitor_cycle() every MONITOR_INTERVAL_SEC seconds.
    Starts immediately so the first results appear in DynamoDB right away.
    """
    print(f"[monitor] Background monitor started (interval={MONITOR_INTERVAL_SEC}s)")
    while True:
        try:
            run_monitor_cycle()
        except Exception as ex:
            print(f"[monitor] Unhandled error in cycle: {ex}")
        time.sleep(MONITOR_INTERVAL_SEC)


# ★ Start background monitor thread once at app startup
_monitor_thread = threading.Thread(
    target=_background_monitor, daemon=True, name="cloud-sentinel-monitor"
)
_monitor_thread.start()


# ══════════════════════════════════════════════════════════════
# SEED DATA
# ══════════════════════════════════════════════════════════════
SEED_USERS = [
    {"UserId": "admin",    "password": "Admin@1234", "Role": "admin", "Status": "active", "NotificationEmails": []},
    {"UserId": "ops_user", "password": "Ops@5678",   "Role": "user",  "Status": "active", "NotificationEmails": []},
    {"UserId": "viewer",   "password": "View@9999",  "Role": "user",  "Status": "active", "NotificationEmails": []},
]


def seed_database(force=False):
    now = datetime.utcnow()

    if not force:
        try:
            logs_count = logs_table.scan(Select="COUNT").get("Count", 0)
            if logs_count > 0:
                print(f"[seed] Logs table has {logs_count} rows — skipping auto-seed.")
                return {"logs_inserted": 0, "users_inserted": 0, "skipped": True}
        except Exception as ex:
            print(f"[seed] Could not count logs: {ex}")
            return {"logs_inserted": 0, "users_inserted": 0, "skipped": True}

    print(f"[seed] Starting seed (force={force}) ...")

    FIXED_LOGS = [
        # ── amazon.com ──────────────────────────────────────────────────────────────────
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(minutes=5)).isoformat(),   "status_code":200,"latency":Decimal("245.5"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0942.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(minutes=10)).isoformat(),  "status_code":200,"latency":Decimal("312.8"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0937.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(minutes=15)).isoformat(),  "status_code":200,"latency":Decimal("198.4"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0932.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(minutes=20)).isoformat(),  "status_code":200,"latency":Decimal("421.0"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0927.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(minutes=25)).isoformat(),  "status_code":200,"latency":Decimal("289.7"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0922.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=3)).isoformat(),     "status_code":200,"latency":Decimal("432.1"), "checksum_match":False,"s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0622.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=6)).isoformat(),     "status_code":200,"latency":Decimal("389.4"), "checksum_match":False,"s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0342.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=7)).isoformat(),     "status_code":301,"latency":Decimal("145.6"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0242.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=8)).isoformat(),     "status_code":200,"latency":Decimal("267.3"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250714_0142.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=12)).isoformat(),    "status_code":200,"latency":Decimal("291.5"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250713_2142.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=22)).isoformat(),    "status_code":200,"latency":Decimal("4823.1"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250713_1142.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=24)).isoformat(),    "status_code":200,"latency":Decimal("334.0"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250713_0942.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=36)).isoformat(),    "status_code":200,"latency":Decimal("312.4"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250712_2142.html"},
        {"SiteURL":"https://www.amazon.com","Timestamp":(now-timedelta(hours=48)).isoformat(),    "status_code":200,"latency":Decimal("289.2"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.amazon.com/amazon_20250712_0942.html"},
        # ── flipkart.com ─────────────────────────────────────────────────────────────────
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(minutes=5)).isoformat(), "status_code":500,"latency":Decimal("1823.4"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250714_0942.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(minutes=30)).isoformat(),"status_code":500,"latency":Decimal("2104.7"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250714_0912.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=1)).isoformat(),   "status_code":500,"latency":Decimal("1756.2"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250714_0842.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=5)).isoformat(),   "status_code":503,"latency":Decimal("3241.0"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250714_0447.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=8)).isoformat(),   "status_code":200,"latency":Decimal("412.9"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250714_0142.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=14)).isoformat(),  "status_code":500,"latency":Decimal("1923.5"),"checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250713_1947.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=24)).isoformat(),  "status_code":200,"latency":Decimal("398.6"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250713_0942.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=36)).isoformat(),  "status_code":200,"latency":Decimal("423.7"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250712_2142.html"},
        {"SiteURL":"https://www.flipkart.com","Timestamp":(now-timedelta(hours=48)).isoformat(),  "status_code":200,"latency":Decimal("389.2"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.flipkart.com/flipkart_20250712_0942.html"},
        # ── github.com ───────────────────────────────────────────────────────────────────
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(minutes=5)).isoformat(),   "status_code":200,"latency":Decimal("334.9"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250714_0942.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(minutes=35)).isoformat(),  "status_code":404,"latency":Decimal("956.2"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250714_0907.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=2)).isoformat(),     "status_code":404,"latency":Decimal("812.5"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250714_0742.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=8)).isoformat(),     "status_code":200,"latency":Decimal("223.7"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250714_0142.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=18)).isoformat(),    "status_code":404,"latency":Decimal("876.3"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250713_1542.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=24)).isoformat(),    "status_code":200,"latency":Decimal("245.1"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250713_0942.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=36)).isoformat(),    "status_code":200,"latency":Decimal("214.3"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250712_2142.html"},
        {"SiteURL":"https://www.github.com","Timestamp":(now-timedelta(hours=48)).isoformat(),    "status_code":200,"latency":Decimal("267.5"), "checksum_match":True, "s3_snapshot_key":"snapshots/www.github.com/github_20250712_0942.html"},
        # ── stackoverflow.com ────────────────────────────────────────────────────────────
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(minutes=5)).isoformat(),  "status_code":0,  "latency":Decimal("0"),    "checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250714_0942.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(minutes=40)).isoformat(), "status_code":0,  "latency":Decimal("0"),    "checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250714_0902.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=4)).isoformat(),    "status_code":403,"latency":Decimal("678.9"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250714_0542.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=8)).isoformat(),    "status_code":200,"latency":Decimal("341.2"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250714_0142.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=20)).isoformat(),   "status_code":0,  "latency":Decimal("0"),    "checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250713_1342.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=24)).isoformat(),   "status_code":200,"latency":Decimal("367.8"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250713_0942.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=36)).isoformat(),   "status_code":200,"latency":Decimal("356.1"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250712_2142.html"},
        {"SiteURL":"https://www.stackoverflow.com","Timestamp":(now-timedelta(hours=48)).isoformat(),   "status_code":200,"latency":Decimal("298.4"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.stackoverflow.com/soflow_20250712_0942.html"},
        # ── wikipedia.org ────────────────────────────────────────────────────────────────
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(minutes=5)).isoformat(),  "status_code":200,"latency":Decimal("189.3"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250714_0942.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(minutes=10)).isoformat(), "status_code":200,"latency":Decimal("210.6"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250714_0937.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(minutes=15)).isoformat(), "status_code":200,"latency":Decimal("176.2"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250714_0932.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(hours=8)).isoformat(),    "status_code":200,"latency":Decimal("198.6"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250714_0142.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(hours=12)).isoformat(),   "status_code":200,"latency":Decimal("187.4"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250713_2142.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(hours=24)).isoformat(),   "status_code":200,"latency":Decimal("201.3"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250713_0942.html"},
        {"SiteURL":"https://www.wikipedia.org","Timestamp":(now-timedelta(hours=36)).isoformat(),   "status_code":200,"latency":Decimal("192.8"),"checksum_match":True,"s3_snapshot_key":"snapshots/www.wikipedia.org/wiki_20250712_2142.html"},
    ]

    logs_inserted = 0
    for item in FIXED_LOGS:
        try:
            logs_table.put_item(Item=item)
            logs_inserted += 1
            print(f"[seed] log {logs_inserted:02d} → {item['SiteURL']:<35} HTTP {item['status_code']}  {item['latency']}ms")
        except Exception as ex:
            print(f"[seed] ERROR inserting log: {ex}")

    print(f"[seed] ✅ {logs_inserted} logs inserted.")

    users_inserted = 0
    for u in SEED_USERS:
        try:
            created_at = datetime.utcnow().isoformat()
            users_table.put_item(Item={
                "UserId":             u["UserId"],
                "CreatedAt":          created_at,
                "PasswordHash":       generate_password_hash(u["password"]),
                "Role":               u["Role"],
                "Status":             u["Status"],
                "NotificationEmails": u["NotificationEmails"],
            })
            users_inserted += 1
            print(f"[seed] user → {u['UserId']:<12} pwd: {u['password']}")
        except Exception as ex:
            print(f"[seed] ERROR inserting user {u['UserId']}: {ex}")

    print(f"[seed] ✅ {users_inserted} users inserted.")
    return {"logs_inserted": logs_inserted, "users_inserted": users_inserted, "skipped": False}


def auto_seed_on_startup():
    print("[startup] Checking DynamoDB logs table ...")
    try:
        result = seed_database(force=False)
        if result["skipped"]:
            print("[startup] Logs already exist — skipping auto-seed.")
        else:
            print(f"[startup] ✅ Seeded {result['logs_inserted']} logs + {result['users_inserted']} users.")
    except Exception as ex:
        print(f"[startup] Seed error: {ex}")


auto_seed_on_startup()


# ══════════════════════════════════════════════════════════════
# DECORATORS
# ══════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(e):
    return bool(EMAIL_RE.match(e))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════
# DYNAMODB HELPERS
# ══════════════════════════════════════════════════════════════
def normalise_log(item):
    try:
        item["latency"] = float(item.get("latency", 0))
    except (TypeError, ValueError):
        item["latency"] = 0.0
    try:
        item["status_code"] = int(item.get("status_code", 0))
    except (TypeError, ValueError):
        item["status_code"] = 0
    # Ensure s3_snapshot_key always exists so templates can reference it safely
    item.setdefault("s3_snapshot_key", "")
    return item


def get_all_logs():
    """Scan CloudSentinelLogs, filter BASELINE rows, sort newest-first."""
    resp  = logs_table.scan(FilterExpression=Attr("Timestamp").ne("BASELINE"))
    items = list(resp.get("Items", []))
    while "LastEvaluatedKey" in resp:
        resp   = logs_table.scan(
            ExclusiveStartKey=resp["LastEvaluatedKey"],
            FilterExpression=Attr("Timestamp").ne("BASELINE"),
        )
        items += resp.get("Items", [])
    items = [normalise_log(i) for i in items]
    items.sort(key=lambda x: x.get("Timestamp", ""), reverse=True)
    return items


def find_user(username):
    resp  = users_table.scan(FilterExpression=Attr("UserId").eq(username))
    items = resp.get("Items", [])
    return items[0] if items else None


def save_notification_emails(username, created_at, emails):
    users_table.update_item(
        Key={"UserId": username, "CreatedAt": created_at},
        UpdateExpression="SET NotificationEmails = :e",
        ExpressionAttributeValues={":e": emails},
    )


# ══════════════════════════════════════════════════════════════
# SNS HELPERS
# ══════════════════════════════════════════════════════════════
def _sns_status_for_arn(sub_arn: str) -> str:
    if not sub_arn or "pending" in sub_arn.lower():
        return "pending"
    if not sub_arn.startswith("arn:aws:sns:"):
        return "pending"
    try:
        attrs = sns_client.get_subscription_attributes(
            SubscriptionArn=sub_arn
        )["Attributes"]
        if attrs.get("PendingConfirmation", "true").lower() == "false":
            return "confirmed"
        return "pending"
    except Exception as ex:
        print(f"[sns] get_subscription_attributes failed for {sub_arn}: {ex}")
        return "deleted"


def get_notification_emails(username):
    """
    Return the notification email list, auto-syncing status from SNS.
    When pending → confirmed, fires an alert digest automatically.
    """
    user = find_user(username)
    if not user:
        return []

    emails     = list(user.get("NotificationEmails", []))
    created_at = user.get("CreatedAt", "")

    if not emails:
        return []

    updated         = False
    synced          = []
    newly_confirmed = []

    for entry in emails:
        sub_arn     = entry.get("subscription_arn", "")
        old_status  = entry.get("status", "pending")
        real_status = _sns_status_for_arn(sub_arn)

        if real_status == "deleted":
            print(f"[sns] Dropping deleted subscription for {entry.get('email')}")
            updated = True
            continue

        if real_status != old_status:
            print(f"[sns] Status: {entry.get('email')} {old_status} → {real_status}")
            entry           = dict(entry)
            entry["status"] = real_status
            updated         = True
            if old_status == "pending" and real_status == "confirmed":
                newly_confirmed.append(entry.get("email"))

        synced.append(entry)

    if updated:
        try:
            save_notification_emails(username, created_at, synced)
        except Exception as ex:
            print(f"[sns] WARNING — could not persist status update: {ex}")

    if newly_confirmed:
        print(f"[sns] New confirmed subscribers: {newly_confirmed}")
        print(f"[sns] Running a fresh live check so the welcome alert reflects real-time status...")
        # ★ Run a full live check cycle in a background thread so the page
        #   doesn't block. This checks every site RIGHT NOW, writes fresh
        #   results to DynamoDB, and calls publish_single_alert() for every
        #   critical/warning it finds — the newly confirmed subscriber gets
        #   the email automatically because they are now on the SNS topic.
        t = threading.Thread(
            target=run_monitor_cycle,
            daemon=True,
            name="confirm-trigger-check",
        )
        t.start()

    return synced


# ══════════════════════════════════════════════════════════════
# BUSINESS LOGIC
# ══════════════════════════════════════════════════════════════
def derive_alerts(logs):
    """
    Build alert list from DynamoDB logs.
    Uses _http_reason_label() so alert card REASON text matches
    the SNS email body exactly (Slides 5 & 6 of walkthrough).
    """
    result = []
    for log in logs:
        status  = log.get("status_code", 0)
        chk     = log.get("checksum_match", True)
        reasons = []
        if status != 200:
            reasons.append(_http_reason_label(status))            # ★ rich label
        if not chk:
            reasons.append("Checksum mismatch · Content may have been tampered or changed")
        if reasons:
            entry = dict(log)
            entry["alert_reasons"] = " · ".join(reasons)
            entry["severity"] = (
                "critical" if (status >= 500 or status == 0) else
                "warning"  if (status >= 400 or not chk)    else
                "info"
            )
            result.append(entry)
    return result


def compute_kpis(logs):
    total = len(logs)
    if total == 0:
        return {"total": 0, "last_status": "N/A", "avg_latency": 0, "alert_count": 0}
    latencies = [l["latency"] for l in logs if l.get("latency")]
    avg_lat   = round(sum(latencies) / len(latencies), 2) if latencies else 0
    return {
        "total":       total,
        "last_status": logs[0].get("status_code", 0),
        "avg_latency": avg_lat,
        "alert_count": len(derive_alerts(logs)),
    }


# ══════════════════════════════════════════════════════════════
# ROUTES — AUTH
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user     = find_user(username)
        if not user or not check_password_hash(user["PasswordHash"], password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
        if user.get("Status") == "disabled":
            flash("Account disabled.", "danger")
            return redirect(url_for("login"))
        session["user_id"]    = user["UserId"]
        session["role"]       = user.get("Role", "user")
        session["created_at"] = user.get("CreatedAt", "")
        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Both fields are required.", "danger")
            return redirect(url_for("register"))
        if find_user(username):
            flash("Username already taken.", "warning")
            return redirect(url_for("register"))
        now = datetime.utcnow().isoformat()
        users_table.put_item(Item={
            "UserId":             username,
            "CreatedAt":          now,
            "PasswordHash":       generate_password_hash(password),
            "Role":               "user",
            "Status":             "active",
            "NotificationEmails": [],
        })
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════
# ROUTES — MAIN PAGES
# ══════════════════════════════════════════════════════════════
@app.route("/dashboard")
@login_required
def dashboard():
    logs   = get_all_logs()
    kpis   = compute_kpis(logs)
    recent = logs[:10]
    return render_template("dashboard.html", kpis=kpis, recent=recent)


@app.route("/history")
@login_required
def history():
    logs          = get_all_logs()
    search        = request.args.get("q", "").strip().lower()
    status_filter = request.args.get("status", "").strip()
    if search:
        logs = [l for l in logs if search in l.get("SiteURL", "").lower()]
    if status_filter:
        logs = [l for l in logs if str(l.get("status_code", "")) == status_filter]
    return render_template("history.html", logs=logs,
                           search=search, status_filter=status_filter)


@app.route("/alerts")
@login_required
def alerts():
    logs                = get_all_logs()
    alert_list          = derive_alerts(logs)
    notification_emails = get_notification_emails(session["user_id"])
    return render_template("alerts.html",
                           alerts=alert_list,
                           notification_emails=notification_emails)


# ══════════════════════════════════════════════════════════════
# ROUTES — EMAIL NOTIFICATIONS
# ══════════════════════════════════════════════════════════════
@app.route("/alerts/add-email", methods=["POST"])
@login_required
def add_notification_email():
    email      = request.form.get("email", "").strip().lower()
    username   = session["user_id"]
    created_at = session.get("created_at", "")

    if not SNS_TOPIC_ARN:
        flash("SNS Topic ARN not resolved — check IAM role.", "danger")
        return redirect(url_for("alerts"))
    if not valid_email(email):
        flash("Invalid email address.", "danger")
        return redirect(url_for("alerts"))

    existing = get_notification_emails(username)
    if any(e["email"] == email for e in existing):
        flash(f"{email} is already subscribed.", "warning")
        return redirect(url_for("alerts"))

    try:
        resp    = sns_client.subscribe(
            TopicArn=SNS_TOPIC_ARN, Protocol="email",
            Endpoint=email, ReturnSubscriptionArn=True,
        )
        sub_arn = resp.get("SubscriptionArn", "pending-confirmation")
    except Exception as ex:
        flash(f"SNS error: {ex}", "danger")
        return redirect(url_for("alerts"))

    existing.append({
        "email":            email,
        "subscription_arn": sub_arn,
        "status":           "pending",
        "added_at":         datetime.utcnow().isoformat(),
    })
    try:
        save_notification_emails(username, created_at, existing)
        flash(
            f"✔ Confirmation email sent to {email}. "
            "Click the AWS link in your inbox — alerts arrive automatically once confirmed.",
            "success",
        )
    except Exception as ex:
        flash(f"DB error: {ex}", "danger")
    return redirect(url_for("alerts"))


@app.route("/alerts/run-check", methods=["POST"])
@login_required
def run_check_now():
    """
    ★ Trigger an immediate monitor cycle on demand.
    Runs the full Lambda-equivalent check synchronously so results appear
    in DynamoDB before the page redirects.
    """
    summaries      = run_monitor_cycle()
    critical_count = sum(1 for s in summaries if s["severity"] == "critical")
    warning_count  = sum(1 for s in summaries if s["severity"] == "warning")
    flash(
        f"✔ Manual check complete — {len(summaries)} sites checked. "
        f"{critical_count} critical, {warning_count} warning.",
        "success" if critical_count == 0 else "danger",
    )
    return redirect(url_for("alerts"))


@app.route("/alerts/remove-email", methods=["POST"])
@login_required
def remove_notification_email():
    email      = request.form.get("email", "").strip().lower()
    username   = session["user_id"]
    created_at = session.get("created_at", "")
    existing   = get_notification_emails(username)
    target     = next((e for e in existing if e["email"] == email), None)

    if not target:
        flash("Email not found.", "warning")
        return redirect(url_for("alerts"))

    sub_arn = target.get("subscription_arn", "")
    is_confirmed_arn = (
        sub_arn
        and "pending" not in sub_arn.lower()
        and sub_arn.startswith("arn:aws:sns:")
    )

    if is_confirmed_arn:
        try:
            sns_client.unsubscribe(SubscriptionArn=sub_arn)
            print(f"[sns] Unsubscribed confirmed ARN: {sub_arn}")
        except Exception as ex:
            print(f"[sns] unsubscribe warning: {ex}")
            flash(f"SNS note (non-fatal): {ex}", "warning")
    else:
        print(f"[sns] Skipping SNS unsubscribe for pending ARN: {sub_arn!r}")

    updated = [e for e in existing if e["email"] != email]
    try:
        save_notification_emails(username, created_at, updated)
        flash(f"✔ {email} removed from notifications.", "success")
    except Exception as ex:
        flash(f"DB error: {ex}", "danger")
    return redirect(url_for("alerts"))


# ══════════════════════════════════════════════════════════════
# ROUTES — S3 SNAPSHOTS BROWSER  (Slide 7 of walkthrough)
# ══════════════════════════════════════════════════════════════
@app.route("/snapshots")
@login_required
def snapshots():
    """
    ★ List all HTML snapshots stored in the cloud-sentinel-snapshots S3 bucket.
    Shows per-site folders, file names, sizes and timestamps — exactly as
    described in Slide 7 of the output walkthrough (forensic archive).
    """
    import boto3 as _b3
    from botocore.exceptions import ClientError as _CE
    from collections import defaultdict

    def _ensure_bucket(s3_client, bucket_name):
        """Create the snapshot bucket if it does not exist. Returns (ok, err_msg)."""
        try:
            if AWS_REGION == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
                )
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls":       True,
                    "IgnorePublicAcls":      True,
                    "BlockPublicPolicy":     True,
                    "RestrictPublicBuckets": True,
                },
            )
            print(f"[s3] ✅ Bucket created: {bucket_name}")
            return True, None
        except _CE as ce:
            code = ce.response["Error"]["Code"]
            if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                return True, None
            msg = f"{code}: {ce.response['Error'].get('Message', str(ce))}"
            print(f"[s3] Could not create bucket: {msg}")
            return False, msg
        except Exception as ex:
            return False, str(ex)

    try:
        acct   = sts_client.get_caller_identity()["Account"]
        bucket = "cloud-sentinel-snapshots"
        s3     = _b3.client("s3", region_name=AWS_REGION)

        # ── List objects; if bucket is missing, create it then show empty state ──
        try:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix="snapshots/")
        except _CE as list_err:
            if list_err.response["Error"]["Code"] == "NoSuchBucket":
                print(f"[s3] Bucket {bucket} does not exist — creating …")
                ok, err_msg = _ensure_bucket(s3, bucket)
                if ok:
                    flash(
                        f"✅ S3 bucket '{bucket}' created successfully. "
                        "Snapshots will appear here after the next failed site check.",
                        "success",
                    )
                else:
                    flash(
                        f"❌ Could not create S3 bucket '{bucket}'. "
                        f"Reason: {err_msg}. "
                        "Fix: attach S3 permissions to your EC2 IAM role, "
                        "then run: python aws_setup.py",
                        "danger",
                    )
                return render_template("snapshots.html", groups={}, bucket=bucket, total=0)
            raise   # unexpected error — fall through to outer except

        raw = resp.get("Contents", [])

        # Group by site (second path segment: snapshots/<site>/<file>)
        groups = defaultdict(list)
        for obj in raw:
            parts = obj["Key"].split("/")
            site  = parts[1] if len(parts) > 1 else "unknown"
            groups[site].append({
                "key":           obj["Key"],
                "filename":      parts[-1],
                "size_kb":       round(obj["Size"] / 1024, 1),
                "last_modified": obj["LastModified"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            })

        return render_template(
            "snapshots.html",
            groups=dict(groups),
            bucket=bucket,
            total=len(raw),
        )
    except Exception as ex:
        flash(f"S3 error: {ex}", "danger")
        return render_template("snapshots.html", groups={}, bucket="", total=0)


@app.route("/snapshots/download")
@login_required
def snapshot_download():
    """Generate a pre-signed URL for a snapshot file so the admin can view it."""
    import boto3 as _b3
    key = request.args.get("key", "")
    if not key or not key.startswith("snapshots/"):
        flash("Invalid snapshot key.", "danger")
        return redirect(url_for("snapshots"))
    try:
        acct   = sts_client.get_caller_identity()["Account"]
        bucket = "cloud-sentinel-snapshots"
        s3     = _b3.client("s3", region_name=AWS_REGION)
        url    = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=300,   # 5-minute link
        )
        from flask import redirect as _redir
        return _redir(url)
    except Exception as ex:
        flash(f"Could not generate download link: {ex}", "danger")
        return redirect(url_for("snapshots"))


# ══════════════════════════════════════════════════════════════
# ROUTES — SETUP & SEED
# ══════════════════════════════════════════════════════════════
@app.route("/setup")
def setup():
    try:
        logs_count = logs_table.scan(Select="COUNT").get("Count", 0)
    except Exception as ex:
        return f"<h2>DynamoDB Error</h2><pre>{ex}</pre>", 500

    if logs_count > 0:
        flash(f"Tables already have {logs_count} log records. Log in below.", "info")
        return redirect(url_for("login"))

    try:
        result = seed_database(force=True)
        flash(
            f"Setup complete! {result['logs_inserted']} logs inserted. "
            "Login: admin / Admin@1234",
            "success",
        )
    except Exception as ex:
        return f"<h2>Seed Error</h2><pre>{ex}</pre>", 500

    return redirect(url_for("login"))


@app.route("/seed")
@login_required
@admin_required
def seed_route():
    result = seed_database(force=True)
    flash(
        f"Re-seeded: {result['logs_inserted']} logs + {result['users_inserted']} users.",
        "success",
    )
    return redirect(url_for("dashboard"))


@app.route("/seed/status")
@login_required
@admin_required
def seed_status():
    return jsonify({
        "CloudSentinelLogs":    logs_table.scan(Select="COUNT").get("Count", 0),
        "CloudSentinelUsers":   users_table.scan(Select="COUNT").get("Count", 0),
        "SNS_TOPIC_ARN":        SNS_TOPIC_ARN or "NOT RESOLVED",
        "monitor_interval_sec": MONITOR_INTERVAL_SEC,
        "monitored_sites":      [s["url"] for s in MONITORED_SITES],
        "status": "ok",
    })


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)