import os
import re
import sqlite3
import uuid
import math
import random
import secrets
import logging
from datetime import datetime
from dotenv import load_dotenv
from flask import (
    Flask, request, render_template, redirect, url_for,
    make_response, session, abort, flash
)
from flagsmith import Flagsmith
from flagsmith.exceptions import FlagsmithClientError

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security: Strong random secret key and hardened session cookies
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # Set to True when served over HTTPS in production
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "experiment.db")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Strict validation regex for visitor identifiers (Zero-PII)
USER_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Common consumer/free webmail domains for account tier classification
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "aol.com", "proton.me", "protonmail.com", "mail.com", "zoho.com",
    "live.com", "msn.com", "gmx.com", "yandex.com"
}

ALLOWED_JOB_ROLES = {
    "software_engineer", "engineering_lead", "devops_sre",
    "product_manager", "cto_founder", "other"
}

# CSRF Session Key
CSRF_SESSION_KEY = "_csrf_token"


def get_csrf_token():
    """Generate or retrieve a cryptographically secure session CSRF token."""
    if CSRF_SESSION_KEY not in session:
        session[CSRF_SESSION_KEY] = secrets.token_hex(24)
    return session[CSRF_SESSION_KEY]


def validate_csrf():
    """Validate incoming CSRF token against session."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get(CSRF_SESSION_KEY)
    if not token or not expected or not secrets.compare_digest(token, expected):
        logger.warning("CSRF validation failed for request")
        abort(400, description="Invalid or missing CSRF token. Please refresh and try again.")


@app.context_processor
def inject_csrf():
    """Make csrf_token helper callable in all Jinja templates."""
    return dict(csrf_token=get_csrf_token)


def sanitize_user_id(user_id):
    """Sanitize and validate visitor identifier matching ^[a-zA-Z0-9_-]{1,64}$."""
    if user_id and isinstance(user_id, str):
        trimmed = user_id.strip()
        if USER_ID_REGEX.match(trimmed):
            return trimmed
    # Fallback to cryptographically safe pseudorandom visitor id
    return f"vis_{secrets.token_hex(6)}"


def infer_account_tier(email=None, explicit_tier=None):
    """Infer account tier ('enterprise' vs 'self_serve') based on email domain or query override."""
    if explicit_tier in ("enterprise", "self_serve"):
        return explicit_tier
    if email and isinstance(email, str) and "@" in email:
        domain = email.split("@")[-1].lower().strip()
        if domain and domain not in FREE_EMAIL_DOMAINS:
            return "enterprise"
        return "self_serve"
    return "self_serve"


# Initialize Flagsmith client
FLAGSMITH_KEY = os.getenv("FLAGSMITH_ENVIRONMENT_KEY")
flagsmith_client = None

if FLAGSMITH_KEY:
    try:
        flagsmith_client = Flagsmith(
            environment_key=FLAGSMITH_KEY,
            enable_events=True,
            enable_analytics=True,
            request_timeout_seconds=4
        )
        logger.info("Flagsmith client initialized successfully.")
    except Exception as e:
        logger.warning("Flagsmith client initialization failed; safe fallback enabled.")
else:
    logger.warning("FLAGSMITH_ENVIRONMENT_KEY not set in .env")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS visitors (
                user_id TEXT PRIMARY KEY,
                variant TEXT NOT NULL,
                account_tier TEXT DEFAULT 'self_serve',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                converted INTEGER DEFAULT 0,
                converted_at TIMESTAMP,
                lead_qualified INTEGER DEFAULT 0,
                qualified_at TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                variant TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Backward compatibility schema migration
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(visitors);")
        columns = [row["name"] for row in cursor.fetchall()]
        if "account_tier" not in columns:
            cursor.execute("ALTER TABLE visitors ADD COLUMN account_tier TEXT DEFAULT 'self_serve';")
        if "lead_qualified" not in columns:
            cursor.execute("ALTER TABLE visitors ADD COLUMN lead_qualified INTEGER DEFAULT 0;")
        if "qualified_at" not in columns:
            cursor.execute("ALTER TABLE visitors ADD COLUMN qualified_at TIMESTAMP;")

        # Scrub any legacy PII from events table to enforce strict Zero-PII privacy
        cursor.execute("""
            UPDATE events 
            SET details = 'Telemetry event (PII scrubbed)'
            WHERE details LIKE '%@%' OR details LIKE '%Name:%';
        """)

        conn.commit()


# Initialize SQLite tables on startup
init_db()


@app.after_request
def set_security_headers(response):
    """Enforce strict security and privacy headers on every HTTP response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


def normal_cdf(x):
    """Cumulative distribution function for standard normal distribution."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def calculate_two_proportion_z_test(n_a, c_a, n_b, c_b):
    """Run two-proportion z-test comparing control (A) and treatment (B)."""
    if n_a > 0 and n_b > 0 and (c_a + c_b) > 0:
        p_a = c_a / n_a
        p_b = c_b / n_b
        p_pooled = (c_a + c_b) / (n_a + n_b)

        if 0 < p_pooled < 1:
            se = math.sqrt(p_pooled * (1.0 - p_pooled) * ((1.0 / n_a) + (1.0 / n_b)))
            if se > 0:
                z = (p_b - p_a) / se
                p_val = 2.0 * (1.0 - normal_cdf(abs(z)))
                p_val = max(0.0001, min(1.0, p_val))
                confidence = round((1.0 - p_val) * 100.0, 2)
                return round(z, 3), round(p_val, 4), confidence

    return 0.0, 1.0, 0.0


def calculate_ab_statistics():
    """Calculate conversion metrics, lead qualification rates, relative lift, and confidence."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT 
                variant,
                COUNT(user_id) AS visitors,
                SUM(converted) AS conversions,
                SUM(lead_qualified) AS qualified
            FROM visitors
            GROUP BY variant
        """).fetchall()

    stats = {
        "six_fields": {"visitors": 0, "conversions": 0, "cr": 0.0, "qualified": 0, "qr": 0.0},
        "three_fields": {"visitors": 0, "conversions": 0, "cr": 0.0, "qualified": 0, "qr": 0.0}
    }

    for row in rows:
        var = row["variant"]
        vis = row["visitors"] or 0
        conv = row["conversions"] or 0
        qual = row["qualified"] or 0
        cr = (conv / vis * 100.0) if vis > 0 else 0.0
        qr = (qual / vis * 100.0) if vis > 0 else 0.0
        stats[var] = {
            "visitors": vis,
            "conversions": conv,
            "cr": round(cr, 2),
            "qualified": qual,
            "qr": round(qr, 2)
        }

    control = stats["six_fields"]
    treatment = stats["three_fields"]

    total_visitors = control["visitors"] + treatment["visitors"]
    total_conversions = control["conversions"] + treatment["conversions"]
    total_qualified = control["qualified"] + treatment["qualified"]

    overall_cr = round((total_conversions / total_visitors * 100.0), 2) if total_visitors > 0 else 0.0
    overall_qr = round((total_qualified / total_visitors * 100.0), 2) if total_visitors > 0 else 0.0

    # 1. Signup Conversion Rate Relative Lift
    if control["cr"] > 0:
        cr_lift = round(((treatment["cr"] - control["cr"]) / control["cr"]) * 100.0, 2)
    elif treatment["cr"] > 0 and control["visitors"] > 0:
        cr_lift = 100.0
    else:
        cr_lift = 0.0

    # 2. Lead Qualification Rate Relative Lift
    if control["qr"] > 0:
        qr_lift = round(((treatment["qr"] - control["qr"]) / control["qr"]) * 100.0, 2)
    elif treatment["qr"] > 0 and control["visitors"] > 0:
        qr_lift = 100.0
    else:
        qr_lift = 0.0

    # 3. Two-proportion z-tests
    z_score, p_value, confidence = calculate_two_proportion_z_test(
        control["visitors"], control["conversions"],
        treatment["visitors"], treatment["conversions"]
    )

    qr_z_score, qr_p_value, qr_confidence = calculate_two_proportion_z_test(
        control["visitors"], control["qualified"],
        treatment["visitors"], treatment["qualified"]
    )

    # Status labels
    if confidence >= 95.0 and control["visitors"] >= 15 and treatment["visitors"] >= 15:
        significance_status = "Statistically Significant (p < 0.05)"
    elif confidence >= 90.0 and control["visitors"] >= 10 and treatment["visitors"] >= 10:
        significance_status = "Directionally Significant (p < 0.10)"
    else:
        significance_status = "Collecting Data (Not Significant Yet)"

    return {
        "control": control,
        "treatment": treatment,
        "total_visitors": total_visitors,
        "total_conversions": total_conversions,
        "total_qualified": total_qualified,
        "overall_cr": overall_cr,
        "overall_qr": overall_qr,
        "relative_lift": cr_lift,
        "qr_lift": qr_lift,
        "z_score": z_score,
        "p_value": p_value,
        "confidence": confidence,
        "qr_z_score": qr_z_score,
        "qr_p_value": qr_p_value,
        "qr_confidence": qr_confidence,
        "significance_status": significance_status
    }


@app.route("/")
def index():
    # 1. Determine sanitized user_id: query override > cookie > generated ID
    user_id_raw = request.args.get("user_id", "").strip() or request.cookies.get("visitor_id", "").strip()
    user_id = sanitize_user_id(user_id_raw)

    # 2. Determine non-PII account_tier trait
    email_raw = request.args.get("email", "").strip()[:150]
    explicit_tier = request.args.get("account_tier") or request.args.get("tier")
    account_tier = infer_account_tier(email_raw, explicit_tier)

    # 3. Query Flagsmith with sanitized visitor ID, non-PII traits, and safe fallback
    variant = "six_fields"
    flag_source = "FALLBACK (Offline Safe)"

    if flagsmith_client:
        try:
            # Zero-PII: Pass ONLY non-personal identity traits (never pass raw emails or names)
            traits = {"account_tier": account_tier}
            identity_flags = flagsmith_client.get_identity_flags(identifier=user_id, traits=traits)
            flag_val = identity_flags.get_feature_value("signup_form_type")
            if flag_val in ("six_fields", "three_fields"):
                variant = flag_val
                flag_source = "Flagsmith (Live API)"
            elif flag_val:
                variant = str(flag_val)
                flag_source = "Flagsmith (Live API)"
        except FlagsmithClientError:
            logger.warning("Flagsmith client error; safe default six_fields applied.")
            variant = "six_fields"
            flag_source = "FALLBACK (Offline Safe)"
        except Exception:
            logger.warning("Flagsmith request timed out or unavailable; safe default six_fields applied.")
            variant = "six_fields"
            flag_source = "FALLBACK (Offline Safe)"

    # 4. Log non-PII exposure in SQLite database
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO visitors (user_id, variant, account_tier, first_seen)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET 
                    variant = excluded.variant,
                    account_tier = excluded.account_tier;
            """, (user_id, variant, account_tier))

            # Non-PII operational telemetry only
            conn.execute("""
                INSERT INTO events (event_type, user_id, variant, details)
                VALUES (?, ?, ?, ?);
            """, ("exposure", user_id, variant, f"Tier: {account_tier}, Source: {flag_source}"))
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record exposure: {e}")

    # Ensure CSRF token is initialized for session
    get_csrf_token()

    # 5. Render template and set secure visitor_id cookie
    response = make_response(render_template(
        "index.html",
        user_id=user_id,
        variant=variant,
        flag_source=flag_source,
        account_tier=account_tier,
        email=email_raw
    ))
    response.set_cookie(
        "visitor_id",
        user_id,
        max_age=30 * 86400,
        httponly=True,
        samesite="Lax"
    )
    return response


@app.route("/signup", methods=["POST"])
def signup():
    # 1. CSRF Protection
    validate_csrf()

    # 2. Input sanitization and length limits
    user_id_raw = request.form.get("user_id") or request.cookies.get("visitor_id")
    user_id = sanitize_user_id(user_id_raw)

    variant = request.form.get("variant", "six_fields")
    if variant not in ("three_fields", "six_fields"):
        variant = "six_fields"

    full_name = request.form.get("full_name", "").strip()[:100]
    email = request.form.get("email", "").strip()[:150]
    company_name = request.form.get("company_name", "").strip()[:100]
    job_role = request.form.get("job_role", "").strip()[:50]
    if job_role and job_role not in ALLOWED_JOB_ROLES:
        job_role = "other"

    # Evaluate lead qualification without persisting raw PII
    is_enterprise_domain = False
    if email and "@" in email:
        domain = email.split("@")[-1].lower().strip()
        if domain and domain not in FREE_EMAIL_DOMAINS:
            is_enterprise_domain = True

    lead_qualified = bool((company_name and job_role) or is_enterprise_domain)

    # 3. Track Primary Flagsmith Conversion: "signup_completed" (Zero-PII)
    flagsmith_signup_tracked = False
    flagsmith_lead_tracked = False

    if flagsmith_client:
        try:
            flagsmith_client.track_event(event="signup_completed", identifier=user_id)
            flagsmith_signup_tracked = True
        except Exception:
            logger.warning("Failed to track 'signup_completed' in Flagsmith; continuing safely.")

        # 4. Track Secondary Guardrail Metric: "lead_qualified" (Zero-PII)
        if lead_qualified:
            try:
                flagsmith_client.track_event(event="lead_qualified", identifier=user_id)
                flagsmith_lead_tracked = True
            except Exception:
                logger.warning("Failed to track 'lead_qualified' in Flagsmith; continuing safely.")

    # 5. Record conversion and lead qualification in SQLite (Zero-PII: No passwords, names, emails, or phones)
    try:
        with get_db() as conn:
            conn.execute("""
                UPDATE visitors
                SET converted = 1,
                    converted_at = CURRENT_TIMESTAMP,
                    lead_qualified = ?,
                    qualified_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE qualified_at END
                WHERE user_id = ?;
            """, (1 if lead_qualified else 0, 1 if lead_qualified else 0, user_id))

            # Non-PII event logging: strictly categorical metadata
            conn.execute("""
                INSERT INTO events (event_type, user_id, variant, details)
                VALUES (?, ?, ?, ?);
            """, ("signup_completed", user_id, variant, f"LeadQualified: {lead_qualified}, FlagsmithTracked: {flagsmith_signup_tracked}"))

            if lead_qualified:
                conn.execute("""
                    INSERT INTO events (event_type, user_id, variant, details)
                    VALUES (?, ?, ?, ?);
                """, ("lead_qualified", user_id, variant, f"RoleCategory: {job_role or 'unspecified'}, EnterpriseDomain: {is_enterprise_domain}"))

            conn.commit()
    except Exception as e:
        logger.error(f"Failed to record conversion in DB: {e}")

    flash(f"Welcome aboard, {full_name or 'Friend'}! Your signup was completed successfully.", "success")
    return render_template(
        "success.html",
        user_id=user_id,
        variant=variant,
        full_name=full_name,
        email=email,
        lead_qualified=lead_qualified,
        flagsmith_tracked=flagsmith_signup_tracked
    )


@app.route("/stats")
def stats():
    data = calculate_ab_statistics()
    get_csrf_token()  # Ensure CSRF token is available for simulation/reset forms

    with get_db() as conn:
        recent_events = conn.execute("""
            SELECT id, event_type, user_id, variant, details, created_at
            FROM events
            ORDER BY id DESC
            LIMIT 30;
        """).fetchall()

    return render_template(
        "stats.html",
        data=data,
        recent_events=recent_events,
        env_key_set=bool(FLAGSMITH_KEY)
    )


@app.route("/api/simulate", methods=["POST"])
def simulate_traffic():
    """Helper to simulate realistic SaaS visitor traffic highlighting conversion vs lead qualification trade-off."""
    validate_csrf()
    count = int(request.form.get("count", 60))
    count = max(1, min(count, 200))  # Bound between 1 and 200

    sample_roles = ["CTO", "VP Engineering", "DevOps Lead", "Staff Engineer", "Product Manager"]

    with get_db() as conn:
        for i in range(count):
            uid = f"sim_{secrets.token_hex(4)}"
            var = "three_fields" if (i % 2 == 0) else "six_fields"
            is_enterprise = (random.random() < 0.40)
            account_tier = "enterprise" if is_enterprise else "self_serve"

            # Realistic SaaS trade-off:
            # 3-fields has higher signup volume (~31%), but lower qualification (~35% of signups)
            # 6-fields has lower signup volume (~22%), but higher qualification (~75% of signups)
            if var == "three_fields":
                converted = 1 if (random.random() < 0.31) else 0
                lead_qualified = 1 if (converted and random.random() < 0.35) else 0
            else:
                converted = 1 if (random.random() < 0.22) else 0
                lead_qualified = 1 if (converted and random.random() < 0.75) else 0

            conn.execute("""
                INSERT INTO visitors (user_id, variant, account_tier, converted, lead_qualified, first_seen, converted_at, qualified_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?);
            """, (
                uid, var, account_tier, converted, lead_qualified,
                datetime.utcnow() if converted else None,
                datetime.utcnow() if lead_qualified else None
            ))

            # Zero-PII event logging: no simulated personal emails or names stored
            conn.execute("""
                INSERT INTO events (event_type, user_id, variant, details)
                VALUES (?, ?, ?, ?);
            """, ("exposure", uid, var, f"Simulated traffic (Tier: {account_tier})"))

            if converted:
                conn.execute("""
                    INSERT INTO events (event_type, user_id, variant, details)
                    VALUES (?, ?, ?, ?);
                """, ("signup_completed", uid, var, f"Simulated conversion (Tier: {account_tier})"))

            if lead_qualified:
                role = random.choice(sample_roles)
                conn.execute("""
                    INSERT INTO events (event_type, user_id, variant, details)
                    VALUES (?, ?, ?, ?);
                """, ("lead_qualified", uid, var, f"Simulated qualified lead (RoleCategory: {role})"))

        conn.commit()

    flash(f"Simulated {count} realistic visitors successfully!", "info")
    return redirect(url_for("stats"))


@app.route("/api/reset", methods=["POST"])
def reset_db():
    """Reset the experiment database for clean demo runs."""
    validate_csrf()
    with get_db() as conn:
        conn.execute("DELETE FROM events;")
        conn.execute("DELETE FROM visitors;")
        conn.commit()
    flash("Experiment database reset successfully. Ready for a clean demo run!", "warning")
    return redirect(url_for("stats"))


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "t")
    logger.info(f"Starting Toggle Wars App on http://127.0.0.1:{port} (debug={debug_mode})")
    app.run(host="127.0.0.1", port=port, debug=debug_mode)
