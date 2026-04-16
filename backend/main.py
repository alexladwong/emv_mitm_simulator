from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import sqlite3
from typing import Any
import urllib.error
import urllib.request
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from crypto_engine import RSACrypto
from emv_engine import EMVTransaction
from mitm_engine import MITMAttack
from risk_engine import RiskEngine


BASE_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = BASE_DIR / "frontend"
DATA_FILE = BASE_DIR / "data" / "transactions.json"
DB_FILE = BASE_DIR / "data" / "simulator.db"


def _load_env_file() -> None:
    env_file = BASE_DIR / ".env"
    if not env_file.exists():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_env_file()

ADMIN_EMAIL = "admin@ladwongdevelopers.dev"
ADMIN_PASSWORD = "Admin@123"
ADMIN_PHONE = "+256752213955"
SESSION_HOURS = 12
LOGIN_CODE_SECONDS = int(os.getenv("LOGIN_CODE_SECONDS", "30"))
SMS_API_URL = os.getenv("SMS_API_URL", "https://yoolasms.com/api/v1/send").strip()
SMS_API_KEY = os.getenv("SMS_API_KEY", "").strip()
SMS_TO_NUMBER = os.getenv("SMS_TO_NUMBER", "").strip()
SMS_SENDER = os.getenv("SMS_SENDER", "EMVLAB").strip() or "EMVLAB"
SMS_DEBUG_FALLBACK = os.getenv("SMS_DEBUG_FALLBACK", "true").strip().lower() in {"1", "true", "yes", "on"}


class TransactionRequest(BaseModel):
    amount: int = Field(default=10000, ge=1)
    attack_enabled: bool = False


class AttackControl(BaseModel):
    enabled: bool = False


class LoginRequest(BaseModel):
    email: str
    password: str


class TwoFactorVerifyRequest(BaseModel):
    challenge_id: str
    code: str = Field(min_length=4, max_length=8)


class PasswordUpdateRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


app = FastAPI(
    title="EMV MITM Simulator",
    description="Contactless Payment Security Research",
    version="2.0.0",
)

emv = EMVTransaction()
mitm = MITMAttack()
crypto = RSACrypto()
risk = RiskEngine()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _mask_phone_number(number: str) -> str:
    if not number:
        return "configured phone"
    digits = "".join(char for char in number if char.isdigit())
    if len(digits) <= 4:
        return f"***{digits}"
    return f"+***{digits[-4:]}"


def _issue_token(email: str) -> dict[str, str]:
    token = uuid4().hex
    expires_at = (_utcnow() + timedelta(hours=SESSION_HOURS)).isoformat()
    with _get_connection() as connection:
        connection.execute(
            "INSERT INTO sessions (token, email, expires_at) VALUES (?, ?, ?)",
            (token, email, expires_at),
        )
        connection.commit()
    return {"token": token, "expires_at": expires_at}


def _issue_login_challenge(email: str) -> dict[str, str]:
    challenge_id = uuid4().hex
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = (_utcnow() + timedelta(seconds=LOGIN_CODE_SECONDS)).isoformat()
    with _get_connection() as connection:
        connection.execute("DELETE FROM login_challenges WHERE expires_at <= ?", (_utcnow().isoformat(),))
        connection.execute(
            """
            INSERT INTO login_challenges (challenge_id, email, code_hash, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (challenge_id, email, _hash_password(code), expires_at),
        )
        connection.commit()
    return {"challenge_id": challenge_id, "code": code, "expires_at": expires_at}


def _send_sms_code(email: str, code: str) -> dict[str, str]:
    message = f"Your EMV simulator admin code is {code}. It expires in {LOGIN_CODE_SECONDS} seconds."
    sms_api_url = _get_setting("SMS_API_URL", SMS_API_URL)
    sms_api_key = _get_setting("SMS_API_KEY", SMS_API_KEY)
    recipient_number = _get_user_phone_number(email) or _get_setting("SMS_TO_NUMBER", SMS_TO_NUMBER)
    sender_name = _get_setting("SMS_SENDER", SMS_SENDER) or SMS_SENDER

    def _debug_delivery(reason: str) -> dict[str, str]:
        print(f"[EMV 2FA DEBUG] {email} verification code: {code}")
        _write_audit_log(
            "2fa_sms",
            email,
            "debug",
            f"{reason}. Debug fallback active for {_mask_phone_number(recipient_number or '+0000')}",
        )
        return {"channel": "debug", "destination": "server console"}

    if sms_api_url and sms_api_key and recipient_number:
        request_body = {
            "phone": recipient_number,
            "message": message,
            "api_key": sms_api_key,
        }
        if sender_name:
            request_body["sender"] = sender_name

        payload = json.dumps(request_body).encode("utf-8")
        request = urllib.request.Request(
            sms_api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            _write_audit_log("2fa_sms", email, "failed", f"SMS delivery failed: {error}")
            if SMS_DEBUG_FALLBACK:
                return _debug_delivery("SMS provider timed out or failed")
            raise HTTPException(status_code=502, detail="Failed to send SMS verification code") from error

        _write_audit_log("2fa_sms", email, "success", f"Verification code sent to {_mask_phone_number(recipient_number)}")
        return {"channel": "sms", "destination": _mask_phone_number(recipient_number)}

    if SMS_DEBUG_FALLBACK:
        return _debug_delivery("SMS provider not configured")

    _write_audit_log("2fa_sms", email, "failed", "SMS provider not configured")
    raise HTTPException(status_code=500, detail="SMS 2FA is not configured. Add SMS_API_KEY and provider settings in .env")


def _verify_login_challenge(payload: TwoFactorVerifyRequest) -> dict[str, str]:
    with _get_connection() as connection:
        challenge = connection.execute(
            """
            SELECT challenge_id, email, code_hash, expires_at, attempts
            FROM login_challenges
            WHERE challenge_id = ?
            """,
            (payload.challenge_id,),
        ).fetchone()

        if not challenge:
            raise HTTPException(status_code=401, detail="Verification session not found")

        if datetime.fromisoformat(challenge["expires_at"]) <= _utcnow():
            connection.execute("DELETE FROM login_challenges WHERE challenge_id = ?", (payload.challenge_id,))
            connection.commit()
            raise HTTPException(status_code=401, detail="Verification code expired")

        submitted_hash = _hash_password(payload.code)
        if not secrets.compare_digest(submitted_hash, challenge["code_hash"]):
            attempts = int(challenge["attempts"]) + 1
            connection.execute(
                "UPDATE login_challenges SET attempts = ? WHERE challenge_id = ?",
                (attempts, payload.challenge_id),
            )
            if attempts >= 5:
                connection.execute("DELETE FROM login_challenges WHERE challenge_id = ?", (payload.challenge_id,))
            connection.commit()
            raise HTTPException(status_code=401, detail="Invalid verification code")

        connection.execute("DELETE FROM login_challenges WHERE challenge_id = ?", (payload.challenge_id,))
        connection.commit()
        return {"email": challenge["email"]}


def _get_token_from_header(authorization: str | None) -> str | None:
    if not authorization:
        return None
    prefix = "Bearer "
    return authorization[len(prefix):] if authorization.startswith(prefix) else None


def _write_audit_log(action: str, email: str | None, status: str, detail: str) -> None:
    with _get_connection() as connection:
        connection.execute(
            "INSERT INTO audit_logs (action, email, status, detail) VALUES (?, ?, ?, ?)",
            (action, email, status, detail),
        )
        connection.commit()


def _require_auth(authorization: str | None) -> dict[str, Any]:
    token = _get_token_from_header(authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    with _get_connection() as connection:
        session = connection.execute(
            "SELECT token, email, expires_at FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=401, detail="Authentication required")
        expires_at = datetime.fromisoformat(session["expires_at"])
        if expires_at <= _utcnow():
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            connection.commit()
            raise HTTPException(status_code=401, detail="Session expired")
    return {"token": session["token"], "email": session["email"], "expires_at": session["expires_at"]}


def _get_connection() -> sqlite3.Connection:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _get_user_phone_number(email: str) -> str:
    with _get_connection() as connection:
        user = connection.execute("SELECT phone_number FROM users WHERE email = ?", (email,)).fetchone()
    return (user["phone_number"] if user and user["phone_number"] else "").strip()


def _get_setting(key: str, fallback: str = "") -> str:
    with _get_connection() as connection:
        row = connection.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if row and row["value"] is not None:
        return str(row["value"]).strip()
    return fallback


def _init_db() -> None:
    with _get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_type TEXT NOT NULL,
                attack_active INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                is_attack_detected INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                cvm TEXT NOT NULL,
                actual_verification INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                phone_number TEXT,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                email TEXT,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS login_challenges (
                challenge_id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        _ensure_column(connection, "users", "phone_number", "TEXT")
        connection.commit()


def _seed_admin_user() -> None:
    with _get_connection() as connection:
        connection.execute(
            """
            INSERT INTO users (email, password_hash, phone_number, role)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                password_hash = excluded.password_hash,
                phone_number = excluded.phone_number,
                role = excluded.role
            """,
            (ADMIN_EMAIL, _hash_password(ADMIN_PASSWORD), ADMIN_PHONE, "admin"),
        )
        connection.commit()


def _read_json_seed() -> list[dict[str, Any]]:
    if not DATA_FILE.exists():
        return []
    with DATA_FILE.open("r", encoding="utf-8") as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError:
            return []
    return payload if isinstance(payload, list) else []


def _migrate_json_logs() -> None:
    records = _read_json_seed()
    if not records:
        return

    with _get_connection() as connection:
        existing = connection.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        if existing:
            return

        for entry in records:
            _insert_transaction(connection, entry)
        connection.commit()


def _insert_transaction(connection: sqlite3.Connection, entry: dict[str, Any]) -> None:
    normalized = _normalize_entry(entry)
    transaction_data = normalized.get("transaction_data", {})
    risk_analysis = normalized.get("risk_analysis", {})
    connection.execute(
        """
        INSERT INTO transactions (
            transaction_type,
            attack_active,
            risk_score,
            risk_level,
            is_attack_detected,
            amount,
            cvm,
            actual_verification,
            payload_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            normalized.get("transaction_type", "UNKNOWN"),
            int(bool(normalized.get("attack_active", False))),
            int(risk_analysis.get("risk_score", 0)),
            risk_analysis.get("risk_level", "UNKNOWN"),
            int(bool(risk_analysis.get("is_attack_detected", False))),
            int(transaction_data.get("amount", 0)),
            transaction_data.get("cvm", "UNKNOWN"),
            int(bool(transaction_data.get("actual_verification", False))),
            json.dumps(normalized),
        ),
    )


def _normalize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    if "risk_analysis" in entry and "transaction_data" in entry:
        return entry

    legacy_risk = entry.get("risk", {})
    tampered = bool(entry.get("tampered")) or entry.get("mitm_scenario") not in (None, "", "none")
    findings = legacy_risk.get("findings", [])
    verdict = legacy_risk.get("verdict", "review")
    risk_level_map = {
        "blocked": "CRITICAL",
        "review": "HIGH",
        "clear": "LOW",
    }

    transaction_data = {
        "amount": int(entry.get("amount", 0)),
        "cvm": "NO_VERIFICATION" if tampered else "PIN_VERIFIED",
        "device_verified": True,
        "actual_verification": not tampered,
        "attacker_modified": tampered,
    }

    risk_analysis = {
        "risk_score": int(legacy_risk.get("risk_score", 0)),
        "risk_level": risk_level_map.get(verdict, "HIGH"),
        "risks": [{"rule": "Legacy Import", "score": int(legacy_risk.get("risk_score", 0)), "message": msg} for msg in findings],
        "recommendation": "Imported from legacy simulator record",
        "is_attack_detected": tampered or verdict == "blocked",
    }

    return {
        "transaction_type": "MITM ATTACK" if tampered else "NORMAL",
        "steps": entry.get("steps", []),
        "risk_analysis": risk_analysis,
        "attack_active": tampered,
        "transaction_data": transaction_data,
        "legacy_import": True,
        "raw_legacy": entry,
    }


def _append_log(entry: dict[str, Any]) -> None:
    with _get_connection() as connection:
        _insert_transaction(connection, entry)
        connection.commit()
    _write_audit_log(
        "transaction_recorded",
        None,
        "success",
        f"{entry.get('transaction_type', 'UNKNOWN')} stored with risk {entry.get('risk_analysis', {}).get('risk_level', 'UNKNOWN')}",
    )


def _read_logs(limit: int = 100) -> list[dict[str, Any]]:
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT payload_json
            FROM transactions
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_normalize_entry(json.loads(row["payload_json"])) for row in rows]


def _read_metrics() -> dict[str, Any]:
    with _get_connection() as connection:
        totals = connection.execute(
            """
            SELECT
                COUNT(*) AS total_runs,
                COALESCE(SUM(attack_active), 0) AS attack_runs,
                COALESCE(SUM(is_attack_detected), 0) AS detections,
                COALESCE(ROUND(AVG(risk_score), 1), 0) AS average_risk
            FROM transactions
            """
        ).fetchone()
        latest = connection.execute(
            """
            SELECT transaction_type, risk_level, amount, created_at
            FROM transactions
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        active_sessions = connection.execute(
            "SELECT COUNT(*) AS total FROM sessions WHERE expires_at > ?",
            (_utcnow().isoformat(),),
        ).fetchone()
        audit_totals = connection.execute(
            "SELECT COUNT(*) AS total FROM audit_logs"
        ).fetchone()

    return {
        "total_runs": int(totals["total_runs"]),
        "attack_runs": int(totals["attack_runs"]),
        "detections": int(totals["detections"]),
        "average_risk": float(totals["average_risk"]),
        "active_sessions": int(active_sessions["total"]),
        "audit_events": int(audit_totals["total"]),
        "latest_run": dict(latest) if latest else None,
        "database": {
            "engine": "sqlite",
            "path": str(DB_FILE),
        },
    }


def _count_transactions() -> int:
    with _get_connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM transactions").fetchone()
    return int(row["total"])


def _count_audit_logs() -> int:
    with _get_connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM audit_logs").fetchone()
    return int(row["total"])


def _read_audit_logs(limit: int = 25, offset: int = 0) -> list[dict[str, Any]]:
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, action, email, status, detail, created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


@app.on_event("startup")
async def startup() -> None:
    _init_db()
    _seed_admin_user()
    _migrate_json_logs()


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "EMV MITM Simulator API", "status": "running"}


@app.get("/dashboard")
async def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/transactions")
async def transactions(
    authorization: str | None = Header(default=None),
    limit: int = Query(default=100, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    _require_auth(authorization)
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT payload_json
            FROM transactions
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [_normalize_entry(json.loads(row["payload_json"])) for row in rows]


@app.get("/api/transactions/meta")
async def transactions_meta(authorization: str | None = Header(default=None)) -> dict[str, int]:
    _require_auth(authorization)
    return {"total": _count_transactions()}


@app.get("/api/metrics")
async def metrics(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return _read_metrics()


@app.get("/api/audit")
async def audit_logs(
    authorization: str | None = Header(default=None),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    _require_auth(authorization)
    return _read_audit_logs(limit, offset)


@app.get("/api/audit/meta")
async def audit_logs_meta(authorization: str | None = Header(default=None)) -> dict[str, int]:
    _require_auth(authorization)
    return {"total": _count_audit_logs()}


@app.post("/api/auth/login")
async def login(payload: LoginRequest) -> dict[str, Any]:
    with _get_connection() as connection:
        user = connection.execute(
            "SELECT email, password_hash, role FROM users WHERE email = ?",
            (payload.email,),
        ).fetchone()

    if not user or not (
        secrets.compare_digest(payload.email, user["email"])
        and secrets.compare_digest(_hash_password(payload.password), user["password_hash"])
    ):
        _write_audit_log("login", payload.email, "failed", "Invalid login attempt")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    challenge = _issue_login_challenge(payload.email)
    delivery = _send_sms_code(payload.email, challenge["code"])
    _write_audit_log("login_password", payload.email, "success", "Password accepted, awaiting SMS verification")
    return {
        "requires_2fa": True,
        "challenge_id": challenge["challenge_id"],
        "expires_at": challenge["expires_at"],
        "delivery": delivery,
        "user": {
            "email": payload.email,
            "role": user["role"],
        },
    }


@app.post("/api/auth/verify-2fa")
async def verify_two_factor(payload: TwoFactorVerifyRequest) -> dict[str, Any]:
    verified = _verify_login_challenge(payload)
    session = _issue_token(verified["email"])
    _write_audit_log("login", verified["email"], "success", "Admin session started after SMS verification")
    return {
        "token": session["token"],
        "expires_at": session["expires_at"],
        "user": {
            "email": verified["email"],
            "role": "admin",
        },
    }


@app.post("/api/auth/logout")
async def logout(authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = _get_token_from_header(authorization)
    if token:
        with _get_connection() as connection:
            session = connection.execute(
                "SELECT email FROM sessions WHERE token = ?",
                (token,),
            ).fetchone()
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
            connection.commit()
        if session:
            _write_audit_log("logout", session["email"], "success", "Admin session terminated")
    return {"status": "logged_out"}


@app.get("/api/auth/me")
async def auth_me(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    session = _require_auth(authorization)
    return {
        "email": session["email"],
        "role": "admin",
        "expires_at": session["expires_at"],
    }


@app.post("/api/auth/change-password")
async def change_password(
    payload: PasswordUpdateRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    session = _require_auth(authorization)
    current_hash = _hash_password(payload.current_password)
    with _get_connection() as connection:
        user = connection.execute(
            "SELECT password_hash FROM users WHERE email = ?",
            (session["email"],),
        ).fetchone()
        if not user or not secrets.compare_digest(current_hash, user["password_hash"]):
            _write_audit_log("password_change", session["email"], "failed", "Current password mismatch")
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE email = ?",
            (_hash_password(payload.new_password), session["email"]),
        )
        connection.commit()
    _write_audit_log("password_change", session["email"], "success", "Admin password updated")
    return {"status": "password_updated"}


@app.post("/api/transaction/normal")
async def normal_transaction(
    request: TransactionRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(authorization)
    mitm.deactivate()
    steps = emv.normal_transaction(request.amount)
    transaction_data = emv.to_analysis_payload(steps, request.amount, attacker_modified=False)
    risk_analysis = risk.analyze(transaction_data)

    response = {
        "transaction_type": "NORMAL",
        "steps": steps,
        "risk_analysis": risk_analysis,
        "attack_active": False,
        "transaction_data": transaction_data,
    }
    _append_log(response)
    return response


@app.post("/api/transaction/attack")
async def attack_transaction(
    request: TransactionRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(authorization)
    mitm.activate()
    steps = emv.attack_transaction(request.amount)
    attack_response = {
        "cvm": steps[2].get("cvm"),
        "device_verified": steps[2].get("device_verified"),
        "actual_verification": False,
        "amount": request.amount,
    }
    modified = mitm.modify_card_response(attack_response)
    transaction_data = emv.to_analysis_payload(steps, request.amount, attacker_modified=True)
    transaction_data.update(modified)
    risk_analysis = risk.analyze(transaction_data)

    response = {
        "transaction_type": "MITM ATTACK",
        "steps": steps,
        "risk_analysis": risk_analysis,
        "attack_log": mitm.get_attack_log(),
        "attack_active": True,
        "transaction_data": transaction_data,
    }
    _append_log(response)
    return response


@app.post("/api/mitm/control")
async def control_mitm(
    control: AttackControl,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(authorization)
    return mitm.activate() if control.enabled else mitm.deactivate()


@app.get("/api/mitm/status")
async def mitm_status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return mitm.get_attack_log()


@app.get("/api/crypto/demo")
async def crypto_demo(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return crypto.demonstrate_attack()


@app.get("/api/crypto/vulnerability")
async def crypto_vulnerability(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return crypto.demonstrate_emv_vulnerability()


@app.get("/api/risks/defenses")
async def get_defenses(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return risk.get_defense_recommendations()


@app.get("/api/the-three-lies")
async def three_lies(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(authorization)
    return {
        "title": "The Three Lies of EMV MITM Attack",
        "lies": [
            {
                "name": "Lie #1",
                "claim": "This is a real card",
                "reality": "Attacker relays communication from a real card, but can modify data.",
                "mitigation": "Cryptographic binding of transaction context",
            },
            {
                "name": "Lie #2",
                "claim": "This device verified the user",
                "reality": "No verification actually occurred. The attacker modified CVM data.",
                "mitigation": "Device attestation and mandatory CVM enforcement",
            },
            {
                "name": "Lie #3",
                "claim": "This is a trusted transaction",
                "reality": "The bank trusts manipulated data and approves a fraudulent flow.",
                "mitigation": "End-to-end verification and anomaly detection",
            },
        ],
        "root_cause": "The EMV trust model assumes honest card behavior and accurate verification reporting.",
    }


app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
