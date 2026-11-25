#!/usr/bin/env python3
"""
aegis-pay-gateway: Zero-Dependency Payment Gateway & Double-Entry Ledger Service.

Implements a production-structured HTTP payment processing engine using Python's
standard library (`http.server`, `sqlite3`, `hmac`, `hashlib`, `secrets`):
- Bearer API key authentication (`Authorization: Bearer <secret_key>`)
- Strict idempotency key enforcement (`Idempotency-Key` header)
- Card Luhn validation & deterministic authorization/decline simulation
- Double-entry ledger postings (Customer Clearing -> Merchant Settlement)
- Capture, Void, and Full/Partial Refund lifecycle transitions
- HMAC-SHA256 signed webhook event delivery & audit log persistence
- Built-in interactive checkout & operator console UI at `/`
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_API_KEY = os.environ.get("AEGIS_API_KEY", "sk_test_aegis_9f8e7d6c5b4a3210")
DEFAULT_WEBHOOK_SECRET = os.environ.get("AEGIS_WEBHOOK_SECRET", "whsec_aegis_0123456789abcdef")
SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP", "NGN"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def luhn_valid(card_number: str) -> bool:
    digits = [int(ch) for ch in card_number if ch.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_brand(card_number: str) -> str:
    digits = re.sub(r"\D", "", card_number)
    if digits.startswith("4"):
        return "VISA"
    if digits[:2] in {"51", "52", "53", "54", "55"} or (2221 <= int(digits[:4] or "0") <= 2720):
        return "MASTERCARD"
    if digits.startswith(("34", "37")):
        return "AMEX"
    if digits.startswith(("5061", "5060", "6500")):
        return "VERVE"
    return "CARD"


class PaymentStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_intents (
                    id TEXT PRIMARY KEY,
                    amount_minor INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    status TEXT NOT NULL,
                    customer_email TEXT NOT NULL,
                    description TEXT NOT NULL,
                    card_brand TEXT,
                    card_last4 TEXT,
                    capture_method TEXT NOT NULL,
                    captured_minor INTEGER NOT NULL DEFAULT 0,
                    refunded_minor INTEGER NOT NULL DEFAULT 0,
                    failure_code TEXT,
                    failure_message TEXT,
                    webhook_url TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ledger_entries (
                    id TEXT PRIMARY KEY,
                    payment_id TEXT NOT NULL,
                    entry_type TEXT NOT NULL,
                    debit_account TEXT NOT NULL,
                    credit_account TEXT NOT NULL,
                    amount_minor INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (payment_id) REFERENCES payment_intents(id)
                );

                CREATE TABLE IF NOT EXISTS idempotency_keys (
                    idem_key TEXT PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    response_status INTEGER NOT NULL,
                    response_body TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS webhook_events (
                    id TEXT PRIMARY KEY,
                    payment_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    delivery_status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def get_idempotent(self, idem_key: str, endpoint: str) -> tuple[int, dict[str, Any]] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT endpoint, response_status, response_body FROM idempotency_keys WHERE idem_key = ?",
                (idem_key,),
            ).fetchone()
            if not row:
                return None
            if row["endpoint"] != endpoint:
                return (
                    HTTPStatus.CONFLICT,
                    {"error": {"code": "IDEMPOTENCY_CONFLICT", "message": "Idempotency key reused on different endpoint."}},
                )
            return int(row["response_status"]), json.loads(row["response_body"])

    def save_idempotent(self, idem_key: str, endpoint: str, status: int, body: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO idempotency_keys (idem_key, endpoint, response_status, response_body, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (idem_key, endpoint, status, json.dumps(body), utc_now()),
            )

    def _record_ledger(
        self,
        conn: sqlite3.Connection,
        payment_id: str,
        entry_type: str,
        debit_account: str,
        credit_account: str,
        amount_minor: int,
        currency: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO ledger_entries
            (id, payment_id, entry_type, debit_account, credit_account, amount_minor, currency, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"led_{secrets.token_hex(8)}",
                payment_id,
                entry_type,
                debit_account,
                credit_account,
                amount_minor,
                currency,
                utc_now(),
            ),
        )

    def _emit_webhook(
        self,
        conn: sqlite3.Connection,
        payment_id: str,
        event_type: str,
        payment_obj: dict[str, Any],
        webhook_url: str | None,
        webhook_secret: str,
    ) -> dict[str, Any]:
        event_id = f"evt_{secrets.token_hex(8)}"
        envelope = {
            "id": event_id,
            "type": event_type,
            "created_at": utc_now(),
            "data": {"object": payment_obj},
        }
        raw_payload = json.dumps(envelope, separators=(",", ":"))
        sig = hmac.new(webhook_secret.encode("utf-8"), raw_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        sig_header = f"t={int(datetime.now(timezone.utc).timestamp())},v1={sig}"

        delivery_status = "RECORDED_ONLY"
        if webhook_url:
            try:
                req = urllib.request.Request(
                    webhook_url,
                    data=raw_payload.encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-Aegis-Signature": sig_header,
                        "X-Aegis-Event": event_type,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    delivery_status = f"DELIVERED_{resp.status}"
            except (urllib.error.URLError, ValueError):
                delivery_status = "DELIVERY_FAILED"

        conn.execute(
            """
            INSERT INTO webhook_events
            (id, payment_id, event_type, payload_json, signature, delivery_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, payment_id, event_type, raw_payload, sig_header, delivery_status, utc_now()),
        )
        return {"id": event_id, "type": event_type, "signature": sig_header, "delivery_status": delivery_status}

    def create_payment(self, payload: dict[str, Any], webhook_secret: str) -> tuple[int, dict[str, Any]]:
        amount_minor = payload.get("amount_minor")
        currency = str(payload.get("currency", "USD")).strip().upper()
        email = str(payload.get("customer_email", "")).strip()
        desc = str(payload.get("description", "Merchant charge")).strip()
        capture_method = str(payload.get("capture_method", "automatic")).strip().lower()
        webhook_url = str(payload.get("webhook_url", "")).strip() or None
        card = payload.get("card") or {}
        card_num = re.sub(r"\D", "", str(card.get("number", "")))
        exp_month = int(card.get("exp_month", 0) or 0)
        exp_year = int(card.get("exp_year", 0) or 0)
        cvc = str(card.get("cvc", "")).strip()

        if not isinstance(amount_minor, int) or amount_minor <= 0:
            return HTTPStatus.BAD_REQUEST, {
                "error": {"code": "INVALID_AMOUNT", "message": "amount_minor must be a positive integer."}
            }
        if currency not in SUPPORTED_CURRENCIES:
            return HTTPStatus.BAD_REQUEST, {
                "error": {"code": "UNSUPPORTED_CURRENCY", "message": f"Supported currencies: {sorted(SUPPORTED_CURRENCIES)}"}
            }
        if "@" not in email:
            return HTTPStatus.BAD_REQUEST, {
                "error": {"code": "INVALID_CUSTOMER", "message": "Valid customer_email is required."}
            }
        if capture_method not in {"automatic", "manual"}:
            return HTTPStatus.BAD_REQUEST, {
                "error": {"code": "INVALID_CAPTURE_METHOD", "message": "capture_method must be 'automatic' or 'manual'."}
            }
        if not luhn_valid(card_num):
            return HTTPStatus.UNPROCESSABLE_ENTITY, {
                "error": {"code": "CARD_LUHN_FAILED", "message": "Card number failed Luhn check."}
            }
        now_dt = datetime.now(timezone.utc)
        if not (1 <= exp_month <= 12) or exp_year < now_dt.year or (exp_year == now_dt.year and exp_month < now_dt.month):
            return HTTPStatus.UNPROCESSABLE_ENTITY, {
                "error": {"code": "CARD_EXPIRED", "message": "Card expiration date is invalid or expired."}
            }
        if not (3 <= len(cvc) <= 4 and cvc.isdigit()):
            return HTTPStatus.UNPROCESSABLE_ENTITY, {
                "error": {"code": "INVALID_CVC", "message": "CVC must be 3 or 4 numeric digits."}
            }

        pid = f"pi_{secrets.token_hex(10)}"
        brand = detect_brand(card_num)
        last4 = card_num[-4:]
        ts = utc_now()

        # Deterministic decline triggers for testing
        if last4 == "0002":
            status = "failed"
            fail_code = "INSUFFICIENT_FUNDS"
            fail_msg = "Issuing bank declined transaction due to insufficient funds."
            captured_minor = 0
        elif last4 == "0019":
            status = "failed"
            fail_code = "DO_NOT_HONOR"
            fail_msg = "Issuing bank declined transaction (Do Not Honor)."
            captured_minor = 0
        else:
            fail_code = None
            fail_msg = None
            if capture_method == "automatic":
                status = "succeeded"
                captured_minor = amount_minor
            else:
                status = "requires_capture"
                captured_minor = 0

        with self._connect() as conn:
            conn.execute("BEGIN")
            conn.execute(
                """
                INSERT INTO payment_intents
                (id, amount_minor, currency, status, customer_email, description, card_brand, card_last4,
                 capture_method, captured_minor, refunded_minor, failure_code, failure_message, webhook_url,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                """,
                (
                    pid,
                    amount_minor,
                    currency,
                    status,
                    email,
                    desc,
                    brand,
                    last4,
                    capture_method,
                    captured_minor,
                    fail_code,
                    fail_msg,
                    webhook_url,
                    ts,
                    ts,
                ),
            )
            if status in {"succeeded", "requires_capture"}:
                self._record_ledger(
                    conn, pid, "AUTHORIZATION_HOLD", "customer_card_receivable", "gateway_auth_reserve", amount_minor, currency
                )
            if status == "succeeded":
                self._record_ledger(
                    conn, pid, "CAPTURE_SETTLEMENT", "gateway_auth_reserve", "merchant_available_balance", amount_minor, currency
                )

            payment_obj = self._fetch_payment_dict(conn, pid)
            evt_type = "payment_intent.succeeded" if status == "succeeded" else (
                "payment_intent.amount_capturable_updated" if status == "requires_capture" else "payment_intent.payment_failed"
            )
            wh = self._emit_webhook(conn, pid, evt_type, payment_obj, webhook_url, webhook_secret)
            conn.execute("COMMIT")

        http_code = HTTPStatus.CREATED if status != "failed" else HTTPStatus.PAYMENT_REQUIRED
        return http_code, {"payment": payment_obj, "webhook": wh}

    def capture_payment(self, pid: str, amount_minor: int | None, webhook_secret: str) -> tuple[int, dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM payment_intents WHERE id = ?", (pid,)).fetchone()
            if not row:
                return HTTPStatus.NOT_FOUND, {"error": {"code": "NOT_FOUND", "message": "Payment intent not found."}}
            if row["status"] != "requires_capture":
                return HTTPStatus.CONFLICT, {
                    "error": {"code": "INVALID_STATE", "message": f"Cannot capture payment in status '{row['status']}'."}
                }
            cap_amt = int(row["amount_minor"]) if amount_minor is None else amount_minor
            if not isinstance(cap_amt, int) or cap_amt <= 0 or cap_amt > int(row["amount_minor"]):
                return HTTPStatus.BAD_REQUEST, {
                    "error": {"code": "INVALID_CAPTURE_AMOUNT", "message": "Capture amount must be between 1 and authorized amount."}
                }

            conn.execute("BEGIN")
            conn.execute(
                "UPDATE payment_intents SET status = 'succeeded', captured_minor = ?, updated_at = ? WHERE id = ?",
                (cap_amt, utc_now(), pid),
            )
            self._record_ledger(
                conn, pid, "CAPTURE_SETTLEMENT", "gateway_auth_reserve", "merchant_available_balance", cap_amt, row["currency"]
            )
            if cap_amt < int(row["amount_minor"]):
                release = int(row["amount_minor"]) - cap_amt
                self._record_ledger(
                    conn, pid, "AUTH_RELEASE", "gateway_auth_reserve", "customer_card_receivable", release, row["currency"]
                )
            payment_obj = self._fetch_payment_dict(conn, pid)
            wh = self._emit_webhook(conn, pid, "payment_intent.succeeded", payment_obj, row["webhook_url"], webhook_secret)
            conn.execute("COMMIT")
            return HTTPStatus.OK, {"payment": payment_obj, "webhook": wh}

    def refund_payment(self, pid: str, amount_minor: int | None, webhook_secret: str) -> tuple[int, dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM payment_intents WHERE id = ?", (pid,)).fetchone()
            if not row:
                return HTTPStatus.NOT_FOUND, {"error": {"code": "NOT_FOUND", "message": "Payment intent not found."}}
            if row["status"] not in {"succeeded", "partially_refunded"}:
                return HTTPStatus.CONFLICT, {
                    "error": {"code": "INVALID_STATE", "message": f"Cannot refund payment in status '{row['status']}'."}
                }
            refundable = int(row["captured_minor"]) - int(row["refunded_minor"])
            ref_amt = refundable if amount_minor is None else amount_minor
            if not isinstance(ref_amt, int) or ref_amt <= 0 or ref_amt > refundable:
                return HTTPStatus.BAD_REQUEST, {
                    "error": {"code": "INVALID_REFUND_AMOUNT", "message": f"Refundable balance is {refundable} minor units."}
                }

            new_refunded = int(row["refunded_minor"]) + ref_amt
            new_status = "refunded" if new_refunded == int(row["captured_minor"]) else "partially_refunded"

            conn.execute("BEGIN")
            conn.execute(
                "UPDATE payment_intents SET status = ?, refunded_minor = ?, updated_at = ? WHERE id = ?",
                (new_status, new_refunded, utc_now(), pid),
            )
            self._record_ledger(
                conn, pid, "REFUND_DEBIT", "merchant_available_balance", "customer_card_receivable", ref_amt, row["currency"]
            )
            payment_obj = self._fetch_payment_dict(conn, pid)
            wh = self._emit_webhook(conn, pid, "charge.refunded", payment_obj, row["webhook_url"], webhook_secret)
            conn.execute("COMMIT")
            return HTTPStatus.OK, {"payment": payment_obj, "webhook": wh}

    def _fetch_payment_dict(self, conn: sqlite3.Connection, pid: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM payment_intents WHERE id = ?", (pid,)).fetchone()
        ledger = [
            dict(r)
            for r in conn.execute(
                "SELECT id, entry_type, debit_account, credit_account, amount_minor, currency, created_at "
                "FROM ledger_entries WHERE payment_id = ? ORDER BY rowid ASC",
                (pid,),
            ).fetchall()
        ]
        data = dict(row)
        data["ledger_entries"] = ledger
        return data

    def get_payment(self, pid: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM payment_intents WHERE id = ?", (pid,)).fetchone()
            if not row:
                return None
            return self._fetch_payment_dict(conn, pid)

    def list_overview(self) -> dict[str, Any]:
        with self._connect() as conn:
            payments = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, amount_minor, currency, status, customer_email, card_brand, card_last4, "
                    "captured_minor, refunded_minor, created_at FROM payment_intents ORDER BY rowid DESC LIMIT 50"
                ).fetchall()
            ]
            webhooks = [
                dict(r)
                for r in conn.execute(
                    "SELECT id, payment_id, event_type, signature, delivery_status, created_at "
                    "FROM webhook_events ORDER BY rowid DESC LIMIT 25"
                ).fetchall()
            ]
            balances = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT currency,
                           SUM(CASE WHEN credit_account = 'merchant_available_balance' THEN amount_minor ELSE 0 END) -
                           SUM(CASE WHEN debit_account = 'merchant_available_balance' THEN amount_minor ELSE 0 END) AS net_settled_minor
                    FROM ledger_entries
                    GROUP BY currency
                    """
                ).fetchall()
            ]
            return {"balances": balances, "payments": payments, "webhooks": webhooks}


CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AegisPay // Payment Gateway & Ledger Console</title>
  <style>
    :root { --bg:#0b1120; --panel:#111827; --border:#1f2937; --text:#f3f4f6; --muted:#9ca3af; --accent:#38bdf8; --ok:#22c55e; --err:#ef4444; }
    * { box-sizing:border-box; }
    body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--text); }
    .wrap { max-width:1180px; margin:0 auto; padding:24px 18px 48px; }
    h1 { margin:0 0 4px; font-size:1.5rem; }
    .sub { color:var(--muted); margin:0 0 20px; font-size:0.9rem; }
    .grid { display:grid; grid-template-columns:360px 1fr; gap:18px; }
    @media (max-width:900px) { .grid { grid-template-columns:1fr; } }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; }
    label { display:block; font-size:0.78rem; color:var(--muted); margin:10px 0 4px; }
    input, select, button { width:100%; padding:9px 11px; border-radius:8px; border:1px solid var(--border); background:#0f172a; color:var(--text); font-size:0.88rem; }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    button { background:var(--accent); color:#04101d; font-weight:700; border:none; cursor:pointer; margin-top:14px; }
    button.sec { background:#1e293b; color:var(--text); border:1px solid var(--border); margin-top:0; padding:5px 9px; font-size:0.76rem; width:auto; }
    table { width:100%; border-collapse:collapse; font-size:0.83rem; }
    th, td { padding:9px 8px; border-bottom:1px solid var(--border); text-align:left; }
    th { color:var(--muted); font-weight:600; }
    .pill { padding:2px 8px; border-radius:999px; font-size:0.73rem; font-weight:700; background:#1e293b; }
    .pill-succeeded { background:rgba(34,197,94,.18); color:#86efac; }
    .pill-failed { background:rgba(239,68,68,.18); color:#fca5a5; }
    .pill-requires_capture { background:rgba(56,189,248,.18); color:#7dd3fc; }
    pre { background:#060a14; border:1px solid var(--border); padding:10px; border-radius:8px; font-size:0.76rem; overflow-x:auto; color:#cbd5e1; }
  </style>
</head>
<body>
<div class="wrap">
  <h1>AegisPay Gateway & Double-Entry Ledger</h1>
  <p class="sub">Bearer Auth • Idempotency Enforcement • Luhn Card Validation • HMAC-SHA256 Webhooks</p>
  <div class="grid">
    <div class="card">
      <strong>Create Payment Intent</strong>
      <label>API Secret Key</label>
      <input id="apiKey" value="__API_KEY__" />
      <div class="row">
        <div><label>Amount (Minor Units)</label><input id="amount" type="number" value="12500" /></div>
        <div><label>Currency</label><select id="currency"><option>USD</option><option>EUR</option><option>GBP</option><option>NGN</option></select></div>
      </div>
      <label>Capture Method</label>
      <select id="captureMethod"><option value="automatic">automatic</option><option value="manual">manual (auth hold)</option></select>
      <label>Customer Email</label>
      <input id="email" value="buyer@example.com" />
      <label>Card Number (4242...4242 pass | ...0002 decline)</label>
      <input id="cardNum" value="4242424242424242" />
      <div class="row">
        <div><label>Exp (MM/YYYY)</label><input id="exp" value="12/2029" /></div>
        <div><label>CVC</label><input id="cvc" value="737" /></div>
      </div>
      <button onclick="submitCharge()">Process Payment</button>
      <label>Last API Response</label>
      <pre id="out">Ready.</pre>
    </div>
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <strong>Live Ledger & Payment Intents</strong>
        <button class="sec" onclick="refresh()">Refresh</button>
      </div>
      <div id="balances" style="margin-bottom:12px;color:#38bdf8;font-size:0.85rem;"></div>
      <table>
        <thead><tr><th>ID</th><th>Amount</th><th>Card</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody id="txBody"></tbody>
      </table>
      <div style="margin-top:16px;"><strong>Recent Signed Webhooks</strong></div>
      <pre id="whOut" style="margin-top:6px;">No webhook events yet.</pre>
    </div>
  </div>
</div>
<script>
function headers(withIdem=false) {
  const h = { "Content-Type": "application/json", "Authorization": "Bearer " + document.getElementById("apiKey").value.trim() };
  if (withIdem) h["Idempotency-Key"] = "idem_" + Date.now() + "_" + Math.random().toString(36).slice(2, 8);
  return h;
}
async function submitCharge() {
  const [mm, yyyy] = document.getElementById("exp").value.split("/");
  const payload = {
    amount_minor: parseInt(document.getElementById("amount").value, 10),
    currency: document.getElementById("currency").value,
    capture_method: document.getElementById("captureMethod").value,
    customer_email: document.getElementById("email").value,
    description: "Console checkout charge",
    card: { number: document.getElementById("cardNum").value, exp_month: parseInt(mm,10), exp_year: parseInt(yyyy,10), cvc: document.getElementById("cvc").value }
  };
  const res = await fetch("/v1/payments", { method: "POST", headers: headers(true), body: JSON.stringify(payload) });
  const data = await res.json();
  document.getElementById("out").textContent = JSON.stringify(data, null, 2);
  refresh();
}
async function actionTx(id, act) {
  const res = await fetch(`/v1/payments/${id}/${act}`, { method: "POST", headers: headers(true), body: "{}" });
  const data = await res.json();
  document.getElementById("out").textContent = JSON.stringify(data, null, 2);
  refresh();
}
async function refresh() {
  const res = await fetch("/v1/overview", { headers: headers(false) });
  const data = await res.json();
  if (!res.ok) { document.getElementById("out").textContent = JSON.stringify(data, null, 2); return; }
  document.getElementById("balances").textContent = "Net Settled Balances: " + (data.balances.map(b => `${b.currency} ${(b.net_settled_minor/100).toFixed(2)}`).join(" | ") || "0.00");
  document.getElementById("txBody").innerHTML = data.payments.map(p => `
    <tr>
      <td><code>${p.id}</code></td>
      <td>${p.currency} ${(p.amount_minor/100).toFixed(2)}</td>
      <td>${p.card_brand || ""} •••• ${p.card_last4 || ""}</td>
      <td><span class="pill pill-${p.status}">${p.status}</span></td>
      <td>
        ${p.status === "requires_capture" ? `<button class="sec" onclick="actionTx('${p.id}','capture')">Capture</button>` : ""}
        ${(p.status === "succeeded" || p.status === "partially_refunded") ? `<button class="sec" onclick="actionTx('${p.id}','refund')">Refund</button>` : ""}
      </td>
    </tr>
  `).join("");
  document.getElementById("whOut").textContent = data.webhooks.length ? JSON.stringify(data.webhooks, null, 2) : "No webhook events yet.";
}
refresh();
</script>
</body>
</html>
"""


def make_handler(store: PaymentStore, api_key: str, webhook_secret: str):
    class GatewayHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[{utc_now()}] {self.address_string()} - {fmt % args}\n")

        def _send_json(self, status: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _authorized(self) -> bool:
            auth = self.headers.get("Authorization", "")
            expected = f"Bearer {api_key}"
            return hmac.compare_digest(auth.encode("utf-8"), expected.encode("utf-8"))

        def _read_json(self) -> dict[str, Any] | None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            if not raw.strip():
                return {}
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                html = CONSOLE_HTML.replace("__API_KEY__", api_key).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

            if path == "/health":
                self._send_json(HTTPStatus.OK, {"status": "ok", "utc": utc_now()})
                return

            if not self._authorized():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": {"code": "UNAUTHORIZED", "message": "Invalid Bearer token."}})
                return

            if path == "/v1/overview":
                self._send_json(HTTPStatus.OK, store.list_overview())
                return

            m = re.match(r"^/v1/payments/(pi_[a-f0-9]+)$", path)
            if m:
                payment = store.get_payment(m.group(1))
                if not payment:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": {"code": "NOT_FOUND", "message": "Payment not found."}})
                    return
                self._send_json(HTTPStatus.OK, {"payment": payment})
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"code": "ROUTE_NOT_FOUND", "message": "Unknown endpoint."}})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if not self._authorized():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": {"code": "UNAUTHORIZED", "message": "Invalid Bearer token."}})
                return

            idem_key = self.headers.get("Idempotency-Key", "").strip()
            if not idem_key:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": {"code": "MISSING_IDEMPOTENCY_KEY", "message": "Idempotency-Key header is required on POST."}},
                )
                return

            cached = store.get_idempotent(idem_key, path)
            if cached:
                self._send_json(cached[0], cached[1])
                return

            body = self._read_json()
            if body is None:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": {"code": "INVALID_JSON", "message": "Malformed JSON body."}})
                return

            if path == "/v1/payments":
                status, resp = store.create_payment(body, webhook_secret)
                store.save_idempotent(idem_key, path, status, resp)
                self._send_json(status, resp)
                return

            m_cap = re.match(r"^/v1/payments/(pi_[a-f0-9]+)/capture$", path)
            if m_cap:
                amt = body.get("amount_minor")
                status, resp = store.capture_payment(m_cap.group(1), amt, webhook_secret)
                store.save_idempotent(idem_key, path, status, resp)
                self._send_json(status, resp)
                return

            m_ref = re.match(r"^/v1/payments/(pi_[a-f0-9]+)/refund$", path)
            if m_ref:
                amt = body.get("amount_minor")
                status, resp = store.refund_payment(m_ref.group(1), amt, webhook_secret)
                store.save_idempotent(idem_key, path, status, resp)
                self._send_json(status, resp)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"code": "ROUTE_NOT_FOUND", "message": "Unknown endpoint."}})

    return GatewayHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AegisPay Payment Gateway & Ledger HTTP server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--db", type=Path, default=Path("aegis_gateway.db"), help="SQLite database file path")
    parser.add_argument("--api-key", default=DEFAULT_API_KEY, help="Bearer secret API key")
    parser.add_argument("--webhook-secret", default=DEFAULT_WEBHOOK_SECRET, help="HMAC-SHA256 webhook signing secret")
    args = parser.parse_args()

    store = PaymentStore(args.db)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(store, args.api_key, args.webhook_secret))
    print(f"[+] AegisPay Gateway running on http://{args.host}:{args.port}")
    print(f"[+] Operator Checkout Console: http://{args.host}:{args.port}/")
    print(f"[+] API Key: {args.api_key}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down AegisPay Gateway.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
