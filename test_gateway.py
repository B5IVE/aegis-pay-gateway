#!/usr/bin/env python3
"""
End-to-end integration test suite for aegis-pay-gateway.

Starts the gateway on an ephemeral local port with a temporary SQLite database,
exercises Bearer auth, idempotency replay, Luhn validation, manual authorization
and capture, partial refunds, double-entry ledger balance reconciliation, and
HMAC-SHA256 webhook signature verification.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from gateway import PaymentStore, make_handler
from webhook_verifier import verify_aegis_signature

API_KEY = "sk_test_unit_123456"
WH_SECRET = "whsec_unit_abcdef"


class PaymentGatewayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        db_path = Path(self.tmp.name) / "test_gateway.db"
        self.store = PaymentStore(db_path)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store, API_KEY, WH_SECRET))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _req(self, method: str, path: str, body: dict | None = None, idem: str | None = None, auth: bool = True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {API_KEY}"
        if idem:
            headers["Idempotency-Key"] = idem
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_auth_and_idempotent_charge_capture_refund_flow(self) -> None:
        # 1. Unauthorized check
        code, _ = self._req("GET", "/v1/overview", auth=False)
        self.assertEqual(code, 401)

        # 2. Manual capture authorization
        payload = {
            "amount_minor": 50000,
            "currency": "USD",
            "capture_method": "manual",
            "customer_email": "alice@example.com",
            "description": "Enterprise subscription",
            "card": {"number": "4242424242424242", "exp_month": 12, "exp_year": 2030, "cvc": "123"},
        }
        code, res1 = self._req("POST", "/v1/payments", body=payload, idem="idem-auth-001")
        self.assertEqual(code, 201)
        pid = res1["payment"]["id"]
        self.assertEqual(res1["payment"]["status"], "requires_capture")

        # 3. Idempotent replay returns exact same payment ID without double charge
        code_rep, res_rep = self._req("POST", "/v1/payments", body=payload, idem="idem-auth-001")
        self.assertEqual(code_rep, 201)
        self.assertEqual(res_rep["payment"]["id"], pid)

        # 4. Capture 500.00 USD
        code_cap, res_cap = self._req("POST", f"/v1/payments/{pid}/capture", body={}, idem="idem-cap-001")
        self.assertEqual(code_cap, 200)
        self.assertEqual(res_cap["payment"]["status"], "succeeded")

        # 5. Partial refund of 150.00 USD
        code_ref, res_ref = self._req(
            "POST", f"/v1/payments/{pid}/refund", body={"amount_minor": 15000}, idem="idem-ref-001"
        )
        self.assertEqual(code_ref, 200)
        self.assertEqual(res_ref["payment"]["status"], "partially_refunded")
        self.assertEqual(res_ref["payment"]["refunded_minor"], 15000)

        # 6. Verify double-entry net settled balance = 50000 - 15000 = 35000
        _, overview = self._req("GET", "/v1/overview")
        usd_bal = [b for b in overview["balances"] if b["currency"] == "USD"][0]
        self.assertEqual(usd_bal["net_settled_minor"], 35000)

    def test_luhn_rejection_and_webhook_hmac(self) -> None:
        bad_payload = {
            "amount_minor": 1000,
            "currency": "USD",
            "customer_email": "bob@example.com",
            "card": {"number": "4242424242424241", "exp_month": 12, "exp_year": 2030, "cvc": "999"},
        }
        code, err = self._req("POST", "/v1/payments", body=bad_payload, idem="idem-bad-luhn")
        self.assertEqual(code, 422)
        self.assertEqual(err["error"]["code"], "CARD_LUHN_FAILED")

        # Verify standalone webhook signature helper
        sample_raw = '{"id":"evt_1","type":"payment_intent.succeeded"}'
        sig_hdr = "t=1700000000,v1=7c5c8c7f7c9e64c4598c44890d568f1e6b3f0c8f629a5e63718d40343e2d317a"
        self.assertFalse(verify_aegis_signature(sample_raw, sig_hdr, WH_SECRET))


if __name__ == "__main__":
    unittest.main()
