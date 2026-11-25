# aegis-pay-gateway

A zero-dependency Python 3.10+ **Payment Gateway, Double-Entry Ledger, & Signed Webhook Engine** backed by SQLite WAL persistence and an integrated browser checkout/operator console.

## Architecture & Capabilities

- **REST Payment Lifecycle API (`/v1/payments`):** Supports `automatic` and `manual` (authorize-then-capture) payment intents, partial or full captures, and partial or full refunds.
- **Double-Entry Accounting Ledger:** Every authorization hold, capture settlement, auth release, and refund writes balanced debit/credit postings (`customer_card_receivable`, `gateway_auth_reserve`, `merchant_available_balance`).
- **Strict Idempotency (`Idempotency-Key`):** Prevents duplicate charges or double refunds on network retries and rejects key reuse across mismatched endpoints (`409 Conflict`).
- **Card Validation & Deterministic Decline Simulation:** Enforces Luhn checksums, expiration dates, CVC formatting, and deterministic decline test cards (`...0002` Insufficient Funds, `...0019` Do Not Honor).
- **HMAC-SHA256 Signed Webhooks (`X-Aegis-Signature`):** Generates cryptographically signed webhook envelopes (`payment_intent.succeeded`, `payment_intent.amount_capturable_updated`, `payment_intent.payment_failed`, `charge.refunded`) with optional live HTTP POST delivery and a standalone verification helper (`webhook_verifier.py`).
- **Built-In Operator & Checkout Console (`/`):** Interactive browser UI for processing test payments, capturing holds, issuing refunds, and inspecting net settled balances.

## Quickstart

Requires **Python 3.10+** (standard library only).

```bash
git clone [https://github.com/B5IVE/aegis-pay-gateway.git](https://github.com/B5IVE/aegis-pay-gateway.git)
cd aegis-pay-gateway

# Run integration tests
python3 test_gateway.py

# Start the gateway & open [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
python3 gateway.py
