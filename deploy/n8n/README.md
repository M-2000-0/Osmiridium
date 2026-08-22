# n8n Automation Workflows

Import these JSON files into [n8n](https://n8n.io) to run Osmiridium's business
operations as a single operator.

## Workflows

| File | Trigger | What it does |
|------|---------|--------------|
| `lead-intake.json` | Webhook `POST /lead` | Validates the lead, creates an Osmiridium session, auto-replies, notifies you |
| `invoicing.json` | Weekly schedule | Fetches usage and emails an invoice when a balance is due |
| `payment-follow-ups.json` | Daily schedule | Lists open invoices and emails a reminder when one is overdue |
| `weekly-report.json` | Weekly schedule | Pulls `GET /metrics` from the coordinator and emails you the report |

## Setup

1. Run n8n (easiest: `docker run -it --rm -p 5678:5678 n8nio/n8n`).
2. Import each workflow via **Workflows → Import from file**.
3. Configure credentials:
   - **SMTP account** — for the email nodes.
   - **HTTP Basic Auth** — for the Stripe call in `payment-follow-ups.json`.
4. Replace placeholder values:
   - `YOUR_OSMIRIDIUM_API_KEY` → your `OSMOSMPC_API_KEY`.
   - `https://osmiridium.example.com` → your public coordinator URL.
   - Email addresses.
5. Activate each workflow.

## Exposing the coordinator webhook

The `lead-intake.json` webhook runs inside n8n. Point your marketing/website
form at `https://<n8n-host>/webhook/lead` (or `/webhook-test/lead` in test mode).