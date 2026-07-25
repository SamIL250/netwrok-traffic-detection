# Network Traffic Monitoring System — Implementation Backlog

Reference checklist for building the project. Compare against the PDF requirements and current MVP.

---

## Already Working (MVP)

- [x] Admin login with bcrypt + JWT
- [x] Role-based access in the API (admin / analyst / viewer)
- [x] Neon PostgreSQL storage
- [x] Traffic log capture (sample agent + continuous daemon + basic live capture)
- [x] Dashboard with stats, charts, traffic logs, CSV export
- [x] Rule-based anomaly detection (unencrypted traffic, bursts, port scans) with automatic runs
- [x] Admin review of anomalies + retraining (threshold adjustment + signature learning)
- [x] Password strength checker
- [x] Email alerts via SMTP with delivery logging and dashboard status view

---

## High Priority (Core Project Gaps)

- [x] **Continuous real-time monitoring** — agent runs as a background service via `--daemon` and start/stop scripts
- [x] **Automatic anomaly detection** — scheduled in the API and triggered after each agent capture batch
- [x] **Secure the traffic agent** — `/api/traffic/logs` requires `X-Agent-Api-Key` header
- [x] **Network scanner in the dashboard** — scan active/unauthorized devices, save results to DB, authorize devices
- [x] **Email alerts end-to-end** — SMTP configured, test delivery, alert status in dashboard
- [x] **User management UI** — create users, assign roles, disable accounts, force password change (API exists, UI does not)
- [x] **Traffic log filters** — add date range filtering (PDF mentions date + IP; currently IP only)
- [x] **Audit log page** — who logged in, reviewed anomalies, exported data (data is stored, no UI)

---

## Medium Priority (Match the PDF Better)

- [x] **PDF report export** — generate downloadable reports for admins
- [x] **Stronger retraining model** — today only threshold tweaks; add signature/rule learning from confirmed intrusions
- [ ] **Intrusion analytics charts** — breakdown by type (brute force, port scan, unencrypted), trends over time
- [ ] **Alert management module** — list alerts, severity, status history, retry failed email
- [ ] **Password reset / change password flow** — especially replace default `admin` password safely
- [ ] **Proper DB migrations** — Alembic instead of `create_all()` for schema changes
- [ ] **Logout / session handling** — token expiry exists, but no proper session revoke or blacklist
- [ ] **RBAC in the UI** — hide or disable actions per role (viewer read-only, analyst can review, admin manages users)

---

## Deployment & School Integration

- [ ] **Deploy on ULK network** — mirror port / gateway access, ICT approval, privacy policy
- [ ] **Production setup** — Docker, env secrets, reverse proxy, process manager (systemd)
- [ ] **Performance targets** — caching, DB indexes, pagination for large log volumes
- [ ] **Monitoring uptime** — health checks, logging, error alerts for the system itself

---

## Quality & Academic Deliverables

- [ ] **Automated tests** — auth, detection rules, API, dashboard flows
- [ ] **UAT checklist** — test cases from PDF (login, detection, SMS, export, RBAC, retraining)
- [ ] **Documentation** — setup guide, architecture diagram, user manual for ICT staff
- [ ] **Evaluation metrics** — false positive rate, detection accuracy, email delivery rate over test period

---

## Nice to Have / v2

- [ ] **ML-based anomaly detection** (e.g. Isolation Forest) on top of rules
- [ ] **Device inventory** — known vs unknown MAC/IP whitelist
- [ ] **Polished frontend** — Bootstrap-style UI instead of basic Streamlit (optional)

---

## Suggested Build Order

| Phase | Focus |
|-------|--------|
| **Week 1** | Agent auth, background agent, auto-detection, date filters |
| **Week 2** | Network scanner UI, user management UI, audit logs |
| **Week 3** | PDF reports, intrusion charts, alert polish |
| **Week 4** | Tests, deployment, ULK integration, documentation |

---

## Quick Reference — What the PDF Requires

| Feature | Status |
|---------|--------|
| Secure login / logout | Partial (login yes, logout basic) |
| Role-based access control | Partial (API yes, UI incomplete) |
| Real-time traffic capture | Partial (continuous daemon; live needs network permissions) |
| Network traffic dashboard | Done (basic) |
| Password strength analysis | Done |
| Anomaly alert generation | Partial (automatic + manual trigger) |
| Email alerts | Done (SMTP + dashboard) |
| Traffic logs (filter + export) | Done (IP + date range + CSV) |
| Network device scan | Done (dashboard + DB + CLI via agent) |
| Retraining / feedback model | Done (threshold tuning + signature learning) |
| PDF reporting | Done (admin dashboard + API) |
| User management | Done (API + dashboard) |

---

## Notes

- Default admin credentials: `admin` / `Admin@123` — change before production.
- Keep secrets in `.env` only; never commit real Neon credentials to `.env.example`.
- For local testing without school network access, use `python agent/capture.py --mode sample`.
