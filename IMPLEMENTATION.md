# Network Traffic Monitoring System — Implementation Backlog

Reference checklist for building the project. Compare against the PDF requirements and current MVP.

---

## Already Working (MVP)

- [x] Admin login with bcrypt + JWT
- [x] Role-based access in the API (admin / analyst / viewer)
- [x] Neon PostgreSQL storage
- [x] Traffic log capture (sample agent + continuous daemon + basic live capture)
- [x] Dashboard with stats, charts, traffic logs, CSV export
- [x] Rule-based anomaly detection (unencrypted traffic, bursts, port scans)
- [x] Admin review of anomalies + simple retraining (threshold adjustment)
- [x] Password strength checker
- [x] SMS alert code stub (Infobip — not wired up yet)

---

## High Priority (Core Project Gaps)

- [x] **Continuous real-time monitoring** — agent runs as a background service via `--daemon` and start/stop scripts
- [ ] **Automatic anomaly detection** — run on a schedule or after each capture batch, not only via "Run Detection Now"
- [ ] **Secure the traffic agent** — `/api/traffic/logs` is open; add API key or agent authentication
- [ ] **Network scanner in the dashboard** — scan exists in CLI only; show active/unauthorized devices in UI and save results to DB
- [ ] **SMS alerts end-to-end** — configure Infobip, test delivery, show alert status in dashboard
- [ ] **User management UI** — create users, assign roles, disable accounts, force password change (API exists, UI does not)
- [ ] **Traffic log filters** — add date range filtering (PDF mentions date + IP; currently IP only)
- [ ] **Audit log page** — who logged in, reviewed anomalies, exported data (data is stored, no UI)

---

## Medium Priority (Match the PDF Better)

- [ ] **PDF report export** — generate downloadable reports for admins
- [ ] **Stronger retraining model** — today only threshold tweaks; add signature/rule learning from confirmed intrusions
- [ ] **Intrusion analytics charts** — breakdown by type (brute force, port scan, unencrypted), trends over time
- [ ] **Alert management module** — list alerts, severity, status history, retry failed SMS
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
- [ ] **Evaluation metrics** — false positive rate, detection accuracy, SMS delivery rate over test period

---

## Nice to Have / v2

- [ ] **ML-based anomaly detection** (e.g. Isolation Forest) on top of rules
- [ ] **Email alerts** as backup to SMS
- [ ] **Device inventory** — known vs unknown MAC/IP whitelist
- [ ] **Polished frontend** — Bootstrap-style UI instead of basic Streamlit (optional)

---

## Suggested Build Order

| Phase | Focus |
|-------|--------|
| **Week 1** | Agent auth, background agent, auto-detection, date filters |
| **Week 2** | Network scanner UI, user management UI, audit logs |
| **Week 3** | SMS alerts, PDF reports, intrusion charts |
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
| Anomaly alert generation | Partial (manual trigger) |
| SMS alerts | Not configured |
| Traffic logs (filter + export) | Partial (IP filter + CSV) |
| Network device scan | Partial (CLI only) |
| Retraining / feedback model | Partial (threshold only) |
| PDF reporting | Not started |
| User management | Partial (API only) |

---

## Notes

- Default admin credentials: `admin` / `Admin@123` — change before production.
- Keep secrets in `.env` only; never commit real Neon credentials to `.env.example`.
- For local testing without school network access, use `python agent/capture.py --mode sample`.
