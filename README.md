# Network Traffic Monitoring and Analysis System

A Python-based network monitoring system for educational institutions. It captures network traffic, detects suspicious activity, and presents results on a secure admin dashboard.

For the full feature backlog, see [IMPLEMENTATION.md](IMPLEMENTATION.md).

**Windows 11:** see [WINDOWS_INSTALL.md](WINDOWS_INSTALL.md) (use `start.ps1` on PowerShell, `start.sh` in Git Bash only).

---

## Prerequisites

- **Python 3.11+** (3.13 tested)
- **Neon PostgreSQL** database ([neon.tech](https://neon.tech))
- **Git** (optional)

On Debian/Ubuntu, install venv support if needed:

```bash
sudo apt install python3-venv python3-pip
```

---

## Installation

### 1. Clone and enter the project

```bash
cd network-traffic-analysis
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If `python3 -m venv` fails because `ensurepip` is missing, bootstrap pip into the venv:

```bash
python3 -m venv .venv
curl -fsSL https://bootstrap.pypa.io/get-pip.py -o get-pip.py
.venv/bin/python3 get-pip.py
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example file and edit it with your Neon credentials:

```bash
cp .env.example .env
```

Required values in `.env`:

```env
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require
SECRET_KEY=your-long-random-secret-key
API_BASE_URL=http://127.0.0.1:8000
AGENT_API_KEY=your-agent-api-key
```

Use the **pooled** Neon connection string and prefix it with `postgresql+psycopg://` (not just `postgresql://`).

The **same** `AGENT_API_KEY` must be set on the server and used by the traffic capture agent. It protects:
- `POST /api/traffic/logs` (traffic ingest)
- `POST /api/internal/detection/run` (agent-triggered detection)

Optional SMTP email alert settings:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=Network Monitor <your-email@gmail.com>
ALERT_EMAIL_TO=your-email@gmail.com
EMAIL_ALERTS_ENABLED=true
```

For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833), not your normal account password.

---

## Database Setup

Initialize tables and seed the default admin user:

```bash
export PYTHONPATH=src
python scripts/init_db.py
```

Or use the helper script:

```bash
./scripts/run.sh init-db
```

Default admin login:

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `Admin@123` |

Change this password before any production use.

---

## Running the Project

### One command (recommended)

From the project root:

```bash
./start.sh
```

This starts everything in the background:
- API server → http://127.0.0.1:8000
- Dashboard → http://localhost:8501
- Traffic capture agent (continuous monitoring)

Other commands:

```bash
./start.sh stop      # stop all services
./start.sh status    # check what's running
./start.sh restart   # restart everything
./start.sh logs      # tail all logs
./start.sh init-db   # initialize database
```

Logs are written to `.run/` (`api.log`, `dashboard.log`, `agent.log`).

---

### Manual mode (separate terminals)

Use this only if you want to run services individually for development:

```bash
source .venv/bin/activate
export PYTHONPATH=src
```

```bash
# Terminal 1 — API
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2 — Dashboard
streamlit run dashboard/app.py

# Terminal 3 — Agent
python agent/capture.py --daemon
```

Configure the agent in `.env`:

```env
AGENT_MODE=sample
AGENT_INTERVAL_SECONDS=5
AGENT_BATCH_SIZE=5
AGENT_INTERFACE=eth0
```

### One-shot agent (manual test data)

```bash
python agent/capture.py --mode sample --count 25
python agent/capture.py --mode live --interface eth0 --count 50
python agent/capture.py --mode scan --subnet-prefix 192.168.1.
```

### Production service (systemd)

Copy and edit `deploy/nta-agent.service`, then:

```bash
sudo cp deploy/nta-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nta-agent
```

---

## Quick Test Checklist

1. Open http://localhost:8501 and log in as `admin`
2. Run the sample agent to generate traffic logs
3. Refresh the dashboard — stats and charts should appear
4. Click **Run Detection Now** to generate anomaly alerts
5. Review alerts under the **Anomalies** page
6. Export logs as CSV from **Traffic Logs**

Health check:

```bash
curl http://127.0.0.1:8000/health
```

---

## Project Structure

```
network-traffic-analysis/
├── backend/main.py       # FastAPI REST API
├── dashboard/app.py      # Streamlit admin UI
├── agent/capture.py      # Traffic capture agent
├── src/nta/              # Core models, auth, detection
├── scripts/              # init-db and run helpers
├── requirements.txt
├── .env.example
└── IMPLEMENTATION.md     # Build backlog
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `No module named 'nta'` | Run `export PYTHONPATH=src` |
| Database connection error | Check `DATABASE_URL` in `.env`; use `postgresql+psycopg://` |
| Dashboard can't reach API | Ensure API is running; check `API_BASE_URL` |
| `python3 -m venv` fails | Install `python3-venv` or use the get-pip bootstrap above |
| Live capture fails | Run with sudo or grant `CAP_NET_RAW`; set correct `--interface` |
| Agent gets 401 errors | Set matching `AGENT_API_KEY` in `.env` and restart all services |

---

## Security Notes

- Never commit `.env` — it is gitignored
- Keep real credentials out of `.env.example`
- Traffic ingest requires the `X-Agent-Api-Key` header (`AGENT_API_KEY` in `.env`)
- Replace the default admin password after first login
