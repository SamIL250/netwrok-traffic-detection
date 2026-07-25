# Network Traffic Monitoring and Analysis System

A Python-based network monitoring system for educational institutions. It captures network traffic, detects suspicious activity, and presents results on a secure admin dashboard.

For the full feature backlog, see [IMPLEMENTATION.md](IMPLEMENTATION.md).

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
```

Use the **pooled** Neon connection string and prefix it with `postgresql+psycopg://` (not just `postgresql://`).

Optional SMS alert settings (Infobip):

```env
INFOBIP_BASE_URL=
INFOBIP_API_KEY=
INFOBIP_SENDER=
ALERT_PHONE_NUMBER=
```

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

---

## Security Notes

- Never commit `.env` — it is gitignored
- Keep real credentials out of `.env.example`
- Secure the traffic ingest endpoint before production (see IMPLEMENTATION.md)
- Replace the default admin password after first login
