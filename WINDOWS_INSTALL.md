# Windows 11 Installation Guide

Install and run the **Network Traffic Monitoring System** on a Windows 11 laptop.

For the general project overview, see [README.md](README.md).

---

## Prerequisites

Install these before starting:

| Tool | Purpose | Download |
|------|---------|----------|
| **Python 3.11+** | Runtime | [python.org/downloads](https://www.python.org/downloads/) |
| **Git for Windows** (recommended) | Clone repo + run `start.sh` via Git Bash | [git-scm.com/download/win](https://git-scm.com/download/win) |
| **Neon PostgreSQL** | Cloud database | [neon.tech](https://neon.tech) |
| **Npcap** (optional) | Live packet capture only | [npcap.com](https://npcap.com/) |

During Python setup, enable:

- **Add python.exe to PATH**
- **Install pip**

For local development on Windows, use **`AGENT_MODE=sample`** (no Npcap required).

---

## 1. Get the project

### Option A — Git

```powershell
cd C:\Users\YourName\development
git clone <your-repo-url> network-traffic-analysis
cd network-traffic-analysis
```

### Option B — ZIP

Extract the project folder, then open PowerShell in that directory.

---

## 2. Create a virtual environment

In **PowerShell** from the project root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Your prompt should show `(.venv)`.

---

## 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Configure environment

```powershell
copy .env.example .env
notepad .env
```

Required settings:

```env
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST/DATABASE?sslmode=require
SECRET_KEY=your-long-random-secret-key-here
API_BASE_URL=http://127.0.0.1:8000
AGENT_API_KEY=your-agent-api-key-here
AGENT_MODE=sample
```

Notes:

- Use your Neon connection string, but prefix it with **`postgresql+psycopg://`** (not `postgresql://`).
- The **same** `AGENT_API_KEY` is used by the API server and the traffic agent.
- Keep **`AGENT_MODE=sample`** on Windows unless you installed Npcap and configured a network interface.

Optional SMTP settings for email alerts are documented in [README.md](README.md).

---

## 5. Initialize the database

With the virtual environment active:

```powershell
$env:PYTHONPATH = "src"
python scripts\init_db.py
```

Default admin login:

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `Admin@123` |

You will be prompted to change this password on first sign-in.

---

## 6. Run the application

### Option A — Git Bash (recommended)

Open **Git Bash** in the project folder:

```bash
./start.sh
```

Other commands:

```bash
./start.sh stop
./start.sh status
./start.sh restart
./start.sh logs
./start.sh init-db
```

Logs are written to `.run\` (`api.log`, `dashboard.log`, `agent.log`).

### Option B — PowerShell (manual, three terminals)

Open **three PowerShell windows**. In each one:

```powershell
cd C:\path\to\network-traffic-analysis
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "src"
```

**Terminal 1 — API**

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Dashboard**

```powershell
streamlit run dashboard\app.py --server.port 8501
```

**Terminal 3 — Agent (sample mode)**

```powershell
python agent\capture.py --daemon
```

---

## 7. Open the app

| Service   | URL |
|-----------|-----|
| Dashboard | http://localhost:8501 |
| API       | http://127.0.0.1:8000 |
| Health check | http://127.0.0.1:8000/health |

Sign in with `admin` / `Admin@123`, then set a new password when prompted.

---

## Quick test checklist

1. Open http://localhost:8501 and sign in.
2. Wait a few seconds — the sample agent generates traffic automatically.
3. Open **Dashboard** — stats and charts should appear.
4. Open **Traffic Logs** and **Anomalies** to confirm data is flowing.
5. (Optional) Click **Run Detection Now** on the dashboard if you are signed in as admin or analyst.

Health check from PowerShell:

```powershell
curl http://127.0.0.1:8000/health
```

---

## Windows-specific notes

| Topic | Guidance |
|-------|----------|
| **Live packet capture** | Requires Npcap and an elevated (Administrator) terminal. Windows interfaces are often named like `\Device\NPF_{...}`, not `eth0`. Use sample mode for development. |
| **Firewall** | Allow Python through Windows Firewall for ports **8000** (API) and **8501** (dashboard) if connections fail. |
| **`No module named 'nta'`** | Set `$env:PYTHONPATH = "src"` before running Python commands. |
| **Database connection errors** | Verify `DATABASE_URL` format and that Neon allows connections from your network. |
| **Agent 401 errors** | Ensure `AGENT_API_KEY` in `.env` matches on server and agent; restart all services after changes. |
| **Login issues** | Hard-refresh the browser (Ctrl+Shift+R) or use a private/incognito window after password resets. |

---

## One-shot sample data (no daemon)

Useful for a quick manual test:

```powershell
$env:PYTHONPATH = "src"
python agent\capture.py --mode sample --count 25
```

---

## Security reminders

- Never commit `.env` — it contains secrets.
- Change the default admin password immediately after first login.
- Use strong, unique values for `SECRET_KEY` and `AGENT_API_KEY` outside local testing.

---

## Related docs

- [README.md](README.md) — general setup and project structure
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — feature backlog and deployment notes
