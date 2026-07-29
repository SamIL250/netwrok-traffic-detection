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

After installing, **disable the Microsoft Store Python shortcuts** (they hijack the `python` command):

1. Open **Settings → Apps → Advanced app settings → App execution aliases**
2. Turn **Off** both **python.exe** and **python3.exe**

On Windows, prefer the **`py`** launcher until the virtual environment is active:

```powershell
py --version
```

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

Extract the project folder, then open PowerShell **inside that folder** (see below).

### Open PowerShell in the project folder (important)

Your terminal must **not** stay in `C:\WINDOWS\system32`. Use one of these:

**From File Explorer**

1. Open the `network-traffic-analysis` folder.
2. Click the address bar, type `powershell`, press Enter.

**From VS Code / Cursor**

1. Open the project folder: **File → Open Folder** → select `network-traffic-analysis`.
2. Open the integrated terminal: **Terminal → New Terminal** (`` Ctrl+` ``).

**Check you are in the right place** — the prompt should end with your project path, for example:

```text
PS C:\Users\YourName\development\network-traffic-analysis>
```

Verify the project files exist:

```powershell
dir
```

You should see `requirements.txt`, `dashboard`, `backend`, and `.env.example`.

---

## 2. Create a virtual environment

In **PowerShell**, make sure you are in the **project root** (not `C:\WINDOWS\system32`), then run:

```powershell
cd C:\Users\YourName\path\to\network-traffic-analysis
py -m venv .venv
```

If `py` is also not found, install Python from [python.org/downloads](https://www.python.org/downloads/) first, then retry.

Confirm the venv was created:

```powershell
dir .venv\Scripts\python.exe
```

If that file exists, activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If activation is blocked by execution policy, run this **once**, then try activate again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Alternative activation syntax (same result):

```powershell
& .\.venv\Scripts\Activate.ps1
```

Your prompt should show `(.venv)` at the start, for example:

```text
(.venv) PS C:\Users\YourName\...\network-traffic-analysis>
```

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
.\.venv\Scripts\python.exe scripts\init_db.py
```

Use `.\.venv\Scripts\python.exe` if bare `python` still opens the Microsoft Store.

**Before running**, confirm `.env` exists and has a real Neon URL (not the placeholder):

```powershell
dir .env
Select-String -Path .env -Pattern "^DATABASE_URL="
```

You should see something like:

```text
DATABASE_URL=postgresql+psycopg://...@ep-xxx.region.aws.neon.tech/neondb?sslmode=require
```

If you only see `localhost` in the error, `.env` is missing or `DATABASE_URL` was never set. Neon gives `postgresql://` — change it to **`postgresql+psycopg://`**.

Default admin login:

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `Admin@123` |

You will be prompted to change this password on first sign-in.

---

## 6. Run the application

### Important: `.sh` files do not run in PowerShell

| What you tried | What happens |
|----------------|--------------|
| Double-click `start.sh` | Windows asks which app should open the file |
| `.\start.sh` in **PowerShell** | Same — PowerShell does not run Bash scripts |
| `./start.sh` in **Git Bash** | Works |

On Windows, use **`start.ps1`** in PowerShell (below), or use **Git Bash** for `start.sh`.

---

### Option A — PowerShell (recommended on Windows)

Open **PowerShell in the project folder**, activate the venv, then:

```powershell
cd C:\Users\Maggi\Desktop\network-traffic-analysis
.\.venv\Scripts\Activate.ps1
.\start.ps1
```

Other commands:

```powershell
.\start.ps1 stop
.\start.ps1 status
.\start.ps1 restart
.\start.ps1 logs
.\start.ps1 init-db
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\start.ps1
```

Logs are written to `.run\` (`api.log`, `dashboard.log`, `agent.log`).

---

### Option B — Git Bash

If you installed **Git for Windows**, open **Git Bash** in the project folder:

```bash
./start.sh
```

The start script uses `.venv/Scripts/python.exe` on Windows (not system `python`).

If `./start.sh` exits after "Waiting for API..." and `api.log` says **Python was not found**, pull the latest code or use **`start.ps1`** in PowerShell instead.

Other commands:

```bash
./start.sh stop
./start.sh status
./start.sh restart
./start.sh logs
./start.sh init-db
```

---

### Option C — PowerShell (manual, three terminals)

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
| **Git Bash: `No module named 'nta'` in api.log** | Update the repo (fixed `PYTHONPATH` for Windows). Or use `.\start.ps1` in PowerShell. |
| **Git Bash: API log says Python not found** | Old `run.sh` looked for Linux venv paths. Update the repo, or use `.\start.ps1` in PowerShell. |
| **`Python was not found` / opens Microsoft Store** | Install Python from [python.org](https://www.python.org/downloads/) (not the Store). Turn off **App execution aliases** for `python.exe` and `python3.exe`. Use `py --version`, then `py -m venv .venv`, or call `.\.venv\Scripts\python.exe` directly. |
| **`Activate.ps1` is not recognized** | You are in the wrong folder (often `C:\WINDOWS\system32`). Run `cd` to the project directory first. Confirm with `dir .venv\Scripts\Activate.ps1`. |
| **Windows asks how to open `.sh` file** | Do not double-click `start.sh`. Use `.\start.ps1` in PowerShell, or `./start.sh` in Git Bash only. |
| **Database connection to `localhost` failed** | Set `DATABASE_URL` in `.env` to your **Neon** cloud URL (`postgresql+psycopg://...`), not a local PostgreSQL install. |
| **`.venv` folder missing** | Run `py -m venv .venv` from the project root before activating. |
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
