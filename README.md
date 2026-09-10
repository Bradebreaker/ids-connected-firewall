# IDS-Connected Firewall

A full-stack **Intrusion Detection System (IDS)** integrated with automated **firewall enforcement**, built as a computer networking academic project.

This is a genuinely functional security tool — it performs real packet analysis using Scapy, enforces real iptables rules, and provides a real-time web dashboard for monitoring and management.

---

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Scapy     │     │  Detection       │     │   Decision      │
│   Packet    │────▶│  Engine          │────▶│   Engine        │
│   Sniffer   │     │  (4 detectors)   │     │  (severity +    │
│             │     │                  │     │   whitelist)    │
└─────────────┘     └──────────────────┘     └───────┬─────────┘
                                                     │
                    ┌────────────────────────────────┬┘
                    ▼                                ▼
            ┌──────────────┐              ┌──────────────────┐
            │  Firewall    │              │   SQLite         │
            │  Manager     │◀────sync────▶│   Database       │
            │  (iptables)  │              │                  │
            └──────────────┘              └────────┬─────────┘
                                                   │
                                          ┌────────▼─────────┐
                                          │   FastAPI         │
                                          │   Backend         │
                                          │  (REST + WS)     │
                                          └────────┬─────────┘
                                                   │
                                          ┌────────▼─────────┐
                                          │   Web Dashboard   │
                                          │  (HTML/CSS/JS)   │
                                          └──────────────────┘
```

### Detection → Decision → Enforcement Pipeline

1. **Packet Sniffer** (`sniffer/`) captures live network traffic using Scapy in a background thread
2. **Detection Engine** (`detection/`) runs every packet through 4 independent detectors:
   - **Signature-based**: regex matching for SQL injection, XSS, command injection, etc.
   - **Port Scan**: tracks distinct ports per source IP in sliding time window
   - **Brute Force**: monitors connection attempts to sensitive ports (SSH, RDP, etc.)
   - **SYN Flood**: statistical anomaly detection using rolling mean + standard deviation
3. **Decision Engine** (`decision/`) evaluates each alert:
   - Checks the **whitelist** — localhost and management IP are NEVER blocked
   - Evaluates **severity threshold** — only medium+ triggers auto-block
   - High severity → permanent block, Medium → temporary block with TTL
4. **Firewall Manager** (`firewall/`) enforces rules in iptables via a custom chain
5. **Database** stores all alerts, rules, and blocked IPs in SQLite
6. **WebSocket** pushes live updates to all connected dashboard clients

---

## ⚠️ Requirements

> **This project requires Linux with root/sudo privileges.**
>
> - Scapy needs `CAP_NET_RAW` for packet capture
> - iptables requires root for firewall rule management
> - The sniffer and firewall features will not work on Windows/macOS

### System Requirements

- **OS**: Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+)
- **Python**: 3.10 or higher
- **iptables**: installed (comes pre-installed on most Linux distros)
- **Root access**: required for packet capture and firewall management

---

## Quick Start

### 1. Clone the project

```bash
cd /path/to/cn-project
```

### 2. Set up a virtual environment (Recommended)

To avoid conflicts with system packages, create and activate a virtual environment:

**On Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**On Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 3. (Optional) Configure settings

Copy and edit the environment file:

```bash
cp .env.example .env
# Edit .env to set your management IP, JWT secret, etc.
```

### 4. Run the application

**On Linux (Requires Root for Sniffer & Firewall):**
```bash
sudo venv/bin/python main.py
```
*(Note: If you activate the venv and run `sudo python3 main.py`, sudo might use the system Python instead of the venv Python. Specifying the path `sudo venv/bin/python` ensures it uses the packages you just installed.)*

**On Windows (Demo / Simulation Mode):**
```powershell
python main.py
```
*(Note: Packet sniffing and iptables management will be automatically disabled, but the web dashboard and API will function fully.)*

### 4. Access the dashboard

Open `http://<server-ip>:8000` in your browser.

**Default credentials:** `admin` / `admin123`

> ⚠️ **Change the default password after first login!**

---

## Project Structure

```
cn project/
├── main.py                      # FastAPI entry point + lifespan
├── config.py                    # Central configuration
├── requirements.txt             # Python dependencies
│
├── db/                          # Database layer
│   ├── database.py              # SQLAlchemy async engine
│   ├── models.py                # ORM models (Alert, FirewallRule, BlockedIP, User)
│   └── schemas.py               # Pydantic request/response models
│
├── sniffer/                     # Packet capture
│   └── capture.py               # Scapy sniffer (runs in background thread)
│
├── detection/                   # IDS detection engine
│   ├── base.py                  # Abstract BaseDetector class
│   ├── signature.py             # Regex-based payload matching
│   ├── port_scan.py             # Sliding window port scan detection
│   ├── brute_force.py           # Brute-force login detection
│   └── syn_flood.py             # Statistical SYN flood detection
│
├── decision/                    # Decision engine
│   └── engine.py                # Severity scoring + whitelist + block decisions
│
├── firewall/                    # Firewall management
│   ├── manager.py               # iptables CRUD via subprocess
│   ├── sync.py                  # DB ↔ iptables reconciliation
│   └── scheduler.py             # APScheduler auto-expiry of temp blocks
│
├── api/                         # FastAPI routes
│   ├── auth.py                  # JWT + bcrypt utilities
│   ├── dependencies.py          # FastAPI dependency injection
│   ├── websocket_manager.py     # WebSocket broadcast manager
│   ├── routes_auth.py           # Login / register endpoints
│   ├── routes_alerts.py         # Alert list + WebSocket stream
│   ├── routes_firewall.py       # Rule CRUD + block/unblock
│   └── routes_stats.py          # Dashboard statistics
│
├── static/                      # Frontend
│   ├── css/dashboard.css        # Advanced dark theme CSS
│   ├── js/
│   │   ├── app.js               # Dashboard + WebSocket client
│   │   ├── auth.js              # Login page logic
│   │   └── firewall.js          # Rule editor logic
│   └── pages/
│       ├── index.html           # Main dashboard
│       ├── login.html           # Login page
│       ├── blocked.html         # Blocked IP management
│       └── rules.html           # Firewall rule editor
│
└── logs/                        # JSON structured log output
```

---

## API Endpoints

| Method | Endpoint            | Description                  | Auth |
|--------|---------------------|------------------------------|------|
| POST   | `/api/login`        | Authenticate, get JWT token  | No   |
| POST   | `/api/register`     | Register new user (admin)    | Yes  |
| GET    | `/api/alerts`       | List alerts (filtered)       | Yes  |
| WS     | `/ws/alerts`        | Live alert WebSocket stream  | Yes  |
| GET    | `/api/rules`        | List firewall rules          | Yes  |
| POST   | `/api/rules`        | Create manual rule           | Yes  |
| PUT    | `/api/rules/{id}`   | Update rule                  | Yes  |
| DELETE | `/api/rules/{id}`   | Delete rule                  | Yes  |
| GET    | `/api/blocked`      | List blocked IPs             | Yes  |
| POST   | `/api/block`        | Manually block an IP         | Yes  |
| POST   | `/api/unblock`      | Manually unblock an IP       | Yes  |
| GET    | `/api/stats`        | Dashboard statistics         | Yes  |

---

## Testing / Demo

### Trigger port scan detection:
```bash
nmap -sS -p 1-1000 <server-ip>
```

### Trigger brute force detection:
```bash
# Rapid SSH connection attempts
for i in $(seq 1 20); do ssh -o ConnectTimeout=1 user@<server-ip>; done
```

### Trigger SYN flood detection:
```bash
hping3 --syn --flood -p 80 <server-ip>
```

### Trigger signature detection:
```bash
curl "http://<server-ip>:8000/?q=1' OR 1=1--"
curl "http://<server-ip>:8000/?q=<script>alert(1)</script>"
```

### Verify iptables enforcement:
```bash
sudo iptables -L IDS_FIREWALL -n --line-numbers -v
```

---

## Key Design Decisions

1. **Custom iptables chain** (`IDS_FIREWALL`): Prevents accidentally flushing the host's own rules during reconciliation.

2. **Whitelist safety**: The decision engine and firewall manager both independently verify the whitelist before blocking — defense in depth.

3. **Async throughout**: Scapy runs in a thread, all API endpoints are `async def`, the scheduler uses `AsyncIOScheduler` — nothing blocks the event loop.

4. **DB as source of truth**: The reconciliation function rebuilds iptables from the database, ensuring they never drift apart.

5. **Modular detectors**: Each detector is an independent class inheriting from `BaseDetector`, making them individually testable and hot-swappable.

---

## License

Academic project — for educational purposes only.
