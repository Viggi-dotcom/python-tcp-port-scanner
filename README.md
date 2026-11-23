# PyPortScan-Lab: Python-Based TCP Network Port Scanner & Security Dashboard

A modern, full-stack cybersecurity auditing utility and lab companion combining a high-performance **Python multi-threaded TCP socket scanner** with a **Next.js 16 (React 19) + Tailwind CSS** interactive web console and **PostgreSQL (Drizzle ORM)** audit database.

Designed for security researchers, network engineers, CTF participants, and lab students to audit authorized local targets, Docker containers, and virtual machines (e.g., Metasploitable, VirtualBox host-only networks).

---

## 🌟 Key Features

- **Multi-Threaded TCP Port Scanning**:
  - Python socket implementation using `concurrent.futures.ThreadPoolExecutor` for parallel connection handshakes.
  - Configurable socket timeouts, thread counts (up to 100), and custom port specifications (e.g. `22,80,443` or `1-1024`).
- **Active & Passive Banner Grabbing**:
  - Probes open ports with standard HTTP/TLS/FTP/SSH handshake requests to extract service banners.
  - Provides raw hex inspection alongside decoded ASCII banners.
- **Port State & Risk Analysis**:
  - Classifies ports into `open`, `closed`, or `filtered`.
  - Maps ports against standard well-known service registries and flags risk levels (`info`, `low`, `medium`, `high`) with remediation security notes.
- **Interactive Web Dashboard**:
  - Real-time scan controls with pre-configured port profiles (*Lab Signature, VBox Vuln Audit, Web & App Stack, DB & Cache, System 1-100*).
  - Target inventory management to track authorized lab machines and virtual targets.
  - Interactive results inspector with hex view, banner preview, risk badges, and latency metrics.
- **Exporting & Reporting**:
  - One-click report generation and downloads in **JSON**, **CSV**, and formatted **TXT** formats.
- **CLI & Dual Execution**:
  - Can be run as a standalone Python CLI tool or orchestrated seamlessly through the web UI via Next.js server endpoints.

---

## 🏗️ Architecture

```
python-tcp-port-scanner/
├── scripts/
│   └── scanner.py             # Core Python TCP socket scanner & banner grabber
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── scan/          # API route executing scanner.py subprocess
│   │   │   ├── scans/         # History & scan record retrieval
│   │   │   ├── targets/       # Lab target configuration & management
│   │   │   ├── source/        # API to inspect/download scanner.py
│   │   │   └── health/        # Service health check endpoint
│   │   ├── globals.css        # Tailwind styles & dark mode palette
│   │   ├── layout.tsx         # Root layout
│   │   └── page.tsx           # Full interactive scanner dashboard UI
│   └── db/
│       ├── schema.ts          # Drizzle ORM PostgreSQL schema
│       ├── seed.ts            # Default targets and lab profile seed data
│       └── index.ts           # PostgreSQL connection pool
├── drizzle.config.json        # Drizzle config
├── package.json               # Next.js dependencies & scripts
└── tsconfig.json              # TypeScript configuration
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**: Verify with `python --version` (or `python3`).
- **Node.js 18+ & npm**: Verify with `node -v` and `npm -v`.
- **PostgreSQL**: Running instance (local service or Docker).

---

### Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Viggi-dotcom/python-tcp-port-scanner.git
   cd python-tcp-port-scanner
   ```

2. **Install Node Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the project root:
   ```env
   DATABASE_URL=postgresql://<username>:<password>@127.0.0.1:5432/app_db
   ```
   *(Ensure the target database exists in PostgreSQL or let the initial startup initialize tables automatically).*

4. **Run the Development Server**:
   ```bash
   npm run dev
   ```

5. **Open the Application**:
   Navigate to [http://localhost:3000](http://localhost:3000) in your browser.

---

## 💻 Standalone Python CLI Usage

The core scanner engine can also be executed directly from the terminal without the web server:

### Basic Scan
```bash
python scripts/scanner.py --host 127.0.0.1 --ports 22,80,443,3000,5432,8080
```

### Full Lab Range with Banner Grabbing & Threading
```bash
python scripts/scanner.py --host 127.0.0.1 --ports 1-1024 --timeout 400 --threads 30 --banner
```

### Output to Structured Reports
```bash
# JSON output to stdout
python scripts/scanner.py --host 192.168.56.101 --ports 21,22,80,3306 --format json

# Export to CSV and Text files simultaneously
python scripts/scanner.py --host 127.0.0.1 --ports 80,443,8080 --csv-out scan_report.csv --txt-out scan_report.txt
```

### CLI Command Options
| Flag | Description | Default |
|---|---|---|
| `--host`, `-H` | Target IP address or hostname to scan *(required)* | - |
| `--ports`, `-p` | Port specification (e.g. `1-1024` or `22,80,443`) | `1-1024` |
| `--timeout`, `-t` | Socket timeout in milliseconds | `500` |
| `--threads`, `-c` | Worker threads for concurrent socket scanning | `20` |
| `--banner`, `-b` | Enable service banner grabbing and hex extraction | Enabled |
| `--no-banner` | Disable banner grabbing for faster scans | - |
| `--format`, `-f` | Output format: `json`, `text`, or `csv` | `json` |
| `--csv-out` | File path to write a structured CSV scan report | - |
| `--txt-out` | File path to write a formatted TXT security report | - |

---

## 🖥️ Web Interface Features

- **Port Presets**: Instantly load targeted port lists for Web Stacks, Databases, Vulnerability Labs, or System ranges.
- **Latency & Risk Metrics**: Real-time breakdown of response latencies, open/closed/filtered distribution, and identified service security risks.
- **Banner Inspector**: View HTTP headers, SSH identification strings, FTP banners, and hexadecimal representation of returned payloads.
- **Scan History**: Keep historical logs of prior scans with search and filter capabilities.
- **One-Click Export**: Export results directly to CSV, JSON, or Plain Text format from the web UI.

---

## 🔒 Security & Compliance Disclaimer

> **Disclaimer**: This tool is designed strictly for educational purposes, security research, local test environments, and authorized penetration testing on systems you own or have explicit permission to test. Unauthorized port scanning or banner grabbing against unauthorized networks or systems may violate applicable laws and regulations.
