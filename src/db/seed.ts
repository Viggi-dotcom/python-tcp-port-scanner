import { db, pool } from "@/db";
import { labTargets, scans, portResults } from "@/db/schema";
import { count } from "drizzle-orm";

let initialized = false;

export async function ensureDbSeeded() {
  if (initialized) return;

  try {
    // Ensure tables exist via idempotent DDL in case drizzle-kit push hasn't run yet
    await pool.query(`
      CREATE TABLE IF NOT EXISTS lab_targets (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        environment TEXT NOT NULL,
        os_profile TEXT NOT NULL,
        default_ports TEXT NOT NULL,
        description TEXT NOT NULL,
        authorized BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        target_host TEXT NOT NULL,
        target_label TEXT NOT NULL DEFAULT 'Authorized Lab Node',
        port_range TEXT NOT NULL,
        timeout_ms INTEGER NOT NULL DEFAULT 500,
        threads INTEGER NOT NULL DEFAULT 20,
        grab_banner BOOLEAN NOT NULL DEFAULT TRUE,
        status TEXT NOT NULL DEFAULT 'completed',
        open_count INTEGER NOT NULL DEFAULT 0,
        closed_count INTEGER NOT NULL DEFAULT 0,
        filtered_count INTEGER NOT NULL DEFAULT 0,
        total_ports_scanned INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0,
        cli_command TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS port_results (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'TCP',
        state TEXT NOT NULL,
        service TEXT NOT NULL DEFAULT 'unknown',
        banner TEXT,
        raw_hex TEXT,
        latency_ms INTEGER,
        security_notes TEXT,
        risk_level TEXT NOT NULL DEFAULT 'info'
      );
    `);

    const [{ value: targetCount }] = await db
      .select({ value: count() })
      .from(labTargets);

    if (targetCount === 0) {
      await db.insert(labTargets).values([
        {
          name: "Localhost Loopback Node (lo0)",
          host: "127.0.0.1",
          environment: "Local System Loopback",
          osProfile: "Debian GNU/Linux 12 (bookworm) Kernel 6.x",
          defaultPorts: "21,22,80,443,3000,5432,6379,8080",
          description:
            "Primary local host system running real OpenSSH, PostgreSQL 15+, Next.js App Server, and local lab listeners.",
          authorized: true,
        },
        {
          name: "Metasploitable2 Lab VM",
          host: "192.168.56.101",
          environment: "VirtualBox Host-Only (vboxnet0)",
          osProfile: "Ubuntu 8.04 LTS Server (x86_64 Vulnerability Testbed)",
          defaultPorts:
            "21,22,23,25,80,111,139,445,512,1524,2121,3306,5432,5900,6667,8180",
          description:
            "Intentionally vulnerable VirtualBox training VM exposing legacy FTP, Telnet, Apache 2.2, Tomcat 5.5, and bind shells.",
          authorized: true,
        },
        {
          name: "DVWA Web Security Node",
          host: "192.168.56.102",
          environment: "VirtualBox Host-Only (vboxnet0)",
          osProfile: "Ubuntu 22.04.4 LTS (Apache 2.4 / MySQL 8.0)",
          defaultPorts: "22,25,80,443,3306,3389,8080",
          description:
            "Damn Vulnerable Web Application & OWASP JuiceShop container host inside isolated VirtualBox subnet.",
          authorized: true,
        },
        {
          name: "Internal Infra & DB Bastion",
          host: "192.168.56.105",
          environment: "VirtualBox Host-Only (vboxnet0)",
          osProfile: "Alpine Linux v3.19 Hardened Bastion",
          defaultPorts: "21,22,23,53,443,445,5432,6379,9000",
          description:
            "Core infrastructure node hosting BIND9 DNS, Caddy TLS Proxy, PostgreSQL 16, Redis 7.2, and Portainer.",
          authorized: true,
        },
        {
          name: "VirtualBox NAT Sandbox Gateway",
          host: "10.0.2.15",
          environment: "VirtualBox NAT Network (eth0)",
          osProfile: "Ubuntu 23.10 Guest NAT Interface",
          defaultPorts: "22,80,135,139,443,445,3389,8000",
          description:
            "Standard VirtualBox default guest NAT address running OpenSSH, lighttpd, and FastAPI telemetry service.",
          authorized: true,
        },
      ]);
    }

    const [{ value: scanCount }] = await db
      .select({ value: count() })
      .from(scans);

    if (scanCount === 0) {
      // Seed 2 realistic completed scans so the workbench is immediately populated
      const [localScan] = await db
        .insert(scans)
        .values({
          targetHost: "127.0.0.1",
          targetLabel: "Localhost Loopback Node (lo0)",
          portRange: "21,22,80,443,3000,5432,6379,8080",
          timeoutMs: 400,
          threads: 20,
          grabBanner: true,
          status: "completed",
          openCount: 7,
          closedCount: 1,
          filteredCount: 0,
          totalPortsScanned: 8,
          durationMs: 24,
          cliCommand:
            'python3 scripts/scanner.py --host 127.0.0.1 --ports "21,22,80,443,3000,5432,6379,8080" --timeout 400 --threads 20 --banner',
        })
        .returning();

      await db.insert(portResults).values([
        {
          scanId: localScan.id,
          port: 21,
          protocol: "TCP",
          state: "open",
          service: "ftp",
          banner: "220 pyftpdlib 1.5.9 (Authorized Local Lab FTP Server) ready.",
          rawHex:
            "32 32 30 20 70 79 66 74 70 64 6c 69 62 20 31 2e 35 2e 39 20 28 41 75 74 68 6f 72 69 7a 65 64 20 4c 6f 63 61 6c 20 4c 61 62",
          latencyMs: 1,
          securityNotes:
            "Cleartext FTP control port; credentials and files transmitted unencrypted.",
          riskLevel: "high",
        },
        {
          scanId: localScan.id,
          port: 22,
          protocol: "TCP",
          state: "open",
          service: "ssh",
          banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u10",
          rawHex:
            "53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48 5f 39 2e 32 70 31 20 44 65 62 69 61 6e 2d 32 2b 64 65 62 31 32 75 31 30 0d 0a",
          latencyMs: 1,
          securityNotes:
            "OpenSSH daemon active; verify PublicKeyAuthentication and Fail2Ban.",
          riskLevel: "info",
        },
        {
          scanId: localScan.id,
          port: 80,
          protocol: "TCP",
          state: "open",
          service: "http",
          banner:
            "HTTP/1.1 200 OK | Server: nginx/1.24.0 (Debian) | X-Lab-Node: localhost-loopback",
          rawHex:
            "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 53 65 72 76 65 72 3a 20 6e 67 69 6e 78 2f 31 2e 32 34 2e 30",
          latencyMs: 2,
          securityNotes:
            "Unencrypted HTTP web service; inspect headers and enforce HTTPS redirect.",
          riskLevel: "low",
        },
        {
          scanId: localScan.id,
          port: 443,
          protocol: "TCP",
          state: "closed",
          service: "https",
          banner: "",
          rawHex: "",
          latencyMs: 1,
          securityNotes:
            "TCP RST received; no listening daemon bound to port.",
          riskLevel: "info",
        },
        {
          scanId: localScan.id,
          port: 3000,
          protocol: "TCP",
          state: "open",
          service: "http-app (Next.js)",
          banner: "HTTP/1.1 200 OK | X-Powered-By: Next.js",
          rawHex:
            "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 58 2d 50 6f 77 65 72 65 64 2d 42 79 3a 20 4e 65 78 74 2e 6a 73",
          latencyMs: 2,
          securityNotes:
            "Active local web application server responding on port 3000.",
          riskLevel: "info",
        },
        {
          scanId: localScan.id,
          port: 5432,
          protocol: "TCP",
          state: "open",
          service: "postgresql",
          banner: "PostgreSQL Wire Protocol (SSL: supported)",
          rawHex:
            "50 6f 73 74 67 72 65 53 51 4c 20 57 69 72 65 20 50 72 6f 74 6f 63 6f 6c 20 28 53 53 4c 3a 20 73 75 70 70 6f 72 74 65 64 29",
          latencyMs: 1,
          securityNotes:
            "PostgreSQL database socket active; verify pg_hba.conf restricts remote hosts.",
          riskLevel: "low",
        },
        {
          scanId: localScan.id,
          port: 6379,
          protocol: "TCP",
          state: "open",
          service: "redis",
          banner:
            "-NOAUTH Authentication required (Redis 7.2.4 Lab Instance)",
          rawHex:
            "2d 4e 4f 41 55 54 48 20 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 72 65 71 75 69 72 65 64",
          latencyMs: 1,
          securityNotes:
            "Redis TCP interface reachable; ensure loopback binding and ACL password protection.",
          riskLevel: "medium",
        },
        {
          scanId: localScan.id,
          port: 8080,
          protocol: "TCP",
          state: "open",
          service: "http-proxy",
          banner:
            "HTTP/1.1 200 OK | Server: Werkzeug/3.0.1 Python/3.11.2 | X-Service: Local-Telemetry-Agent",
          rawHex:
            "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 53 65 72 76 65 72 3a 20 57 65 72 6b 7a 65 75 67 2f 33 2e 30 2e 31",
          latencyMs: 1,
          securityNotes:
            "Apache Tomcat / Alternative HTTP application listener.",
          riskLevel: "low",
        },
      ]);

      const [vboxScan] = await db
        .insert(scans)
        .values({
          targetHost: "192.168.56.101",
          targetLabel: "Metasploitable2 Lab VM (vboxnet0)",
          portRange: "21,22,23,25,80,111,139,445,1524,2121,3306,5432,5900,8180",
          timeoutMs: 400,
          threads: 25,
          grabBanner: true,
          status: "completed",
          openCount: 12,
          closedCount: 0,
          filteredCount: 2,
          totalPortsScanned: 14,
          durationMs: 68,
          cliCommand:
            'python3 scripts/scanner.py --host 192.168.56.101 --ports "21,22,23,25,80,111,139,445,1524,2121,3306,5432,5900,8180" --timeout 400 --threads 25 --banner',
        })
        .returning();

      await db.insert(portResults).values([
        {
          scanId: vboxScan.id,
          port: 21,
          protocol: "TCP",
          state: "open",
          service: "ftp (vsFTPd 2.3.4)",
          banner: "220 (vsFTPd 2.3.4)",
          rawHex: "32 32 30 20 28 76 73 46 54 50 64 20 32 2e 33 2e 34 29 0d 0a",
          latencyMs: 1,
          securityNotes:
            "CRITICAL: vsFTPd 2.3.4 contains known smiley-face backdoor (CVE-2011-2523).",
          riskLevel: "high",
        },
        {
          scanId: vboxScan.id,
          port: 22,
          protocol: "TCP",
          state: "open",
          service: "ssh (OpenSSH 4.7p1)",
          banner: "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1",
          rawHex:
            "53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48 5f 34 2e 37 70 31 20 44 65 62 69 61 6e 2d 38 75 62 75 6e 74 75 31 0d 0a",
          latencyMs: 1,
          securityNotes:
            "Outdated OpenSSH 4.7p1 build detected; upgrade to mitigate legacy key vulnerability.",
          riskLevel: "medium",
        },
        {
          scanId: vboxScan.id,
          port: 23,
          protocol: "TCP",
          state: "open",
          service: "telnet",
          banner: "..... | Metasploitable2-Linux login:",
          rawHex:
            "ff fd 18 ff fd 20 0d 0a 4d 65 74 61 73 70 6c 6f 69 74 61 62 6c 65 32 2d 4c 69 6e 75 78 20 6c 6f 67 69 6e 3a 20",
          latencyMs: 2,
          securityNotes:
            "Legacy cleartext Telnet daemon; replace immediately with SSHv2.",
          riskLevel: "high",
        },
        {
          scanId: vboxScan.id,
          port: 25,
          protocol: "TCP",
          state: "open",
          service: "smtp",
          banner: "220 metasploitable.localdomain ESMTP Postfix (Ubuntu)",
          rawHex:
            "32 32 30 20 6d 65 74 61 73 70 6c 6f 69 74 61 62 6c 65 2e 6c 6f 63 61 6c 64 6f 6d 61 69 6e 20 45 53 4d 54 50",
          latencyMs: 2,
          securityNotes:
            "SMTP mail relay; inspect for open relay and STARTTLS enforcement.",
          riskLevel: "medium",
        },
        {
          scanId: vboxScan.id,
          port: 80,
          protocol: "TCP",
          state: "open",
          service: "http (Apache 2.2.8)",
          banner:
            "HTTP/1.1 200 OK | Server: Apache/2.2.8 (Ubuntu) DAV/2 | X-Powered-By: PHP/5.2.4-2ubuntu5.10",
          rawHex:
            "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 53 65 72 76 65 72 3a 20 41 70 61 63 68 65 2f 32 2e 32 2e 38",
          latencyMs: 2,
          securityNotes:
            "End-of-Life Apache 2.2.8 / PHP 5.2 stack exposed; multiple remote code execution CVEs.",
          riskLevel: "high",
        },
        {
          scanId: vboxScan.id,
          port: 111,
          protocol: "TCP",
          state: "open",
          service: "rpcbind",
          banner: "......*o......rpcbind-v2-sunrpc",
          rawHex: "80 00 00 1c 2a 6f 91 02 00 00 00 01 72 70 63 62 69 6e 64",
          latencyMs: 1,
          securityNotes:
            "Portmapper / SunRPC service; common enumeration vector in lab VMs.",
          riskLevel: "medium",
        },
        {
          scanId: vboxScan.id,
          port: 139,
          protocol: "TCP",
          state: "filtered",
          service: "netbios-ssn",
          banner: "",
          rawHex: "",
          latencyMs: 400,
          securityNotes:
            "Packet dropped by host firewall / iptables DROP rule (timeout expired).",
          riskLevel: "info",
        },
        {
          scanId: vboxScan.id,
          port: 445,
          protocol: "TCP",
          state: "filtered",
          service: "microsoft-ds",
          banner: "",
          rawHex: "",
          latencyMs: 400,
          securityNotes:
            "Packet dropped by host firewall / iptables DROP rule (timeout expired).",
          riskLevel: "info",
        },
        {
          scanId: vboxScan.id,
          port: 1524,
          protocol: "TCP",
          state: "open",
          service: "ingreslock",
          banner: "root@metasploitable:/# id -> uid=0(root) gid=0(root)",
          rawHex:
            "72 6f 6f 74 40 6d 65 74 61 73 70 6c 6f 69 74 61 62 6c 65 3a 2f 23 20 69 64 20 2d 3e 20 75 69 64 3d 30 28 72 6f 6f 74 29",
          latencyMs: 1,
          securityNotes:
            "Metasploitable root bind shell backdoor port; immediate incident risk.",
          riskLevel: "high",
        },
        {
          scanId: vboxScan.id,
          port: 2121,
          protocol: "TCP",
          state: "open",
          service: "ccproxy-ftp",
          banner:
            "220 ProFTPD 1.3.1 Server (Debian) [::ffff:192.168.56.101]",
          rawHex:
            "32 32 30 20 50 72 6f 46 54 50 44 20 31 2e 33 2e 31 20 53 65 72 76 65 72",
          latencyMs: 1,
          securityNotes:
            "Secondary FTP lab daemon; verify anonymous login permissions.",
          riskLevel: "medium",
        },
        {
          scanId: vboxScan.id,
          port: 3306,
          protocol: "TCP",
          state: "open",
          service: "mysql",
          banner: "5.0.51a-3ubuntu5. | ...mysql_native_password",
          rawHex:
            "35 2e 30 2e 35 31 61 2d 33 75 62 75 6e 74 75 35 00 0a 00 00 00 6d 79 73 71 6c",
          latencyMs: 2,
          securityNotes:
            "MySQL / MariaDB database listener; restrict bind-address to loopback.",
          riskLevel: "medium",
        },
        {
          scanId: vboxScan.id,
          port: 5432,
          protocol: "TCP",
          state: "open",
          service: "postgresql",
          banner: "PostgreSQL Wire Protocol (SSL: disabled / SCRAM-SHA-256 ready)",
          rawHex:
            "50 6f 73 74 67 72 65 53 51 4c 20 57 69 72 65 20 50 72 6f 74 6f 63 6f 6c",
          latencyMs: 2,
          securityNotes:
            "PostgreSQL database socket active; verify pg_hba.conf restricts remote hosts.",
          riskLevel: "low",
        },
        {
          scanId: vboxScan.id,
          port: 5900,
          protocol: "TCP",
          state: "open",
          service: "vnc",
          banner: "RFB 003.003",
          rawHex: "52 46 42 20 30 30 33 2e 30 30 33 0a",
          latencyMs: 1,
          securityNotes:
            "Virtual Network Computing (VNC) remote desktop; often weak password auth.",
          riskLevel: "high",
        },
        {
          scanId: vboxScan.id,
          port: 8180,
          protocol: "TCP",
          state: "open",
          service: "tomcat",
          banner:
            "HTTP/1.1 200 OK | Server: Apache-Coyote/1.1 (Tomcat 5.5)",
          rawHex:
            "48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 53 65 72 76 65 72 3a 20 41 70 61 63 68 65 2d 43 6f 79 6f 74 65",
          latencyMs: 2,
          securityNotes:
            "Apache Tomcat administrative HTTP connector; audit default tomcat:tomcat creds.",
          riskLevel: "medium",
        },
      ]);
    }

    initialized = true;
  } catch (err) {
    console.error("Database seed warning:", err);
  }
}
