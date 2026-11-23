import { NextRequest, NextResponse } from "next/server";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { db } from "@/db";
import { scans, portResults } from "@/db/schema";
import { ensureDbSeeded } from "@/db/seed";

const execFileAsync = promisify(execFile);

interface ScannerPortResult {
  port: number;
  protocol: string;
  state: "open" | "closed" | "filtered";
  service: string;
  banner: string;
  rawHex: string;
  latencyMs: number;
  securityNotes: string;
  riskLevel: "info" | "low" | "medium" | "high";
  source?: string;
}

interface ScannerOutput {
  timestamp: string;
  targetHost: string;
  targetLabel: string;
  portRange: string;
  timeoutMs: number;
  threads: number;
  grabBanner: boolean;
  totalPortsScanned: number;
  openCount: number;
  closedCount: number;
  filteredCount: number;
  durationMs: number;
  cliCommand: string;
  results: ScannerPortResult[];
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    await ensureDbSeeded();

    const body = await request.json();
    const targetHost = String(body.targetHost || "127.0.0.1").trim();
    const portRange = String(
      body.portRange || "21,22,80,443,3000,5432,6379,8080"
    ).trim();
    const timeoutMs = Math.max(
      50,
      Math.min(5000, Number(body.timeoutMs) || 400)
    );
    const threads = Math.max(1, Math.min(100, Number(body.threads) || 20));
    const grabBanner = body.grabBanner !== false;

    const scriptPath = path.join(process.cwd(), "scripts", "scanner.py");
    const args = [
      scriptPath,
      "--host",
      targetHost,
      "--ports",
      portRange,
      "--timeout",
      String(timeoutMs),
      "--threads",
      String(threads),
      grabBanner ? "--banner" : "--no-banner",
      "--format",
      "json",
    ];

    let stdout = "";
    const pythonExecutable = process.platform === "win32" ? "python" : "python3";
    try {
      const res = await execFileAsync(pythonExecutable, args, {
        timeout: 45000,
        maxBuffer: 10 * 1024 * 1024,
      });
      stdout = res.stdout;
    } catch (execErr: unknown) {
      const e = execErr as { stdout?: string; stderr?: string; message?: string };
      if (e.stdout) {
        try {
          const parsedErr = JSON.parse(e.stdout);
          if (parsedErr.error) {
            return NextResponse.json(
              { error: parsedErr.error },
              { status: 400 }
            );
          }
        } catch {
          // fall through
        }
      }
      return NextResponse.json(
        {
          error:
            e.stderr ||
            e.message ||
            "Failed to execute Python TCP port scanner subprocess.",
        },
        { status: 400 }
      );
    }

    const scanOutput: ScannerOutput = JSON.parse(stdout);
    if (scanOutput.error) {
      return NextResponse.json({ error: scanOutput.error }, { status: 400 });
    }

    // Persist scan job metadata into PostgreSQL
    const [insertedScan] = await db
      .insert(scans)
      .values({
        targetHost: scanOutput.targetHost,
        targetLabel: body.targetLabel || scanOutput.targetLabel,
        portRange: scanOutput.portRange,
        timeoutMs: scanOutput.timeoutMs,
        threads: scanOutput.threads,
        grabBanner: scanOutput.grabBanner,
        status: "completed",
        openCount: scanOutput.openCount,
        closedCount: scanOutput.closedCount,
        filteredCount: scanOutput.filteredCount,
        totalPortsScanned: scanOutput.totalPortsScanned,
        durationMs: scanOutput.durationMs,
        cliCommand: scanOutput.cliCommand,
      })
      .returning();

    // Persist port results in batches to handle large port ranges cleanly
    const resultsToInsert = scanOutput.results.map((r) => ({
      scanId: insertedScan.id,
      port: r.port,
      protocol: r.protocol || "TCP",
      state: r.state,
      service: r.service || "unknown",
      banner: r.banner || "",
      rawHex: r.rawHex || "",
      latencyMs: r.latencyMs ?? 1,
      securityNotes: r.securityNotes || "",
      riskLevel: r.riskLevel || "info",
    }));

    const insertedPortResults = [];
    const batchSize = 250;
    for (let i = 0; i < resultsToInsert.length; i += batchSize) {
      const chunk = resultsToInsert.slice(i, i + batchSize);
      const rows = await db.insert(portResults).values(chunk).returning();
      insertedPortResults.push(...rows);
    }

    return NextResponse.json({
      scan: insertedScan,
      results: insertedPortResults,
    });
  } catch (error: unknown) {
    console.error("POST /api/scan error:", error);
    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : "Internal error executing TCP port scan",
      },
      { status: 500 }
    );
  }
}
