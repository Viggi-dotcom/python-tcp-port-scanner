import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { labTargets } from "@/db/schema";
import { ensureDbSeeded } from "@/db/seed";
import { asc, eq } from "drizzle-orm";

function isAuthorizedLabAddress(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (h === "localhost" || h === "127.0.0.1" || h === "::1") return true;
  if (h.startsWith("127.")) return true;
  if (h.startsWith("10.")) return true;
  if (h.startsWith("192.168.")) return true;
  const m = h.match(/^172\.(\d{1,3})\./);
  if (m) {
    const secondOctet = Number(m[1]);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  return false;
}

export async function GET() {
  try {
    await ensureDbSeeded();
    const targets = await db
      .select()
      .from(labTargets)
      .orderBy(asc(labTargets.id));
    return NextResponse.json({ targets });
  } catch (error: unknown) {
    console.error("GET /api/targets error:", error);
    return NextResponse.json(
      { error: "Failed to fetch lab targets" },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    await ensureDbSeeded();
    const body = await request.json();
    const name = String(body.name || "").trim();
    const host = String(body.host || "").trim();
    const environment = String(
      body.environment || "VirtualBox Host-Only (vboxnet0)"
    ).trim();
    const osProfile = String(
      body.osProfile || "Linux Lab Target (Custom)"
    ).trim();
    const defaultPorts = String(
      body.defaultPorts || "21,22,80,443,3000,5432,8080"
    ).trim();
    const description = String(
      body.description || "Authorized local or VirtualBox test target."
    ).trim();

    if (!name || !host) {
      return NextResponse.json(
        { error: "Target name and IP/host are required." },
        { status: 400 }
      );
    }

    if (!isAuthorizedLabAddress(host)) {
      return NextResponse.json(
        {
          error:
            "Only authorized loopback (127.0.0.0/8) or private RFC1918 VirtualBox subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) may be registered.",
        },
        { status: 400 }
      );
    }

    const [created] = await db
      .insert(labTargets)
      .values({
        name,
        host,
        environment,
        osProfile,
        defaultPorts,
        description,
        authorized: true,
      })
      .returning();

    return NextResponse.json({ target: created }, { status: 201 });
  } catch (error: unknown) {
    console.error("POST /api/targets error:", error);
    return NextResponse.json(
      { error: "Failed to register lab target" },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    await ensureDbSeeded();
    const id = Number(request.nextUrl.searchParams.get("id"));
    if (isNaN(id)) {
      return NextResponse.json({ error: "Invalid target ID" }, { status: 400 });
    }
    await db.delete(labTargets).where(eq(labTargets.id, id));
    return NextResponse.json({ deleted: true, id });
  } catch (error: unknown) {
    console.error("DELETE /api/targets error:", error);
    return NextResponse.json(
      { error: "Failed to delete lab target" },
      { status: 500 }
    );
  }
}
