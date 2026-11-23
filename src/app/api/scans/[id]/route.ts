import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { scans, portResults } from "@/db/schema";
import { ensureDbSeeded } from "@/db/seed";
import { eq, asc } from "drizzle-orm";

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    await ensureDbSeeded();
    const { id } = await context.params;
    const scanId = Number(id);

    if (isNaN(scanId)) {
      return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 });
    }

    const [scan] = await db.select().from(scans).where(eq(scans.id, scanId));
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    const results = await db
      .select()
      .from(portResults)
      .where(eq(portResults.scanId, scanId))
      .orderBy(asc(portResults.port));

    return NextResponse.json({ scan, results });
  } catch (error: unknown) {
    console.error("GET /api/scans/[id] error:", error);
    return NextResponse.json(
      { error: "Failed to fetch scan details" },
      { status: 500 }
    );
  }
}

export async function DELETE(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    await ensureDbSeeded();
    const { id } = await context.params;
    const scanId = Number(id);

    if (isNaN(scanId)) {
      return NextResponse.json({ error: "Invalid scan ID" }, { status: 400 });
    }

    await db.delete(scans).where(eq(scans.id, scanId));
    return NextResponse.json({ deleted: true, id: scanId });
  } catch (error: unknown) {
    console.error("DELETE /api/scans/[id] error:", error);
    return NextResponse.json(
      { error: "Failed to delete scan record" },
      { status: 500 }
    );
  }
}
