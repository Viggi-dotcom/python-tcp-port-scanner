import { NextResponse } from "next/server";
import { db } from "@/db";
import { scans, portResults } from "@/db/schema";
import { ensureDbSeeded } from "@/db/seed";
import { desc, eq, asc } from "drizzle-orm";

export async function GET() {
  try {
    await ensureDbSeeded();

    const allScans = await db
      .select()
      .from(scans)
      .orderBy(desc(scans.createdAt), desc(scans.id))
      .limit(30);

    // Fetch port results for the most recent scan immediately so initial load is complete
    let latestResults: (typeof portResults.$inferSelect)[] = [];
    if (allScans.length > 0) {
      latestResults = await db
        .select()
        .from(portResults)
        .where(eq(portResults.scanId, allScans[0].id))
        .orderBy(asc(portResults.port));
    }

    return NextResponse.json({
      scans: allScans,
      latestScan: allScans[0] || null,
      latestResults,
    });
  } catch (error: unknown) {
    console.error("GET /api/scans error:", error);
    return NextResponse.json(
      { error: "Failed to fetch scan history" },
      { status: 500 }
    );
  }
}
