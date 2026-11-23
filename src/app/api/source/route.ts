import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs/promises";
import path from "node:path";

export async function GET(request: NextRequest) {
  try {
    const scriptPath = path.join(process.cwd(), "scripts", "scanner.py");
    const content = await fs.readFile(scriptPath, "utf-8");

    if (request.nextUrl.searchParams.get("download") === "1") {
      return new NextResponse(content, {
        status: 200,
        headers: {
          "Content-Type": "text/x-python; charset=utf-8",
          "Content-Disposition": 'attachment; filename="scanner.py"',
        },
      });
    }

    return NextResponse.json({
      filename: "scripts/scanner.py",
      language: "python",
      lines: content.split("\n").length,
      content,
    });
  } catch (error: unknown) {
    console.error("GET /api/source error:", error);
    return NextResponse.json(
      { error: "Failed to read Python scanner source" },
      { status: 500 }
    );
  }
}
