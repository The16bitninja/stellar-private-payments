import { NextResponse } from "next/server";
import { reconstructFeed } from "@/lib/server/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const { secret, disclosures } = await req.json();
    if (!secret) {
      return NextResponse.json({ error: "missing auditor secret" }, { status: 400 });
    }
    return NextResponse.json({ results: reconstructFeed(secret, disclosures ?? []) });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : String(e) },
      { status: 500 },
    );
  }
}
