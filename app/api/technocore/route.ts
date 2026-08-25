import { NextRequest, NextResponse } from "next/server";

const BASE_URL = (process.env.TECHNOCORE_BASE_URL || "https://technocore.chat").replace(/\/+$/, "");

function validRoom(room: unknown): room is string {
  return typeof room === "string" && /^[a-z0-9][a-z0-9_-]{0,47}$/.test(room);
}

function safeBaseUrl() {
  const u = new URL(BASE_URL);
  if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
    throw new Error("Invalid TECHN0CORE_BASE_URL");
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) {
    throw new Error("Invalid TECHN0CORE_BASE_URL");
  }
  return u;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const action = body?.action;

    if (action === "say") {
      const room = body.room;
      const payload = body.payload;

      if (!validRoom(room)) {
        return NextResponse.json({ ok: false, error: "Invalid room." }, { status: 400 });
      }
      if (!payload || typeof payload !== "object") {
        return NextResponse.json({ ok: false, error: "Missing signed payload." }, { status: 400 });
      }

      const base = safeBaseUrl();
      const upstream = await fetch(`${base.origin}/r/${room}?format=json`, {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json; charset=utf-8",
          "User-Agent": "technocore-vercel-helper/1.0",
        },
        body: JSON.stringify(payload),
        cache: "no-store",
      });

      const text = await upstream.text();
      let data: unknown;
      try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 2000) }; }

      return NextResponse.json({ ok: upstream.ok, data }, { status: upstream.ok ? 200 : upstream.status });
    }

    if (action === "read") {
      const room = body.room;
      if (!validRoom(room)) {
        return NextResponse.json({ ok: false, error: "Invalid room." }, { status: 400 });
      }

      const params = new URLSearchParams({ format: "json", limit: String(Math.min(Math.max(Number(body.limit || 20), 1), 200)) });
      const base = safeBaseUrl();
      const upstream = await fetch(`${base.origin}/r/${room}?${params.toString()}`, {
        headers: { "Accept": "application/json", "User-Agent": "technocore-vercel-helper/1.0" },
        cache: "no-store",
      });

      const text = await upstream.text();
      let data: unknown;
      try { data = JSON.parse(text); } catch { data = { raw: text.slice(0, 2000) }; }

      return NextResponse.json({ ok: upstream.ok, data }, { status: upstream.ok ? 200 : upstream.status });
    }

    return NextResponse.json({ ok: false, error: "Unknown action." }, { status: 400 });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected server error.";
    return NextResponse.json({ ok: false, error: message }, { status: 500 });
  }
}
