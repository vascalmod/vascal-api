import { db } from "../../lib/db";
import { logEvent, clientIp } from "../../lib/validate";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/push-offsets { game_version, table_json, min_build }
// table_json: { classes: { BattleManager: "0x..." }, globals: {...}, fields: {...} }
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    if (typeof b?.game_version !== "string" || typeof b?.table_json !== "object" || !b.table_json) {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    await db().query(
        `INSERT INTO offsets (game_version, table_json, min_build) VALUES ($1, $2, $3)
         ON CONFLICT (game_version) DO UPDATE SET table_json = $2, min_build = $3, created_at = now()`,
        [b.game_version, JSON.stringify(b.table_json), String(b?.min_build ?? "")]
    );
    await logEvent(null, "offsets_push", clientIp(req), { game_version: b.game_version });
    return Response.json({ ok: true });
}
