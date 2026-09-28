import { db } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/revoke-id { id } — same as revoke-key, by row id (console use).
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    const id = Number(b?.id);
    if (!id) return Response.json({ error: "bad_request" }, { status: 400 });
    const r = await db().query(`UPDATE keys SET status = 'revoked' WHERE id = $1 RETURNING id`, [id]);
    if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [id]);
    await logEvent(id, "revoke", clientIp(req), { via: "console" });
    return Response.json({ ok: true });
}
