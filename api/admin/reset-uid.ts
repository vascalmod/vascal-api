import { db, sha256Hex } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/reset-uid { license_key } — clears UID lock (device/account change).
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    const hash = await sha256Hex(String(b?.license_key ?? ""));
    const r = await db().query(`UPDATE keys SET bound_uid = NULL WHERE license_key_hash = $1 RETURNING id`, [hash]);
    if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [r.rows[0].id]);
    await logEvent(r.rows[0].id, "uid_reset", clientIp(req), {});
    return Response.json({ ok: true });
}
