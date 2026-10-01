import { db, sha256Hex, q } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/reset-uid { license_key } | { id } [, field: "uid"|"hwid"|"both"]
// Clears UID lock, device lock, or both (device/account change).
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    let id: number | null = null;
    if (typeof b?.license_key === "string" && b.license_key) {
        const hash = await sha256Hex(String(b.license_key));
        const f = await db().query(`SELECT id FROM keys WHERE license_key_hash = $1 LIMIT 1`, [hash]);
        if (!f.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
        id = Number(f.rows[0].id);
    } else if (Number(b?.id)) {
        id = Number(b.id);
    } else {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    const field = b?.field === "hwid" ? "hwid" : b?.field === "both" ? "both" : "uid";
    const exists = await db().query(`SELECT id FROM keys WHERE id = $1 LIMIT 1`, [id]);
    if (!exists.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    if (field === "uid") {
        await db().query(`UPDATE keys SET bound_uid = NULL WHERE id = $1`, [id]);
        await db().query(`UPDATE key_devices SET uid = NULL WHERE key_id = $1`, [id]);
    } else {
        // hwid / both: delete seat rows (uids go with them), freeing the seats.
        await db().query(`DELETE FROM key_devices WHERE key_id = $1`, [id]);
        await db().query(`UPDATE keys SET bound_uid = NULL, bound_hwid = NULL WHERE id = $1`, [id]);
    }
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [id]);
    await logEvent(id, field === "uid" ? "uid_reset" : field === "hwid" ? "hwid_reset" : "full_reset", clientIp(req), {});
    return Response.json({ ok: true });
}
