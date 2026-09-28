import { db, sha256Hex, q } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/revoke-key { license_key } | { id } [, { erase: true }]
// Revoke kills key + live sessions. erase:true hard-deletes the row
// (devices/sessions cascade, events keep a null key_id for audit).
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    let id: string | null = null;
    if (typeof b?.license_key === "string" && b.license_key) {
        const hash = await sha256Hex(String(b.license_key));
        const f = await db().query(`SELECT kuuid FROM keys WHERE license_key_hash = $1 LIMIT 1`, [hash]);
        if (!f.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
        id = String(f.rows[0].kuuid);
    } else if (typeof b?.id === "string" && b.id) {
        id = b.id;
    } else {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    if (b?.erase === true) {
        const r = await db().query(`DELETE FROM keys WHERE kuuid = $1 RETURNING kuuid`, [id]);
        if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
        await logEvent(null, "key_deleted", clientIp(req), { id });
        return Response.json({ ok: true, erased: true });
    }
    const r = await db().query(`UPDATE keys SET status = 'revoked' WHERE kuuid = $1 RETURNING kuuid`, [id]);
    if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [id]);
    await logEvent(id, "revoke", clientIp(req), {});
    return Response.json({ ok: true });
}
