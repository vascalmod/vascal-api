import { db } from "../../lib/db.js";

// GET /api/admin/list-keys?status=&limit=&offset= (header x-admin-secret)
// Rows carry hashes only (plaintext is never stored). Includes device count + last event.
// ..&events=1[&key_id=][&etype=] returns the audit trail instead (same slot, no new function).

export async function GET(req: Request): Promise<Response> {
    if (req.headers.get("x-admin-secret") !== process.env.ADMIN_SECRET) {
        return Response.json({ error: "forbidden" }, { status: 403 });
    }
    const url = new URL(req.url);
    const status = url.searchParams.get("status") || "";
    if (url.searchParams.get("events") === "1") {
        const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
        const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
        const etype = url.searchParams.get("etype") || "";
        const keyId = Number(url.searchParams.get("key_id") || 0);
        const conds: string[] = [];
        const params: any[] = [];
        if (keyId) {
            params.push(keyId);
            conds.push(`e.key_id = $${params.length}`);
        }
        if (etype) {
            params.push(etype);
            conds.push(`e.type = $${params.length}`);
        }
        params.push(limit, offset);
        const { rows } = await db().query(
            `SELECT e.id, e.key_id, e.type, e.ip, e.meta, e.at FROM events e` +
                (conds.length ? ` WHERE ${conds.join(" AND ")}` : ``) +
                ` ORDER BY e.at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        return Response.json({ events: rows });
    }
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const where = status === "active" || status === "revoked" || status === "suspended" ? "WHERE k.status = $3" : "";
    const params: any[] = [limit, offset];
    if (where) params.push(status);
    const { rows } = await db().query(
        `SELECT k.id, k.plan, k.expires_at, k.bound_uid, k.status, k.note, k.created_at,
                k.key_prefix, k.key_suffix,
                (SELECT count(*)::int FROM devices d WHERE d.key_id = k.id) AS devices,
                (SELECT max(at) FROM events e WHERE e.key_id = k.id) AS last_seen
         FROM keys k ${where} ORDER BY k.created_at DESC LIMIT $1 OFFSET $2`,
        params
    );
    return Response.json({ keys: rows });
}
