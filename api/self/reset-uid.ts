import { db, sha256Hex } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";
import { throttle } from "../../lib/rate-limit.js";

// POST /api/self/reset-uid { license_key }
// Clears the UID binding; next login binds the new account.
// Rolling limit: 2 per 24h. Every reset audit-logged, UID history retained.

export async function POST(req: Request): Promise<Response> {
    const ip = clientIp(req);
    if (!throttle(`self:${ip}`, 20, 60)) return Response.json({ error: "rate_limited" }, { status: 429 });
    let b: any;
    try {
        b = await req.json();
    } catch {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    if (typeof b?.license_key !== "string") return Response.json({ error: "bad_request" }, { status: 400 });
    const hash = await sha256Hex(String(b.license_key).trim());
    const { rows } = await db().query(`SELECT kuuid, status FROM keys WHERE license_key_hash = $1 LIMIT 1`, [hash]);
    if (!rows.length) return Response.json({ error: "bad_key" }, { status: 401 });
    const k = rows[0];
    if (k.status !== "active") return Response.json({ error: "revoked" }, { status: 401 });
    const rc = await db().query(
        `SELECT count(*)::int AS n FROM events WHERE key_id = $1 AND type = 'uid_reset_self' AND at > now() - interval '24 hours'`,
        [k.kuuid]
    );
    if ((rc.rows[0]?.n ?? 0) >= 2) {
        await logEvent(k.kuuid, "reset_denied", ip, {});
        return Response.json({ error: "limit_reached" }, { status: 429 });
    }
    await db().query(`UPDATE keys SET bound_uid = NULL WHERE kuuid = $1`, [k.kuuid]);
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [k.kuuid]);
    await logEvent(k.kuuid, "uid_reset_self", ip, {});
    return Response.json({ ok: true });
}
