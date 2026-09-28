import { db, sha256Hex } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";
import { throttle } from "../../lib/rate-limit.js";

// POST /api/self/status { license_key }
// -> { plan, expires_at, bound_uid_masked, resets_left_today } | { error }
// Key-as-credential. Only safe fields leave the server.

function maskUid(uid: number | null): string {
    if (uid === null || uid === undefined) return "none";
    const s = String(uid);
    if (s.length <= 4) return "****";
    return s.slice(0, 2) + "****" + s.slice(-2);
}

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
    const { rows } = await db().query(
        `SELECT kuuid, plan, expires_at, bound_uid, status FROM keys WHERE license_key_hash = $1 LIMIT 1`,
        [hash]
    );
    if (!rows.length) return Response.json({ error: "bad_key" }, { status: 401 });
    const k = rows[0];
    if (k.status !== "active") return Response.json({ error: "revoked" }, { status: 401 });
    const rc = await db().query(
        `SELECT count(*)::int AS n FROM events WHERE key_id = $1 AND type = 'uid_reset_self' AND at > now() - interval '24 hours'`,
        [k.kuuid]
    );
    const used = rc.rows[0]?.n ?? 0;
    return Response.json({
        plan: k.plan,
        expires_at: k.expires_at,
        bound_uid_masked: maskUid(k.bound_uid === null ? null : Number(k.bound_uid)),
        resets_left_today: Math.max(0, 2 - used),
    });
}
