import { db } from "../lib/db";
import { verifyToken, mintToken, newJti, TOKEN_TTL_SEC } from "../lib/token";
import { logEvent, clientIp } from "../lib/validate";
import { throttle } from "../lib/rate-limit";

// POST /api/heartbeat { token, game_uid }
// -> 200 { ok: true, token, offsets_delta?, expires_in } | 401 { ok: false, error }
// Sliding refresh: every accepted beat mints a fresh token (old JTI revoked).

export async function POST(req: Request): Promise<Response> {
    const ip = clientIp(req);
    let b: any;
    try {
        b = await req.json();
    } catch {
        return Response.json({ ok: false, error: "bad_json" }, { status: 400 });
    }
    const { token, game_uid } = b ?? {};
    if (typeof token !== "string" || typeof game_uid !== "number") {
        return Response.json({ ok: false, error: "bad_request" }, { status: 400 });
    }
    if (!throttle(`hb:${token.slice(-16)}`, 20, 60)) return Response.json({ ok: false, error: "rate_limited" }, { status: 429 });

    const claims = verifyToken(token);
    if (!claims || claims.uid !== game_uid) {
        return Response.json({ ok: false, error: "bad_token" }, { status: 401 });
    }
    const { rows } = await db().query(`SELECT key_id, revoked FROM sessions WHERE jti = $1 LIMIT 1`, [claims.jti]);
    if (!rows.length || rows[0].revoked) return Response.json({ ok: false, error: "revoked" }, { status: 401 });

    const k = await db().query(`SELECT status, expires_at FROM keys WHERE id = $1 LIMIT 1`, [claims.key_id]);
    if (!k.rows.length || k.rows[0].status !== "active") return Response.json({ ok: false, error: "revoked" }, { status: 401 });
    if (new Date(k.rows[0].expires_at).getTime() < Date.now()) {
        return Response.json({ ok: false, error: "expired" }, { status: 401 });
    }

    // Rotate: revoke old JTI, mint fresh.
    const jti = newJti();
    const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;
    await db().query(`UPDATE sessions SET revoked = TRUE WHERE jti = $1`, [claims.jti]);
    await db().query(
        `INSERT INTO sessions (jti, key_id, uid, build_tag, expires_at) VALUES ($1, $2, $3, $4, to_timestamp($5))`,
        [jti, claims.key_id, game_uid, claims.build, exp]
    );
    const fresh = mintToken({ jti, uid: game_uid, key_id: claims.key_id, build: claims.build, over: claims.over, exp });

    return Response.json({ ok: true, token: fresh, expires_in: TOKEN_TTL_SEC });
}
