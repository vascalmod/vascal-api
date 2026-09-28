import { db, q } from "../lib/db.js";
import { verifyToken, mintToken, newJti, TOKEN_TTL_SEC } from "../lib/token.js";
import { logEvent, clientIp } from "../lib/validate.js";
import { throttle } from "../lib/rate-limit.js";

// POST /api/heartbeat { token, game_uid, seal? }
// -> 200 { ok: true, token, expires_in } | 401 { ok: false, error }
// Sliding refresh: every accepted beat mints a fresh token (old JTI revoked).
// seal: client-measured Trust::Seal(), checked against the release row for the
// session's build tag. Mismatch = tampered binary -> revoke + anomaly.

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
    const { rows } = await q(`SELECT key_id, revoked FROM sessions WHERE jti = $1 LIMIT 1`, [claims.jti]);
    if (!rows.length || rows[0].revoked) return Response.json({ ok: false, error: "revoked" }, { status: 401 });

    const k = await q(`SELECT status, expires_at FROM keys WHERE kuuid = $1 LIMIT 1`, [claims.key_id]);
    if (!k.rows.length || k.rows[0].status !== "active") return Response.json({ ok: false, error: "revoked" }, { status: 401 });
    if (new Date(k.rows[0].expires_at).getTime() < Date.now()) {
        return Response.json({ ok: false, error: "expired" }, { status: 401 });
    }

    // Attestation: reported seal must match the release row for this build tag.
    if (typeof b?.seal === "string" && b.seal.length === 64) {
        try {
            const sr = await q(`SELECT seals FROM releases WHERE tag = $1 ORDER BY at DESC LIMIT 1`, [claims.build]);
            const want = sr.rows.length && sr.rows[0].seals ? sr.rows[0].seals.trust : null;
            if (typeof want === "string" && want.length === 64 && b.seal.toLowerCase() !== want.toLowerCase()) {
                await q(`UPDATE sessions SET revoked = TRUE WHERE key_id = $1`, [Number(claims.key_id)]);
                await logEvent(String(claims.key_id), "anomaly", ip, { reason: "seal_mismatch", build: claims.build });
                return Response.json({ ok: false, error: "revoked" }, { status: 401 });
            }
        } catch {
            // fail-open on DB hiccups; the client's own seal check still guards
        }
    }

    // Rotate: revoke old JTI, mint fresh.
    const jti = newJti();
    const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;
    const keyId = String(claims.key_id);
    await q(`UPDATE sessions SET revoked = TRUE WHERE jti = $1`, [claims.jti]);
    await q(
        `INSERT INTO sessions (jti, key_id, uid, build_tag, expires_at) VALUES ($1, $2, $3, $4, to_timestamp($5))`,
        [jti, keyId, game_uid, claims.build, exp]
    );
    const fresh = mintToken({ jti, uid: game_uid, key_id: keyId, build: claims.build, over: claims.over, exp });

    return Response.json({ ok: true, token: fresh, expires_in: TOKEN_TTL_SEC });
}
