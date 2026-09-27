import { db } from "../lib/db";
import { mintToken, newJti, TOKEN_TTL_SEC } from "../lib/token";
import { consumeNonce } from "../lib/nonce";
import { checkKey, logEvent, clientIp } from "../lib/validate";
import { throttle } from "../lib/rate-limit";

// POST /api/login { license_key, game_uid, build_tag, game_version, nonce }
// -> 200 { token, offsets, expires_in } | 4xx { error }

export async function POST(req: Request): Promise<Response> {
    const ip = clientIp(req);
    if (!throttle(`login:${ip}`, 10, 60)) return Response.json({ error: "rate_limited" }, { status: 429 });

    let b: any;
    try {
        b = await req.json();
    } catch {
        return Response.json({ error: "bad_json" }, { status: 400 });
    }
    const { license_key, game_uid, build_tag, game_version, nonce } = b ?? {};
    if (typeof license_key !== "string" || typeof game_uid !== "number" || !game_uid) {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    if (typeof nonce !== "string" || !consumeNonce(nonce)) {
        return Response.json({ error: "bad_nonce" }, { status: 401 });
    }

    const v = await checkKey(license_key, game_uid);
    if (!v.ok) {
        await logEvent(null, "login_fail", ip, { code: v.code, uid: game_uid });
        const status = v.code === "rate_limited" ? 429 : 401;
        return Response.json({ error: v.code }, { status });
    }

    // Offsets ride INSIDE the authed answer — no anonymous offset endpoint exists.
    const { rows } = await db().query(`SELECT table_json, min_build FROM offsets WHERE game_version = $1 LIMIT 1`, [
        String(game_version ?? ""),
    ]);
    if (!rows.length) {
        await logEvent(v.key_id, "login_unsupported", ip, { game_version });
        return Response.json({ error: "unsupported_version" }, { status: 409 });
    }
    if (rows[0].min_build && String(build_tag ?? "") < String(rows[0].min_build)) {
        await logEvent(v.key_id, "login_stale_build", ip, { build_tag });
        return Response.json({ error: "update_required" }, { status: 409 });
    }

    const jti = newJti();
    const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;
    const token = mintToken({ jti, uid: game_uid, key_id: v.key_id, build: String(build_tag ?? ""), over: String(game_version), exp });
    await db().query(
        `INSERT INTO sessions (jti, key_id, uid, build_tag, expires_at) VALUES ($1, $2, $3, $4, to_timestamp($5))`,
        [jti, v.key_id, game_uid, String(build_tag ?? ""), exp]
    );
    await logEvent(v.key_id, "login_ok", ip, { uid: game_uid, build_tag });

    return Response.json({
        token,
        offsets: rows[0].table_json,
        plan: v.plan,
        expires_at: v.expires_at,
        expires_in: TOKEN_TTL_SEC,
    });
}
