import { db, sha256Hex, q } from "./db.js";

// Shared verdict used by login + heartbeat. Fail-closed: any null = reject.
// key_id is the keys.id integer end to end (8-digit random, non-sequential).

export type Verdict =
    | { ok: true; key_id: number; plan: string; expires_at: string; bound_uid: number | null }
    | { ok: false; code: string };

export async function checkKey(license_key: string, uid: number, hwid: string = ""): Promise<Verdict> {
    const hash = await sha256Hex(license_key.trim());
    const { rows } = await q(
        `SELECT id, plan, expires_at, bound_uid, bound_hwid, status FROM keys WHERE license_key_hash = $1 LIMIT 1`,
        [hash]
    );
    if (!rows.length) return { ok: false, code: "bad_key" };
    const k = rows[0];
    if (k.status !== "active") return { ok: false, code: "revoked" };
    if (new Date(k.expires_at).getTime() < Date.now()) return { ok: false, code: "expired" };

    // UID lock: first login binds, later logins must match (reset via admin).
    const keyId = Number(k.id);
    if (k.bound_uid === null) {
        await q(`UPDATE keys SET bound_uid = $1 WHERE id = $2`, [uid, keyId]);
        await q(
            `INSERT INTO devices (key_id, uid) VALUES ($1, $2)
             ON CONFLICT (key_id, uid) DO UPDATE SET last_seen = now()`,
            [keyId, uid]
        );
        return { ok: true, key_id: keyId, plan: k.plan, expires_at: k.expires_at, bound_uid: uid };
    }
    if (Number(k.bound_uid) !== uid) {
        await q(
            `INSERT INTO events (key_id, type, meta) VALUES ($1, 'anomaly', $2)`,
            [keyId, JSON.stringify({ reason: "uid_mismatch", seen_uid: uid, bound_uid: Number(k.bound_uid) })]
        );
        return { ok: false, code: "uid_locked" };
    }
    // Device lock: first login binds, later logins must match (admin reset moves it).
    // Empty hwid = legacy client: uid lock still applies, device check skipped.
    const hw = String(hwid ?? "").trim();
    if (hw) {
        if (!k.bound_hwid) {
            await q(`UPDATE keys SET bound_hwid = $1 WHERE id = $2`, [hw, keyId]);
        } else if (k.bound_hwid !== hw) {
            await q(
                `INSERT INTO events (key_id, type, meta) VALUES ($1, 'anomaly', $2)`,
                [keyId, JSON.stringify({ reason: "hwid_mismatch", seen_hwid: hw, bound_hwid: k.bound_hwid })]
            );
            return { ok: false, code: "hwid_locked" };
        }
    }
    await q(
        `INSERT INTO devices (key_id, uid) VALUES ($1, $2)
         ON CONFLICT (key_id, uid) DO UPDATE SET last_seen = now()`,
        [keyId, uid]
    );
    return { ok: true, key_id: keyId, plan: k.plan, expires_at: k.expires_at, bound_uid: Number(k.bound_uid) };
}

export async function logEvent(key_id: number | null, type: string, ip: string, meta: object = {}): Promise<void> {
    await q(`INSERT INTO events (key_id, type, ip, meta) VALUES ($1, $2, $3, $4)`, [
        key_id,
        type,
        ip,
        JSON.stringify(meta),
    ]);
}

export function clientIp(req: Request): string {
    return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}
