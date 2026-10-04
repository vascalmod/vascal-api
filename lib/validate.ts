import { db, sha256Hex, q } from "./db.js";

// Shared verdict used by login + heartbeat. Fail-closed: any null = reject.
// key_id is the keys.id integer end to end (8-digit random, non-sequential).

export type Verdict =
    | { ok: true; key_id: number; plan: string; expires_at: string; bound_uid: number | null }
    | { ok: false; code: string };

export async function checkKey(license_key: string, uid: number, hwid: string = "", ip: string = "login"): Promise<Verdict> {
    const hash = await sha256Hex(license_key.trim());
    const { rows } = await q(
        `SELECT id, plan, expires_at, status, max_devices, duration_days FROM keys WHERE license_key_hash = $1 LIMIT 1`,
        [hash]
    );
    if (!rows.length) return { ok: false, code: "bad_key" };
    const k = rows[0];
    if (k.status !== "active") return { ok: false, code: "revoked" };
    if (new Date(k.expires_at).getTime() < Date.now()) return { ok: false, code: "expired" };

    // Seat model: one row per device, independent expiry from activation.
    // Legacy single-lock columns (bound_uid/bound_hwid) retired; seats rule.
    const keyId = Number(k.id);
    const maxDev = Math.max(1, Number(k.max_devices) || 1);
    const durDays = Math.max(1, Number(k.duration_days) || 3);
    const hw = String(hwid ?? "").trim();
    if (!hw) return { ok: false, code: "hwid_required" };
    const sr = await q(`SELECT uid, expires_at FROM key_devices WHERE key_id = $1 AND hwid = $2 LIMIT 1`, [keyId, hw]);
    let seatUid: number | null;
    let seatExp: string;
    if (!sr.rows.length) {
        const cnt = await q(`SELECT count(*)::int AS n FROM key_devices WHERE key_id = $1`, [keyId]);
        if ((cnt.rows[0]?.n ?? 0) >= maxDev) {
            await q(`INSERT INTO events (key_id, type, meta) VALUES ($1, 'anomaly', $2)`,
                [keyId, JSON.stringify({ reason: "device_limit", seen_hwid: hw })]);
            return { ok: false, code: "device_limit" };
        }
        const exp = new Date(Date.now() + durDays * 864e5).toISOString();
        await q(`INSERT INTO key_devices (key_id, hwid, uid, expires_at) VALUES ($1, $2, $3, $4)`,
            [keyId, hw, uid, exp]);
        seatUid = uid;
        seatExp = exp;
        await logEvent(keyId, "seat_activated", ip, { uid, hwid: hw });
    } else {
        if (new Date(sr.rows[0].expires_at).getTime() < Date.now()) return { ok: false, code: "expired" };
        // No UID lock: any game account is accepted on a live device seat.
        // The seat (key_id, hwid) is the sharing boundary, not the UID.
        // uid column = last-seen; full sighting history lives in devices.
        if (sr.rows[0].uid === null || Number(sr.rows[0].uid) !== uid) {
            await q(`UPDATE key_devices SET uid = $1 WHERE key_id = $2 AND hwid = $3`, [uid, keyId, hw]);
            await logEvent(keyId, "uid_added", ip, { uid, hwid: hw });
        }
        seatUid = uid;
        seatExp = sr.rows[0].expires_at;
    }
    await q(
        `INSERT INTO devices (key_id, uid) VALUES ($1, $2)
         ON CONFLICT (key_id, uid) DO UPDATE SET last_seen = now()`,
        [keyId, uid]
    );
    return { ok: true, key_id: keyId, plan: k.plan, expires_at: seatExp, bound_uid: seatUid };
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
