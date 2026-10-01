import { db } from "../../lib/db.js";
import { openKey } from "../../lib/keywrap.js";
import { logEvent } from "../../lib/validate.js";

// GET /api/admin/list-keys?status=&limit=&offset= (header x-admin-secret)
// Rows carry hashes only (plaintext is never stored). Includes device count + last event.
// ..&events=1[&key_id=][&etype=] returns the audit trail instead (same slot, no new function).
// ..&devices=1[&key_id=] uid history rows. ..&seats=1[&key_id=] seat rows.
// ..&sessions=1[&key_id=] session rows. ..&offsets=1[&game_version=] offset rows.
// ..&releases=1 release rows. All read-only multiplexes over the one function slot.

export async function GET(req: Request): Promise<Response> {
    if (req.headers.get("x-admin-secret") !== process.env.ADMIN_SECRET) {
        return Response.json({ error: "forbidden" }, { status: 403 });
    }
    const url = new URL(req.url);
    const status = url.searchParams.get("status") || "";
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const keyId = Number(url.searchParams.get("key_id") || 0);
    if (url.searchParams.get("devices") === "1") {
        const cond = keyId ? `WHERE d.key_id = $3` : ``;
        const params: any[] = [limit, offset];
        if (keyId) params.push(keyId);
        const { rows } = await db().query(
            `SELECT d.id, d.key_id, d.uid, d.first_seen, d.last_seen FROM devices d ${cond} ORDER BY d.last_seen DESC LIMIT $1 OFFSET $2`,
            params
        );
        return Response.json({ devices: rows });
    }
    if (url.searchParams.get("seats") === "1") {
        const cond = keyId ? `WHERE s.key_id = $3` : ``;
        const params: any[] = [limit, offset];
        if (keyId) params.push(keyId);
        const { rows } = await db().query(
            `SELECT s.key_id, s.hwid, s.uid, s.activated_at, s.expires_at,
                    CASE WHEN s.expires_at < now() THEN 'expired' ELSE 'active' END AS status
             FROM key_devices s ${cond} ORDER BY s.activated_at DESC LIMIT $1 OFFSET $2`,
            params
        );
        return Response.json({ seats: rows });
    }
    if (url.searchParams.get("sessions") === "1") {
        const cond = keyId ? `WHERE s.key_id = $3` : ``;
        const params: any[] = [limit, offset];
        if (keyId) params.push(keyId);
        const { rows } = await db().query(
            `SELECT s.jti, s.key_id, s.uid, s.build_tag, s.issued_at, s.expires_at, s.revoked,
                    CASE WHEN s.revoked THEN 'REVOKED' WHEN s.expires_at < now() THEN 'EXPIRED' ELSE 'ACTIVE' END AS status
             FROM sessions s ${cond} ORDER BY s.issued_at DESC LIMIT $1 OFFSET $2`,
            params
        );
        return Response.json({ sessions: rows });
    }
    if (url.searchParams.get("offsets") === "1") {
        const ver = url.searchParams.get("game_version") || "";
        if (ver) {
            const { rows } = await db().query(`SELECT game_version, table_json, min_build, created_at FROM offsets WHERE game_version = $1 LIMIT 1`, [ver]);
            if (!rows.length) return Response.json({ error: "not_found" }, { status: 404 });
            return Response.json({ offset: rows[0] });
        }
        const { rows } = await db().query(
            `SELECT game_version, min_build, created_at,
                    (SELECT count(*)::int FROM jsonb_object_keys(table_json)) AS keys
             FROM offsets ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
            [limit, offset]
        );
        return Response.json({ offsets: rows });
    }
    if (url.searchParams.get("releases") === "1") {
        const { rows } = await db().query(
            `SELECT id, tag, url, sha256, notes, seals, at FROM releases ORDER BY at DESC LIMIT $1 OFFSET $2`,
            [limit, offset]
        );
        return Response.json({ releases: rows });
    }
    // Reveal mode: ?reveal=<id> returns the plaintext once, audit-logged. Same slot.
    if (url.searchParams.get("reveal")) {
        const id = Number(url.searchParams.get("reveal") || 0);
        if (!id) return Response.json({ error: "bad_request" }, { status: 400 });
        const rk = await db().query(`SELECT key_enc FROM keys WHERE id = $1 LIMIT 1`, [id]);
        if (!rk.rows.length || !rk.rows[0].key_enc) return Response.json({ error: "not_found" }, { status: 404 });
        const pt = openKey(rk.rows[0].key_enc);
        if (!pt) return Response.json({ error: "not_found" }, { status: 404 });
        await logEvent(id, "key_revealed", req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "", {});
        return Response.json({ license_key: pt });
    }
    if (url.searchParams.get("events") === "1") {
        const etype = url.searchParams.get("etype") || "";
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
    const where = status === "active" || status === "revoked" || status === "suspended" ? "WHERE k.status = $3" : "";
    const params: any[] = [limit, offset];
    if (where) params.push(status);
    const { rows } = await db().query(
        `SELECT k.id, k.plan, k.expires_at, k.bound_uid, k.bound_hwid, k.max_devices, k.duration_days, k.status, k.note, k.created_at,
                k.key_prefix, k.key_suffix,
                (SELECT count(*)::int FROM devices d WHERE d.key_id = k.id) AS devices,
                (SELECT count(*)::int FROM key_devices s WHERE s.key_id = k.id) AS seats,
                (SELECT max(at) FROM events e WHERE e.key_id = k.id) AS last_seen
         FROM keys k ${where} ORDER BY k.created_at DESC LIMIT $1 OFFSET $2`,
        params
    );
    return Response.json({ keys: rows });
}
