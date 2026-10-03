import { db, q } from "../../lib/db.js";
import { openKey } from "../../lib/keywrap.js";
import { logEvent, clientIp } from "../../lib/validate.js";
import { throttle } from "../../lib/rate-limit.js";
import { hashPassword, checkPassword, mintResellerSession, requireReseller, revokeResellerSession, revokeAllResellerSessions } from "../../lib/reseller-auth.js";
import { createHash, randomBytes } from "crypto";

// GET /api/admin/list-keys?status=&limit=&offset= (header x-admin-secret)
// Rows carry hashes only (plaintext is never stored). Includes device count + last event.
// ..&events=1[&key_id=][&etype=] returns the audit trail instead (same slot, no new function).
// ..&devices=1[&key_id=] uid history rows. ..&seats=1[&key_id=] seat rows.
// ..&sessions=1[&key_id=] session rows. ..&offsets=1[&game_version=] offset rows.
// ..&releases=1 release rows. All read-only multiplexes over the one function slot.

export async function GET(req: Request): Promise<Response> {
    const url = new URL(req.url);
    // Reseller surface (same function slot): /api/admin/list-keys?action=<name>
    // with `x-reseller-token`. Every data query constrains reseller_id to session identity.
    const raction = url.searchParams.get("action") || "";
    if (["session", "dashboard", "keys", "key", "customers", "sales", "activity", "pricing", "reveal"].includes(raction)) {
        const rid = await requireReseller(req);
        if (typeof rid !== "number") return rid;
        try {
            if (raction === "reveal") {
                const id = Number(url.searchParams.get("id") || 0);
                if (!id) return Response.json({ error: "bad_request" }, { status: 400 });
                const rk = await db().query(`SELECT key_enc FROM keys WHERE id = $1 AND reseller_id = $2 LIMIT 1`, [id, rid]);
                if (!rk.rows.length || !rk.rows[0].key_enc) return Response.json({ error: "not_found" }, { status: 404 });
                const pt = openKey(rk.rows[0].key_enc);
                if (!pt) return Response.json({ error: "not_found" }, { status: 404 });
                await logEvent(id, "key_revealed", clientIp(req), { rid });
                return Response.json({ license_key: pt });
            }
            if (raction === "session") {
                const { rows } = await q(`SELECT id, username, plan, status FROM resellers WHERE id = $1 LIMIT 1`, [rid]);
                return Response.json({ reseller: rows[0] });
            }
            if (raction === "dashboard") return rDashboard(rid);
            if (raction === "keys") return rKeys(rid, url);
            if (raction === "key") return rKeyDetail(rid, url);
            if (raction === "customers") return rCustomers(rid, url);
            if (raction === "sales") return rSales(rid, url);
            if (raction === "activity") return rActivity(rid, url);
            return rPricing();
        } catch (e: any) {
            return Response.json({ error: "backend_error" }, { status: 500 });
        }
    }
    if (req.headers.get("x-admin-secret") !== process.env.ADMIN_SECRET) {
        return Response.json({ error: "forbidden" }, { status: 403 });
    }
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

// ================= reseller surface (Hobby 12-function budget: no new file) =================
function deny(): Response {
    return Response.json({ error: "forbidden" }, { status: 403 });
}
function isAdmin(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}
function newKey(): string {
    return `VSC-${randomBytes(9).toString("hex").toUpperCase()}`;
}
async function rlog(rid: number, type: string, ip: string, meta: object = {}): Promise<void> {
    await logEvent(null, type, ip, { rid, ...meta });
}

// ---------------------------------------------------------------- login ---
async function rLogin(req: Request): Promise<Response> {
    const ip = clientIp(req);
    if (!throttle(`rlogin:${ip}`, 10, 60)) return Response.json({ error: "rate_limited" }, { status: 429 });
    const b = await req.json().catch(() => ({}));
    const username = String(b?.username ?? "").trim();
    const password = String(b?.password ?? "");
    if (!username || !password) return Response.json({ error: "unauthorized" }, { status: 401 });
    const { rows } = await q(`SELECT id, password_hash, status FROM resellers WHERE username = $1 LIMIT 1`, [username]);
    if (!rows.length || !checkPassword(password, rows[0].password_hash)) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
    }
    if (rows[0].status !== "active") return Response.json({ error: "unauthorized" }, { status: 401 });
    const rid = Number(rows[0].id);
    await q(`UPDATE resellers SET last_login_at = now() WHERE id = $1`, [rid]);
    await rlog(rid, "reseller_login", ip, { username });
    const { token, exp } = await mintResellerSession(rid);
    return Response.json({ token, exp });
}

// --------------------------------------------------------------- dashboard ---
async function rDashboard(rid: number): Promise<Response> {
    const me = await q(`SELECT plan, max_keys, max_devices_per_key, status FROM resellers WHERE id = $1 LIMIT 1`, [rid]);
    const generated = await q(`SELECT count(*)::int AS n FROM keys WHERE reseller_id = $1`, [rid]);
    const sold = await q(
        `SELECT count(DISTINCT k.id)::int AS n FROM keys k JOIN key_devices s ON s.key_id = k.id WHERE k.reseller_id = $1`,
        [rid]
    );
    const active = await q(
        `SELECT count(*)::int AS n FROM key_devices s JOIN keys k ON k.id = s.key_id
         WHERE k.reseller_id = $1 AND k.status = 'active' AND s.expires_at > now()`,
        [rid]
    );
    const expired = await q(
        `SELECT count(*)::int AS n FROM key_devices s JOIN keys k ON k.id = s.key_id
         WHERE k.reseller_id = $1 AND s.expires_at <= now()`,
        [rid]
    );
    const g = generated.rows[0]?.n ?? 0;
    return Response.json({
        generated: g,
        sold: sold.rows[0]?.n ?? 0,
        available: g - (sold.rows[0]?.n ?? 0),
        active: active.rows[0]?.n ?? 0,
        expired: expired.rows[0]?.n ?? 0,
        inventory: { used: g, max: Number(me.rows[0]?.max_keys ?? 0) },
        plan: me.rows[0]?.plan ?? "",
        status: me.rows[0]?.status ?? "",
    });
}

// ------------------------------------------------------------------- keys ---
const KEY_COLS = `k.id, k.plan, k.expires_at, k.status, k.note, k.created_at, k.key_prefix, k.key_suffix,
    k.max_devices, k.duration_days,
    (SELECT count(*)::int FROM key_devices s WHERE s.key_id = k.id) AS seats,
    (SELECT max(at) FROM events e WHERE e.key_id = k.id) AS last_seen`;

async function rKeys(rid: number, url: URL): Promise<Response> {
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const status = url.searchParams.get("status") || "";
    const plan = url.searchParams.get("plan") || "";
    const qq = (url.searchParams.get("q") || "").trim();
    const conds = [`k.reseller_id = $1`];
    const params: any[] = [rid];
    if (status === "active" || status === "revoked" || status === "suspended") {
        params.push(status);
        conds.push(`k.status = $${params.length}`);
    }
    if (plan) {
        params.push(plan);
        conds.push(`k.plan = $${params.length}`);
    }
    if (qq) {
        params.push(`%${qq}%`);
        conds.push(`(k.note ILIKE $${params.length} OR k.plan ILIKE $${params.length} OR k.key_prefix ILIKE $${params.length})`);
    }
    params.push(limit, offset);
    const { rows } = await db().query(
        `SELECT ${KEY_COLS} FROM keys k WHERE ${conds.join(" AND ")} ORDER BY k.created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
    );
    return Response.json({ keys: rows });
}

async function rKeyDetail(rid: number, url: URL): Promise<Response> {
    const id = Number(url.searchParams.get("id") || 0);
    if (!id) return Response.json({ error: "bad_request" }, { status: 400 });
    const { rows } = await db().query(`SELECT ${KEY_COLS} FROM keys k WHERE k.id = $1 AND k.reseller_id = $2 LIMIT 1`, [id, rid]);
    if (!rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    const seats = await q(`SELECT hwid, uid, activated_at, expires_at FROM key_devices WHERE key_id = $1 ORDER BY activated_at`, [id]);
    const events = await q(`SELECT id, type, ip, at FROM events WHERE key_id = $1 ORDER BY at DESC LIMIT 20`, [id]);
    const sales = await q(`SELECT id, sale_amount, plan, duration, customer_ref, created_at FROM reseller_sales WHERE key_id = $1 AND reseller_id = $2 ORDER BY created_at DESC`, [id, rid]);
    return Response.json({ key: rows[0], seats: seats.rows, events: events.rows, sales: sales.rows });
}

async function rGenerate(rid: number, req: Request): Promise<Response> {
    const ip = clientIp(req);
    if (!throttle(`rgen:${rid}`, 10, 60)) return Response.json({ error: "rate_limited" }, { status: 429 });
    const b = await req.json().catch(() => ({}));
    const qty = Math.max(1, Math.min(50, Number(b?.quantity ?? 1) || 1));
    const me = await q(`SELECT max_keys, max_devices_per_key, status FROM resellers WHERE id = $1 LIMIT 1`, [rid]);
    if (!me.rows.length || me.rows[0].status !== "active") return Response.json({ error: "unauthorized" }, { status: 401 });
    const maxKeys = Number(me.rows[0].max_keys);
    const maxDev = Math.max(1, Math.min(50, Number(b?.max_devices ?? me.rows[0].max_devices_per_key) || 1));
    const durDays = Math.max(1, Math.min(365, Number(b?.duration_days ?? 3) || 3));
    const days = Math.max(1, Number(b?.days ?? 30) || 30);
    // Serialized against concurrent batches: lock the reseller row, recount
    // inside the transaction. Parallel requests queue here instead of racing.
    const client = await db().connect();
    try {
        await client.query("BEGIN");
        const locked = await client.query(`SELECT max_keys FROM resellers WHERE id = $1 FOR UPDATE`, [rid]);
        const maxKeysTx = Number(locked.rows[0]?.max_keys ?? maxKeys);
        const curTx = await client.query(`SELECT count(*)::int AS n FROM keys WHERE reseller_id = $1`, [rid]);
        if ((curTx.rows[0]?.n ?? 0) + qty > maxKeysTx) {
            await client.query("ROLLBACK");
            client.release();
            return Response.json({ error: "limit_reached", made: 0, max: maxKeysTx }, { status: 400 });
        }
    // Plaintext keys are returned once, like the admin flow (hash + enc stored).
    const { sealKey } = await import("../../lib/keywrap.js");
    const made: string[] = [];
    for (let i = 0; i < qty; i++) {
        const key = newKey();
        const hash = createHash("sha256").update(key, "utf8").digest("hex");
        const exp = new Date(Date.now() + days * 864e5).toISOString();
        let id = 0;
        for (let t = 0; t < 5; t++) {
            id = 10000000 + Math.floor(Math.random() * 90000000);
            try {
                await client.query(
                    `INSERT INTO keys (id, license_key_hash, key_prefix, key_suffix, key_enc, plan, expires_at, note, max_devices, duration_days, reseller_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                    [id, hash, key.slice(0, 8), key.slice(-4), sealKey(key), String(b?.plan ?? "monthly"), exp, String(b?.note ?? ""), maxDev, durDays, rid]
                );
                break;
            } catch (e: any) {
                if (t === 4 || !String(e?.message || e).includes("duplicate")) throw e;
                id = 0;
            }
        }
        if (!id) {
            await client.query("ROLLBACK");
            client.release();
            return Response.json({ error: "retry", made, count: made.length }, { status: 503 });
        }
        await rlog(rid, "reseller_generate", ip, { key_id: id });
        made.push(key);
    }
    await client.query("COMMIT");
    client.release();
    return Response.json({ keys: made, count: made.length });
    } catch (e: any) {
        try { await client.query("ROLLBACK"); } catch { /* already closed */ }
        try { client.release(); } catch { /* already released */ }
        throw e;
    }
}

// --------------------------------------------------------------- customers ---
async function rCustomers(rid: number, url: URL): Promise<Response> {
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const qq = (url.searchParams.get("q") || "").trim();
    const conds = [`k.reseller_id = $1`];
    const params: any[] = [rid];
    if (qq) {
        params.push(qq);
        conds.push(`CAST(d.uid AS TEXT) LIKE $${params.length}`);
    }
    params.push(limit, offset);
    const { rows } = await db().query(
        `SELECT d.uid, d.key_id, k.plan, k.status, d.first_seen AS activated_at,
                (SELECT max(s.expires_at) FROM key_devices s WHERE s.key_id = d.key_id AND s.uid = d.uid) AS expires_at,
                (SELECT count(*)::int FROM key_devices s WHERE s.key_id = d.key_id AND s.uid = d.uid) AS devices,
                (SELECT max(e.at) FROM events e WHERE e.key_id = d.key_id) AS last_seen
         FROM devices d JOIN keys k ON k.id = d.key_id
         WHERE ${conds.join(" AND ")} ORDER BY d.last_seen DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
    );
    return Response.json({ customers: rows });
}

// ------------------------------------------------------------------ sales ---
async function rSales(rid: number, url: URL): Promise<Response> {
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const { rows } = await db().query(
        `SELECT id, key_id, sale_amount, plan, duration, customer_ref, created_at
         FROM reseller_sales WHERE reseller_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
        [rid, limit, offset]
    );
    return Response.json({ sales: rows });
}

async function rSell(rid: number, req: Request): Promise<Response> {
    const b = await req.json().catch(() => ({}));
    const keyId = Number(b?.key_id || 0);
    if (!keyId) return Response.json({ error: "bad_request" }, { status: 400 });
    const own = await q(`SELECT id, plan, duration_days FROM keys WHERE id = $1 AND reseller_id = $2 LIMIT 1`, [keyId, rid]);
    if (!own.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    const amt = b?.sale_amount === undefined || b?.sale_amount === null || b?.sale_amount === "" ? null : Number(b.sale_amount);
    if (b?.sale_amount !== undefined && b?.sale_amount !== null && b?.sale_amount !== "" && !(amt! >= 0)) {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    const r = await q(
        `INSERT INTO reseller_sales (reseller_id, key_id, sale_amount, plan, duration, customer_ref)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at`,
        [rid, keyId, amt, String(b?.plan ?? own.rows[0].plan ?? ""), Number(b?.duration ?? own.rows[0].duration_days ?? 0) || 0, String(b?.customer_ref ?? "")]
    );
    await rlog(rid, "reseller_sale", clientIp(req), { key_id: keyId, sale_id: r.rows[0].id });
    return Response.json({ ok: true, sale_id: r.rows[0].id });
}

// ---------------------------------------------------------------- activity ---
async function rActivity(rid: number, url: URL): Promise<Response> {
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const { rows } = await db().query(
        `SELECT e.id, e.key_id, e.type, e.ip, e.meta, e.at FROM events e
         LEFT JOIN keys k ON k.id = e.key_id
         WHERE k.reseller_id = $1 OR (e.key_id IS NULL AND e.meta->>'rid' = $2)
         ORDER BY e.at DESC LIMIT $3 OFFSET $4`,
        [rid, String(rid), limit, offset]
    );
    return Response.json({ events: rows });
}

// ----------------------------------------------------------------- pricing ---
async function rPricing(): Promise<Response> {
    // No pricing table exists in-repo; structure mirrors the seat model.
    // Amounts stay null until real pricing is configured — never invented.
    return Response.json({
        contact: "Contact your seller",
        plans: [
            { name: "weekly", duration_days: 7, devices: 1, amount: null },
            { name: "monthly", duration_days: 30, devices: 1, amount: null },
            { name: "season", duration_days: 90, devices: 1, amount: null },
            { name: "lifetime", duration_days: 36500, devices: 1, amount: null },
        ],
    });
}

// ------------------------------------------------------------- admin branch ---
async function adminCreate(req: Request): Promise<Response> {
    const b = await req.json().catch(() => ({}));
    const username = String(b?.username ?? "").trim();
    const password = String(b?.password ?? "");
    if (!username || password.length < 8) return Response.json({ error: "bad_request" }, { status: 400 });
    const r = await q(
        `INSERT INTO resellers (username, password_hash, plan, max_keys, max_devices_per_key)
         VALUES ($1,$2,$3,$4,$5) RETURNING id, username, plan, max_keys, max_devices_per_key, status, created_at`,
        [username, hashPassword(password), String(b?.plan ?? "standard"),
         Math.max(1, Number(b?.max_keys ?? 100) || 100),
         Math.max(1, Math.min(50, Number(b?.max_devices_per_key ?? 5) || 5))]
    ).catch((e: any) => {
        if (String(e?.message || e).includes("duplicate")) return null;
        throw e;
    });
    if (!r) return Response.json({ error: "exists" }, { status: 409 });
    await logEvent(null, "reseller_created", clientIp(req), { rid: r.rows[0].id, username });
    return Response.json({ reseller: r.rows[0] });
}

async function adminSet(req: Request): Promise<Response> {
    const b = await req.json().catch(() => ({}));
    const id = Number(b?.id || 0);
    if (!id) return Response.json({ error: "bad_request" }, { status: 400 });
    const sets: string[] = [`updated_at = now()`];
    const params: any[] = [];
    if (b?.status === "active" || b?.status === "disabled") {
        params.push(b.status);
        sets.push(`status = $${params.length}`);
    }
    if (typeof b?.plan === "string" && b.plan) {
        params.push(b.plan);
        sets.push(`plan = $${params.length}`);
    }
    if (Number(b?.max_keys) > 0) {
        params.push(Math.floor(Number(b.max_keys)));
        sets.push(`max_keys = $${params.length}`);
    }
    if (Number(b?.max_devices_per_key) > 0) {
        params.push(Math.max(1, Math.min(50, Number(b.max_devices_per_key))));
        sets.push(`max_devices_per_key = $${params.length}`);
    }
    if (sets.length === 1) return Response.json({ error: "bad_request" }, { status: 400 });
    params.push(id);
    const r = await db().query(
        `UPDATE resellers SET ${sets.join(", ")} WHERE id = $${params.length}
         RETURNING id, username, plan, status, max_keys, max_devices_per_key, updated_at`,
        params
    );
    if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    if (b?.status === "disabled") await revokeAllResellerSessions(id);
    await logEvent(null, "reseller_updated", clientIp(req), { rid: id });
    return Response.json({ reseller: r.rows[0] });
}

async function adminPassword(req: Request): Promise<Response> {
    const b = await req.json().catch(() => ({}));
    const id = Number(b?.id || 0);
    const password = String(b?.password ?? "");
    if (!id || password.length < 8) return Response.json({ error: "bad_request" }, { status: 400 });
    const r = await db().query(`UPDATE resellers SET password_hash = $1, updated_at = now() WHERE id = $2 RETURNING id`, [hashPassword(password), id]);
    if (!r.rows.length) return Response.json({ error: "not_found" }, { status: 404 });
    await revokeAllResellerSessions(id);
    await logEvent(null, "reseller_password_reset", clientIp(req), { rid: id });
    return Response.json({ ok: true });
}

// Reseller POST actions (same function slot).
export async function POST(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const action = url.searchParams.get("action") || "";
    if (action === "login") {
        try {
            return await rLogin(req);
        } catch {
            return Response.json({ error: "backend_error" }, { status: 500 });
        }
    }
    if (action === "logout") {
        const rid = await requireReseller(req);
        if (typeof rid !== "number") return rid;
        await revokeResellerSession(req.headers.get("x-reseller-token") || "");
        await rlog(rid, "reseller_logout", clientIp(req), {}).catch(() => {});
        return Response.json({ ok: true });
    }
    if (action === "generate" || action === "sell") {
        const rid = await requireReseller(req);
        if (typeof rid !== "number") return rid;
        try {
            return action === "generate" ? await rGenerate(rid, req) : await rSell(rid, req);
        } catch (e: any) {
            return Response.json({ error: "backend_error" }, { status: 500 });
        }
    }
    if (action === "admin-create" || action === "admin-set" || action === "admin-password") {
        if (!isAdmin(req)) return deny();
        try {
            if (action === "admin-create") return await adminCreate(req);
            if (action === "admin-set") return await adminSet(req);
            return await adminPassword(req);
        } catch (e: any) {
            return Response.json({ error: "backend_error" }, { status: 500 });
        }
    }
    return Response.json({ error: "bad_request" }, { status: 400 });
}
