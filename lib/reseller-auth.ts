import { randomBytes, scryptSync, timingSafeEqual } from "crypto";
import { q } from "./db.js";
import { mintToken, verifyToken } from "./token.js";

export const RESELLER_TTL_SEC = 8 * 3600;
const AUD = "reseller-v1";

// Stored format: `scrypt$<salt-hex>$<hash-hex>` (N=16384, r=8, p=1, 32 bytes).
export function hashPassword(pw: string): string {
    const salt = randomBytes(16);
    const h = scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 });
    return `scrypt$${salt.toString("hex")}$${Buffer.from(h).toString("hex")}`;
}

export function checkPassword(pw: string, stored: string): boolean {
    try {
        const [tag, saltHex, hashHex] = stored.split("$");
        if (tag !== "scrypt" || !saltHex || !hashHex) return false;
        const h = scryptSync(pw, Buffer.from(saltHex, "hex"), 32, { N: 16384, r: 8, p: 1 });
        return timingSafeEqual(Buffer.from(h), Buffer.from(hashHex, "hex"));
    } catch { return false; }
}

// Reuses the Ed25519 pair; audience string keeps license tokens unusable here and vice versa.
// The jti row makes logout / password-reset / disable revoke live sessions.
export async function mintResellerSession(rid: number): Promise<{ token: string; exp: number }> {
    const exp = Math.floor(Date.now() / 1000) + RESELLER_TTL_SEC;
    const jti = randomBytes(16).toString("hex");
    const token = mintToken({ jti, uid: 0, key_id: 0, build: AUD, over: String(rid), exp } as any);
    await q(`INSERT INTO reseller_sessions (jti, reseller_id, expires_at) VALUES ($1, $2, to_timestamp($3))`, [jti, rid, exp]);
    return { token, exp };
}

export async function verifyResellerSession(token: string): Promise<{ rid: number; exp: number } | null> {
    const c: any = verifyToken(token);
    if (!c || c.build !== AUD) return null;
    const rid = Number(c.over);
    if (!rid || !c.jti) return null;
    const { rows } = await q(
        `SELECT expires_at, revoked FROM reseller_sessions WHERE jti = $1 AND reseller_id = $2 LIMIT 1`,
        [String(c.jti), rid]
    );
    if (!rows.length || rows[0].revoked) return null;
    if (new Date(rows[0].expires_at).getTime() < Date.now()) return null;
    return { rid, exp: c.exp };
}

export async function revokeResellerSession(token: string): Promise<void> {
    try {
        const c: any = verifyToken(token);
        if (c?.jti) await q(`UPDATE reseller_sessions SET revoked = TRUE WHERE jti = $1`, [String(c.jti)]);
    } catch { /* best effort on the way out */ }
}

export async function revokeAllResellerSessions(rid: number): Promise<void> {
    await q(`UPDATE reseller_sessions SET revoked = TRUE WHERE reseller_id = $1`, [rid]);
}

// Returns rid or a ready 401 Response. Rejects missing/bad/revoked sessions and disabled resellers.
export async function requireReseller(req: Request): Promise<number | Response> {
    const t = (req.headers.get("x-reseller-token") || "").trim();
    const v = t ? await verifyResellerSession(t) : null;
    if (!v) return Response.json({ error: "unauthorized" }, { status: 401 });
    const { rows } = await q(`SELECT id, status FROM resellers WHERE id = $1 LIMIT 1`, [v.rid]);
    if (!rows.length || rows[0].status !== "active") return Response.json({ error: "unauthorized" }, { status: 401 });
    return Number(rows[0].id);
}
