import { createHash, randomBytes } from "crypto";
import { db, q } from "../../lib/db.js";
import { sealKey } from "../../lib/keywrap.js";

// All admin ops: header `x-admin-secret: $ADMIN_SECRET`.

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

function deny(): Response {
    return Response.json({ error: "forbidden" }, { status: 403 });
}

function newKey(): string {
    return `VSC-${randomBytes(9).toString("hex").toUpperCase()}`;
}

// POST /api/admin/create-key { plan, days, note } -> { license_key, id } (plaintext shown ONCE)
// ids are random 8-digit (non-sequential, no reuse gaps); retry on rare collision.
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return deny();
    const b = await req.json().catch(() => ({}));
    const days = Number(b?.days ?? 30);
    const key = newKey();
    const hash = createHash("sha256").update(key, "utf8").digest("hex");
    const exp = new Date(Date.now() + days * 864e5).toISOString();
    for (let t = 0; t < 5; t++) {
        const id = 10000000 + Math.floor(Math.random() * 90000000);
        try {
            await db().query(
                `INSERT INTO keys (id, license_key_hash, key_prefix, key_suffix, key_enc, plan, expires_at, note) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                [id, hash, key.slice(0, 8), key.slice(-4), sealKey(key), String(b?.plan ?? "monthly"), exp, String(b?.note ?? "")]
            );
            return Response.json({ license_key: key, id, expires_at: exp });
        } catch (e: any) {
            if (t === 4 || !String(e?.message || e).includes("duplicate")) throw e;
        }
    }
    return Response.json({ error: "retry" }, { status: 503 });
}
