import { createHash, randomBytes } from "crypto";
import { db, q } from "../../lib/db.js";

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

// POST /api/admin/create-key { plan, days, note } -> { license_key } (plaintext shown ONCE)
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return deny();
    const b = await req.json().catch(() => ({}));
    const days = Number(b?.days ?? 30);
    const key = newKey();
    const hash = createHash("sha256").update(key, "utf8").digest("hex");
    const exp = new Date(Date.now() + days * 864e5).toISOString();
    await db().query(
        `INSERT INTO keys (license_key_hash, key_prefix, key_suffix, plan, expires_at, note) VALUES ($1, $2, $3, $4, $5, $6)`,
        [hash, key.slice(0, 8), key.slice(-4), String(b?.plan ?? "monthly"), exp, String(b?.note ?? "")]
    );
    return Response.json({ license_key: key, expires_at: exp });
}
