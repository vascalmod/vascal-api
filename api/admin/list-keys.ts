import { db } from "../../lib/db.js";

// GET /api/admin/list-keys?status=active&limit=50&offset=0 (header x-admin-secret)
// Rows carry hashes only (plaintext is never stored). Includes device count + last event.

export async function GET(req: Request): Promise<Response> {
    if (req.headers.get("x-admin-secret") !== process.env.ADMIN_SECRET) {
        return Response.json({ error: "forbidden" }, { status: 403 });
    }
    const url = new URL(req.url);
    const status = url.searchParams.get("status") || "";
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const offset = Math.max(0, Number(url.searchParams.get("offset") || 0));
    const where = status === "active" || status === "revoked" || status === "suspended" ? "WHERE k.status = $3" : "";
    const params: any[] = [limit, offset];
    if (where) params.push(status);
    const { rows } = await db().query(
        `SELECT k.id, k.plan, k.expires_at, k.bound_uid, k.status, k.note, k.created_at,
                (SELECT count(*)::int FROM devices d WHERE d.key_id = k.id) AS devices,
                (SELECT max(at) FROM events e WHERE e.key_id = k.id) AS last_seen
         FROM keys k ${where} ORDER BY k.created_at DESC LIMIT $1 OFFSET $2`,
        params
    );
    return Response.json({ keys: rows });
}
