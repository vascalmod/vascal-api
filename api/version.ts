import { q } from "../lib/db.js";

// GET /api/version?tag=1.0.0 -> { latest, url, sha256, notes, update: bool }
// Public. update=true when latest != caller's tag (caller decides; server never forces).

export async function GET(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const tag = url.searchParams.get("tag") ?? "";
    const { rows } = await q(
        `SELECT tag, url, sha256, notes FROM releases ORDER BY at DESC LIMIT 1`
    );
    if (!rows.length) return Response.json({ latest: tag, update: false });
    const r = rows[0];
    return Response.json({
        latest: r.tag,
        url: r.url,
        sha256: r.sha256,
        notes: r.notes ?? "",
        update: r.tag !== tag,
    });
}
