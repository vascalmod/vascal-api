import { q } from "../../lib/db.js";
import { logEvent, clientIp } from "../../lib/validate.js";

function authed(req: Request): boolean {
    return req.headers.get("x-admin-secret") === process.env.ADMIN_SECRET;
}

// POST /api/admin/push-release { tag, url, sha256, notes, seals? }
// url: public download link (Supabase Storage object URL). sha256: hex of the binary.
// seals: {"trust":"<hex>"} — expected Trust::Seal() for this build.
export async function POST(req: Request): Promise<Response> {
    if (!authed(req)) return Response.json({ error: "forbidden" }, { status: 403 });
    const b = await req.json().catch(() => ({}));
    if (typeof b?.tag !== "string" || typeof b?.url !== "string" || typeof b?.sha256 !== "string") {
        return Response.json({ error: "bad_request" }, { status: 400 });
    }
    await q(`INSERT INTO releases (tag, url, sha256, notes, seals) VALUES ($1, $2, $3, $4, $5)`, [
        b.tag,
        b.url,
        b.sha256.toLowerCase(),
        String(b?.notes ?? ""),
        JSON.stringify(b?.seals && typeof b.seals === "object" ? b.seals : {}),
    ]);
    await logEvent(null, "release_push", clientIp(req), { tag: b.tag });
    return Response.json({ ok: true });
}
