import { createHmac, randomBytes, timingSafeEqual } from "crypto";

// Stateless single-use-ish nonces: HMAC(timestamp.rand). No storage, survives cold starts.
// Replay window killed by 120s expiry + server rejecting reused (nonce, uid) pairs per login attempt.

const SECRET = process.env.NONCE_SECRET!;
const TTL_SEC = 120;

export function issueNonce(): string {
    const ts = Math.floor(Date.now() / 1000);
    const rand = randomBytes(12).toString("hex");
    const body = `${ts}.${rand}`;
    const mac = createHmac("sha256", SECRET).update(body).digest("hex");
    return `${body}.${mac}`;
}

export function consumeNonce(nonce: string): boolean {
    try {
        const [ts, rand, mac] = nonce.split(".");
        if (!ts || !rand || !mac) return false;
        if (Math.floor(Date.now() / 1000) - Number(ts) > TTL_SEC) return false;
        const expect = createHmac("sha256", SECRET).update(`${ts}.${rand}`).digest("hex");
        const a = Buffer.from(mac, "hex");
        const b = Buffer.from(expect, "hex");
        return a.length === b.length && timingSafeEqual(a, b);
    } catch {
        return false;
    }
}
