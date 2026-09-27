import { randomBytes, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey } from "crypto";

// Ed25519 session tokens: "v1.<base64url(payload)>.<base64url(sig)>"
// Payload: { jti, uid, key_id, build, over, exp } — over = offsets version (game_version row id)

const PRIV_PEM = process.env.TOKEN_PRIVKEY!; // PKCS8 PEM, server-only
const PUB_PEM = process.env.TOKEN_PUBKEY!;   // SPKI PEM, also baked into the native client

export const TOKEN_TTL_SEC = 12 * 60; // 12-minute sessions, refreshed by heartbeat

function b64u(buf: Buffer): string {
    return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64u(s: string): Buffer {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Buffer.from(s, "base64");
}

export function mintToken(args: { jti: string; uid: number; key_id: number; build: string; over: string; exp: number }): string {
    const payload = Buffer.from(JSON.stringify(args), "utf8");
    const sig = sign(null, payload, createPrivateKey(PRIV_PEM));
    return `v1.${b64u(payload)}.${b64u(sig)}`;
}

export function verifyToken(token: string): { jti: string; uid: number; key_id: number; build: string; over: string; exp: number } | null {
    try {
        const [ver, p, s] = token.split(".");
        if (ver !== "v1" || !p || !s) return null;
        const payload = unb64u(p);
        if (!verify(null, payload, createPublicKey(PUB_PEM), unb64u(s))) return null;
        const claims = JSON.parse(payload.toString("utf8"));
        if (typeof claims.exp !== "number" || Date.now() / 1000 > claims.exp + 300) return null; // 5-min skew grace
        return claims;
    } catch {
        return null;
    }
}

export function newJti(): string {
    return randomBytes(16).toString("hex");
}

// One-time dev helper (never ship an endpoint calling this):
// node -e "console.log(require('./lib/token').genKeypair().join('\n'))"
export function genKeypair(): [string, string] {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return [
        privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
        publicKey.export({ format: "pem", type: "spki" }).toString(),
    ];
}
