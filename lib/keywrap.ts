import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "crypto";

// Sealed envelopes for license plaintext. Key derived from ADMIN_SECRET —
// a database breach alone reveals nothing. Reveal is audit-logged per use.

function kek(): Buffer {
    return scryptSync(process.env.ADMIN_SECRET!, "vascal-keywrap", 32);
}

export function sealKey(plaintext: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", kek(), iv);
    const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
    return `${iv.toString("hex")}.${ct.toString("hex")}.${c.getAuthTag().toString("hex")}`;
}

export function openKey(env: string): string | null {
    try {
        const [iv, ct, tag] = env.split(".");
        const d = createDecipheriv("aes-256-gcm", kek(), Buffer.from(iv, "hex"));
        d.setAuthTag(Buffer.from(tag, "hex"));
        return Buffer.concat([d.update(Buffer.from(ct, "hex")), d.final()]).toString("utf8");
    } catch {
        return null;
    }
}
