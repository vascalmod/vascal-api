import { Pool } from "pg";

// Single shared pool. DATABASE_URL comes from Vercel env vars.
let pool: Pool | null = null;

export function db(): Pool {
    if (!pool) {
        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            max: 5, // serverless-safe ceiling
            ssl: { rejectUnauthorized: false }, // pooler chain (Supabase) isn't in Node's CA set
            connectionTimeoutMillis: 20000, // survive Supabase free-tier wake-ups
            idleTimeoutMillis: 10000,
        });
    }
    return pool;
}

export async function sha256Hex(input: string): Promise<string> {
    const { createHash } = await import("crypto");
    return createHash("sha256").update(input, "utf8").digest("hex");
}

// One retry around every query: absorbs cold-start wake-ups without
// pushing retry logic into every endpoint.
export async function q(text: string, params: any[] = []): Promise<any> {
    try {
        return await db().query(text, params);
    } catch {
        await new Promise((r) => setTimeout(r, 1500));
        return await db().query(text, params);
    }
}
