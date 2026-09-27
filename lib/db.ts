import { Pool } from "pg";

// Single shared pool. DATABASE_URL comes from Vercel env vars.
let pool: Pool | null = null;

export function db(): Pool {
    if (!pool) {
        pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            max: 5, // serverless-safe ceiling
            ssl: { rejectUnauthorized: false }, // pooler chain (Supabase) isn't in Node's CA set
        });
    }
    return pool;
}

export async function sha256Hex(input: string): Promise<string> {
    const { createHash } = await import("crypto");
    return createHash("sha256").update(input, "utf8").digest("hex");
}
