import { issueNonce } from "../lib/nonce.js";

export async function GET(): Promise<Response> {
    return Response.json({ nonce: issueNonce() });
}
