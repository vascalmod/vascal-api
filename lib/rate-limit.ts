// Minimal in-memory throttle. Resets on cold start — good enough for abuse friction,
// real distributed limiting can come later (Upstash). Fail-open on weird keys.

const hits = new Map<string, { n: number; reset: number }>();

export function throttle(key: string, limit: number, windowSec: number): boolean {
    const now = Date.now();
    const e = hits.get(key);
    if (!e || now > e.reset) {
        hits.set(key, { n: 1, reset: now + windowSec * 1000 });
        return true;
    }
    e.n++;
    return e.n <= limit;
}
