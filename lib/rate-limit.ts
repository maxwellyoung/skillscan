// Best-effort per-instance protection; serverless instances do not share state.
const buckets = new Map<string, { count: number; expires: number }>();
let active = 0;
export function admitScan(key: string, remote: boolean): (() => void) | null {
  const now = Date.now();
  for (const [id, bucket] of Array.from(buckets)) if (bucket.expires <= now) buckets.delete(id);
  const id = `${remote ? 'remote' : 'code'}:${key}`;
  const bucket = buckets.get(id) || { count: 0, expires: now + 60_000 };
  if (active >= 4 || bucket.count >= (remote ? 5 : 30) || (!buckets.has(id) && buckets.size >= 1000)) return null;
  bucket.count++;
  buckets.set(id, bucket);
  active++;
  let released = false;
  return () => { if (!released) { active--; released = true; } };
}
