import { UpstreamError, readBoundedResponse } from './remote';

// A local cap protects each instance and leaves two slots available to paste scans.
const buckets = new Map<string, { count: number; expires: number }>();
let active = 0;
let activeRemote = 0;
export function admitScan(key: string, remote: boolean): (() => void) | null {
  const now = Date.now();
  for (const [id, bucket] of Array.from(buckets)) if (bucket.expires <= now) buckets.delete(id);
  const id = `${remote ? 'remote' : 'code'}:${key}`;
  const bucket = buckets.get(id) || { count: 0, expires: now + 60_000 };
  if (active >= 4 || remote && activeRemote >= 2 || bucket.count >= (remote ? 5 : 30) || (!buckets.has(id) && buckets.size >= 1000)) return null;
  bucket.count++;
  buckets.set(id, bucket);
  active++;
  if (remote) activeRemote++;
  let released = false;
  return () => {
    if (released) return;
    if (remote) activeRemote--;
    active--;
    released = true;
  };
}

const TAKE_REMOTE_SLOT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], 60) end
return count
`;

/** Optional fleet-wide admission sends only an aggregate counter to the configured provider. */
export async function admitSharedRemoteScan(signal: AbortSignal): Promise<boolean> {
  const url = process.env.SKILLSCAN_REDIS_REST_URL;
  const token = process.env.SKILLSCAN_REDIS_REST_TOKEN;
  if (!url && !token) return true;
  try {
    if (!url || !token) throw new Error('Incomplete shared limiter configuration');
    const endpoint = new URL(url);
    if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.upstash.io') || endpoint.port || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) {
      throw new Error('Invalid shared limiter endpoint');
    }
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(1500)]);
    const response = await fetch(endpoint.href, {
      method: 'POST', cache: 'no-store', redirect: 'error', signal: deadline,
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify(['EVAL', TAKE_REMOTE_SLOT, 1, 'skillscan:remote-scans']),
    });
    if (!response.ok) throw new Error('Shared limiter failed');
    const data = JSON.parse(new TextDecoder().decode(await readBoundedResponse(response, 1024, deadline))) as { result?: number };
    if (typeof data.result !== 'number' || !Number.isSafeInteger(data.result) || data.result < 1) throw new Error('Invalid shared limiter result');
    return data.result <= 60;
  } catch {
    throw new UpstreamError('Remote scan admission is temporarily unavailable.', 502);
  }
}
