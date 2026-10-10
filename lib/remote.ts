import { trustedHttpsUrl } from './urls';

export class RemoteBudget {
  private requests = 0;
  private readonly deadline: number;
  constructor(readonly signal?: AbortSignal, readonly maxRequests = 80, durationMs = 45_000) {
    this.deadline = Date.now() + durationMs;
  }
  nextSignal(): AbortSignal {
    if (++this.requests > this.maxRequests) throw new Error('Remote scan request limit reached');
    const remaining = this.deadline - Date.now();
    if (remaining <= 0) throw new Error('Remote scan deadline reached');
    const timeout = AbortSignal.timeout(Math.min(10_000, remaining));
    return this.signal ? AbortSignal.any([this.signal, timeout]) : timeout;
  }
}

export async function trustedFetch(input: string, hosts: readonly string[], budget: RemoteBudget, init: RequestInit = {}): Promise<Response> {
  const url = trustedHttpsUrl(input, hosts);
  return fetch(url.href, { ...init, redirect: 'error', signal: budget.nextSignal(), cache: 'no-store' });
}

/** A response that crossed its byte limit; callers may fall back to a smaller source. */
export class ResponseTooLargeError extends Error {
  constructor() { super('Response exceeds the scan size limit'); }
}

/** Limits actual streamed bytes, independently of attacker-provided length headers. */
export async function readBoundedResponse(response: Response, maxBytes: number, signal?: AbortSignal): Promise<Uint8Array> {
  if (Number(response.headers.get('content-length')) > maxBytes) {
    await response.body?.cancel();
    throw new ResponseTooLargeError();
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (signal?.aborted) throw new Error('Request body read timed out');
      if (done) break;
      size += value.length;
      if (size > maxBytes) {
        await reader.cancel();
        throw new ResponseTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    signal?.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

export async function readBoundedJson(response: Response): Promise<unknown> {
  return JSON.parse(new TextDecoder().decode(await readBoundedResponse(response, 2_000_000)));
}
