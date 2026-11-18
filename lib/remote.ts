import { trustedHttpsUrl } from './urls';

export class UpstreamError extends Error {
  constructor(message: string, readonly status: 400 | 429 | 502 | 504, readonly retryAfter?: string) { super(message); }

  static fromResponse(source: string, response: Response): UpstreamError {
    if (response.status === 429 || response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0') {
      const delay = response.headers.get('retry-after');
      return new UpstreamError(source + ' is limiting requests. Try again shortly.', 429, delay && /^\d{1,5}$/.test(delay) ? delay : '60');
    }
    return response.status >= 500
      ? new UpstreamError(source + ' is temporarily unavailable.', 502)
      : new UpstreamError('The requested ' + source + ' target could not be read.', 400);
  }
}

export class RemoteBudget {
  private requests = 0;
  private readonly deadline: number;
  constructor(readonly signal?: AbortSignal, readonly maxRequests = 80, durationMs = 45_000) {
    this.deadline = Date.now() + durationMs;
  }
  nextSignal(): AbortSignal {
    if (++this.requests > this.maxRequests) throw new Error('Remote scan request limit reached');
    const remaining = this.deadline - Date.now();
    if (remaining <= 0) throw new UpstreamError('Remote scan deadline reached', 504);
    const timeout = AbortSignal.timeout(Math.min(10_000, remaining));
    return this.signal ? AbortSignal.any([this.signal, timeout]) : timeout;
  }
}

export async function trustedFetch(input: string, hosts: readonly string[], budget: RemoteBudget, init: RequestInit = {}): Promise<Response> {
  const url = trustedHttpsUrl(input, hosts);
  const signal = budget.nextSignal();
  try {
    return await fetch(url.href, { ...init, redirect: 'error', signal, cache: 'no-store' });
  } catch {
    if (signal.aborted) throw new UpstreamError('Remote request timed out or was cancelled.', 504);
    throw new UpstreamError('Could not reach the upstream service.', 502);
  }
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
