export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}

// Identical GET requests made at the same moment share one network request: a page that shows the same control many times
// (say, one per incident) can never flood the browser's 6-connections-per-server queue and slow everything else down.
const pending = new Map<string, Promise<unknown>>();

// The session is an httpOnly cookie; X-Requested-With is the CSRF guard the API requires.
export function api<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  if (method !== 'GET' || options.body) return request<T>(path, options);
  const shared = pending.get(path);
  if (shared) return shared as Promise<T>;
  const p = request<T>(path, options).finally(() => pending.delete(path));
  pending.set(path, p);
  return p;
}

async function request<T>(path: string, options: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'smwatch', ...(options.headers || {}) },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (data as { detail?: unknown }).detail;
    let message = `Request failed (${response.status})`;
    if (typeof detail === 'string') message = detail;
    else if (Array.isArray(detail)) message = detail.map(item => (item as { msg?: string }).msg || JSON.stringify(item)).join('; ');
    throw new ApiError(message, response.status);
  }
  return data as T;
}

export const post = <T = unknown>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });
export const put = <T = unknown>(path: string, body: unknown) => api<T>(path, { method: 'PUT', body: JSON.stringify(body) });
export const del = <T = unknown>(path: string) => api<T>(path, { method: 'DELETE' });
