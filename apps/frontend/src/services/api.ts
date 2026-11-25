export const AUTHORIZATION_LOST = 'atomic:authorization-lost';
function checkAuthorization(path: string, status: number) {
  if (status === 401 || (path.split('?')[0] === '/me' && [403, 503].includes(status)))
    window.dispatchEvent(new CustomEvent(AUTHORIZATION_LOST, { detail: { status } }));
}
export class APIError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin',
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const body = await response.json();
  if (!response.ok) {
    checkAuthorization(path, response.status);
    throw new APIError(
      body.error?.code ?? 'request_failed',
      body.error?.message ?? 'Request failed',
      response.status,
    );
  }
  return body as T;
}
export function post<T>(path: string, body: unknown, key?: string) {
  return api<T>(path, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: key ? { 'Idempotency-Key': key } : {},
  });
}
export async function allItems<T>(path: string): Promise<T[]> {
  const result: T[] = [];
  let offset = 0;
  for (;;) {
    const page = await api<{ items: T[]; total: number }>(
      `${path}${path.includes('?') ? '&' : '?'}limit=200&offset=${offset}`,
    );
    result.push(...page.items);
    offset += page.items.length;
    if (offset >= page.total || !page.items.length) return result;
  }
}

export async function downloadAgentPackage(
  actorId: string,
  payload: {
    api_url: string;
    include_enrollment: boolean;
    catalog_revision: string;
    delivery_mode?: string;
  },
) {
  const response = await fetch(`/api/v1/actors/${actorId}/agent-package`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    checkAuthorization(`/actors/${actorId}/agent-package`, response.status);
    const data = await response.json();
    throw new APIError(
      data.error?.code ?? 'package_failed',
      data.error?.message ?? 'Agent package generation failed',
      response.status,
    );
  }
  const filename =
    /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ??
    'AtomicControlAgent.zip';
  const checksum = response.headers.get('X-Package-SHA256') ?? '';
  const mode = response.headers.get('X-Package-Mode') ?? 'configuration_only';
  const expires = Number(response.headers.get('X-Enrollment-Expires-At')) || null;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return { filename, checksum, mode, expiresAt: expires };
}
