/** Cliente API: TODA la funcionalidad pasa por /api/v1 (nada de datos
 * inventados en el frontend). Devuelve también el x-request-id para que
 * el usuario/instructor pueda correlacionar con los logs de Sentinel. */
export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch('/api/v1' + path, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) { const err = new Error(data?.error?.message || `Error ${res.status}`); err.status = res.status; err.code = data?.error?.code; err.requestId = res.headers.get('x-request-id'); throw err; }
  return { data, requestId: res.headers.get('x-request-id') };
}
export const fmtDate = s => s ? String(s).slice(0, 10) : '—';
