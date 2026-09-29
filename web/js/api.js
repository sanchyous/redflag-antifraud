// Клиент API. Ключ доступа (X-API-Key) хранится в sessionStorage вкладки и никогда не попадает в URL.

const KEY = 'redflag.apiKey';

export const getKey = () => sessionStorage.getItem(KEY) || '';
export const setKey = (k) => (k ? sessionStorage.setItem(KEY, k) : sessionStorage.removeItem(KEY));

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

/** Запрос к API. Возвращает разобранный JSON; при не-2xx бросает ApiError. */
export async function api(path, { method = 'GET', body, timeout = 8000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const key = getKey();
  if (key) headers['X-API-Key'] = key;
  try {
    const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: ctrl.signal });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* не JSON */ }
    if (!res.ok) throw new ApiError(res.status, (data && (data.error || data.detail)) || res.statusText, data);
    return data;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if (e.name === 'AbortError') throw new ApiError(0, 'превышено время ожидания ответа');
    throw new ApiError(0, 'нет связи с сервисом');
  } finally {
    clearTimeout(timer);
  }
}

export const getStatus = () => api('/v1/status');
export const getStats = (windowSec, points) => api(`/v1/stats?window=${windowSec}&points=${points}`);
export const getEvents = (limit = 50, decision = '') => api(`/v1/events?limit=${limit}${decision ? '&decision=' + decision : ''}`);
export const getModel = () => api('/v1/model');
export const getFans = () => api('/v1/graph/fans');
export const scoreCall = (call) => api('/v1/calls/score', { method: 'POST', body: call });
