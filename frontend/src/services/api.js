const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

function readCsrfCookie() {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

/**
 * Wraps fetch with the things every call in this app needs:
 *  - credentials: 'include' so the HttpOnly session cookie is sent/stored —
 *    NOT an Authorization header, since we deliberately never hold a token
 *    in JavaScript-accessible memory or storage (see backend SessionService
 *    Javadoc for why).
 *  - the CSRF double-submit header: the backend's CsrfDoubleSubmitFilter
 *    sets a readable XSRF-TOKEN cookie and requires state-changing requests
 *    to echo it back in X-XSRF-TOKEN. A cross-site attacker's page can't
 *    read this cookie (browsers block cross-origin cookie access), so it
 *    can't forge this header even if it can trigger the request.
 *  - consistent error handling: the backend always returns
 *    { code, message, timestamp } on failure, normalized here into a thrown
 *    Error the UI can display directly via err.message.
 */
async function request(path, options = {}) {
  const method = options.method || 'GET';
  const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
  const csrfToken = isMutating ? readCsrfCookie() : null;

  const response = await fetch(`${BASE_URL}${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(csrfToken ? { 'X-XSRF-TOKEN': csrfToken } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });

  const isJson = response.headers.get('content-type')?.includes('application/json');
  const body = isJson ? await response.json().catch(() => null) : null;

  if (!response.ok) {
    const message = body?.message || `Request failed (${response.status})`;
    const error = new Error(message);
    error.code = body?.code;
    error.status = response.status;
    throw error;
  }

  return body;
}

export const api = {
  get: (path) => request(path, { method: 'GET' }),
  post: (path, data) => request(path, { method: 'POST', body: data !== undefined ? JSON.stringify(data) : undefined }),
  patch: (path, data) => request(path, { method: 'PATCH', body: data !== undefined ? JSON.stringify(data) : undefined }),
  delete: (path) => request(path, { method: 'DELETE' }),
};
