/**
 * Central API configuration for SPECTER frontend.
 * 
 * In development (npm run dev): Vite proxies /api → localhost:8000
 * so we use relative URLs — no CORS issues ever.
 * 
 * In production (built + served from same origin): also relative.
 * 
 * Only set VITE_API_URL in .env if backend is on a different host.
 */

export const API_BASE = import.meta.env.VITE_API_URL || "";

/**
 * Wrapper around fetch with error handling.
 * Returns parsed JSON or throws with a readable message.
 */
export async function apiFetch(path, options = {}) {
  const url = `${API_BASE}${path}`;
  let response;
  
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        ...(options.body && !(options.body instanceof FormData)
          ? { "Content-Type": "application/json" }
          : {}),
        ...options.headers,
      },
    });
  } catch (networkError) {
    // Network error — backend not reachable
    throw new Error(
      `Cannot reach SPECTER backend at ${url}. ` +
      `Make sure Docker is running: docker-compose up -d`
    );
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const err = await response.json();
      detail = err.detail || err.message || detail;
    } catch {}
    throw new Error(detail);
  }

  return response.json();
}

export const api = {
  get:  (path)         => apiFetch(path),
  post: (path, body)   => apiFetch(path, {
    method: "POST",
    body: body instanceof FormData ? body : JSON.stringify(body),
  }),
};
