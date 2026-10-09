/**
 * CyberRakshak AI — Authenticated API Client
 * Manages cryptographic session tokens and secure workspace-authorized API requests.
 */

const TOKEN_KEY = 'cyberrakshak_session_token';
const USER_KEY = 'cyberrakshak_session_user';

export function getAuthToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAuthToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {}
}

export function clearAuthSession(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {}
}

export function getStoredUser(): any | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(user: any): void {
  try {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {}
}

/**
 * Authenticated Fetch wrapper
 * Automatically injects the Authorization Bearer header into every request.
 */
export async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return fetch(url, {
    ...options,
    headers
  });
}

/**
 * Authenticate with email & password
 */
export async function loginWithCredentials(email: string, password: string) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Authentication failed (${res.status})`);
  }

  const data = await res.json();
  if (data.token) {
    setAuthToken(data.token);
    setStoredUser(data.user);
  }
  return data;
}

/**
 * Explicit demo mode session initialization (only available when demo mode is active)
 */
export async function initDemoSession(role: 'Owner' | 'Analyst' = 'Owner') {
  const res = await fetch('/api/auth/demo', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role })
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Demo session initialization failed (${res.status})`);
  }

  const data = await res.json();
  if (data.token) {
    setAuthToken(data.token);
    setStoredUser(data.user);
  }
  return data;
}

// Global browser fetch interceptor: ensures all /api requests include Authorization Bearer header
if (typeof window !== 'undefined' && window.fetch) {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async function (input: RequestInfo | URL, init?: RequestInit) {
    let url = '';
    if (typeof input === 'string') {
      url = input;
    } else if (input instanceof URL) {
      url = input.toString();
    } else if (input && typeof (input as any).url === 'string') {
      url = (input as any).url;
    }

    if (url.startsWith('/api') && !url.startsWith('/api/health') && !url.startsWith('/api/auth/login') && !url.startsWith('/api/auth/demo')) {
      const token = getAuthToken();
      if (token) {
        init = init || {};
        const headers = new Headers(init.headers || (typeof input === 'object' && 'headers' in input ? (input as any).headers : {}));
        if (!headers.has('Authorization')) {
          headers.set('Authorization', `Bearer ${token}`);
        }
        init.headers = headers;
      }
    }
    return nativeFetch(input, init);
  };
}
