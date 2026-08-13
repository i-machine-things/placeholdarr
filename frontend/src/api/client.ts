type UnauthorizedHandler = () => void;
let onUnauthorized: UnauthorizedHandler | null = null;

/** Called from App.tsx once auth state is known, so a mid-session cookie
 * expiry bounces the user back to the login screen instead of every call
 * site needing to know about auth. A failed login itself is an *expected*
 * 401 (must render inline as "Invalid password", not bounce anyone), so
 * requests to /api/auth/login never trigger this handler. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  onUnauthorized = handler;
}

function notifyUnauthorizedIfNeeded(path: string, status: number) {
  if (status === 401 && path !== "/api/auth/login") {
    onUnauthorized?.();
  }
}

function humanizeFetchFailure(err: unknown): Error {
  if (err instanceof TypeError) {
    return new Error(
      "Cannot reach the Placeholdarr API (network error). Trying to reconnect…",
    );
  }
  if (err instanceof Error && /failed to fetch/i.test(err.message)) {
    return new Error(
      "Cannot reach the Placeholdarr API. Confirm the backend is running and the page is served from the same origin as /api (or configure your reverse proxy).",
    );
  }
  return err instanceof Error ? err : new Error(String(err));
}

export async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      headers: {
        Accept: "application/json",
      },
      ...init,
    });
  } catch (err) {
    throw humanizeFetchFailure(err);
  }

  if (!response.ok) {
    notifyUnauthorizedIfNeeded(path, response.status);
    let message = `Request failed: ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string; detail?: string };
      message = payload.message || payload.detail || message;
    } catch {
      // Keep fallback message when response is not JSON.
    }
    throw new Error(message);
  }

  return (await response.json()) as T;
}

export async function postJson<T>(path: string, body?: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: {
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    throw humanizeFetchFailure(err);
  }
  if (!response.ok) {
    notifyUnauthorizedIfNeeded(path, response.status);
    let message = `Request failed: ${response.status}`;
    try {
      const payload = (await response.json()) as { message?: string; detail?: string };
      message = payload.message || payload.detail || message;
    } catch {
      /* ignore */
    }
    throw new Error(message);
  }
  return (await response.json()) as T;
}
