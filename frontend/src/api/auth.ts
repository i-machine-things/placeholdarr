import { fetchJson, postJson } from "./client";
import type { AuthStatus } from "../types/api";

export function getAuthStatus(): Promise<AuthStatus> {
  return fetchJson<AuthStatus>("/api/auth/status");
}

export function setupCredentials(username: string, password: string): Promise<{ ok: boolean }> {
  return postJson<{ ok: boolean }>("/api/auth/setup", { username, password });
}

export function login(
  username: string,
  password: string,
  rememberMe: boolean,
): Promise<{ ok: boolean }> {
  return postJson<{ ok: boolean }>("/api/auth/login", {
    username,
    password,
    remember_me: rememberMe,
  });
}

export function logout(): Promise<{ ok: boolean }> {
  return postJson<{ ok: boolean }>("/api/auth/logout");
}

export function changePassword(
  currentPassword: string,
  newPassword: string,
  newUsername?: string,
): Promise<{ ok: boolean }> {
  return postJson<{ ok: boolean }>("/api/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
    new_username: newUsername,
  });
}

export function getWebhookApiKey(): Promise<{ webhook_api_key: string | null }> {
  return fetchJson<{ webhook_api_key: string | null }>("/api/auth/webhook-key");
}

export function regenerateWebhookApiKey(): Promise<{ webhook_api_key: string }> {
  return postJson<{ webhook_api_key: string }>("/api/auth/webhook-key/regenerate");
}
