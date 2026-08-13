import { useState, type CSSProperties, type FormEvent } from "react";
import { login } from "../api/auth";
import type { Brand } from "../brandTypes";
import { BrandLogo } from "../App";

export function LoginScreen(props: {
  setupShellClass: string;
  surfaceStyle: CSSProperties;
  brand: Brand;
  accentHex: string;
  appLabel: string;
  onSuccess: () => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password, rememberMe);
      props.onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className={`${props.setupShellClass} setup-boot-shell`} style={props.surfaceStyle}>
      <div className="flex w-full max-w-[min(92vw,22rem)] flex-col items-center gap-7">
        <div className="flex flex-col items-center gap-3 opacity-90">
          <BrandLogo brand={props.brand} accentHex={props.accentHex} className="h-14 w-auto max-w-[11rem] object-contain" />
          <div className="text-center text-[13px] font-headline font-bold uppercase tracking-[0.22em] text-slate-500">
            {props.appLabel}
          </div>
        </div>
        <form onSubmit={handleSubmit} className="w-full space-y-4 text-left">
          <div>
            <label className="block text-[13px] font-semibold text-slate-400 mb-1">Username</label>
            <input
              className="w-full bg-[#0b111b] border border-[#424753]/40 rounded-lg px-3 py-2 text-[14px] text-slate-200"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              disabled={submitting}
              autoFocus
            />
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-slate-400 mb-1">Password</label>
            <input
              className="w-full bg-[#0b111b] border border-[#424753]/40 rounded-lg px-3 py-2 text-[14px] text-slate-200"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              autoComplete="current-password"
              disabled={submitting}
            />
          </div>
          <label className="flex items-center gap-2 text-[13px] text-slate-400">
            <input
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              disabled={submitting}
            />
            Remember me
          </label>
          <div className="min-h-[1.5rem] text-[14px]" aria-live="polite">
            {error ? (
              <p className="text-red-400/95" role="alert">
                {error}
              </p>
            ) : null}
          </div>
          <button
            type="submit"
            className="btn-brand-tertiary w-full px-5 py-2 rounded-lg text-[14px] font-headline uppercase tracking-wider"
            disabled={submitting}
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
