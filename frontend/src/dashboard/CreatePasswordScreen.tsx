import { useState, type CSSProperties, type FormEvent } from "react";
import { setupCredentials } from "../api/auth";
import type { Brand } from "../brandTypes";
import { BrandLogo } from "../App";

const MIN_PASSWORD_LENGTH = 8; // must track core/auth.py's MIN_PASSWORD_LENGTH

/** Shown before anything else — including onboarding — on a totally fresh
 * install, or after upgrading an existing install that never had a password
 * set. Reuses the same full-screen shell wrapper as SetupBootShell so it
 * looks at home in the app, without depending on that component's
 * loading-bar internals. */
export function CreatePasswordScreen(props: {
  setupShellClass: string;
  surfaceStyle: CSSProperties;
  brand: Brand;
  accentHex: string;
  appLabel: string;
  onSuccess: () => void;
}) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (!username.trim()) {
      setError("Username is required.");
      return;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      await setupCredentials(username.trim(), password);
      props.onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the admin account.");
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
          <div className="text-center text-[15px] text-slate-300">
            Create an admin account to protect this dashboard before continuing.
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-slate-400 mb-1">Username</label>
            <input
              className="w-full bg-[#0b111b] border border-[#424753]/40 rounded-lg px-3 py-2 text-[14px] text-slate-200"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              disabled={submitting}
            />
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-slate-400 mb-1">Password</label>
            <input
              className="w-full bg-[#0b111b] border border-[#424753]/40 rounded-lg px-3 py-2 text-[14px] text-slate-200"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              type="password"
              autoComplete="new-password"
              disabled={submitting}
            />
          </div>
          <div>
            <label className="block text-[13px] font-semibold text-slate-400 mb-1">Confirm password</label>
            <input
              className="w-full bg-[#0b111b] border border-[#424753]/40 rounded-lg px-3 py-2 text-[14px] text-slate-200"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              type="password"
              autoComplete="new-password"
              disabled={submitting}
            />
          </div>
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
            {submitting ? "Creating…" : "Create admin account"}
          </button>
        </form>
      </div>
    </div>
  );
}
