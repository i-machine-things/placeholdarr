import { useEffect, useRef } from "react";
import { getAuthStatus } from "../api/auth";
import type { AuthStatus } from "../types/api";

/** Fetch login/session status on demand (mount + tab focus). No periodic interval.
 * Structurally mirrors useSetupStatusPoll, but unlike that hook this one is
 * always enabled from first render — it's how the app discovers whether to
 * show anything at all. */
export function useAuthStatusPoll(opts: {
  enabled: boolean;
  onStatus: (status: AuthStatus) => void;
  onError?: (message: string) => void;
}) {
  const onStatusRef = useRef(opts.onStatus);
  const onErrorRef = useRef(opts.onError);

  useEffect(() => {
    onStatusRef.current = opts.onStatus;
    onErrorRef.current = opts.onError;
  }, [opts.onError, opts.onStatus]);

  useEffect(() => {
    if (!opts.enabled) return;

    let stopped = false;

    const refresh = async () => {
      if (stopped) return;
      const hidden = typeof document !== "undefined" && document.visibilityState !== "visible";
      if (hidden) return;

      try {
        const status = await getAuthStatus();
        if (!stopped) {
          onStatusRef.current(status);
        }
      } catch (err) {
        if (!stopped) {
          onErrorRef.current?.(err instanceof Error ? err.message : "Unable to load auth status");
        }
      }
    };

    void refresh();

    const onVisibility = () => {
      if (stopped) return;
      if (typeof document !== "undefined" && document.visibilityState === "visible") {
        void refresh();
      }
    };

    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      stopped = true;
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [opts.enabled]);
}
