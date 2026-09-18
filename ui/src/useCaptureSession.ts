import { useCallback, useEffect, useState } from "react";

const POLL_MS = 2_000;

export interface CaptureSession {
  enabled: boolean;
  state: "stopped" | "starting" | "running" | "stopping";
  expiresAt?: string;
  desiredWorkers: number;
  readyWorkers: number;
  error?: string;
  defaultDuration: string;
  maxDuration: string;
}

// A 404 means an older/default hub, where the existing capture-pause control
// remains the correct UI. Other failures are retained as actionable feedback.
export function useCaptureSession() {
  const [session, setSession] = useState<CaptureSession | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try {
      const r = await fetch("/api/capture/session");
      if (r.status === 404) return;
      const body = await r.text();
      const data = (() => { try { return JSON.parse(body) as CaptureSession; } catch { return null; } })();
      if (data?.enabled) setSession(data);
      if (!r.ok) { setError(data?.error || body); return; }
      if (data) { setSession(data); setError(""); }
    } catch { setError("Unable to reach the hub while checking capture session."); }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, POLL_MS); return () => clearInterval(id); }, [load]);
  const mutate = useCallback(async (path: string, duration?: string) => {
    try {
      const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: duration ? JSON.stringify({ duration }) : undefined });
      if (!r.ok) { setError(await r.text()); return; }
      setSession(await r.json()); setError("");
      void load();
    } catch { setError("Unable to reach the hub while changing capture session."); }
  }, [load]);
  return { session, error, start: (duration: string) => mutate("/api/capture/session/start", duration), stop: () => mutate("/api/capture/session/stop") };
}
