// The webview's only door to the Python core: thin wrappers over the Rust bridge commands.
// No business logic here either; the core answers, the screens draw.
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type CoreError = { code: string; message: string };

export function isCoreError(e: unknown): e is CoreError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

/** Any method except key.unlock (refused by the bridge; use unlock()). */
export function call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>("core_call", { method, params });
}

/** The passphrase goes straight to the bridge; never keep it in a variable longer than this call. */
export function unlock(passphrase: string): Promise<{ unlocked: boolean }> {
  return invoke("core_unlock", { passphrase });
}

export function onCoreEvent(name: "progress" | "log" | "restarted" | "exited", cb: (payload: unknown) => void): Promise<UnlistenFn> {
  return listen(`core://${name}`, (e) => cb(e.payload));
}

export function coreStderr(): Promise<string[]> {
  return invoke<string[]>("core_stderr");
}

/** Try the keychain: key.unlock without a passphrase. Resolves to false when nothing is cached. */
export async function unlockFromKeychain(): Promise<boolean> {
  try {
    const r = await invoke<{ unlocked: boolean }>("core_call", { method: "key.unlock", params: {} });
    return !!r.unlocked;
  } catch {
    return false;
  }
}

export function launchArgs(): Promise<string[]> {
  return invoke<string[]>("launch_args");
}

export function mcpCommand(): Promise<string> {
  return invoke<string>("mcp_command");
}

// ---- the coach (Bet 15). Every coach command goes through here: no other file calls invoke. ------------

export type CoachMode = "off" | "local" | "cloud";
export type CoachSettings = { mode: CoachMode; base_url: string; model: string; key_in_keychain: boolean; include_points: boolean };
/** What a failed coach command rejects with: two fixed strings from closed enums and, for an error status, its number. */
export type CoachError = { code: string; message: string; status: number | null };
export type CoachKeyState = "absent" | "cached" | "stale" | "session_only";
export type CoachOutcome = { kind: "ok" } | { kind: "rejected"; detail: string } | { kind: "too_large" } | { kind: "tool_error"; detail: string };
export type CoachTrace = { tool: string; arguments_sent: unknown; bytes_sent: number; projected: unknown; outcome: CoachOutcome };
export type CoachReply = { text: string; trace: CoachTrace[] };
export type ProbeReport = {
  reachable: boolean;
  tools: "yes" | "no" | "unknown";
  context: "ok" | "too_small" | "unknown";
  measured_prompt_tokens: number | null;
  status: number | null;
  error: string | null;
};

export function coachAsk(text: string): Promise<CoachReply> {
  return invoke<CoachReply>("coach_ask", { text });
}

export function coachReset(): Promise<void> {
  return invoke("coach_reset");
}

export function coachProbe(): Promise<ProbeReport> {
  return invoke<ProbeReport>("coach_probe");
}

export function coachSettingsGet(): Promise<CoachSettings> {
  return invoke<CoachSettings>("coach_settings_get");
}

export function coachSettingsSet(settings: CoachSettings): Promise<CoachSettings> {
  return invoke<CoachSettings>("coach_settings_set", { settings });
}

/** The provider key goes straight to the shell; never keep it in a variable longer than this call. */
export function coachKeySet(key: string, remember: boolean): Promise<CoachKeyState> {
  return invoke<CoachKeyState>("coach_key_set", { key, remember });
}

export function coachKeyForget(): Promise<CoachKeyState> {
  return invoke<CoachKeyState>("coach_key_forget");
}

export function coachKeyState(): Promise<CoachKeyState> {
  return invoke<CoachKeyState>("coach_key_state");
}

/** `code: message` from a coach error, and only that (plus the status number): never any other text. */
export function coachErrorText(e: unknown): string {
  if (typeof e === "object" && e !== null && typeof (e as CoachError).code === "string" && typeof (e as CoachError).message === "string") {
    const err = e as CoachError;
    return `${err.code}: ${err.message}${typeof err.status === "number" ? ` (status ${err.status})` : ""}`;
  }
  return "coach_failed: the request did not complete";
}
