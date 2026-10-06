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

export function onCoreEvent(name: "progress" | "log" | "restarted" | "exited" | "pair" | "relay" | "import", cb: (payload: unknown) => void): Promise<UnlistenFn> {
  return listen(`core://${name}`, (e) => cb(e.payload));
}

/** Whether something is being dragged over the window. Rust watches the OS drag (the window's own drag events carry
 *  the dragged paths, so this page never listens to them) and tells the page only `{ over }`; the drop itself is
 *  handled in Rust, `import_drop.rs`. */
export function onDragHover(cb: (over: boolean) => void): Promise<UnlistenFn> {
  return listen<{ over?: boolean }>("core://drag", (e) => cb(e.payload?.over === true));
}

/** Debug builds only: types the six digits read from DISCONECT_DEBUG_DIGITS_FILE (evidence runs). */
export function debugPairDigitsFromFile(): Promise<unknown> {
  return invoke("debug_pair_digits_from_file");
}

/** Debug builds only: key.unlock with the passphrase in DISCONECT_DEBUG_PASSPHRASE_FILE (evidence runs). */
export function debugUnlockFromFile(): Promise<unknown> {
  return invoke("debug_unlock_from_file");
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
/** What a failed coach command rejects with: two fixed strings from closed enums and, for an error status, its number.
 *  A failed question also carries what had already left before it: the tool calls in a request that was sent. */
export type CoachError = { code: string; message: string; status: number | null; trace?: CoachTrace[]; sends?: number };
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

/** What a failed question had already sent: the trace entries of the error (empty for any other failure). */
export function coachErrorTrace(e: unknown): CoachTrace[] {
  const trace = typeof e === "object" && e !== null ? (e as CoachError).trace : undefined;
  return Array.isArray(trace) ? trace : [];
}

/** `code: message` from a coach error, and only that (plus the status number): never any other text. */
export function coachErrorText(e: unknown): string {
  if (typeof e === "object" && e !== null && typeof (e as CoachError).code === "string" && typeof (e as CoachError).message === "string") {
    const err = e as CoachError;
    return `${err.code}: ${err.message}${typeof err.status === "number" ? ` (status ${err.status})` : ""}`;
  }
  return "coach_failed: the request did not complete";
}

// ---- the hand-off to the user's own chat (Bet 15c). No login, no key, no session for any of the five. ----

export type ProviderId = "chat_gpt" | "claude" | "gemini" | "le_chat" | "deep_seek";
export type HandoffText = { text: string; bytes: number; shortened: { thinned: number; truncated: number; dropped_facts: number } };

/** The hand-off text: the five sendable tools, through the identical gate the coach loop sends through. Works
 *  whether the coach is on or off; rejects with the same CoachError shape a failed question rejects with. */
export function handoffBuild(windowDays: 7 | 28 | 90, includePoints: boolean): Promise<HandoffText> {
  return invoke<HandoffText>("handoff_build", { windowDays, includePoints });
}

/** Open one of the five fixed sites in the system browser. The one argument is always a closed enum value;
 *  no string ever crosses from the webview into it. */
/** `code: message` from a hand-off error, else a fixed hand-off sentence (never the coach's wording). */
export function handoffErrorText(e: unknown): string {
  if (typeof e === "object" && e !== null && typeof (e as CoachError).code === "string" && typeof (e as CoachError).message === "string") {
    const err = e as CoachError;
    return `${err.code}: ${err.message}`;
  }
  return "handoff_failed: the hand-off could not be built";
}

export function handoffOpen(provider: ProviderId): Promise<void> {
  return invoke("handoff_open", { provider });
}

// ---- support channels (Bet 17, donations only). Opens no network connection of its own: the buttons open
// the system browser. The command is macOS-only; off macOS it does not exist and the call rejects. ----------

/** The Rust `SupportSite` enum refuses anything it does not itself name, at the IPC boundary — so a plain
 *  `string` here is as safe as a branded one: a value made up on this side is simply never accepted. */
export type SupportSiteId = string;
export type SupportSiteDto = { id: SupportSiteId; name: string; host: string };

export function supportSites(): Promise<SupportSiteDto[]> {
  return invoke<SupportSiteDto[]>("support_sites");
}

export function supportOpen(id: SupportSiteId): Promise<void> {
  return invoke("support_open", { site: id });
}

// ---- the live link (Bet 9 follow-up). Dev builds only: the lab's Python reads the watch as a child process. ----

/** One line from the live link: a status change or a reading (unix seconds, the product's metric id, an int). */
export type LiveLine = { status?: string; stop?: string; t?: number; metric?: string; value?: number };
export type LiveStatus = { running: boolean; available: boolean; stub?: boolean; seq?: number };

export function liveStart(): Promise<LiveStatus> {
  return invoke<LiveStatus>("live_start");
}

export function liveStop(): Promise<LiveStatus> {
  return invoke<LiveStatus>("live_stop");
}

export function liveState(): Promise<LiveStatus> {
  return invoke<LiveStatus>("live_state");
}

export function onLiveLine(cb: (line: LiveLine) => void): Promise<UnlistenFn> {
  return listen("live://line", (e) => cb(e.payload as LiveLine));
}

export function onLiveEnded(cb: (exit: number | null) => void): Promise<UnlistenFn> {
  return listen("live://ended", (e) => cb((e.payload as { exit: number | null }).exit));
}

/** What the sweep of the readings folder answered after a link ended ("stored", "nothing new stored" or "not stored (…)"), and the number of the link it belongs to. */
export function onLiveStored(cb: (text: string, seq: number) => void): Promise<UnlistenFn> {
  return listen("live://stored", (e) => {
    const { text, seq } = e.payload as { text: string; seq: number };
    cb(text, seq);
  });
}
