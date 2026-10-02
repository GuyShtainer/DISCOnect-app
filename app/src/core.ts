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
