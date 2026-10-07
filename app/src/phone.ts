// The phone's native doors: the camera scan, the screen-awake switch and (debug builds only) the offer text from a file.
// Like core.ts, this file names webview commands; the pairing screens in app.ts call these wrappers. Nothing here
// keeps, logs or returns more than the one value it is asked for, and the scanned text goes straight back to the
// caller (the offer text is worth something while its offer is live; it is never stored).
import { invoke } from "@tauri-apps/api/core";

export type CameraPermission = "granted" | "denied" | "prompt" | "prompt-with-rationale";

/** Ask for the camera when it has not been asked yet; the answer is one of the plugin's permission words. */
export async function cameraPermission(): Promise<CameraPermission> {
  const now = await invoke<{ camera: CameraPermission }>("plugin:barcode-scanner|check_permissions");
  if (now.camera === "granted" || now.camera === "denied") return now.camera;
  const asked = await invoke<{ camera: CameraPermission }>("plugin:barcode-scanner|request_permissions");
  return asked.camera;
}

/** One scan: the QR code only, with the camera drawn *behind* the page (the page's own Cancel stays on top). Resolves
 *  with the first decoded text and stops the camera; rejects with "cancelled" after [[cancelScan]]. */
export async function scanQr(): Promise<string> {
  const r = await invoke<{ content?: string }>("plugin:barcode-scanner|scan", { formats: ["QR_CODE"], windowed: true });
  return typeof r.content === "string" ? r.content : "";
}

/** Stop a scan in progress (its pending [[scanQr]] rejects). */
export function cancelScan(): Promise<void> {
  return invoke("plugin:barcode-scanner|cancel");
}

/** iOS: keep the screen from locking while the pairing code is up (`UIApplication.idleTimerDisabled`). */
export function keepAwake(on: boolean): Promise<void> {
  return invoke("keep_awake", { on });
}

/** Debug iOS builds only: the offer text the Mac side wrote to `DISCONECT_DEBUG_OFFER_FILE` (the simulator has no camera). */
export function debugOfferFromFile(): Promise<string> {
  return invoke<string>("debug_offer_from_file");
}

/** iOS: take the shell's cover off after the page has painted Unlock (the cover is held across the lock after an absence). */
export function coverRelease(): Promise<void> {
  return invoke("cover_release");
}

// ---- the relay list (19d, I5 row 4): the phone's shell owns it. The page gets words and numbers only: never a folder's location or the saved handle that reopens it. The
// core's own `relays` param is refused when the page sends it; the shell builds it.

export type RelaySite = { pushed?: number; healed?: number; behind?: number; pulled?: number; rejected?: number; error?: string | null; at?: number };
export type RelayEntry = {
  id: string;
  kind: "folder" | "lan";
  label: string;
  available: boolean;
  display: string | null; // a folder's last two path parts
  url: string | null;
  added_at: number;
  site: RelaySite | null;
  last_push_at: number | null;
  last_pull_at: number | null;
};

/** iOS: the list, with the paired Mac's address from the relay setting (`mac_url`) for the Add-Mac form. */
export function relaysList(): Promise<{ relays: RelayEntry[]; mac_url: string | null; unreadable?: boolean }> {
  return invoke("relays_list");
}

/** iOS: the Files picker for one folder. Resolves `{ cancelled: true }` when the person backs out. */
export function relaysAddFolder(): Promise<{ cancelled: boolean; id?: string }> {
  return invoke("relays_add_folder");
}

/** iOS: a LAN relay from the Settings form: the address the person typed (the shell checks it; the paired Mac needs no call). */
export function relaysAddLan(url: string, label?: string): Promise<{ id: string }> {
  return invoke("relays_add_lan", { url, label: label ?? null });
}

export function relaysRemove(id: string): Promise<void> {
  return invoke("relays_remove", { id });
}

export function relaysRename(id: string, label: string): Promise<void> {
  return invoke("relays_rename", { id, label });
}

// ---- the phone as a producer (19b, I5 row 3): the shell imports session files from its own folder; the page names no path.

/** What this phone has produced: counts and a span (unix seconds), never a reading. */
export type Produced = { sessions: number; readings: number; last_from: number | null; last_to: number | null; last_at: number | null };

/** iOS: import the session files waiting in the phone's own folder (the shell builds the path; this passes nothing). */
export function liveImport(): Promise<{ files: number; ok: number; duplicate: number; failed: number; refused: number; readings: number; sessions: number }> {
  return invoke("live_import");
}

/** iOS: the Sync screen's "From this phone" counts. */
export function liveProduced(): Promise<Produced> {
  return invoke("live_produced");
}

/** Debug iOS builds only (`--debug-live-seed`): write one synthetic session and import it, once per start. */
export function liveDebugSeed(): Promise<unknown> {
  return invoke("live_debug_seed");
}
