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
