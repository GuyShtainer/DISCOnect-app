import { defineConfig } from "vite";
// @ts-expect-error type error without @types/node package
import process from "node:process";
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(() => ({
  // The page reads its --debug-* flags only when import.meta.env.DEV is true. `tauri build --debug` runs a
  // production-mode vite build, so say DEV is true there too (the tauri CLI sets TAURI_ENV_DEBUG); a release build keeps it false
  // and the flag code is dropped from the bundle.
  // `__PHONE__` is the same kind of build-time constant: true when the tauri CLI builds for iOS (it sets
  // TAURI_ENV_PLATFORM to the target's platform for the before-build command), so a desktop bundle reads it as false.
  define: {
    ...(process.env.TAURI_ENV_DEBUG === "true" ? { "import.meta.env.DEV": "true" } : {}),
    __PHONE__: JSON.stringify(process.env.TAURI_ENV_PLATFORM === "ios"),
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
