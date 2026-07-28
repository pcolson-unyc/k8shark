import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// In dev, proxy the hub API + WebSocket so the front always talks to same-origin
// /api and /ws (exactly like nginx does in the cluster). Override the hub target
// with K8SHARK_HUB=http://host:port when running `npm run dev`.
const hub = process.env.K8SHARK_HUB || "http://localhost:8898";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: hub, changeOrigin: true },
      "/ws": { target: hub.replace("http", "ws"), ws: true },
    },
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      output: {
        // Pin react/react-dom (and scheduler, which react-dom pulls in and
        // which must stay in the same chunk to avoid a second module instance)
        // into their own vendor chunk. This is NOT about shipping fewer bytes
        // on a cold load — it's cache stability: the React runtime is ~150 KB
        // that doesn't change between k8shark releases, so keeping it out of
        // the app chunk means a dashboard update only invalidates the app
        // hash and returning users re-download the app code alone.
        //
        // Deliberately not doing route/panel-level React.lazy splitting on top
        // of this: measured at ~10% off the initial bundle here, and it costs
        // first paint — the dashboard renders essentially everything (table +
        // detail + service map) on the first screen, so a lazy chunk is just a
        // second round-trip before the user sees traffic.
        manualChunks(id: string) {
          if (/[\\/]node_modules[\\/](react-dom|react|scheduler)[\\/]/.test(id)) {
            return "react-vendor";
          }
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
