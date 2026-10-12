import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are served by the control plane (neurawall/services/control_plane/static/app).
// The console lives under /app; the product site is served at the root.
export default defineConfig({
  base: "/app/",
  plugins: [react()],
  build: {
    outDir: "../neurawall/services/control_plane/static/app",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8080", "/healthz": "http://localhost:8080" },
  },
});
