import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built assets are served by the control plane (neurawall/services/control_plane/static).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../neurawall/services/control_plane/static",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8080", "/healthz": "http://localhost:8080" },
  },
});
