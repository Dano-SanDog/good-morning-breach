import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: "localhost",
    fs: { strict: true },
  },
  build: {
    outDir: "internal/httpserver/static/build",
    sourcemap: false,
    assetsInlineLimit: 0,
  },
});
