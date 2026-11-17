import { defineConfig } from "vite";

export default defineConfig({
  server: {
    host: "localhost",
    fs: { strict: true },
  },
  build: { sourcemap: false },
});
