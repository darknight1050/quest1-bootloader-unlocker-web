import { defineConfig } from "vite";

export default defineConfig({
  // WebUSB needs a secure context; localhost qualifies.
  server: { port: 5173, host: "localhost" },
  build: { target: "es2022" },
});
