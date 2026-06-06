import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBaseUrl =
    env.VITE_API_BASE_URL ?? process.env.VITE_API_BASE_URL ?? "http://localhost:4000";

  return {
    root: "web",
    envDir: "..",
    plugins: [react()],
    define: {
      "import.meta.env.VITE_API_BASE_URL": JSON.stringify(apiBaseUrl),
    },
    server: {
      host: "0.0.0.0",
      port: 5173,
    },
    preview: {
      host: "0.0.0.0",
      port: 5173,
    },
    build: {
      outDir: "../dist-web",
      emptyOutDir: true,
    },
  };
});
