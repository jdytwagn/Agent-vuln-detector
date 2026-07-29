import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, "..", "");
  const apiKey = env.AGENT_DETECTOR_API_KEY || "";
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": {
          target: "http://127.0.0.1:8000",
          headers: apiKey ? { "X-API-Key": apiKey } : undefined
        }
      }
    }
  };
});
