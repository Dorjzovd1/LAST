import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import type { ProxyOptions } from "vite";

// Backend (FastAPI) localhost:8000 deer ajilна. /api bolon /ws-iig proxy hiine.
//
// Backend түр унтарсан / socket reset үед http-proxy нь EPIPE/ECONNRESET алдаа
// шиддэг. Доорх handler-ууд тэдгээрийг "чимээгүй" барьж, консолыг бохирдуулахаас
// сэргийлнэ (DEBUG_PROXY=1 үед л логлоно).
const quietProxyErrors = (proxy: any) => {
  proxy.on("error", (err: NodeJS.ErrnoException) => {
    if (process.env.DEBUG_PROXY) {
      console.warn(`[proxy] ${err.code ?? err.message}`);
    }
  });
  // WebSocket upgrade хийгдсэн socket-ийн алдааг шингээж, unhandled болгохгүй.
  proxy.on("proxyReqWs", (_proxyReq: any, _req: any, socket: NodeJS.EventEmitter) => {
    socket.on("error", () => {});
  });
  proxy.on("open", (socket: NodeJS.EventEmitter) => {
    socket.on("error", () => {});
  });
};

const apiProxy: ProxyOptions = {
  target: "http://localhost:8000",
  changeOrigin: true,
  configure: quietProxyErrors,
};

const wsProxy: ProxyOptions = {
  target: "ws://localhost:8000",
  ws: true,
  configure: quietProxyErrors,
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": apiProxy,
      "/ws": wsProxy,
    },
  },
});
