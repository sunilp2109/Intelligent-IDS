import { API_BASE_URL } from "./api";

export const WS_STATES = {
  CONNECTING: "CONNECTING",
  CONNECTED: "CONNECTED",
  DISCONNECTED: "DISCONNECTED",
};

export const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000, 15000];

export function websocketUrl(apiBase = API_BASE_URL) {
  const url = new URL("/ws/events", `${apiBase.replace(/\/$/, "")}/`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export function createEventSocket({
  onMessage,
  onStatus,
  onReconnect,
  WebSocketImpl = globalThis.WebSocket,
} = {}) {
  let socket = null;
  let closed = false;
  let attempts = 0;
  let timer = null;
  let everOpened = false;

  const setStatus = (status) => {
    onStatus?.(status);
  };

  const clearTimer = () => {
    if (timer != null) {
      clearTimeout(timer);
      timer = null;
    }
  };

  const connect = () => {
    if (closed || typeof WebSocketImpl !== "function") {
      setStatus(WS_STATES.DISCONNECTED);
      return;
    }
    clearTimer();
    setStatus(WS_STATES.CONNECTING);
    const ws = new WebSocketImpl(websocketUrl());
    socket = ws;

    ws.onopen = () => {
      const shouldRefresh = everOpened;
      everOpened = true;
      attempts = 0;
      setStatus(WS_STATES.CONNECTED);
      if (shouldRefresh) onReconnect?.();
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        onMessage?.(payload);
      } catch {
        /* invalid JSON must not crash the dashboard */
      }
    };

    ws.onerror = () => {};

    ws.onclose = () => {
      if (socket === ws) socket = null;
      setStatus(WS_STATES.DISCONNECTED);
      if (closed) return;
      const delay = RECONNECT_DELAYS_MS[Math.min(attempts, RECONNECT_DELAYS_MS.length - 1)];
      attempts += 1;
      timer = setTimeout(connect, delay);
    };
  };

  const close = () => {
    closed = true;
    clearTimer();
    if (socket) {
      const current = socket;
      socket = null;
      try {
        current.close();
      } catch {
        /* ignore */
      }
    }
    setStatus(WS_STATES.DISCONNECTED);
  };

  connect();
  return { close };
}
