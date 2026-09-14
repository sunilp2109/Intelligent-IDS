import "@testing-library/jest-dom/vitest";

class QuietWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = QuietWebSocket.CONNECTING;
    this.sent = [];
    queueMicrotask(() => {
      if (this.readyState === QuietWebSocket.CLOSED) return;
      this.readyState = QuietWebSocket.OPEN;
      this.onopen?.();
    });
  }

  send(data) {
    this.sent.push(data);
  }

  close() {
    this.readyState = QuietWebSocket.CLOSED;
    this.onclose?.({ code: 1000 });
  }
}

globalThis.WebSocket = QuietWebSocket;
