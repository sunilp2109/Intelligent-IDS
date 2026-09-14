import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, test, vi } from "vitest";
import App from "../App";
import { RealtimeProvider } from "../context/RealtimeContext";
import { DashboardPage } from "../pages/Dashboard";
import { createEventSocket, websocketUrl, WS_STATES } from "../services/websocket";
import { applySecurityEvent, emptyRealtimeState, mergeEventRows } from "../utils/realtimeState";

function jsonResponse(payload, ok = true, status = 200) {
  return Promise.resolve({
    ok,
    status,
    json: async () => payload,
  });
}

function mockDashboardApis() {
  const counts = { stats: 0 };
  globalThis.fetch = async (url) => {
    const path = String(url);
    if (path.includes("/api/dashboard/stats")) {
      counts.stats += 1;
      return jsonResponse({ total_events: counts.stats > 1 ? 1 : 0, normal: 0, suspicious: 0, malicious: counts.stats > 1 ? 1 : 0, critical: counts.stats > 1 ? 1 : 0, active_alerts: counts.stats > 1 ? 1 : 0 });
    }
    if (path.includes("/api/dashboard/timeline")) return jsonResponse([]);
    if (path.includes("/api/dashboard/attacks")) return jsonResponse([]);
    if (path.includes("/api/dashboard/risks")) return jsonResponse([]);
    if (path.includes("/api/dashboard/recent")) return jsonResponse([]);
    if (path.includes("/api/dashboard/alerts")) return jsonResponse([]);
    return jsonResponse({ detail: "missing mock" }, false, 500);
  };
  return counts;
}

const sampleEvent = {
  event_type: "security_event",
  timestamp: "2026-09-14T18:30:12+00:00",
  data: {
    log_id: 123,
    detection_id: 9,
    source_ip: "192.0.2.50",
    classification: "malicious",
    confidence_score: 0.94,
    attack_category: "BRUTE_FORCE",
    risk_score: 87,
    risk_level: "CRITICAL",
    recommended_action: "BLOCK",
  },
};

function createSocketHarness() {
  let handlers = {};
  const socket = { close: vi.fn() };
  const factory = (opts) => {
    handlers = opts;
    opts.onStatus?.(WS_STATES.CONNECTING);
    return socket;
  };
  return {
    socket,
    factory,
    open() {
      handlers.onStatus?.(WS_STATES.CONNECTED);
    },
    disconnect() {
      handlers.onStatus?.(WS_STATES.DISCONNECTED);
    },
    reconnect() {
      handlers.onStatus?.(WS_STATES.CONNECTED);
      handlers.onReconnect?.();
    },
    message(payload) {
      handlers.onMessage?.(payload);
    },
  };
}

afterEach(() => {
  vi.useRealTimers();
});

test("websocket url uses the API origin", () => {
  expect(websocketUrl("http://127.0.0.1:8000")).toBe("ws://127.0.0.1:8000/ws/events");
  expect(websocketUrl("https://ids.example/")).toBe("wss://ids.example/ws/events");
});

test("websocket connects and reports status changes", async () => {
  const statuses = [];
  const sockets = [];
  class MockSocket {
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      sockets.push(this);
    }
    close() {
      this.readyState = 3;
      this.onclose?.({ code: 1000 });
    }
  }
  const client = createEventSocket({
    onStatus: (status) => statuses.push(status),
    WebSocketImpl: MockSocket,
  });
  expect(statuses[0]).toBe(WS_STATES.CONNECTING);
  act(() => sockets[0].onopen());
  expect(statuses.at(-1)).toBe(WS_STATES.CONNECTED);
  act(() => sockets[0].onclose({ code: 1000 }));
  expect(statuses.at(-1)).toBe(WS_STATES.DISCONNECTED);
  client.close();
});

test("invalid websocket JSON is ignored", () => {
  const onMessage = vi.fn();
  const sockets = [];
  class MockSocket {
    constructor() {
      sockets.push(this);
    }
    close() {}
  }
  const client = createEventSocket({ onMessage, WebSocketImpl: MockSocket });
  expect(() => sockets[0].onmessage({ data: "{bad" })).not.toThrow();
  expect(onMessage).not.toHaveBeenCalled();
  client.close();
});

test("reconnection uses backoff and REST refresh callback", async () => {
  vi.useFakeTimers();
  const onReconnect = vi.fn();
  const sockets = [];
  class MockSocket {
    constructor() {
      sockets.push(this);
    }
    close() {
      this.onclose?.({ code: 1000 });
    }
  }
  const client = createEventSocket({ onReconnect, WebSocketImpl: MockSocket });
  act(() => sockets[0].onopen());
  act(() => sockets[0].onclose({ code: 1001 }));
  expect(sockets.length).toBe(1);
  act(() => vi.advanceTimersByTime(1000));
  expect(sockets.length).toBe(2);
  act(() => sockets[1].onopen());
  expect(onReconnect).toHaveBeenCalledTimes(1);
  client.close();
});

test("websocket cleanup closes the socket", () => {
  const sockets = [];
  class MockSocket {
    constructor() {
      sockets.push(this);
      this.closed = false;
    }
    close() {
      this.closed = true;
    }
  }
  const client = createEventSocket({ WebSocketImpl: MockSocket });
  client.close();
  expect(sockets[0].closed).toBe(true);
});

test("valid event appears in the live feed and duplicate is ignored", async () => {
  mockDashboardApis();
  const harness = createSocketHarness();
  render(
    <MemoryRouter>
      <RealtimeProvider socketFactory={harness.factory}>
        <DashboardPage />
      </RealtimeProvider>
    </MemoryRouter>,
  );
  await screen.findByText("Live security events");
  act(() => {
    harness.open();
    harness.message(sampleEvent);
    harness.message(sampleEvent);
  });
  expect((await screen.findAllByText("192.0.2.50")).length).toBe(2);
  expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
  expect(screen.getByText("87")).toBeInTheDocument();
});

test("critical alert updates the alert section", async () => {
  mockDashboardApis();
  const harness = createSocketHarness();
  render(
    <MemoryRouter>
      <RealtimeProvider socketFactory={harness.factory}>
        <DashboardPage />
      </RealtimeProvider>
    </MemoryRouter>,
  );
  await screen.findByText("No active alerts.");
  act(() => {
    harness.open();
    harness.message(sampleEvent);
  });
  expect(await screen.findByText("Open")).toBeInTheDocument();
  expect(screen.queryByText("No active alerts.")).not.toBeInTheDocument();
});

test("reconnect refreshes REST dashboard state", async () => {
  const counts = mockDashboardApis();
  const harness = createSocketHarness();
  render(
    <MemoryRouter>
      <RealtimeProvider socketFactory={harness.factory}>
        <DashboardPage />
      </RealtimeProvider>
    </MemoryRouter>,
  );
  await screen.findByText("Total events");
  const initial = counts.stats;
  act(() => harness.reconnect());
  await waitFor(() => expect(counts.stats).toBeGreaterThan(initial));
});

test("provider unmount closes the websocket", () => {
  const harness = createSocketHarness();
  const view = render(
    <MemoryRouter>
      <RealtimeProvider socketFactory={harness.factory}>
        <DashboardPage />
      </RealtimeProvider>
    </MemoryRouter>,
  );
  view.unmount();
  expect(harness.socket.close).toHaveBeenCalled();
});

test("app connection status is not hard-coded", async () => {
  mockDashboardApis();
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
  expect(screen.getByTestId("ws-status")).toHaveAttribute("data-status", "CONNECTING");
  await waitFor(() => expect(screen.getByTestId("ws-status")).toHaveAttribute("data-status", "CONNECTED"));
  expect(screen.getByText("Connected")).toBeInTheDocument();
});

test("merge helpers keep a single row per detection", () => {
  let state = applySecurityEvent(emptyRealtimeState(), sampleEvent);
  state = applySecurityEvent(state, sampleEvent);
  expect(state.liveEvents).toHaveLength(1);
  expect(state.liveAlerts).toHaveLength(1);
  const merged = mergeEventRows([{ detection_id: 9, source_ip: "old", timestamp: "2026-09-14T18:00:00+00:00" }], state.liveEvents);
  expect(merged).toHaveLength(1);
  expect(merged[0].source_ip).toBe("192.0.2.50");
});
