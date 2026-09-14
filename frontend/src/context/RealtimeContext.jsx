import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { createEventSocket, WS_STATES } from "../services/websocket";
import { applySecurityEvent, emptyRealtimeState } from "../utils/realtimeState";

const RealtimeContext = createContext(null);

export function RealtimeProvider({ children, socketFactory = createEventSocket }) {
  const [status, setStatus] = useState(WS_STATES.CONNECTING);
  const [snapshot, setSnapshot] = useState(emptyRealtimeState);
  const [generation, setGeneration] = useState(0);
  const listeners = useRef(new Set());

  const subscribe = useCallback((listener) => {
    listeners.current.add(listener);
    return () => listeners.current.delete(listener);
  }, []);

  useEffect(() => {
    const socket = socketFactory({
      onStatus: setStatus,
      onMessage: (payload) => {
        if (payload?.event_type === "security_event" || payload?.event_type === "alert_created") {
          setSnapshot((current) => applySecurityEvent(current, payload));
        }
        listeners.current.forEach((listener) => listener(payload));
      },
      onReconnect: () => {
        setSnapshot(emptyRealtimeState());
        setGeneration((value) => value + 1);
      },
    });
    return () => socket.close();
  }, [socketFactory]);

  const value = useMemo(
    () => ({
      status,
      liveEvents: snapshot.liveEvents,
      liveAlerts: snapshot.liveAlerts,
      generation,
      subscribe,
    }),
    [status, snapshot, generation, subscribe],
  );

  return <RealtimeContext.Provider value={value}>{children}</RealtimeContext.Provider>;
}

export function useRealtime() {
  const context = useContext(RealtimeContext);
  if (!context) {
    return {
      status: WS_STATES.DISCONNECTED,
      liveEvents: [],
      liveAlerts: [],
      generation: 0,
      subscribe: () => () => {},
    };
  }
  return context;
}
