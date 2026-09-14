import { WS_STATES } from "../../services/websocket";

const STYLES = {
  [WS_STATES.CONNECTED]: "bg-emerald-400",
  [WS_STATES.CONNECTING]: "bg-amber-400",
  [WS_STATES.DISCONNECTED]: "bg-slate-500",
};

export function ConnectionStatus({ status }) {
  const label =
    status === WS_STATES.CONNECTED ? "Connected" : status === WS_STATES.CONNECTING ? "Connecting" : "Disconnected";
  return (
    <div className="flex items-center gap-2 text-xs" data-testid="ws-status" data-status={status}>
      <span className={`inline-block h-2.5 w-2.5 rounded-full ${STYLES[status] || STYLES[WS_STATES.DISCONNECTED]}`} />
      <div>
        <p className="uppercase tracking-wide text-soc-muted">Live monitoring</p>
        <p className="text-sm text-white">{label}</p>
      </div>
    </div>
  );
}
