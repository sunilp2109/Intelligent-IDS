import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useRealtime } from "../context/RealtimeContext";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

function StatusRow({ label, ok, detail }) {
  return (
    <div className="flex items-start justify-between gap-4 border-t border-soc-border px-4 py-3">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-soc-muted">{detail}</p>
      </div>
      <span className={ok ? "badge-normal" : "badge-malicious"}>{ok ? "Available" : "Unavailable"}</span>
    </div>
  );
}

export function SystemStatusPage() {
  const { status } = useRealtime();
  const { data, error, loading } = useApi(api.getSystemStatus);
  return (
    <div className="panel max-w-3xl">
      <div className="px-4 py-3 text-sm text-soc-muted">Live backend/status values. Nothing is faked as online.</div>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {data ? (
        <>
          <StatusRow label="Backend API" ok={data.backend?.status === "ok"} detail="FastAPI process responded." />
          <StatusRow
            label="Database"
            ok={data.database?.status === "ok"}
            detail={data.database?.engine || "unknown engine"}
          />
          <StatusRow
            label="ML model artifact"
            ok={Boolean(data.ml_model?.loaded)}
            detail={
              data.ml_model?.loaded
                ? `${data.ml_model.model_name || "model"} ${data.ml_model.model_version || ""}`.trim()
                : "No trained model file is present. Train Module 4 before expecting detections."
            }
          />
          <StatusRow
            label="Honeypot collector"
            ok={true}
            detail={`${data.collector?.mode || "simulated_jsonl"} · ${data.collector?.events_ingested ?? 0} ingested events`}
          />
          <StatusRow
            label="Dashboard WebSocket"
            ok={status === "CONNECTED"}
            detail={
              data.realtime
                ? `${data.realtime.websocket_path || "/ws/events"} · ${data.realtime.connected_clients ?? 0} backend clients · auth ${data.realtime.authentication || "not_implemented"} · UI ${status}`
                : `UI ${status}`
            }
          />
          <ul className="space-y-1 px-4 py-3 text-xs text-soc-muted">
            {(data.notes || []).map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}
