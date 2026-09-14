import { useMemo, useState } from "react";
import { AlertList } from "../components/alerts/AlertList";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const FILTERS = [
  { label: "High / Critical", value: "HIGH,CRITICAL" },
  { label: "Critical", value: "CRITICAL" },
  { label: "High", value: "HIGH" },
  { label: "Medium", value: "MEDIUM" },
  { label: "Low", value: "LOW" },
];

export function AlertsPage() {
  const [levels, setLevels] = useState("HIGH,CRITICAL");
  const { data, error, loading } = useApi(() => api.getAlerts(levels), levels);
  const counts = useMemo(() => (data ? data.length : 0), [data]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {FILTERS.map((filter) => (
          <button
            key={filter.value}
            type="button"
            onClick={() => setLevels(filter.value)}
            className={`rounded border px-3 py-1 text-xs uppercase tracking-wide ${
              levels === filter.value ? "border-soc-accent text-white" : "border-soc-border text-soc-muted"
            }`}
          >
            {filter.label}
          </button>
        ))}
      </div>
      <div className="panel">
        <div className="border-b border-soc-border px-4 py-3 text-sm text-soc-muted">{counts} matching alerts</div>
        {loading ? <LoadingState /> : null}
        {error ? <ErrorState message={error} /> : null}
        {data && data.length === 0 ? <EmptyState message="No active alerts." /> : null}
        {data && data.length > 0 ? <AlertList alerts={data} /> : null}
      </div>
    </div>
  );
}
