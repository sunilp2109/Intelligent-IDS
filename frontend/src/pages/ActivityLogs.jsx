import { useState } from "react";
import { EventsTable } from "../components/tables/EventsTable";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function ActivityLogsPage() {
  const [sourceIp, setSourceIp] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [classification, setClassification] = useState("");
  const [query, setQuery] = useState({});
  const { data, error, loading } = useApi(() => api.getLogs(query), JSON.stringify(query));

  function applyFilters(event) {
    event.preventDefault();
    setQuery({
      source_ip: sourceIp,
      risk_level: riskLevel,
      classification,
    });
  }

  return (
    <div className="space-y-4">
      <form className="panel grid gap-3 p-4 md:grid-cols-4" onSubmit={applyFilters}>
        <label className="text-xs uppercase tracking-wide text-soc-muted">
          Source IP
          <input
            className="mt-1 w-full rounded border border-soc-border bg-soc-bg px-3 py-2 font-mono text-sm"
            value={sourceIp}
            onChange={(event) => setSourceIp(event.target.value)}
            placeholder="192.0.2."
          />
        </label>
        <label className="text-xs uppercase tracking-wide text-soc-muted">
          Classification
          <select
            className="mt-1 w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm"
            value={classification}
            onChange={(event) => setClassification(event.target.value)}
          >
            <option value="">All</option>
            <option value="normal">Normal</option>
            <option value="suspicious">Suspicious</option>
            <option value="malicious">Malicious</option>
          </select>
        </label>
        <label className="text-xs uppercase tracking-wide text-soc-muted">
          Risk level
          <select
            className="mt-1 w-full rounded border border-soc-border bg-soc-bg px-3 py-2 text-sm"
            value={riskLevel}
            onChange={(event) => setRiskLevel(event.target.value)}
          >
            <option value="">All</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </label>
        <div className="flex items-end">
          <button type="submit" className="w-full rounded border border-soc-accent px-3 py-2 text-sm text-soc-accent">
            Apply filters
          </button>
        </div>
      </form>
      <section className="panel p-4">
        {loading ? <LoadingState /> : null}
        {error ? <ErrorState message={error} /> : null}
        {data && data.items.length === 0 ? <EmptyState message="No events recorded" /> : null}
        {data && data.items.length > 0 ? (
          <>
            <p className="mb-3 text-xs text-soc-muted">{data.count} matching activity logs</p>
            <EventsTable rows={data.items} />
          </>
        ) : null}
      </section>
    </div>
  );
}
