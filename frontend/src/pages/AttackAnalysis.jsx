import { AttackDistributionChart } from "../components/charts/AttackDistributionChart";
import { EventsTable } from "../components/tables/EventsTable";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function AttackAnalysisPage() {
  const attacks = useApi(api.getAttackDistribution);
  const recent = useApi(api.getRecentEvents);

  return (
    <div className="space-y-4">
      <section className="panel p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Category distribution</h2>
        {attacks.loading ? <LoadingState /> : null}
        {attacks.error ? <ErrorState message={attacks.error} /> : null}
        {attacks.data && attacks.data.length === 0 ? <EmptyState message="No attack data available" /> : null}
        {attacks.data && attacks.data.length > 0 ? <AttackDistributionChart data={attacks.data} /> : null}
      </section>
      <section className="panel p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Analyzed detections</h2>
        {recent.loading ? <LoadingState /> : null}
        {recent.error ? <ErrorState message={recent.error} /> : null}
        {recent.data && recent.data.length === 0 ? <EmptyState /> : null}
        {recent.data && recent.data.length > 0 ? <EventsTable rows={recent.data} /> : null}
      </section>
    </div>
  );
}
