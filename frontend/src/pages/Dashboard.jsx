import { AttackDistributionChart } from "../components/charts/AttackDistributionChart";
import { RiskDistributionChart } from "../components/charts/RiskDistributionChart";
import { TimelineChart } from "../components/charts/TimelineChart";
import { StatCard } from "../components/cards/StatCard";
import { AlertList } from "../components/alerts/AlertList";
import { EventsTable } from "../components/tables/EventsTable";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function DashboardPage() {
  const stats = useApi(api.getDashboardStats);
  const timeline = useApi(api.getTimeline);
  const attacks = useApi(api.getAttackDistribution);
  const risks = useApi(api.getRiskDistribution);
  const recent = useApi(api.getRecentEvents);
  const alerts = useApi(() => api.getAlerts("HIGH,CRITICAL"));

  return (
    <div className="space-y-6">
      <section>
        {stats.loading ? <LoadingState /> : null}
        {stats.error ? <ErrorState message={stats.error} /> : null}
        {stats.data ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
            <StatCard label="Total events" value={stats.data.total_events} />
            <StatCard label="Normal" value={stats.data.normal} tone="normal" />
            <StatCard label="Suspicious" value={stats.data.suspicious} tone="suspicious" />
            <StatCard label="Malicious" value={stats.data.malicious} tone="malicious" />
            <StatCard label="Critical risks" value={stats.data.critical} tone="critical" />
            <StatCard label="Active alerts" value={stats.data.active_alerts} tone="alert" />
          </div>
        ) : null}
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="panel p-4 xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Activity timeline</h2>
          {timeline.loading ? <LoadingState /> : null}
          {timeline.error ? <ErrorState message={timeline.error} /> : null}
          {timeline.data && timeline.data.length === 0 ? <EmptyState message="No security events recorded." /> : null}
          {timeline.data && timeline.data.length > 0 ? <TimelineChart data={timeline.data} /> : null}
        </div>
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Recent alerts</h2>
          {alerts.loading ? <LoadingState /> : null}
          {alerts.error ? <ErrorState message={alerts.error} /> : null}
          {alerts.data && alerts.data.length === 0 ? <EmptyState message="No active alerts." /> : null}
          {alerts.data && alerts.data.length > 0 ? <AlertList alerts={alerts.data} /> : null}
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Attack categories</h2>
          {attacks.loading ? <LoadingState /> : null}
          {attacks.error ? <ErrorState message={attacks.error} /> : null}
          {attacks.data && attacks.data.length === 0 ? <EmptyState message="No attack data available" /> : null}
          {attacks.data && attacks.data.length > 0 ? <AttackDistributionChart data={attacks.data} /> : null}
        </div>
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Risk distribution</h2>
          {risks.loading ? <LoadingState /> : null}
          {risks.error ? <ErrorState message={risks.error} /> : null}
          {risks.data && risks.data.length === 0 ? <EmptyState message="No risk assessments recorded." /> : null}
          {risks.data && risks.data.length > 0 ? <RiskDistributionChart data={risks.data} /> : null}
        </div>
      </section>

      <section className="panel p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Recent security events</h2>
        {recent.loading ? <LoadingState /> : null}
        {recent.error ? <ErrorState message={recent.error} /> : null}
        {recent.data && recent.data.length === 0 ? <EmptyState message="No events recorded" /> : null}
        {recent.data && recent.data.length > 0 ? <EventsTable rows={recent.data} /> : null}
      </section>
    </div>
  );
}
