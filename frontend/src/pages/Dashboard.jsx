import { useEffect } from "react";
import { AttackDistributionChart } from "../components/charts/AttackDistributionChart";
import { RiskDistributionChart } from "../components/charts/RiskDistributionChart";
import { TimelineChart } from "../components/charts/TimelineChart";
import { StatCard } from "../components/cards/StatCard";
import { AlertList } from "../components/alerts/AlertList";
import { EventsTable } from "../components/tables/EventsTable";
import { LiveEventFeed } from "../components/realtime/LiveEventFeed";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useRealtime } from "../context/RealtimeContext";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { mergeEventRows } from "../utils/realtimeState";

export function DashboardPage() {
  const { liveEvents, liveAlerts, generation, subscribe } = useRealtime();
  const stats = useApi(api.getDashboardStats, String(generation));
  const timeline = useApi(api.getTimeline, String(generation));
  const attacks = useApi(api.getAttackDistribution, String(generation));
  const risks = useApi(api.getRiskDistribution, String(generation));
  const recent = useApi(api.getRecentEvents, String(generation));
  const alerts = useApi(() => api.getAlerts("HIGH,CRITICAL"), String(generation));

  useEffect(() => {
    let timer = null;
    const unsubscribe = subscribe((payload) => {
      if (payload?.event_type !== "security_event") return;
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        stats.reload();
        timeline.reload();
        attacks.reload();
        risks.reload();
        recent.reload();
        alerts.reload();
      }, 250);
    });
    return () => {
      unsubscribe();
      window.clearTimeout(timer);
    };
  }, [subscribe, stats.reload, timeline.reload, attacks.reload, risks.reload, recent.reload, alerts.reload]);

  const mergedRecent = mergeEventRows(recent.data, liveEvents, 20);
  const mergedAlerts = mergeEventRows(alerts.data, liveAlerts, 20);

  return (
    <div className="space-y-6">
      <section>
        {stats.loading && !stats.data ? <LoadingState /> : null}
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

      <section className="panel p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Live security events</h2>
        <LiveEventFeed events={liveEvents} />
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <div className="panel p-4 xl:col-span-2">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Activity timeline</h2>
          {timeline.loading && !timeline.data ? <LoadingState /> : null}
          {timeline.error ? <ErrorState message={timeline.error} /> : null}
          {timeline.data && timeline.data.length === 0 ? <EmptyState message="No security events recorded." /> : null}
          {timeline.data && timeline.data.length > 0 ? <TimelineChart data={timeline.data} /> : null}
        </div>
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Recent alerts</h2>
          {alerts.loading && !alerts.data && mergedAlerts.length === 0 ? <LoadingState /> : null}
          {alerts.error ? <ErrorState message={alerts.error} /> : null}
          {mergedAlerts.length === 0 && !alerts.loading ? <EmptyState message="No active alerts." /> : null}
          {mergedAlerts.length > 0 ? <AlertList alerts={mergedAlerts} /> : null}
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Attack categories</h2>
          {attacks.loading && !attacks.data ? <LoadingState /> : null}
          {attacks.error ? <ErrorState message={attacks.error} /> : null}
          {attacks.data && attacks.data.length === 0 ? <EmptyState message="No attack data available" /> : null}
          {attacks.data && attacks.data.length > 0 ? <AttackDistributionChart data={attacks.data} /> : null}
        </div>
        <div className="panel p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Risk distribution</h2>
          {risks.loading && !risks.data ? <LoadingState /> : null}
          {risks.error ? <ErrorState message={risks.error} /> : null}
          {risks.data && risks.data.length === 0 ? <EmptyState message="No risk assessments recorded." /> : null}
          {risks.data && risks.data.length > 0 ? <RiskDistributionChart data={risks.data} /> : null}
        </div>
      </section>

      <section className="panel p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-soc-muted">Recent security events</h2>
        {recent.loading && !recent.data && mergedRecent.length === 0 ? <LoadingState /> : null}
        {recent.error ? <ErrorState message={recent.error} /> : null}
        {mergedRecent.length === 0 && !recent.loading ? <EmptyState message="No events recorded" /> : null}
        {mergedRecent.length > 0 ? <EventsTable rows={mergedRecent} /> : null}
      </section>
    </div>
  );
}
