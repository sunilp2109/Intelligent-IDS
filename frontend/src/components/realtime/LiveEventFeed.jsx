import { Badge } from "../common/Badge";
import { formatClock, prettyCategory } from "../../utils/format";

export function LiveEventFeed({ events }) {
  if (!events?.length) {
    return (
      <p className="px-1 py-4 text-sm text-soc-muted" role="status">
        No live events in this session.
      </p>
    );
  }
  return (
    <ul className="divide-y divide-soc-border">
      {events.map((event) => {
        const alert = ["HIGH", "CRITICAL"].includes(String(event.risk_level || "").toUpperCase());
        return (
          <li
            key={event.detection_id || event.attack_log_id}
            className={`grid gap-2 px-1 py-3 text-sm sm:grid-cols-7 ${alert ? "live-alert-row" : ""}`}
          >
            <span className="font-mono text-xs text-soc-muted">{formatClock(event.timestamp)}</span>
            <span className="font-mono">{event.source_ip || "—"}</span>
            <Badge kind="classification" value={event.classification} />
            <span>{prettyCategory(event.attack_category)}</span>
            <Badge kind="risk" value={event.risk_level} />
            <span className="font-mono">{event.risk_score ?? "—"}</span>
            <Badge kind="action" value={event.recommended_action} />
          </li>
        );
      })}
    </ul>
  );
}
