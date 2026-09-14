import { Link } from "react-router-dom";
import { Badge } from "../common/Badge";
import { formatTime, prettyCategory } from "../../utils/format";

export function AlertList({ alerts }) {
  return (
    <ul className="divide-y divide-soc-border">
      {alerts.map((alert) => (
        <li key={alert.detection_id} className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <div className="flex items-center gap-2">
              <Badge kind="risk" value={alert.risk_level} />
              <span className="text-sm">{prettyCategory(alert.attack_category)}</span>
            </div>
            <p className="mt-1 font-mono text-xs text-soc-muted">
              {alert.source_ip || "unknown source"} · {formatTime(alert.timestamp)}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm">{alert.risk_score ?? "—"} / 100</span>
            <Badge kind="action" value={alert.recommended_action} />
            <Link className="text-xs uppercase tracking-wide text-soc-accent" to={`/events/${alert.detection_id}`}>
              Open
            </Link>
          </div>
        </li>
      ))}
    </ul>
  );
}
