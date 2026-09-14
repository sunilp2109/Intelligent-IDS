import { Link } from "react-router-dom";
import { Badge } from "../common/Badge";
import { formatPercent, formatTime, prettyCategory } from "../../utils/format";

export function EventsTable({ rows }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-soc-muted">
          <tr>
            <th className="px-3 py-2">Time</th>
            <th className="px-3 py-2">Source</th>
            <th className="px-3 py-2">Classification</th>
            <th className="px-3 py-2">Attack</th>
            <th className="px-3 py-2">Risk</th>
            <th className="px-3 py-2">Confidence</th>
            <th className="px-3 py-2">Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={row.detection_id || row.attack_log_id || index} className="border-t border-soc-border">
              <td className="px-3 py-2 font-mono text-xs">{formatTime(row.timestamp)}</td>
              <td className="px-3 py-2 font-mono">{row.source_ip || "—"}</td>
              <td className="px-3 py-2">
                <Badge kind="classification" value={row.classification} />
              </td>
              <td className="px-3 py-2">{prettyCategory(row.attack_category)}</td>
              <td className="px-3 py-2">
                <Badge kind="risk" value={row.risk_level} />
              </td>
              <td className="px-3 py-2 font-mono">{formatPercent(row.confidence_score)}</td>
              <td className="px-3 py-2">
                {row.detection_id ? (
                  <Link className="text-soc-accent hover:underline" to={`/events/${row.detection_id}`}>
                    <Badge kind="action" value={row.recommended_action} />
                  </Link>
                ) : (
                  <Badge kind="action" value={row.recommended_action} />
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
