import { useParams } from "react-router-dom";
import { ShapBarChart } from "../components/charts/ShapBarChart";
import { Badge } from "../components/common/Badge";
import { EmptyState, ErrorState, LoadingState } from "../components/common/StatusPanels";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { formatPercent, formatTime, prettyCategory } from "../utils/format";

function Breakdown({ breakdown }) {
  const rows = [
    ["classification", "Classification"],
    ["confidence", "Confidence"],
    ["attack_category", "Attack category"],
    ["behavior", "Behavior"],
    ["evidence_strength", "Evidence strength"],
  ];
  return (
    <dl className="space-y-2">
      {rows.map(([key, label]) => (
        <div key={key} className="flex justify-between text-sm">
          <dt className="text-soc-muted">{label}</dt>
          <dd className="font-mono">{breakdown?.[key] ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function AttackDetailsPage() {
  const { detectionId } = useParams();
  const { data, error, loading } = useApi(() => api.getAttackDetails(detectionId), String(detectionId));
  const shapFeatures = data?.explanation?.top_features || data?.explanation?.feature_contributions || [];

  return (
    <div className="space-y-4">
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error && !data ? <EmptyState /> : null}
      {data ? (
        <>
          <section className="panel grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-soc-muted">Classification</p>
              <div className="mt-2">
                <Badge kind="classification" value={data.classification} />
              </div>
              <p className="mt-2 font-mono text-sm">Confidence {formatPercent(data.confidence_score)}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-soc-muted">Attack</p>
              <p className="mt-2 text-lg">{prettyCategory(data.attack_category)}</p>
              <p className="text-xs text-soc-muted">{data.source_ip} · {formatTime(data.timestamp)}</p>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-soc-muted">Risk</p>
              <p className="mt-2 font-mono text-2xl">{data.risk?.risk_score ?? "—"} / 100</p>
              <Badge kind="risk" value={data.risk?.risk_level || data.risk_level} />
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-soc-muted">Recommended</p>
              <div className="mt-2">
                <Badge kind="action" value={data.risk?.recommended_action || data.recommended_action} />
              </div>
              <p className="mt-2 text-xs text-soc-muted">
                {data.risk?.operator_guidance || "—"} · recommendation only
              </p>
            </div>
          </section>

          <section className="grid gap-4 lg:grid-cols-2">
            <div className="panel p-5">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-soc-muted">Detection</h2>
              <dl className="mt-3 space-y-2 text-sm">
                <div className="flex justify-between"><dt className="text-soc-muted">Status</dt><dd>{data.status || "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-soc-muted">Attempts</dt><dd className="font-mono">{data.attempts ?? "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-soc-muted">Log ID</dt><dd className="font-mono">{data.attack_log_id ?? "—"}</dd></div>
              </dl>
            </div>
            <div className="panel p-5">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-soc-muted">Risk breakdown</h2>
              {data.risk ? <div className="mt-3"><Breakdown breakdown={data.risk.risk_breakdown} /></div> : <EmptyState message="No risk assessment stored." />}
            </div>
          </section>

          <section className="panel p-5">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-soc-muted">Behavioral evidence</h2>
            {data.analysis ? (
              <div className="mt-3 grid gap-4 md:grid-cols-2">
                <div>
                  <p className="text-xs text-soc-muted">Evidence strength</p>
                  <p className="mt-1"><Badge kind="risk" value={data.analysis.evidence_strength} /></p>
                  <ul className="mt-3 space-y-1 text-sm">
                    {(data.analysis.indicators || []).map((item) => (
                      <li key={item} className="font-mono text-xs">{item}</li>
                    ))}
                    {(data.analysis.indicators || []).length === 0 ? <li className="text-soc-muted">No indicators stored.</li> : null}
                  </ul>
                </div>
                <div>
                  <p className="text-xs text-soc-muted">Evidence values</p>
                  <ul className="mt-3 space-y-1 font-mono text-xs">
                    {Object.entries(data.analysis.evidence || {}).map(([key, value]) => (
                      <li key={key}>{key}: {String(value)}</li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              <div className="mt-3"><EmptyState message="No attack analysis stored for this detection." /></div>
            )}
          </section>

          <section className="panel p-5">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-soc-muted">Why the model predicted this</h2>
            {shapFeatures.length === 0 ? (
              <div className="mt-3"><EmptyState message="No SHAP explanation is stored. Run POST /api/explain for this feature vector." /></div>
            ) : (
              <div className="mt-3 grid gap-4 lg:grid-cols-2">
                <ShapBarChart features={shapFeatures} />
                <table className="min-w-full text-left text-sm">
                  <thead className="text-xs uppercase text-soc-muted">
                    <tr>
                      <th className="py-2">Feature</th>
                      <th>Value</th>
                      <th>SHAP</th>
                      <th>Direction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shapFeatures.map((item) => (
                      <tr key={item.feature} className="border-t border-soc-border font-mono text-xs">
                        <td className="py-2">{item.feature}</td>
                        <td>{item.value}</td>
                        <td>{Number(item.shap_value).toFixed(4)}</td>
                        <td>{item.direction}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      ) : null}
    </div>
  );
}
