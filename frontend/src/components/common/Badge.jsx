export function Badge({ value, kind = "neutral" }) {
  const map = {
    classification: {
      normal: "badge-normal",
      suspicious: "badge-suspicious",
      malicious: "badge-malicious",
    },
    risk: {
      low: "badge-low",
      medium: "badge-medium",
      high: "badge-high",
      critical: "badge-critical",
    },
    action: {
      allow: "badge-low",
      alert: "badge-high",
      block: "badge-critical",
      monitor: "badge-medium",
      investigate: "badge-high",
      contain: "badge-critical",
    },
  };
  const key = String(value || "—").toLowerCase();
  const className = map[kind]?.[key] || "badge-neutral";
  return <span className={className}>{value || "—"}</span>;
}
