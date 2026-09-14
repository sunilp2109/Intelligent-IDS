export function StatCard({ label, value, tone = "default" }) {
  const tones = {
    default: "text-soc-text",
    normal: "text-emerald-300",
    suspicious: "text-amber-300",
    malicious: "text-red-300",
    critical: "text-red-200",
    alert: "text-orange-300",
  };
  return (
    <article className="panel px-4 py-4">
      <p className="text-xs uppercase tracking-[0.16em] text-soc-muted">{label}</p>
      <p className={`mt-2 font-mono text-3xl font-semibold ${tones[tone] || tones.default}`}>
        {value === null || value === undefined ? "—" : value}
      </p>
    </article>
  );
}
