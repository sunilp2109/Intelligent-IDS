import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function ShapBarChart({ features }) {
  const data = (features || []).map((item) => ({
    ...item,
    label: item.feature,
  }));
  return (
    <div className="h-80">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
          <CartesianGrid stroke="#1e293b" horizontal={false} />
          <XAxis type="number" stroke="#94a3b8" />
          <YAxis type="category" dataKey="label" stroke="#94a3b8" width={150} tick={{ fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }}
            formatter={(value, _name, props) => [
              Number(value).toFixed(4),
              `SHAP (${props.payload.direction || "contribution"})`,
            ]}
          />
          <Bar dataKey="shap_value">
            {data.map((entry) => (
              <Cell key={entry.feature} fill={entry.shap_value >= 0 ? "#34d399" : "#f87171"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
