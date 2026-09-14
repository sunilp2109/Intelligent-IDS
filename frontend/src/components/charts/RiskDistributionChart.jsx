import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const COLORS = {
  LOW: "#64748b",
  MEDIUM: "#f59e0b",
  HIGH: "#fb923c",
  CRITICAL: "#f87171",
};

export function RiskDistributionChart({ data }) {
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 24 }}>
          <CartesianGrid stroke="#1e293b" horizontal={false} />
          <XAxis type="number" stroke="#94a3b8" allowDecimals={false} />
          <YAxis type="category" dataKey="level" stroke="#94a3b8" width={80} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
          <Bar dataKey="count">
            {data.map((entry) => (
              <Cell key={entry.level} fill={COLORS[entry.level] || "#38bdf8"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
