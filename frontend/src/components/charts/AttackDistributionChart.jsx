import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { prettyCategory } from "../../utils/format";

const COLORS = ["#38bdf8", "#f59e0b", "#f87171", "#a78bfa", "#34d399", "#fb7185"];

export function AttackDistributionChart({ data }) {
  const chartData = data.map((item) => ({ ...item, name: prettyCategory(item.category) }));
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={chartData} dataKey="count" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>
            {chartData.map((entry, index) => (
              <Cell key={entry.category} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
