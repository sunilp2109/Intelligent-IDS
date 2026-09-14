import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function TimelineChart({ data }) {
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis dataKey="timestamp" stroke="#94a3b8" tick={{ fontSize: 11 }} />
          <YAxis stroke="#94a3b8" allowDecimals={false} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
          <Legend />
          <Bar dataKey="normal" stackId="class" fill="#34d399" name="Normal" />
          <Bar dataKey="suspicious" stackId="class" fill="#fbbf24" name="Suspicious" />
          <Bar dataKey="malicious" stackId="class" fill="#f87171" name="Malicious" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
