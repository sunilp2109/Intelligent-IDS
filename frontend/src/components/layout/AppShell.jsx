import { NavLink } from "react-router-dom";
import { ConnectionStatus } from "../realtime/ConnectionStatus";
import { useRealtime } from "../../context/RealtimeContext";

const links = [
  { to: "/", label: "Dashboard" },
  { to: "/alerts", label: "Alerts" },
  { to: "/logs", label: "Activity Logs" },
  { to: "/analysis", label: "Attack Analysis" },
  { to: "/status", label: "System / Model" },
];

export function AppShell({ children, onRefresh }) {
  const { status } = useRealtime();
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[220px_1fr]">
      <aside className="border-b border-soc-border bg-soc-panel lg:border-b-0 lg:border-r">
        <div className="px-5 py-6">
          <p className="text-[11px] uppercase tracking-[0.22em] text-soc-accent">Intelligent IDS</p>
          <h1 className="mt-1 text-lg font-semibold">Security Monitor</h1>
          <p className="mt-2 text-xs text-soc-muted">Operator console. BLOCK is a recommendation only.</p>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-4 lg:flex-col">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) =>
                `rounded px-3 py-2 text-sm ${isActive ? "bg-slate-800 text-white" : "text-soc-muted hover:bg-slate-900 hover:text-white"}`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="min-w-0">
        <header className="flex items-center justify-between gap-4 border-b border-soc-border px-6 py-4">
          <p className="text-sm text-soc-muted">Honeypot-assisted intrusion monitoring</p>
          <div className="flex items-center gap-4">
            <ConnectionStatus status={status} />
            {onRefresh ? (
              <button
                type="button"
                onClick={onRefresh}
                className="rounded border border-soc-border px-3 py-1.5 text-xs uppercase tracking-wide text-soc-muted hover:text-white"
              >
                Refresh
              </button>
            ) : null}
          </div>
        </header>
        <main className="px-6 py-6">{children}</main>
      </div>
    </div>
  );
}
