import { useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { RealtimeProvider } from "./context/RealtimeContext";
import { AppShell } from "./components/layout/AppShell";
import { ActivityLogsPage } from "./pages/ActivityLogs";
import { AlertsPage } from "./pages/Alerts";
import { AttackAnalysisPage } from "./pages/AttackAnalysis";
import { AttackDetailsPage } from "./pages/AttackDetails";
import { DashboardPage } from "./pages/Dashboard";
import { SystemStatusPage } from "./pages/SystemStatus";

export default function App() {
  const [refreshKey, setRefreshKey] = useState(0);
  return (
    <RealtimeProvider>
      <AppShell onRefresh={() => setRefreshKey((value) => value + 1)}>
        <Routes>
          <Route path="/" element={<DashboardPage key={refreshKey} />} />
          <Route path="/alerts" element={<AlertsPage key={refreshKey} />} />
          <Route path="/logs" element={<ActivityLogsPage key={refreshKey} />} />
          <Route path="/analysis" element={<AttackAnalysisPage key={refreshKey} />} />
          <Route path="/events/:detectionId" element={<AttackDetailsPage key={refreshKey} />} />
          <Route path="/status" element={<SystemStatusPage key={refreshKey} />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </RealtimeProvider>
  );
}
