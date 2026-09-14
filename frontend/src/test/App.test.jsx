import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { DashboardPage } from "../pages/Dashboard";
import { AttackDetailsPage } from "../pages/AttackDetails";
import { EventsTable } from "../components/tables/EventsTable";
import App from "../App";

function jsonResponse(payload, ok = true, status = 200) {
  return Promise.resolve({
    ok,
    status,
    json: async () => payload,
  });
}

function mockDashboardApis(overrides = {}) {
  globalThis.fetch = async (url) => {
    const path = String(url);
    if (path.includes("/api/dashboard/stats")) return jsonResponse(overrides.stats || { total_events: 0, normal: 0, suspicious: 0, malicious: 0, critical: 0, active_alerts: 0 });
    if (path.includes("/api/dashboard/timeline")) return jsonResponse(overrides.timeline || []);
    if (path.includes("/api/dashboard/attacks")) return jsonResponse(overrides.attacks || []);
    if (path.includes("/api/dashboard/risks")) return jsonResponse(overrides.risks || []);
    if (path.includes("/api/dashboard/recent")) return jsonResponse(overrides.recent || []);
    if (path.includes("/api/dashboard/alerts")) return jsonResponse(overrides.alerts || []);
    return jsonResponse({ detail: "missing mock" }, false, 500);
  };
}

test("dashboard shows empty zeros from the API", async () => {
  mockDashboardApis();
  render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  );
  expect(await screen.findByText("Total events")).toBeInTheDocument();
  expect(screen.getAllByText("0").length).toBeGreaterThan(0);
  expect(screen.getByText("No security events recorded.")).toBeInTheDocument();
  expect(screen.getByText("No active alerts.")).toBeInTheDocument();
});

test("dashboard shows an error when the API is unavailable", async () => {
  globalThis.fetch = async () => jsonResponse({ detail: "Unable to load security data." }, false, 500);
  render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  );
  expect((await screen.findAllByRole("alert")).length).toBeGreaterThan(0);
});

test("navigation exposes operator pages", async () => {
  mockDashboardApis();
  render(
    <MemoryRouter>
      <App />
    </MemoryRouter>,
  );
  expect(screen.getByText("Dashboard")).toBeInTheDocument();
  expect(screen.getByText("Alerts")).toBeInTheDocument();
  expect(screen.getByText("Activity Logs")).toBeInTheDocument();
  expect(screen.getByText("Attack Analysis")).toBeInTheDocument();
  expect(screen.getByText("System / Model")).toBeInTheDocument();
  await waitFor(() => expect(screen.getByTestId("ws-status")).toHaveAttribute("data-status", "CONNECTED"));
});

test("events table renders backend fields", () => {
  render(
    <MemoryRouter>
      <EventsTable
        rows={[
          {
            detection_id: 3,
            timestamp: "2026-09-14T10:00:00Z",
            source_ip: "192.0.2.30",
            classification: "malicious",
            attack_category: "BRUTE_FORCE",
            risk_level: "CRITICAL",
            confidence_score: 0.94,
            recommended_action: "BLOCK",
          },
        ]}
      />
    </MemoryRouter>,
  );
  expect(screen.getByText("192.0.2.30")).toBeInTheDocument();
  expect(screen.getByText("malicious")).toBeInTheDocument();
  expect(screen.getByText("CRITICAL")).toBeInTheDocument();
});

test("attack detail renders stored SHAP and risk values", async () => {
  globalThis.fetch = async () =>
    jsonResponse({
      classification: "malicious",
      confidence_score: 0.94,
      attack_category: "BRUTE_FORCE",
      source_ip: "192.0.2.30",
      timestamp: "2026-09-14T10:00:00Z",
      status: "demo",
      attempts: 20,
      attack_log_id: 1,
      risk: {
        risk_score: 87,
        risk_level: "CRITICAL",
        recommended_action: "BLOCK",
        operator_guidance: "CONTAIN",
        risk_breakdown: { classification: 30, confidence: 18, attack_category: 20, behavior: 14, evidence_strength: 5 },
      },
      analysis: { evidence_strength: "HIGH", indicators: ["HIGH_FAILED_LOGIN_RATIO"], evidence: { login_attempts: 20 } },
      explanation: {
        top_features: [{ feature: "failed_login_ratio", value: 0.95, shap_value: 0.31, direction: "increases_prediction" }],
      },
    });
  render(
    <MemoryRouter initialEntries={["/events/3"]}>
      <Routes>
        <Route path="/events/:detectionId" element={<AttackDetailsPage />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findByText("87 / 100")).toBeInTheDocument();
  expect(screen.getByText("failed_login_ratio")).toBeInTheDocument();
  expect(screen.getByText("0.3100")).toBeInTheDocument();
});
