const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

async function request(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      if (typeof payload.detail === "string") detail = payload.detail;
    } catch {
      /* ignore parse errors */
    }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

export const api = {
  getDashboardStats: () => request("/api/dashboard/stats"),
  getTimeline: () => request("/api/dashboard/timeline"),
  getAttackDistribution: () => request("/api/dashboard/attacks"),
  getRiskDistribution: () => request("/api/dashboard/risks"),
  getRecentEvents: () => request("/api/dashboard/recent?limit=20"),
  getAlerts: (levels = "HIGH,CRITICAL") =>
    request(`/api/dashboard/alerts?levels=${encodeURIComponent(levels)}`),
  getLogs: (params = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value) query.set(key, value);
    });
    const suffix = query.toString() ? `?${query}` : "";
    return request(`/api/dashboard/logs${suffix}`);
  },
  getAttackDetails: (id) => request(`/api/dashboard/events/${id}`),
  getSystemStatus: () => request("/api/system/status"),
};

export { API_BASE_URL };
