export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function formatClock(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString();
}

export function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  return `${Math.round(Number(value) * 100)}%`;
}

export function classificationClass(value) {
  const key = String(value || "").toLowerCase();
  if (key === "malicious") return "badge-malicious";
  if (key === "suspicious") return "badge-suspicious";
  if (key === "normal") return "badge-normal";
  return "badge-neutral";
}

export function riskClass(value) {
  const key = String(value || "").toUpperCase();
  if (key === "CRITICAL") return "badge-critical";
  if (key === "HIGH") return "badge-high";
  if (key === "MEDIUM") return "badge-medium";
  if (key === "LOW") return "badge-low";
  return "badge-neutral";
}

export function actionClass(value) {
  const key = String(value || "").toUpperCase();
  if (key === "BLOCK") return "badge-critical";
  if (key === "ALERT") return "badge-high";
  if (key === "ALLOW") return "badge-low";
  return "badge-neutral";
}

export function prettyCategory(value) {
  if (!value) return "—";
  return String(value).replaceAll("_", " ");
}
