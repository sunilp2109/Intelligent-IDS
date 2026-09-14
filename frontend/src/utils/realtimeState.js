export const ALERT_LEVELS = new Set(["HIGH", "CRITICAL"]);

export function rowKey(row) {
  if (row?.detection_id != null) return `detection:${row.detection_id}`;
  if (row?.attack_log_id != null) return `log:${row.attack_log_id}`;
  if (row?.log_id != null) return `log:${row.log_id}`;
  return null;
}

export function toDashboardRow(message) {
  const data = message?.data || {};
  return {
    detection_id: data.detection_id ?? null,
    attack_log_id: data.log_id ?? null,
    timestamp: message?.timestamp || null,
    source_ip: data.source_ip || null,
    classification: data.classification || null,
    confidence_score: data.confidence_score ?? null,
    attack_category: data.attack_category || null,
    risk_level: data.risk_level || null,
    risk_score: data.risk_score ?? null,
    recommended_action: data.recommended_action || null,
    live: true,
  };
}

export function isAlert(row) {
  return ALERT_LEVELS.has(String(row?.risk_level || "").toUpperCase());
}

export function prependUnique(list, item, limit = 50) {
  const key = rowKey(item);
  if (key && (list || []).some((row) => rowKey(row) === key)) return list;
  return [item, ...(list || [])].slice(0, limit);
}

export function mergeEventRows(restRows = [], liveRows = [], limit = 50) {
  const map = new Map();
  for (const row of restRows || []) {
    const key = rowKey(row);
    if (key) map.set(key, row);
  }
  for (const row of liveRows || []) {
    const key = rowKey(row);
    if (key) map.set(key, { ...map.get(key), ...row });
  }
  return Array.from(map.values())
    .sort((left, right) => String(right.timestamp || "").localeCompare(String(left.timestamp || "")))
    .slice(0, limit);
}

export function applySecurityEvent(state, message) {
  if (!message || (message.event_type !== "security_event" && message.event_type !== "alert_created")) {
    return state;
  }
  if (message.event_type === "alert_created" && !isAlert(message.data || {})) {
    return state;
  }
  const row = toDashboardRow(message);
  const key = rowKey(row);
  if (!key) return state;
  const seen = new Set(state.seen || []);
  if (seen.has(key)) return state;
  seen.add(key);
  const liveEvents = prependUnique(state.liveEvents, row);
  const liveAlerts = isAlert(row) ? prependUnique(state.liveAlerts, row) : state.liveAlerts;
  return { ...state, seen, liveEvents, liveAlerts };
}

export function emptyRealtimeState() {
  return { seen: new Set(), liveEvents: [], liveAlerts: [] };
}
