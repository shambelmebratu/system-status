export type Status = 'up' | 'down' | 'alert' | 'unknown';
export type Mode = 'ping' | 'agent' | 'push';

export type ProcessSample = { pid: number; name: string; user?: string; cpu: number; memory?: number };
export type Metrics = {
  hostname?: string; platform?: string; agent_version?: string; cpu?: number; cpu_count?: number; memory?: number; disk?: number;
  load?: number; swap?: number; uptime_seconds?: number; net_rx_bps?: number | null; net_tx_bps?: number | null;
  latency_ms?: number; reachability?: string; processes?: ProcessSample[]; capabilities?: string[]; os?: string; kernel?: string; arch?: string; install?: 'systemd' | 'macos' | 'docker' | 'bundled' | '';
};

export type Server = {
  id: number; name: string; host: string; monitor_mode: Mode; check_interval_seconds: number; endpoint: string;
  agent_token: string; enabled: boolean; cpu_threshold: number; memory_threshold: number; disk_threshold: number;
  load_threshold: number; swap_threshold: number; process_names: string; process_threshold: number;
  last_status: Status; last_checked_at: string | null; last_seen_at: string | null; last_error: string | null;
  last_metrics: Metrics | null; uptime_24h: number | null; public: boolean; install_token?: string;
  token_issued_at?: string | null; token_rotation_pending?: boolean; last_agent_ip?: string | null; public_ip?: string | null; private_ips?: string[]; alert_events?: string[]; alert_channels?: number[]; alert_reminder_minutes?: number | null; same_machine_as?: { id: number; name: string }[];
};
export type Service = {
  id: number; name: string; url: string; expected_status: number; interval_seconds: number; enabled: boolean; public: boolean;
  server_id: number | null; last_status: Status; last_checked_at: string | null; last_latency_ms: number | null;
  last_http_status: number | null; last_error: string | null; uptime_24h: number | null;
  alert_events?: string[]; alert_channels?: number[]; alert_reminder_minutes?: number | null;
};
export type ChannelType = 'telegram' | 'webhook' | 'slack' | 'whatsapp';
export type Channel = { id: number; name: string; type: ChannelType; token: string; chat_id?: string; endpoint?: string; phone_number_id?: string; template_name?: string; enabled: boolean; notify_kinds?: string[]; notify_events?: string[] };
export type AlertEvent = { id: number; target_type: string; severity: string; message: string; sent: boolean; delivery_error: string | null; delivery_attempts: number; created_at: string };
export type Incident = {
  id: number; target_type: 'server' | 'service' | 'cluster'; target_id: number; target_name: string; severity: 'critical' | 'warning';
  title: string; detail: string | null; started_at: string; resolved_at: string | null; duration_seconds: number;
};
export type Dashboard = {
  servers: Server[]; services: Service[]; events: AlertEvent[];
  threshold_defaults: { cpu: number; memory: number; disk: number; load: number; swap: number; process: number; server_interval_seconds: number };
  agents?: { latest: string; latest_k8s: string };
  limits?: { reminder_minutes: number; usage_warn_percent: number; usage_bad_percent: number; k8s_offline_seconds: number; enrollment_default_minutes: number; enrollment_max_minutes: number; log_result_ttl_minutes: number };
  summary: { servers: number; services: number; up: number; alerts: number; open_incidents: number };
};
export type Point = { t: string; [key: string]: number | string | undefined };
export type Daily = { date: string; pct: number | null };
export type ServerHistory = {
  points: Point[]; samples: number; uptime_pct: number | null; daily: Daily[];
  latency_points: Point[]; latency_avg: number | null; latency_p95: number | null; latency_max: number | null;
};
export type ServiceHistory = {
  points: Point[]; checks: number; uptime_pct: number | null; latency_avg: number | null; latency_p95: number | null;
  latency_max: number | null; recent_failures: { t: string; error: string | null; http_status: number | null }[]; daily: Daily[];
};
export type Range = '1h' | '6h' | '24h' | '7d' | '30d';

export type Enrollment = {
  id: number; label: string; token: string; uses: number; max_uses: number | null; created_at: string; expires_at: string | null;
  last_used_at: string | null; created_by?: string | null; revoked: boolean; active: boolean; state: 'active' | 'expired' | 'revoked' | 'used up';
};

export type ScheduledMessage = {
  id: number; name: string; text: string; channel_ids: number[]; repeat: 'once' | 'daily' | 'weekly'; time_of_day: string; days_of_week: number[];
  run_at: string | null; timezone: string; enabled: boolean; next_run_at: string | null; last_run_at: string | null;
  last_status: 'sent' | 'partial' | 'failed' | 'missed' | null; last_error: string | null; preview: string | null;
};

export type Role = 'admin' | 'operator' | 'viewer';
export type Me = { id: number; email: string; name: string; role: Role; active: boolean; must_change_password: boolean; last_login_at: string | null; created_at: string | null };
export const ROLE_INFO: Record<Role, { label: string; blurb: string }> = {
  admin: { label: 'Admin', blurb: 'Everything, including managing users and their roles.' },
  operator: { label: 'Operator', blurb: 'Manage servers, services, alerts, schedules, logs and agent install links. Cannot manage users.' },
  viewer: { label: 'Viewer', blurb: 'Read-only: dashboards, uptime and incidents. No logs, no changes.' },
};

export type AuditEvent = { id: number; ts: string; actor: string; actor_role: string | null; action: string; target: string; detail: string | null; ip: string | null; success: boolean };

export type ClusterSummary = {
  agent_version: string; k8s_version: string; error: string; nodes_total: number; nodes_ready: number; not_ready_nodes: string[]; namespaces: number;
  pods_total: number; pods_running: number; pods_pending: number; pods_failed: number; pods_succeeded: number; pods_crashloop: number; restarts: number; pods_truncated: boolean;
  deployments_total: number; deployments_unavailable: number; statefulsets_total: number; statefulsets_unavailable: number; daemonsets_total: number; daemonsets_unavailable: number;
  hpa_total: number; usage_available: boolean; cpu_m: number | null; cpu_alloc_m: number | null; mem_mib: number | null; mem_alloc_mib: number | null; problems: string[];
};
export type K8sLogPolicy = { enabled: boolean; include: string[]; exclude: string[] };
export type Cluster = {
  id: number; name: string; enabled: boolean; status: Status; last_error: string | null; last_seen_at: string | null; k8s_version: string | null; agent_version: string | null;
  agent_outdated?: boolean; latest_agent_version?: string;
  summary: ClusterSummary | null; token_issued_at: string | null; token_rotation_pending: boolean; last_agent_ip: string | null; created_by: string | null; created_at: string;
  log_policy: K8sLogPolicy; restricted: boolean;
  alert_events?: string[]; alert_channels?: number[]; alert_reminder_minutes?: number | null;
};
