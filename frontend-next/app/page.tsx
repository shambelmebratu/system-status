'use client';

import { FormEvent, ReactNode, useEffect, useState } from 'react';
import styles from './page.module.css';
import targetStyles from './targets.module.css';
import agentGuide from './agent-guide.module.css';
import controls from './controls.module.css';
import deployStyles from './agent-deploy.module.css';
import pingStyles from './ping-only.module.css';

type Target = {
  id: number;
  name: string;
  monitor_mode?: 'ping' | 'agent';
  check_interval_seconds?: number;
  host?: string;
  endpoint?: string;
  url?: string;
  agent_token?: string;
  process_names?: string;
  process_threshold?: number;
  cpu_threshold?: number;
  memory_threshold?: number;
  disk_threshold?: number;
  load_threshold?: number;
  swap_threshold?: number;
  expected_status?: number;
  interval_seconds?: number;
  last_status: string;
  last_http_status?: number;
  last_checked_at?: string;
  last_latency_ms?: number;
  last_error?: string;
  last_metrics?: { processes?: { name: string; cpu: number }[] };
};
type ChannelType = 'telegram' | 'webhook' | 'slack' | 'whatsapp';
type Channel = { id: number; name: string; type: ChannelType; token: string; chat_id?: string; endpoint?: string; phone_number_id?: string; template_name?: string; template_language?: string; enabled: boolean };
type AlertEvent = { id: number; target_type: string; severity: string; message: string; sent: boolean; delivery_error?: string | null; delivery_attempts: number; created_at: string };
type Dashboard = {
  servers: Target[];
  services: Target[];
  events: AlertEvent[];
  threshold_defaults?: { cpu: number; memory: number; disk: number; load: number; swap: number; process: number; server_interval_seconds: number };
  summary: { servers: number; services: number; up: number; alerts: number };
};

async function request<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('northstar_token') : '';
  const response = await fetch(`/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (data as { detail?: unknown }).detail;
    if (typeof detail === 'string') throw new Error(detail);
    if (Array.isArray(detail)) {
      const messages = detail.map(item => (typeof item === 'string' ? item : (item as { msg?: string }).msg || JSON.stringify(item)));
      throw new Error(messages.join('; ') || `Request failed (${response.status})`);
    }
    throw new Error(`Request failed (${response.status})`);
  }
  return data as T;
}

export default function Home() {
  const [companyName, setCompanyName] = useState('Northstar Operations');
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState<number | null>(null);
  const [tab, setTab] = useState('overview');
  const [editingServerId, setEditingServerId] = useState<number | null>(null);
  const [editingServerHasToken, setEditingServerHasToken] = useState(false);
  const [editingServiceId, setEditingServiceId] = useState<number | null>(null);

  const [serverName, setServerName] = useState('');
  const [serverHost, setServerHost] = useState('');
  const [monitorMode, setMonitorMode] = useState<'ping' | 'agent'>('ping');
  const [serverIntervalSeconds, setServerIntervalSeconds] = useState('60');
  const [endpoint, setEndpoint] = useState('');
  const [agentToken, setAgentToken] = useState('');
  const [processNames, setProcessNames] = useState('');
  const [thresholds, setThresholds] = useState({ cpu: '85', memory: '90', disk: '85', load: '10', swap: '80', process: '80' });

  const [serviceName, setServiceName] = useState('');
  const [serviceUrl, setServiceUrl] = useState('');
  const [expectedStatus, setExpectedStatus] = useState('200');
  const [intervalSeconds, setIntervalSeconds] = useState('60');

  const [channelName, setChannelName] = useState('');
  const [channelType, setChannelType] = useState<ChannelType>('telegram');
  const [botToken, setBotToken] = useState('');
  const [chatId, setChatId] = useState('');
  const [channelEndpoint, setChannelEndpoint] = useState('');
  const [whatsAppPhoneNumberId, setWhatsAppPhoneNumberId] = useState('');
  const [whatsAppTemplate, setWhatsAppTemplate] = useState('northstar_alert');
  const [whatsAppLanguage, setWhatsAppLanguage] = useState('en_US');

  function announce(message: string, failed = false) {
    setError(failed ? message : '');
    setNotice(failed ? '' : message);
    window.setTimeout(() => { setNotice(''); setError(''); }, 6000);
  }

  async function load(applyThresholdDefaults = false) {
    try {
      const [data, channelData] = await Promise.all([
        request<Dashboard>('/dashboard'),
        request<Channel[]>('/channels'),
      ]);
      setDashboard(data);
      setChannels(channelData);
      if (applyThresholdDefaults && data.threshold_defaults) {
        setThresholds({
          cpu: String(data.threshold_defaults.cpu),
          memory: String(data.threshold_defaults.memory),
          disk: String(data.threshold_defaults.disk),
          load: String(data.threshold_defaults.load),
          swap: String(data.threshold_defaults.swap),
          process: String(data.threshold_defaults.process),
        });
        setServerIntervalSeconds(String(data.threshold_defaults.server_interval_seconds));
      }
    } catch (caught) {
      setToken(null);
      localStorage.removeItem('northstar_token');
      setError((caught as Error).message);
    }
  }

  useEffect(() => {
    void request<{ company_name: string; primary_color: string; accent_color: string }>('/branding')
      .then(branding => {
        setCompanyName(branding.company_name);
        document.documentElement.style.setProperty('--brand-primary', branding.primary_color);
        document.documentElement.style.setProperty('--brand-accent', branding.accent_color);
        document.title = branding.company_name;
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const saved = localStorage.getItem('northstar_token');
    if (saved) {
      setToken(saved);
      void load(true);
    }
  }, []);

  async function signIn(event: FormEvent) {
    event.preventDefault();
    setError('');
    try {
      const result = await request<{ token: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      localStorage.setItem('northstar_token', result.token);
      setToken(result.token);
      await load(true);
    } catch (caught) {
      setError((caught as Error).message);
    }
  }

  async function saveServer(event: FormEvent) {
    event.preventDefault();
    try {
      await request(editingServerId ? `/servers/${editingServerId}` : '/servers', {
        method: editingServerId ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: serverName,
          host: serverHost,
          monitor_mode: monitorMode,
          check_interval_seconds: Number(serverIntervalSeconds),
          endpoint: monitorMode === 'agent' ? endpoint : '',
          agent_token: monitorMode === 'agent' ? agentToken : '',
          process_names: processNames,
          cpu_threshold: Number(thresholds.cpu),
          memory_threshold: Number(thresholds.memory),
          disk_threshold: Number(thresholds.disk),
          load_threshold: Number(thresholds.load),
          swap_threshold: Number(thresholds.swap),
          process_threshold: Number(thresholds.process),
        }),
      });
      setServerName(''); setServerHost(''); setMonitorMode('ping'); setServerIntervalSeconds(String(dashboard?.threshold_defaults?.server_interval_seconds ?? 60)); setEndpoint(''); setAgentToken(''); setProcessNames(''); setEditingServerId(null); setEditingServerHasToken(false);
      announce(editingServerId ? 'Server updated.' : 'Server saved. The worker will check it on the next monitoring cycle.');
      await load();
    } catch (caught) { announce((caught as Error).message, true); }
  }

  async function saveService(event: FormEvent) {
    event.preventDefault();
    try {
      await request(editingServiceId ? `/services/${editingServiceId}` : '/services', {
        method: editingServiceId ? 'PUT' : 'POST',
        body: JSON.stringify({
          name: serviceName,
          url: serviceUrl,
          expected_status: Number(expectedStatus),
          interval_seconds: Number(intervalSeconds),
        }),
      });
      setServiceName(''); setServiceUrl(''); setEditingServiceId(null);
      announce(editingServiceId ? 'Service monitor updated.' : 'Service monitor saved. Run “Check now” to test it immediately.');
      await load();
    } catch (caught) { announce((caught as Error).message, true); }
  }

  function editServer(server: Target) {
    setTab('servers');
    setEditingServerId(server.id);
    setEditingServerHasToken(server.agent_token === 'configured');
    setServerName(server.name);
    setServerHost(server.host || '');
    setMonitorMode(server.monitor_mode || (server.endpoint ? 'agent' : 'ping'));
    setServerIntervalSeconds(String(server.check_interval_seconds ?? 60));
    setEndpoint(server.endpoint || '');
    setAgentToken('');
    setProcessNames(server.process_names || '');
    setThresholds({
      cpu: String(server.cpu_threshold ?? 85),
      memory: String(server.memory_threshold ?? 90),
      disk: String(server.disk_threshold ?? 85),
      load: String(server.load_threshold ?? 10),
      swap: String(server.swap_threshold ?? 80),
      process: String(server.process_threshold ?? 80),
    });
  }

  function editService(service: Target) {
    setTab('services');
    setEditingServiceId(service.id);
    setServiceName(service.name);
    setServiceUrl(service.url || '');
    setExpectedStatus(String(service.expected_status ?? 200));
    setIntervalSeconds(String(service.interval_seconds ?? 60));
  }

  function cancelEdit() {
    setEditingServerId(null);
    setEditingServerHasToken(false);
    setEditingServiceId(null);
    setServerName(''); setServerHost(''); setEndpoint(''); setAgentToken(''); setProcessNames('');
    setMonitorMode('ping'); setServerIntervalSeconds(String(dashboard?.threshold_defaults?.server_interval_seconds ?? 60));
    setServiceName(''); setServiceUrl(''); setExpectedStatus('200'); setIntervalSeconds('60');
  }

  async function checkService(id: number) {
    setBusy(id);
    try {
      const result = await request<{ status: string; http_status: number | null; latency_ms: number; error: string | null }>(`/services/${id}/check`, { method: 'POST' });
      announce(`${result.status.toUpperCase()} · HTTP ${result.http_status ?? 'no response'} · ${result.latency_ms} ms${result.error ? ` · ${result.error}` : ''}`, result.status !== 'up');
      await load();
    } catch (caught) { announce((caught as Error).message, true); }
    finally { setBusy(null); }
  }

  async function saveChannel(event: FormEvent) {
    event.preventDefault();
    try {
      await request('/channels', {
        method: 'POST',
        body: JSON.stringify({
          name: channelName,
          type: channelType,
          token: botToken,
          chat_id: chatId,
          endpoint: channelEndpoint,
          phone_number_id: whatsAppPhoneNumberId,
          template_name: whatsAppTemplate,
          template_language: whatsAppLanguage,
        }),
      });
      setChannelName(''); setBotToken(''); setChatId(''); setChannelEndpoint(''); setWhatsAppPhoneNumberId('');
      announce(`${channelTypeLabel(channelType)} channel saved. Use “Send test” to verify delivery.`);
      await load();
    } catch (caught) { announce((caught as Error).message, true); }
  }

  async function testChannel(channel: Channel) {
    setBusy(channel.id);
    try {
      const result = await request<{ detail: string }>(`/channels/${channel.id}/test`, { method: 'POST' });
      announce(result.detail || `Test message sent to ${channel.name}.`);
    } catch (caught) { announce(`Channel test failed: ${(caught as Error).message}`, true); }
    finally { setBusy(null); }
  }

  async function deleteTarget(path: string, label: string) {
    if (!window.confirm(`Remove this ${label}?`)) return;
    try { await request(path, { method: 'DELETE' }); announce(`${label} removed.`); await load(); }
    catch (caught) { announce((caught as Error).message, true); }
  }

  function channelTypeLabel(type: ChannelType): string {
    return ({ telegram: 'Telegram', webhook: 'Webhook', slack: 'Slack', whatsapp: 'WhatsApp Cloud API' })[type];
  }

  async function runChecks() {
    try { await request('/monitor/run', { method: 'POST' }); announce('Monitoring run started. Refreshing results shortly.'); window.setTimeout(() => void load(), 2500); }
    catch (caught) { announce((caught as Error).message, true); }
  }

  if (!token) return (
    <main className={styles.login}>
      <section className={styles.loginArt}>
        <span className={styles.eyebrow}>{companyName.toUpperCase()} / CONTROL PLANE</span>
        <div><h1>Know before<br /><i>they know.</i></h1><p>One command center for every host, service, and signal.</p></div>
        <small>MONITORING SYSTEM 03.0</small>
      </section>
      <form className={styles.loginForm} onSubmit={signIn}>
        <span className={styles.eyebrow}>ADMIN ACCESS</span><h2>Welcome back.</h2>
        <p>Sign in to manage your monitored infrastructure.</p>
        <label>Email<input type="email" value={email} onChange={event => setEmail(event.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={event => setPassword(event.target.value)} required /></label>
        <button>Enter console <b>↗</b></button>
        {error && <div className={styles.error}>{error}</div>}
      </form>
    </main>
  );

  const summary = dashboard?.summary || { servers: 0, services: 0, up: 0, alerts: 0 };
  const nav = [['overview', '◈ Overview'], ['servers', '⌁ Servers'], ['services', '◌ Services'], ['channels', '◉ Alert channels']];
  return (
    <main className={styles.shell}>
      <aside className={styles.sidebar}>
        <div className={styles.brand}><b>{companyName.trim().charAt(0).toUpperCase() || 'N'}</b><span>{companyName.toUpperCase()}<small>OPERATIONS</small></span></div>
        <nav>{nav.map(([key, label]) => <button key={key} className={tab === key ? styles.active : ''} onClick={() => setTab(key)}>{label}</button>)}</nav>
        <div className={styles.sidebarBottom}><span className={styles.online}>●</span> Control plane online<button onClick={() => { localStorage.removeItem('northstar_token'); setToken(null); }}>Sign out ↗</button></div>
      </aside>
      <section className={styles.content}>
        <header><div><span className={styles.eyebrow}>OPERATIONS / {tab.toUpperCase()}</span><h1>{tab === 'overview' ? 'Good morning, admin.' : `Manage ${tab}.`}</h1></div><button className={controls.secondary} onClick={runChecks}>Run checks ↻</button></header>
        {(error || notice) && <div className={`${styles.notice} ${error ? styles.error : ''}`}>{error || notice}</div>}

        {tab === 'overview' && <>
          <div className={styles.hero}><div><span className={styles.label}>SYSTEM PULSE</span><h2>Infrastructure at a glance.</h2><p>Your monitoring network is watching {summary.servers} servers and {summary.services} services.</p></div><div className={styles.pulse}><b>{summary.alerts}</b><small>active<br />alerts</small></div></div>
          <div className={styles.stats}><div><span>Monitored hosts</span><b>{summary.servers}</b><small>{summary.up} reporting up</small></div><div><span>Service checks</span><b>{summary.services}</b><small>Independent HTTP monitors</small></div><div><span>Open alerts</span><b>{summary.alerts}</b><small>{summary.alerts ? 'Needs attention' : 'Everything quiet'}</small></div></div>
          <section className={styles.list}>
            <div className={styles.row}><b>Recent notifications</b><small>Delivery status and retry details</small></div>
            {!dashboard?.events.length ? <p className={styles.empty}>No alerts recorded yet.</p> : dashboard.events.map(event => <div className={styles.row} key={event.id}>
              <b>{event.message.replace(/<\/?b>/g, '').split('\n')[0]}</b>
              <small>{new Date(event.created_at).toLocaleString()}</small>
              <span className={`${styles.status} ${event.sent ? styles.up : styles.down}`}>{event.sent ? '● delivered' : `● pending (${event.delivery_attempts}/10)`}</span>
              {event.delivery_error && <small className={styles.error}>{event.delivery_error}</small>}
            </div>)}
          </section>
        </>}

        {tab === 'servers' && <>
          {monitorMode === 'ping' ? <section className={agentGuide.guide}>
            <div className={agentGuide.guideHead}>
              <div><h2>Ping-only monitoring · no agent required</h2><p>Enter a hostname or IP to check whether the server responds to ICMP ping. This reports only up/down availability—not CPU, memory, storage, or process details.</p></div>
              <span className={agentGuide.badge}>ICMP reachability</span>
            </div>
            <p className={agentGuide.guideFoot}>Choose <strong>Host metrics + ping</strong> in the mode field if you also need resource and process metrics; that mode requires the Docker agent on the monitored host.</p>
          </section> : <section className={agentGuide.guide}>
            <div className={agentGuide.guideHead}>
              <div><h2>Host metrics require an agent on each server</h2><p>This mode checks ICMP reachability and reads CPU, RAM, storage, load, swap, and processes from the Docker agent. HTTP/API service checks do not need an agent.</p></div>
              <span className={agentGuide.badge}>Docker · one per host</span>
            </div>
            <div className={agentGuide.steps}>
              <div className={agentGuide.step}><b>01 / PREPARE</b><span>Copy the project to the remote Linux host, or copy the <strong>agent/</strong> deployment files there.</span></div>
              <div className={agentGuide.step}><b>02 / CONFIGURE</b><span>Set a unique 32+ character AGENT_TOKEN in <strong>agent/.env</strong>. Paste that same value into this server form.</span></div>
              <div className={agentGuide.step}><b>03 / RUN</b><span>Build and start the Docker agent. Restrict port 9100 to the control plane or private network.</span></div>
            </div>
            <div className={deployStyles.deployChoice}>
              <div><b>Build on the remote host <em>· available now</em></b><span>Copy/clone this project to the monitored host. From its project root:</span></div>
              <pre>{`cd monitoring_app/agent
cp .env.example .env
# Edit .env: AGENT_TOKEN=$(openssl rand -hex 32)
cd ..
docker build -f agent/Dockerfile -t northstar-agent:local .
docker compose --env-file agent/.env -f agent/docker-compose.yml up -d`}</pre>
            </div>
            <details className={deployStyles.publishDetails}>
              <summary>Already published to Docker Hub?</summary>
              <p>Set AGENT_IMAGE in <strong>agent/.env</strong> to your public image, then run these on the remote host:</p>
              <pre>{`cd monitoring_app/agent
docker compose pull
docker compose up -d`}</pre>
            </details>
            <p className={agentGuide.guideFoot}>After startup, configure Host/IP and endpoint <strong>http://&lt;remote-host&gt;:9100</strong> below. Metrics returned include CPU, memory, storage, load, swap, uptime, and top processes. HTTP service monitors do not use this agent.</p>
          </section>}
          <Form title={editingServerId ? 'Edit monitored server' : 'Add monitored server'} onSubmit={saveServer} submitLabel={editingServerId ? 'Save server changes' : 'Add server +'} onCancel={editingServerId ? cancelEdit : undefined}>
            <input value={serverName} onChange={event => setServerName(event.target.value)} placeholder="Display name, e.g. Production edge" required />
            <input value={serverHost} onChange={event => setServerHost(event.target.value)} placeholder="Host/IP for reachability, e.g. 10.0.0.12" required />
            <select aria-label="Server monitoring mode" value={monitorMode} onChange={event => setMonitorMode(event.target.value as 'ping' | 'agent')}>
              <option value="ping">Ping only — availability (no agent)</option>
              <option value="agent">Host metrics + ping — Docker agent required</option>
            </select>
            <input value={serverIntervalSeconds} onChange={event => setServerIntervalSeconds(event.target.value)} aria-label="Server check interval seconds" placeholder="Check interval seconds" type="number" min="5" required />
            {monitorMode === 'agent' && <>
              <input value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder="Agent URL, e.g. http://10.0.0.12:9100" required />
              <input value={agentToken} onChange={event => setAgentToken(event.target.value)} placeholder={editingServerId && editingServerHasToken ? 'Leave blank to keep the saved agent token' : 'Required: paste the same strong AGENT_TOKEN used by the agent'} type="password" required={!editingServerId || !editingServerHasToken} minLength={32} />
              <input value={processNames} onChange={event => setProcessNames(event.target.value)} placeholder="Processes to watch, comma-separated (optional)" />
              <div className={styles.thresholdGrid}>{Object.entries(thresholds).map(([key, value]) => <input key={key} aria-label={`${key} threshold`} value={value} onChange={event => setThresholds({ ...thresholds, [key]: event.target.value })} placeholder={`${key} threshold`} type="number" min="0" />)}</div>
            </>}
            <small className={styles.help}>{monitorMode === 'ping' ? 'Only ICMP up/down status will be collected. Select agent mode to collect host resources and processes.' : 'The agent provides CPU, RAM, storage, load, swap, uptime, and top processes; the control plane also pings this host.'}</small>
          </Form>
          <TargetList items={dashboard?.servers || []} kind="server" onEdit={editServer} onDelete={id => deleteTarget(`/servers/${id}`, 'server')} />
        </>}

        {tab === 'services' && <>
          <Form title={editingServiceId ? 'Edit service monitor' : 'Add independent HTTP check'} onSubmit={saveService} submitLabel={editingServiceId ? 'Save monitor changes' : 'Add service +'} onCancel={editingServiceId ? cancelEdit : undefined}>
            <input value={serviceName} onChange={event => setServiceName(event.target.value)} placeholder="Service name, e.g. Public API" required />
            <input value={serviceUrl} onChange={event => setServiceUrl(event.target.value)} placeholder="https://example.com/health" type="url" required />
            <div className={styles.thresholdGrid}>
              <input value={expectedStatus} onChange={event => setExpectedStatus(event.target.value)} aria-label="Expected HTTP status" placeholder="Expected status (200)" type="number" min="100" max="599" required />
              <input value={intervalSeconds} onChange={event => setIntervalSeconds(event.target.value)} aria-label="Check interval seconds" placeholder="Interval seconds (60)" type="number" min="15" required />
            </div>
            <small className={styles.help}>No server setup required. The monitor requests this URL directly, records the HTTP status and latency, sends a down reminder on every configured check interval, and sends one recovery alert when it returns up.</small>
          </Form>
          <TargetList items={dashboard?.services || []} kind="service" busy={busy} onCheck={checkService} onEdit={editService} onDelete={id => deleteTarget(`/services/${id}`, 'service monitor')} />
        </>}

        {tab === 'channels' && <>
          <section className={agentGuide.guide}>
            <div className={agentGuide.guideHead}>
              <div>
                <h2>{CHANNEL_GUIDES[channelType].title}</h2>
                <p>{CHANNEL_GUIDES[channelType].intro}</p>
              </div>
              <span className={agentGuide.badge}>{CHANNEL_GUIDES[channelType].badge}</span>
            </div>
            <div className={agentGuide.steps}>
              {CHANNEL_GUIDES[channelType].steps.map(([label, text]) => (
                <div className={agentGuide.step} key={label}><b>{label}</b><span>{text}</span></div>
              ))}
            </div>
            {channelType === 'webhook' && <pre>{`POST application/json
Authorization: Bearer <optional token>

{
  "source": "Northstar Operations",
  "text": "Service down: Public API",
  "sent_at": "2026-10-03T13:00:00+00:00"
}`}</pre>}
            {channelType === 'whatsapp' && <p className={agentGuide.guideFoot}>Utility template body example: <strong>Northstar alert: {`{{1}}`}</strong>. The monitor fills {`{{1}}`} with the alert text. Recipients must opt in and the number must be allowed in your WhatsApp Cloud API setup.</p>}
            <p className={agentGuide.guideFoot}>You can save more than one channel. Every enabled channel receives the same alert. After saving, use <strong>Send test</strong> before relying on it.</p>
          </section>
          <Form title={`Add ${channelTypeLabel(channelType)} notification channel`} onSubmit={saveChannel} submitLabel="Save notification channel">
            <select aria-label="Notification provider" value={channelType} onChange={event => { setChannelType(event.target.value as ChannelType); setBotToken(''); setChatId(''); setChannelEndpoint(''); }}>
              <option value="telegram">Telegram bot</option>
              <option value="webhook">Generic JSON webhook</option>
              <option value="slack">Slack Incoming Webhook</option>
              <option value="whatsapp">WhatsApp Cloud API</option>
            </select>
            <input value={channelName} onChange={event => setChannelName(event.target.value)} placeholder={`Channel name, e.g. ${channelTypeLabel(channelType)}`} required />
            {channelType === 'telegram' && <>
              <input value={botToken} onChange={event => setBotToken(event.target.value)} placeholder="Telegram bot token" type="password" required />
              <input value={chatId} onChange={event => setChatId(event.target.value)} placeholder="Telegram chat/group ID" required />
            </>}
            {channelType === 'webhook' && <>
              <input value={channelEndpoint} onChange={event => setChannelEndpoint(event.target.value)} placeholder="https://example.com/alerts" type="url" required />
              <input value={botToken} onChange={event => setBotToken(event.target.value)} placeholder="Bearer token (optional)" type="password" />
            </>}
            {channelType === 'slack' && <>
              <input value={channelEndpoint} onChange={event => setChannelEndpoint(event.target.value)} placeholder="https://hooks.slack.com/services/..." type="url" required />
            </>}
            {channelType === 'whatsapp' && <>
              <input value={botToken} onChange={event => setBotToken(event.target.value)} placeholder="Meta WhatsApp Cloud API access token" type="password" required />
              <input value={whatsAppPhoneNumberId} onChange={event => setWhatsAppPhoneNumberId(event.target.value)} placeholder="WhatsApp Phone Number ID" required />
              <input value={chatId} onChange={event => setChatId(event.target.value)} placeholder="Recipient phone, e.g. 15551234567" required />
              <div className={styles.thresholdGrid}>
                <input value={whatsAppTemplate} onChange={event => setWhatsAppTemplate(event.target.value)} placeholder="Approved template name" required />
                <input value={whatsAppLanguage} onChange={event => setWhatsAppLanguage(event.target.value)} placeholder="Template language, e.g. en_US" required />
              </div>
            </>}
          </Form>
          <section className={styles.list}>
            {channels.length === 0 ? <p className={styles.empty}>No notification channels configured yet.</p> : channels.map(channel => <div className={styles.row} key={channel.id}>
              <b>{channel.name}</b><small>{channelTypeLabel(channel.type)} · {channel.type === 'webhook' || channel.type === 'slack' ? (channel.endpoint === 'configured' ? 'endpoint saved' : 'endpoint missing') : (channel.token === 'configured' ? 'credentials saved' : 'credentials missing')}</small>
              <button className={controls.secondary} disabled={busy === channel.id} onClick={() => void testChannel(channel)}>{busy === channel.id ? 'Sending…' : 'Send test'}</button>
              <button className={controls.danger} onClick={() => void deleteTarget(`/channels/${channel.id}`, 'notification channel')}>Remove</button>
            </div>)}
          </section>
        </>}
      </section>
    </main>
  );
}

const CHANNEL_GUIDES: Record<ChannelType, { badge: string; title: string; intro: string; steps: [string, string][] }> = {
  telegram: {
    badge: 'Bot API',
    title: 'Set up Telegram',
    intro: 'Alerts are posted by a Telegram bot to a person, group, or channel you choose.',
    steps: [
      ['01 / CREATE BOT', 'In Telegram, open @BotFather, send /newbot, and copy the bot token into the form.'],
      ['02 / ADD BOT', 'Message the bot, or add it to a group/channel and grant it permission to post.'],
      ['03 / CHAT ID', 'Call https://api.telegram.org/bot<token>/getUpdates and copy chat.id. Group IDs are usually negative.'],
    ],
  },
  webhook: {
    badge: 'HTTP POST',
    title: 'Set up a generic webhook',
    intro: 'Northstar POSTs JSON to any HTTPS (or HTTP) receiver you control — PagerDuty, n8n, custom APIs, and similar tools.',
    steps: [
      ['01 / RECEIVER', 'Create an endpoint that accepts POST with Content-Type application/json.'],
      ['02 / AUTH', 'Optionally require a Bearer token. Paste that same secret here; it is sent as Authorization.'],
      ['03 / URL', 'Paste the full receiver URL. It must start with http:// or https://.'],
    ],
  },
  slack: {
    badge: 'Incoming Webhook',
    title: 'Set up Slack',
    intro: 'Alerts appear in a Slack channel through an Incoming Webhook URL. Keep that URL secret.',
    steps: [
      ['01 / APP', 'Open api.slack.com/apps, create or select an app in the workspace that should receive alerts.'],
      ['02 / WEBHOOKS', 'Open Incoming Webhooks, turn the feature on, then Add New Webhook to Workspace.'],
      ['03 / CHANNEL', 'Pick the Slack channel, authorize, and paste the https://hooks.slack.com/services/... URL here.'],
    ],
  },
  whatsapp: {
    badge: 'Cloud API',
    title: 'Set up WhatsApp Cloud API',
    intro: 'Proactive alerts use Meta WhatsApp Cloud API with an approved Utility template. Consumer WhatsApp cannot be used as a bot token.',
    steps: [
      ['01 / APP', 'In Meta Developers, create an app and add the WhatsApp product. Copy the access token and Phone Number ID.'],
      ['02 / TEMPLATE', 'Create a Utility template with one body variable {{1}} and wait until Meta marks it Approved.'],
      ['03 / RECIPIENT', 'Enter the destination in international digits (country code + number, no spaces). Test numbers must be allowed in the WhatsApp app settings.'],
    ],
  },
};

function Form({ title, children, onSubmit, submitLabel, onCancel }: { title: string; children: ReactNode; onSubmit: (event: FormEvent) => void; submitLabel?: string; onCancel?: () => void }) {
  return <form className={styles.form} onSubmit={onSubmit}><span className={styles.label}>CONFIGURATION</span><h2>{title}</h2>{children}<div className={controls.formActions}><button className={controls.primary}>{submitLabel || 'Save'}</button>{onCancel && <button type="button" className={controls.secondary} onClick={onCancel}>Cancel editing</button>}</div></form>;
}

function TargetList({ items, kind, busy, onCheck, onEdit, onDelete }: { items: Target[]; kind: 'server' | 'service'; busy?: number | null; onCheck?: (id: number) => void; onEdit: (target: Target) => void; onDelete: (id: number) => void }) {
  if (!items.length) return <section className={`${styles.list} ${targetStyles.targetList}`}><p className={styles.empty}>No {kind === 'server' ? 'servers' : 'service monitors'} configured yet.</p></section>;
  return <section className={`${styles.list} ${targetStyles.targetList}`}>{items.map(item => <article className={targetStyles.targetCard} key={item.id}>
    <div className={targetStyles.cardHeader}>
      <div className={targetStyles.identity}><b>{item.name}</b><span>{kind === 'server' ? `${item.monitor_mode === 'ping' ? 'PING ONLY' : 'HOST METRICS + AGENT'} · ${item.host || 'Host not set'}` : 'HTTP service monitor'}</span></div>
      <span className={`${styles.status} ${styles[item.last_status] || ''}`}>{item.last_status === 'up' ? '●' : '●'} {item.last_status}</span>
    </div>
    {kind === 'service' ? <div className={targetStyles.endpoint} title={item.url}>{item.url}</div> : item.monitor_mode === 'agent' ? <div className={targetStyles.endpoint} title={item.endpoint}>{item.endpoint}</div> : <div className={pingStyles.pingOnly}>◎ <strong>ICMP ping only</strong><span>No agent endpoint configured</span></div>}
    <div className={targetStyles.facts}>
      {kind === 'service' && <span><strong>HTTP</strong> {item.last_http_status ?? '—'} <i>/</i> expected {item.expected_status ?? 200}</span>}
      {kind === 'service' && <span><strong>Latency</strong> {item.last_latency_ms != null ? `${item.last_latency_ms} ms` : '—'}</span>}
      {kind === 'service' && <span><strong>Check interval</strong> every {item.interval_seconds ?? 60}s</span>}
      {kind === 'server' && <span><strong>Check interval</strong> every {item.check_interval_seconds ?? 60}s</span>}
      {kind === 'server' && item.last_metrics?.processes?.length ? <span><strong>Top process</strong> {item.last_metrics.processes[0].name} · {item.last_metrics.processes[0].cpu}% CPU</span> : null}
      {item.last_checked_at && <span><strong>Last check</strong> {new Date(item.last_checked_at).toLocaleString()}</span>}
    </div>
    {item.last_error && <div className={targetStyles.targetError}>{item.last_error}</div>}
    <div className={targetStyles.actions}>
      {kind === 'service' && <button className={targetStyles.secondaryAction} disabled={busy === item.id} onClick={() => onCheck?.(item.id)}>{busy === item.id ? 'Checking…' : 'Check now'}</button>}
      <button className={targetStyles.secondaryAction} onClick={() => onEdit(item)}>Edit</button>
      <button className={targetStyles.removeAction} onClick={() => onDelete(item.id)}>Remove</button>
    </div>
  </article>)}</section>;
}
