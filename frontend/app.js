// Owner: Brandon Lyubarsky (Application / Dashboard)
let currentFilter = 'ALL';
let allEventsCache = [];
let eventSource = null;

document.addEventListener('DOMContentLoaded', async () => {
  await fetchStatus();
  await fetchEvents();
  connectSSE();
  setInterval(fetchStatus, 3000);
});

function connectSSE() {
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/api/stream');
  eventSource.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === 'EVENT' && msg.data) handleIncomingEvent(msg.data);
    } catch {}
  };
  eventSource.onerror = () => {
    eventSource.close();
    setTimeout(connectSSE, 3000);
  };
}

function handleIncomingEvent(evt) {
  allEventsCache.unshift(evt);
  if (allEventsCache.length > 300) allEventsCache.pop();

  const id = evt.event_type === 'ALLOWED' ? 'stat-allowed' : (evt.event_type === 'BLOCKED' ? 'stat-blocked' : 'stat-alerts');
  const el = document.getElementById(id);
  if (el) el.textContent = (parseInt(el.textContent) || 0) + 1;
  updateTotalCount();

  if (currentFilter === 'ALL' || evt.event_type === currentFilter) {
    const tbody = document.getElementById('event-table-body');
    const emptyRow = tbody.querySelector('.table-empty');
    if (emptyRow) tbody.innerHTML = '';
    tbody.insertAdjacentHTML('afterbegin', buildEventRowHtml(evt));
    if (tbody.children.length > 100) tbody.lastElementChild.remove();
  }
}

function updateTotalCount() {
  const allowed = parseInt(document.getElementById('stat-allowed')?.textContent) || 0;
  const blocked = parseInt(document.getElementById('stat-blocked')?.textContent) || 0;
  const alerts = parseInt(document.getElementById('stat-alerts')?.textContent) || 0;
  const allEl = document.getElementById('stat-all');
  if (allEl) allEl.textContent = allowed + blocked + alerts;
}

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data.gateway?.counts) {
      document.getElementById('stat-allowed').textContent = data.gateway.counts.allowed || 0;
      document.getElementById('stat-blocked').textContent = data.gateway.counts.blocked || 0;
      document.getElementById('stat-alerts').textContent = data.gateway.counts.alerts || 0;
      updateTotalCount();
    }
    if (data.device) {
      const dev = data.device;
      document.getElementById('device-led-indicator').textContent = dev.led_state === 1 ? 'ON' : 'OFF';
      if (dev.temperature !== undefined) document.getElementById('device-temp').textContent = dev.temperature.toFixed(1);
      if (dev.humidity !== undefined) document.getElementById('device-humidity').textContent = dev.humidity.toFixed(1);
    }
  } catch {}
}

async function fetchEvents() {
  try {
    const res = await fetch(`/api/events?limit=80&type=${currentFilter}`);
    const data = await res.json();
    allEventsCache = data.events || [];
    renderEventTable(allEventsCache);
  } catch {}
}

function renderEventTable(events) {
  const tbody = document.getElementById('event-table-body');
  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No events recorded.</td></tr>';
    return;
  }
  tbody.innerHTML = events.map(buildEventRowHtml).join('');
}

function buildEventRowHtml(evt) {
  const badgeClass = evt.event_type === 'BLOCKED' ? 'blocked' : (evt.event_type === 'ALERT' ? 'alert' : 'allowed');
  const time = evt.timestamp ? evt.timestamp.split(' ')[1] || evt.timestamp : '';
  return `<tr>
    <td style="font-family:ui-monospace, monospace; font-size:0.75rem;">${escapeHtml(time)}</td>
    <td><span class="badge-tag ${badgeClass}">${escapeHtml(evt.event_type)}</span></td>
    <td><span class="ip-pair">${escapeHtml(evt.source_ip)} &rarr; ${escapeHtml(evt.dest_ip)}</span></td>
    <td><span class="port-code">:${evt.dest_port} (${escapeHtml(evt.protocol)})</span></td>
    <td><div class="rule-title">${escapeHtml(evt.rule_triggered)}</div><div class="rule-detail">${escapeHtml(evt.details || '')}</div></td>
  </tr>`;
}

function setFilter(filter) {
  currentFilter = filter;
  document.querySelectorAll('.filter-tab').forEach(b => b.classList.toggle('active', b.getAttribute('data-filter') === filter));
  renderEventTable(filter === 'ALL' ? allEventsCache : allEventsCache.filter(e => e.event_type === filter));
}

async function runScenario(scenarioKey) {
  try {
    await fetch('/api/attack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: scenarioKey }) });
    await fetchStatus();
  } catch {}
}

async function runCommand(action) {
  try {
    await fetch('/api/command', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }) });
    await fetchStatus();
  } catch {}
}

async function clearEventLogs() {
  try {
    await fetch('/api/reset', { method: 'POST' });
    allEventsCache = [];
    renderEventTable([]);
    document.getElementById('stat-allowed').textContent = '0';
    document.getElementById('stat-blocked').textContent = '0';
    document.getElementById('stat-alerts').textContent = '0';
    updateTotalCount();
  } catch {}
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
