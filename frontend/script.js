const form = document.querySelector('#chat-form');
const promptInput = document.querySelector('#prompt');
const chatLog = document.querySelector('#chat-log');
const loader = document.querySelector('#loader');
const sendButton = document.querySelector('#send-button');
const errorBox = document.querySelector('#form-error');
let selectedMode = 'protected';

function escapeText(value) {
  const span = document.createElement('span');
  span.textContent = value == null ? '' : String(value);
  return span.innerHTML;
}

function appendMessage(role, text) {
  const empty = chatLog.querySelector('.empty-state');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = `message ${role}`;
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;
  row.appendChild(bubble);
  chatLog.appendChild(row);
  chatLog.scrollTop = chatLog.scrollHeight;
}

function seconds(value) {
  return value == null ? '—' : `${Number(value).toFixed(2)} s`;
}

function setDecision(data) {
  const decision = data.security_decision || 'AWAITING';
  const decisionKey = decision.toLowerCase();
  const badge = document.querySelector('#decision-badge');
  badge.textContent = decision;
  badge.className = `decision-badge ${decisionKey === 'allow' || decisionKey === 'baseline' ? 'allow' : decisionKey}`;
  const ring = document.querySelector('#score-ring');
  ring.className = 'score-ring ' + (data.risk_level ? data.risk_level.toLowerCase() : 'neutral');
  if (ring.className.includes('moderate')) ring.className = 'score-ring flag';
  if (ring.className.includes('low')) ring.className = 'score-ring allow';
  if (ring.className.includes('critical') || ring.className.includes('high')) ring.className = 'score-ring block';
  document.querySelector('#risk-score').textContent = data.risk_score ?? '—';
  document.querySelector('#risk-level').textContent = data.risk_level || '—';
  document.querySelector('#forwarded').textContent = data.ollama_invoked ? 'Yes' : 'No';
  document.querySelector('#threats').textContent = data.threat_categories?.length ? data.threat_categories.join(', ') : 'None detected';
  document.querySelector('#explanation').textContent = data.explanation || 'No explanation available.';
  document.querySelector('#model-latency').textContent = seconds(data.model_latency_seconds);
  document.querySelector('#security-latency').textContent = seconds(data.security_latency_seconds);
  document.querySelector('#total-latency').textContent = seconds(data.total_latency_seconds);
}

async function loadHealth() {
  try {
    const response = await fetch('/api/health');
    const data = await response.json();
    const status = document.querySelector('#system-status');
    status.textContent = data.ollama_connectivity && data.model_available ? 'Online · Model ready' : 'Degraded · Ollama unavailable';
  } catch {
    document.querySelector('#system-status').textContent = 'Backend unavailable';
  }
}

async function loadEvents() {
  try {
    const response = await fetch('/api/security/events?limit=8');
    if (!response.ok) return;
    const events = await response.json();
    const body = document.querySelector('#events-body');
    if (!events.length) { body.innerHTML = '<tr><td colspan="5" class="muted">No security events recorded.</td></tr>'; return; }
    body.innerHTML = events.map(event => `<tr><td>${escapeText(event.timestamp_utc || '—')}</td><td>${escapeText(event.event_id)}</td><td>${escapeText(event.risk_score ?? '—')}</td><td>${escapeText(event.security_decision || '—')}</td><td>${escapeText(event.threat_categories?.join(', ') || 'None')}</td></tr>`).join('');
  } catch { /* The dashboard remains usable if audit data is temporarily unavailable. */ }
}

for (const button of document.querySelectorAll('.mode-button')) {
  button.addEventListener('click', () => {
    document.querySelectorAll('.mode-button').forEach(item => item.classList.remove('active'));
    button.classList.add('active');
    selectedMode = button.dataset.mode;
  });
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const prompt = promptInput.value.trim();
  errorBox.textContent = '';
  if (!prompt) { errorBox.textContent = 'Enter a prompt before sending.'; return; }
  appendMessage('user', prompt);
  promptInput.value = '';
  loader.classList.remove('hidden');
  sendButton.disabled = true;
  try {
    const response = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({prompt, mode:selectedMode})});
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'The request could not be completed.');
    appendMessage('assistant', data.model_response);
    setDecision(data);
    loadEvents();
  } catch (error) {
    errorBox.textContent = error.message;
  } finally {
    loader.classList.add('hidden');
    sendButton.disabled = false;
  }
});

document.querySelector('#clear-chat').addEventListener('click', () => {
  chatLog.innerHTML = '<div class="empty-state"><div>⌁</div><strong>Ready for analysis</strong><span>Enter a prompt to inspect its security profile and model response.</span></div>';
});

loadHealth();
loadEvents();
