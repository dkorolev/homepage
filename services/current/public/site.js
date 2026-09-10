const board = document.querySelector('#color-board');
let protocol = '2025-11-25';
let nextId = 0;
let initialized = false;

function renderColors(latest) {
  board.replaceChildren();
  if (!latest.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'The board is fresh. Be the first to add a name.';
    board.append(empty);
  }
  for (const entry of latest) {
    const item = document.createElement('div');
    item.className = 'color-item';
    const swatch = document.createElement('span');
    swatch.className = 'swatch';
    if (/^#[0-9a-f]{6}$/i.test(entry.hex)) swatch.style.backgroundColor = entry.hex;
    const details = document.createElement('div');
    const name = document.createElement('strong');
    name.textContent = entry.name;
    const color = document.createElement('small');
    color.textContent = `${entry.color} / ${entry.hex}`;
    details.append(name, color);
    item.append(swatch, details);
    board.append(item);
  }
}

async function refreshColors() {
  const response = await fetch('/api/colors');
  if (!response.ok) throw new Error('Could not load the board.');
  renderColors((await response.json()).latest);
}

async function rpc(method, params, notification = false) {
  const response = await fetch('/mcp', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': protocol },
    body: JSON.stringify({ jsonrpc: '2.0', ...(notification ? {} : { id: ++nextId }), method, params }),
  });
  if (!response.ok) throw new Error(response.status === 429 ? 'A few too many requests. Try again in a minute.' : 'The color tool could not complete this request.');
  if (notification) return;
  const message = await response.json();
  if (message.error) throw new Error(message.error.message);
  return message.result;
}

document.querySelector('#color-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button');
  const status = document.querySelector('#color-status');
  button.disabled = true;
  try {
    if (!initialized) {
      const result = await rpc('initialize', { protocolVersion: protocol, capabilities: {}, clientInfo: { name: 'current-browser-demo', version: '1.0.0' } });
      protocol = result.protocolVersion;
      await rpc('notifications/initialized', {}, true);
      initialized = true;
    }
    const result = await rpc('tools/call', { name: 'assign_color', arguments: { name: document.querySelector('#color-name').value } });
    if (result.isError) throw new Error('Use a printable name between 1 and 60 characters.');
    const value = result.structuredContent;
    renderColors(value.latest);
    status.textContent = `${value.assignment.name}, your color is ${value.assignment.color}. You’re on the public board.`;
  } catch (error) { status.textContent = error.message; }
  finally { button.disabled = false; }
});

const endpoint = `${location.origin}/mcp`;
document.querySelector('#mcp-url').value = endpoint;
const agentPrompt = document.querySelector('#mcp-agent-prompt');
agentPrompt.value = agentPrompt.value.replace('https://current.ai/mcp', endpoint);
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    const status = document.querySelector('#mcp-copy-status');
    try {
      await navigator.clipboard.writeText(field.value);
      status.textContent = button.dataset.copied;
    } catch {
      field.focus();
      field.select();
      status.textContent = 'Text selected. Use your device’s Copy action, or press Ctrl+C / ⌘C.';
    }
  });
}

fetch('/api/session').then(response => response.json()).then(session => {
  if (session.account) {
    document.querySelector('#current-id').textContent = session.account.current_id;
    document.querySelector('#account-link').textContent = `Current ${session.account.current_id}`;
  }
  document.querySelector('#dima-link').href = session.dima_url;
  document.querySelector('#enterprise-link').hidden = !session.enterprise;
  if (!session.google || !session.github) document.querySelector('#provider-status').textContent = 'Some sign-in providers still need credentials. See the configuration guide.';
}).catch(() => {});

refreshColors().catch(() => { board.textContent = 'The board is temporarily unavailable. Please reload.'; });
setInterval(() => { if (!document.hidden) refreshColors().catch(() => {}); }, 8000);
