const token = document.querySelector('meta[name="safesync-token"]').content;
let snapshot = null;
let busy = false;

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
})[character]);
const formatSize = (size) => size == null ? '-' : size < 1024 ? `${size} B` : `${(size / 1024).toFixed(1)} KB`;
const shortHash = (side) => side ? side.sha256 : '-';
const time = (nanoseconds) => new Date(Number(BigInt(nanoseconds || 0) / 1000000n)).toLocaleTimeString();

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-SafeSync-Token': token, ...(options.headers || {}) }
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}

function toast(message, error = false) {
  const node = $('toast');
  node.textContent = message;
  node.className = `toast show${error ? ' error' : ''}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.className = 'toast', 3200);
}

function render(data) {
  snapshot = data;
  $('connection').textContent = data.watch.error ? `Stopped: ${data.watch.error}` : data.watch.running ? 'Watching' : 'Ready';
  $('left-root').textContent = data.roots.left;
  $('right-root').textContent = data.roots.right;
  $('watch-button').textContent = data.watch.running ? 'Stop watch' : 'Start watch';
  $('watch-button').className = `button ${data.watch.running ? 'danger' : 'primary'}`;
  $('updated').textContent = new Date().toLocaleTimeString();
  const counts = data.files.reduce((result, file) => ({ ...result, [file.status]: (result[file.status] || 0) + 1 }), {});
  $('count-sync').textContent = counts.in_sync || 0;
  $('count-active').textContent = (counts.mid_operation || 0) + (counts.left_only || 0) + (counts.right_only || 0);
  $('count-conflict').textContent = data.conflicts.length;
  $('count-total').textContent = data.files.length;
  $('conflict-badge').textContent = data.conflicts.length;
  renderFiles();
  renderConflicts(data.conflicts);
  renderEvents('watch-events', data.watch.events, (event) => `${event.side} ${event.kind} ${event.source}${event.destination ? ` -> ${event.destination}` : ''}`);
  renderEvents('operation-events', data.operation_log, (event) => `${event.event} ${event.kind || event.choice || ''} ${event.destination || event.conflict_id || ''}`);
  $('journal-json').textContent = JSON.stringify(data.journal, null, 2);
  $('state-json').textContent = JSON.stringify(data.state, null, 2);
}

function renderFiles() {
  if (!snapshot) return;
  const query = $('file-search').value.toLowerCase();
  const filter = $('status-filter').value;
  const files = snapshot.files.filter((file) => file.path.toLowerCase().includes(query) && (filter === 'all' || file.status === filter));
  $('file-rows').innerHTML = files.map((file) => `
    <tr>
      <td class="path-cell">${escapeHtml(file.path)}</td>
      <td><span class="status ${escapeHtml(file.status)}">${escapeHtml(file.status.replace('_', ' '))}</span></td>
      <td><span class="size">${formatSize(file.left?.size)}</span><span class="hash" title="${shortHash(file.left)}">${shortHash(file.left)}</span></td>
      <td><span class="size">${formatSize(file.right?.size)}</span><span class="hash" title="${shortHash(file.right)}">${shortHash(file.right)}</span></td>
    </tr>`).join('');
}

function renderConflicts(conflicts) {
  $('conflict-empty').hidden = conflicts.length > 0;
  $('conflict-list').innerHTML = conflicts.map((conflict) => `
    <article class="conflict-item">
      <div class="conflict-head"><h2>${escapeHtml(conflict.display_path)}</h2><span class="kind">${escapeHtml(conflict.kind)}</span></div>
      <div class="versions">${conflict.versions.map((version) => `
        <div class="version"><strong>${escapeHtml(version.side)}</strong><span class="size"> · ${formatSize(version.size)}</span>
        <code title="${escapeHtml(version.content_hash)}">${escapeHtml(version.content_hash)}</code>
        <code>${escapeHtml(version.preferred_path || version.stored_relative)}</code></div>`).join('')}</div>
      <div class="resolve-actions">
        <button class="button secondary resolve" data-id="${conflict.conflict_id}" data-choice="left" ${conflict.resolvable ? '' : 'disabled'}>Use left</button>
        <button class="button secondary resolve" data-id="${conflict.conflict_id}" data-choice="right" ${conflict.resolvable ? '' : 'disabled'}>Use right</button>
        <button class="button primary resolve" data-id="${conflict.conflict_id}" data-choice="keep_both" ${conflict.resolvable ? '' : 'disabled'}>Keep both</button>
      </div>
    </article>`).join('');
}

function renderEvents(id, events, label) {
  $(id).innerHTML = [...events].reverse().map((event) => `<li><time>${time(event.timestamp_ns)}</time>${escapeHtml(label(event))}</li>`).join('');
}

async function mutate(path, body = {}) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach((button) => button.disabled = true);
  try {
    const value = await request(path, { method: 'POST', body: JSON.stringify(body) });
    render(value.status || value);
    toast('Operation completed');
  } catch (error) {
    toast(error.message, true);
    await refresh();
  } finally {
    busy = false;
    document.querySelectorAll('button').forEach((button) => button.disabled = false);
  }
}

async function refresh() {
  if (busy) return;
  try {
    render(await request('/api/status'));
  } catch (error) {
    $('connection').textContent = 'Disconnected';
  }
}

document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach((node) => node.classList.toggle('active', node === tab));
  document.querySelectorAll('.view').forEach((view) => view.classList.toggle('active', view.id === `view-${tab.dataset.tab}`));
}));
$('file-search').addEventListener('input', renderFiles);
$('status-filter').addEventListener('change', renderFiles);
$('sync-button').addEventListener('click', () => mutate('/api/sync'));
$('watch-button').addEventListener('click', () => mutate(snapshot?.watch.running ? '/api/watch/stop' : '/api/watch/start'));
$('conflict-list').addEventListener('click', (event) => {
  const button = event.target.closest('.resolve');
  if (button) mutate(`/api/conflicts/${button.dataset.id}/resolve`, { choice: button.dataset.choice });
});

refresh();
setInterval(refresh, 700);
