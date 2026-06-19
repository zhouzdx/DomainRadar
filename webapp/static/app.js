// DomainRadar web UI - SSE driven scan client.
'use strict';

const $ = (id) => document.getElementById(id);

const state = {
  evtSource: null,
  jobId: null,
  domain: null,
  subdomains: [],   // [{host, ips: []}]
  resolving: true,
};

const els = {
  form:         $('scanForm'),
  input:        $('domainInput'),
  btn:          $('scanBtn'),
  optBrute:     $('optBruteforce'),
  optResolve:   $('optResolve'),
  errorBox:     $('errorBox'),
  sourcesPanel: $('sourcesPanel'),
  sourcesGrid:  $('sourcesGrid'),
  sourcesMeta:  $('sourcesMeta'),
  summaryPanel: $('summaryPanel'),
  statDomain:   $('statDomain'),
  statTotal:    $('statTotal'),
  statAlive:    $('statAlive'),
  statElapsed:  $('statElapsed'),
  dlTxt:        $('dlTxt'),
  dlAlive:      $('dlAlive'),
  dlJson:       $('dlJson'),
  resultsPanel: $('resultsPanel'),
  resultsBody:  $('resultsBody'),
  filterInput:  $('filterInput'),
  filterAlive:  $('filterAlive'),
  filterMeta:   $('filterMeta'),
  emptyState:   $('emptyState'),
};

// ---------- Helpers ----------
function showError(msg) {
  els.errorBox.textContent = msg;
  els.errorBox.classList.remove('hidden');
}
function clearError() {
  els.errorBox.classList.add('hidden');
  els.errorBox.textContent = '';
}

function setLoading(loading) {
  els.btn.disabled = loading;
  els.btn.classList.toggle('loading', loading);
  els.btn.querySelector('.btn-label').textContent = loading ? '扫描中…' : '开始扫描';
}

function resetUI() {
  clearError();
  els.sourcesPanel.classList.add('hidden');
  els.summaryPanel.classList.add('hidden');
  els.resultsPanel.classList.add('hidden');
  els.sourcesGrid.innerHTML = '';
  els.resultsBody.innerHTML = '';
  state.subdomains = [];
}

function makeSourceCard(name) {
  const card = document.createElement('div');
  card.className = 'source-card querying';
  card.dataset.source = name;
  card.innerHTML = `
    <div class="source-name"><span class="dot"></span>${escapeHtml(name)}</div>
    <div class="source-count">…</div>
    <div class="source-status">查询中</div>
  `;
  return card;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// ---------- SSE event handlers ----------
function onStart(data) {
  state.jobId = data.job_id;
  state.domain = data.domain;
  state.resolving = !!data.resolve;

  els.sourcesPanel.classList.remove('hidden');
  els.sourcesMeta.textContent = `${data.sources.length} 个源 · ${state.resolving ? '解析开启' : '不解析'}`;
  els.sourcesGrid.innerHTML = '';
  for (const name of data.sources) {
    els.sourcesGrid.appendChild(makeSourceCard(name));
  }
}

function onSourceStart(data) {
  // Card is already created in onStart - mark as querying.
  const card = els.sourcesGrid.querySelector(`[data-source="${CSS.escape(data.source)}"]`);
  if (card) card.classList.add('querying');
}

function onSourceDone(data) {
  const card = els.sourcesGrid.querySelector(`[data-source="${CSS.escape(data.source)}"]`);
  if (!card) return;
  card.classList.remove('querying');
  card.classList.add(data.count > 0 ? 'done' : 'empty');
  card.querySelector('.source-count').textContent = data.count;
  card.querySelector('.source-status').textContent = data.count > 0 ? '完成' : '无数据';
}

function onResolveStart(data) {
  // Append a virtual card for the resolve phase.
  const card = document.createElement('div');
  card.className = 'source-card querying';
  card.dataset.source = '__resolve__';
  card.innerHTML = `
    <div class="source-name"><span class="dot"></span>DNS 解析</div>
    <div class="source-count">${data.count}</div>
    <div class="source-status">解析中…</div>
  `;
  els.sourcesGrid.appendChild(card);
}

function onResolveDone(data) {
  const card = els.sourcesGrid.querySelector('[data-source="__resolve__"]');
  if (!card) return;
  card.classList.remove('querying');
  card.classList.add('done');
  card.querySelector('.source-status').textContent = `${data.alive} 个存活`;
}

function onComplete(data) {
  // Summary
  els.summaryPanel.classList.remove('hidden');
  els.statDomain.textContent  = data.domain;
  els.statTotal.textContent   = data.total;
  els.statAlive.textContent   = data.alive;
  els.statElapsed.textContent = `${data.elapsed}s`;

  els.dlTxt.href   = `/api/result/${data.job_id}/download/txt`;
  els.dlAlive.href = `/api/result/${data.job_id}/download/alive`;
  els.dlJson.href  = `/api/result/${data.job_id}/download/json`;

  // Build subdomain list
  state.subdomains = data.subdomains.map((host) => ({
    host,
    ips: (data.resolved && data.resolved[host]) || [],
  }));

  els.resultsPanel.classList.remove('hidden');
  renderTable();
}

function onError(data) {
  showError(`扫描错误: ${data.message || '未知错误'}`);
}

// ---------- Table rendering ----------
function renderTable() {
  const filter = els.filterInput.value.trim().toLowerCase();
  const aliveOnly = els.filterAlive.checked;

  const rows = state.subdomains.filter((s) => {
    if (filter && !s.host.toLowerCase().includes(filter)) return false;
    if (aliveOnly && s.ips.length === 0) return false;
    return true;
  });

  els.filterMeta.textContent = `显示 ${rows.length} / ${state.subdomains.length}`;

  if (rows.length === 0) {
    els.resultsBody.innerHTML = '';
    els.emptyState.classList.remove('hidden');
    return;
  }
  els.emptyState.classList.add('hidden');

  const frag = document.createDocumentFragment();
  rows.forEach((row, idx) => {
    const tr = document.createElement('tr');
    let badge;
    if (!state.resolving) {
      badge = '<span class="badge unknown">未解析</span>';
    } else if (row.ips.length > 0) {
      badge = '<span class="badge alive">ALIVE</span>';
    } else {
      badge = '<span class="badge dead">无记录</span>';
    }
    tr.innerHTML = `
      <td class="col-idx">${idx + 1}</td>
      <td class="col-host">${escapeHtml(row.host)}</td>
      <td class="col-ips">${row.ips.length ? escapeHtml(row.ips.join(', ')) : '—'}</td>
      <td class="col-status">${badge}</td>
    `;
    frag.appendChild(tr);
  });
  els.resultsBody.innerHTML = '';
  els.resultsBody.appendChild(frag);
}

// ---------- Form submit ----------
els.form.addEventListener('submit', (e) => {
  e.preventDefault();

  const domain = els.input.value.trim().toLowerCase();
  if (!domain || !domain.includes('.')) {
    showError('请输入有效的域名（例如 example.com）');
    return;
  }

  // Cancel any ongoing scan
  if (state.evtSource) {
    state.evtSource.close();
    state.evtSource = null;
  }

  resetUI();
  setLoading(true);

  const params = new URLSearchParams({
    domain,
    bruteforce: els.optBrute.checked ? '1' : '0',
    resolve:    els.optResolve.checked ? '1' : '0',
  });
  const es = new EventSource(`/api/scan?${params.toString()}`);
  state.evtSource = es;

  es.addEventListener('start',         (e) => onStart(JSON.parse(e.data)));
  es.addEventListener('source_start',  (e) => onSourceStart(JSON.parse(e.data)));
  es.addEventListener('source_done',   (e) => onSourceDone(JSON.parse(e.data)));
  es.addEventListener('resolve_start', (e) => onResolveStart(JSON.parse(e.data)));
  es.addEventListener('resolve_done',  (e) => onResolveDone(JSON.parse(e.data)));
  es.addEventListener('error', (e) => {
    // Could be a real server-sent 'error' event, or a connection drop.
    if (e.data) {
      try { onError(JSON.parse(e.data)); } catch (_) { /* ignore */ }
    }
  });
  es.addEventListener('complete', (e) => {
    onComplete(JSON.parse(e.data));
    es.close();
    state.evtSource = null;
    setLoading(false);
  });

  // Native EventSource onerror fires on disconnect.
  es.onerror = () => {
    if (state.evtSource && state.evtSource.readyState === EventSource.CLOSED) {
      setLoading(false);
      state.evtSource = null;
    }
  };
});

els.filterInput.addEventListener('input',  renderTable);
els.filterAlive.addEventListener('change', renderTable);

// Pre-fill from query string for quick sharing: /?domain=example.com
(function bootstrap() {
  const q = new URLSearchParams(location.search);
  const d = q.get('domain');
  if (d) {
    els.input.value = d;
  }
})();
