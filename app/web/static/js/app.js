/* AI Code Reviewer dashboard.
 * All text from reviews (code, titles, AI explanations) is inserted with textContent,
 * never innerHTML, so a reviewed repository can't inject script into this page.
 * The only innerHTML use is highlight.js output, which escapes its input. */
(() => {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const STAGES = [
    { key: 'prepare', label: 'Find changes', match: ['queued', 'clone', 'diff'] },
    { key: 'review', label: 'AI review', match: ['review'] },
    { key: 'process', label: 'Merge results', match: ['process'] },
    { key: 'summary', label: 'Summary', match: ['summary', 'done', 'end'] },
  ];
  const CATEGORY_LABEL = {
    bug: 'Bug', security: 'Security', performance: 'Performance', reliability: 'Reliability',
    maintainability: 'Maintainability', testing: 'Testing', style: 'Style',
  };
  const HLJS_LANG = { python: 'python', javascript: 'javascript', typescript: 'typescript', java: 'java', csharp: 'csharp',
    go: 'go', ruby: 'ruby', php: 'php', rust: 'rust', c: 'c', cpp: 'cpp', kotlin: 'kotlin', swift: 'swift', scala: 'scala',
    yaml: 'yaml', json: 'json', xml: 'xml' };
  const VERDICT_DOT = { FAIL: 'dot dot-fail', WARN: 'dot dot-warn', PASS: 'dot dot-pass' };

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else if (key === 'style' && typeof value === 'object') Object.assign(node.style, value);
        else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2), value);
        else if (key === 'dataset') Object.assign(node.dataset, value);
        else node.setAttribute(key, value === true ? '' : value);
      }
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name, cls) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    if (cls) svg.setAttribute('class', cls);
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); return node; };
  const show = (node, on = true) => { node.hidden = !on; };
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const isHidden = (f) => Boolean(f.suppressed);
  const sevLabel = (s) => (s === 'CRITICAL' ? 'Crit' : s.charAt(0) + s.slice(1).toLowerCase());
  const lineRange = (f) => (f.end_line && f.end_line !== f.line ? `${f.line}-${f.end_line}` : `${f.line}`);

  function timeAgo(iso) {
    if (!iso) return '';
    const secs = (Date.now() - new Date(iso).getTime()) / 1000;
    if (secs < 60) return 'just now';
    if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
    if (secs < 86400) return `${Math.round(secs / 3600)} h ago`;
    return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }

  async function api(method, url, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const res = await fetch(url, opts);
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    if (!res.ok) {
      let msg = `Request failed (${res.status})`;
      if (data && data.detail) {
        msg = Array.isArray(data.detail) ? data.detail.map((d) => d.msg.replace(/^Value error, /, '')).join('; ') : data.detail;
      }
      throw new Error(msg);
    }
    return data;
  }

  function toast(message, type) {
    const node = el('div', { class: `toast ${type || ''}`, role: 'status', text: message });
    $('#toasts').append(node);
    setTimeout(() => node.remove(), type === 'error' ? 8000 : 3500);
  }

  // ------------------------------------------------------------------ state
  const state = {
    projects: [], project: null, scan: null, result: null, selected: null,
    filters: { sev: new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']), cat: '', q: '', fixOnly: false, showHidden: false, file: '' },
    openFiles: new Set(), stream: null, pollTimer: null, suppressTarget: null, ai: null,
  };

  // ------------------------------------------------------------------ theme
  function currentTheme() {
    const set = document.documentElement.getAttribute('data-theme');
    if (set) return set;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme() {
    const dark = currentTheme() === 'dark';
    $('#hljs-light').disabled = dark;
    $('#hljs-dark').disabled = !dark;
    const btn = $('#themeBtn');
    clear(btn).append(icon(dark ? 'sun' : 'moon'));
    btn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
  }

  $('#themeBtn').addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('cr-theme', next); } catch (e) { /* storage unavailable */ }
    applyTheme();
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);

  // ------------------------------------------------------------------ sidebar
  function openSidebar(on) { $('#sidebar').classList.toggle('open', on); show($('#scrim'), on); }
  $('#openSidebar').addEventListener('click', () => openSidebar(true));
  $('#closeSidebar').addEventListener('click', () => openSidebar(false));
  $('#scrim').addEventListener('click', () => openSidebar(false));

  async function loadAiStatus() {
    const box = clear($('#aiStatus'));
    try {
      state.ai = await api('GET', '/api/ai');
    } catch (e) { return; }
    const ok = state.ai.available;
    box.append(el('span', { class: `dot ${ok ? 'dot-pass' : 'dot-fail'}` }),
      el('span', { text: ok ? `AI: ${state.ai.provider} / ${state.ai.model}` : `AI not set up: ${state.ai.reason}` }));
    box.title = ok ? '' : state.ai.reason;
  }

  async function loadProjects() {
    try { state.projects = await api('GET', '/api/projects'); } catch (e) { toast(e.message, 'error'); return; }
    renderProjects();
  }

  function renderProjects() {
    const list = clear($('#projectList'));
    if (!state.projects.length) {
      list.append(el('div', { class: 'muted small', style: { padding: '6px' }, text: 'No projects yet.' }));
      return;
    }
    for (const p of state.projects) {
      const active = state.project && state.project.id === p.id;
      list.append(el('button', {
        class: `project${active ? ' active' : ''}`, 'aria-current': active ? 'page' : null, title: p.path_or_url,
        onclick: () => { selectProject(p.id); openSidebar(false); },
      },
      el('span', { class: p.running_scan ? 'dot dot-running' : (VERDICT_DOT[p.last_verdict] || 'dot dot-none') }),
      el('span', { style: { minWidth: 0 } },
        el('div', { class: 'project-name', text: p.name }),
        el('div', { class: 'project-sub', text: `${p.base_ref ? `vs ${p.base_ref}` : 'whole project'}${p.last_scan ? ` · ${timeAgo(p.last_scan)}` : ''}` }))));
    }
  }

  // ------------------------------------------------------------------ project selection
  function renderTopbar() {
    const p = state.project;
    const meta = clear($('#projectMeta'));
    $('#projectName').textContent = p ? p.name : 'Welcome';
    show($('#runGroup'), Boolean(p));
    show($('#settingsBtn'), Boolean(p));
    show($('#pdfBtn'), Boolean(p && state.result));
    if (!p) return;
    meta.append(el('span', { title: p.path_or_url }, icon(p.source_type === 'github' ? 'github' : 'folder'),
      p.path_or_url.length > 60 ? `…${p.path_or_url.slice(-58)}` : p.path_or_url));
    const ref = state.result ? state.result.base_ref : p.base_ref;
    meta.append(el('span', null, icon('branch'), ref ? `changes since ${ref}` : 'whole project'));
    if (state.scan && state.scan.finished_at) meta.append(el('span', null, `reviewed ${timeAgo(state.scan.finished_at)}`));
    $('#scanBaseRef').value = p.base_ref || '';
  }

  function showView(view) {
    show($('#welcome'), view === 'welcome');
    show($('#noScan'), view === 'noscan');
    show($('#progressCard'), view === 'progress');
    show($('#results'), view === 'results');
    show($('#errorCard'), false);
  }

  async function selectProject(id) {
    stopWatching();
    const p = state.projects.find((x) => x.id === id);
    if (!p) return;
    Object.assign(state, { project: p, scan: null, result: null, selected: null });
    state.openFiles.clear();
    resetFilters(false);
    try { history.replaceState(null, '', `#/p/${id}`); } catch (e) { /* ignore */ }
    renderProjects();
    renderTopbar();
    showView('loading');
    await loadLatest();
  }

  function noScan(title, text) {
    $('#noScanTitle').textContent = title;
    $('#noScanText').textContent = text;
    showView('noscan');
  }

  async function loadLatest() {
    const p = state.project;
    let data;
    try { data = await api('GET', `/api/projects/${p.id}/latest`); } catch (e) { toast(e.message, 'error'); return; }
    if (state.project !== p) return;
    const scan = data.scan;
    state.scan = scan;
    state.result = null;
    if (!scan) { renderTopbar(); noScan('No review yet', 'Run the first review to see what the AI finds in your changes.'); return; }
    if (scan.status === 'running') { watchScan(scan.id); return; }
    if (scan.status === 'error') {
      renderTopbar();
      noScan('Review failed', 'Fix the problem below, then run the review again.');
      show($('#errorCard'), true);
      $('#errorText').textContent = scan.error || 'Unknown error';
      return;
    }
    if (!scan.result || !scan.result.files) {
      renderTopbar();
      noScan('Run a new review', 'The last result was made by the older scanner-based version. Run a review to see AI results.');
      return;
    }
    state.result = scan.result;
    renderTopbar();
    showView('results');
    renderResult();
  }

  // ------------------------------------------------------------------ running a review
  async function runScan(options) {
    const p = state.project;
    if (!p) return;
    $('#runBtn').disabled = true;
    try {
      const { scan_id: scanId } = await api('POST', `/api/projects/${p.id}/scans`, options || {});
      p.running_scan = scanId;
      renderProjects();
      watchScan(scanId);
    } catch (e) {
      toast(e.message, 'error');
    } finally {
      $('#runBtn').disabled = false;
    }
  }

  function stopWatching() {
    if (state.stream) { state.stream.close(); state.stream = null; }
    if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
  }

  const progress = { stage: 'prepare', files: new Map(), total: 0 };

  function renderProgress(message) {
    const idx = STAGES.findIndex((s) => s.key === progress.stage);
    const stepper = clear($('#stepper'));
    STAGES.forEach((s, i) => stepper.append(el('li', { class: i < idx ? 'done' : i === idx ? 'active' : '', text: s.label })));
    if (message) $('#progressMsg').textContent = message;
    const done = [...progress.files.values()].filter((f) => f.status === 'reviewed' || f.status === 'error').length;
    if (progress.total) $('#progressTitle').textContent = `Reviewing… ${done} of ${progress.total} files`;
    const grid = clear($('#toolGrid'));
    for (const [path, f] of progress.files) {
      const label = f.status === 'running' ? 'reviewing…' : f.status === 'reviewed' ? plural(f.findings || 0, 'issue') : f.status;
      grid.append(el('div', { class: `tool-pill ${f.status === 'reviewed' ? 'ran' : f.status}`, title: f.message || path },
        el('span', { class: 'dot' }), el('span', { class: 'name', text: path.split('/').pop() }), el('span', { class: 'st', text: label })));
    }
  }

  function handleEvent(event) {
    const stage = STAGES.find((s) => s.match.includes(event.stage));
    if (stage) progress.stage = stage.key;
    if (event.total !== undefined) progress.total = event.total;
    if (event.tool) progress.files.set(event.tool, { status: event.status, message: event.message, findings: event.findings });
    renderProgress(event.message && !event.tool ? event.message : null);
    if (event.stage === 'end') {
      stopWatching();
      if (event.status === 'error') toast(`Review failed: ${event.message || 'see details'}`, 'error');
      else toast('Review finished');
      loadProjects().then(() => {
        if (state.project) state.project = state.projects.find((x) => x.id === state.project.id) || state.project;
        renderProjects();
      });
      loadLatest();
    }
  }

  function watchScan(scanId) {
    stopWatching();
    progress.stage = 'prepare';
    progress.files = new Map();
    progress.total = 0;
    $('#progressTitle').textContent = 'Reviewing…';
    $('#progressMsg').textContent = 'Starting';
    renderProgress();
    showView('progress');
    show($('#pdfBtn'), false);
    if (window.EventSource) {
      const es = new EventSource(`/api/scans/${scanId}/events`);
      state.stream = es;
      es.onmessage = (msg) => { try { handleEvent(JSON.parse(msg.data)); } catch (e) { console.error(e); } };
      es.onerror = () => { if (!state.stream) return; es.close(); state.stream = null; pollScan(scanId); };
    } else {
      pollScan(scanId);
    }
  }

  function pollScan(scanId) {
    state.pollTimer = setInterval(async () => {
      try {
        const scan = await api('GET', `/api/scans/${scanId}`);
        if (scan.status !== 'running') handleEvent({ stage: 'end', status: scan.status, message: scan.error });
      } catch (e) { /* keep trying */ }
    }, 2500);
  }

  $('#runBtn').addEventListener('click', () => runScan({}));
  $('#noScanRun').addEventListener('click', () => runScan({}));
  $('#runOptionsBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    const pop = $('#runOptions');
    pop.hidden = !pop.hidden;
    $('#runOptionsBtn').setAttribute('aria-expanded', String(!pop.hidden));
    if (!pop.hidden) $('#scanBaseRef').focus();
  });
  document.addEventListener('click', (e) => {
    const pop = $('#runOptions');
    if (!pop.hidden && !pop.contains(e.target)) { pop.hidden = true; $('#runOptionsBtn').setAttribute('aria-expanded', 'false'); }
  });
  $('#runWithOptions').addEventListener('click', () => {
    $('#runOptions').hidden = true;
    const ref = $('#scanBaseRef').value.trim();
    runScan(ref ? { base_ref: ref } : { whole_project: true });
  });
  $('#runWholeProject').addEventListener('click', () => {
    $('#runOptions').hidden = true;
    runScan({ whole_project: true });
  });
  $('#pdfBtn').addEventListener('click', () => {
    if (state.scan) window.open(`/api/scans/${state.scan.id}/report.pdf`, '_blank', 'noopener');
  });

  // ------------------------------------------------------------------ results
  function renderResult() {
    const r = state.result;
    if (!r) return;
    renderVerdict(r);
    renderChange(r);
    renderSeverity(r);
    renderSummary(r);
    renderCategoryOptions(r);
    renderFindings();
    renderFiles(r);
    const still = state.selected && r.findings.find((f) => f.fingerprint === state.selected);
    if (still) renderDetail(still); else { state.selected = null; renderDetail(null); }
  }

  function renderVerdict(r) {
    $('#verdictCard').className = `card verdict-card v-${r.verdict}`;
    $('#verdictValue').textContent = r.verdict_label;
    $('#verdictReason').textContent = r.verdict_reason;
    const s = r.stats || {};
    $('#verdictFoot').textContent = [plural(s.issues || 0, 'issue'), s.ignored ? `${s.ignored} ignored` : null].filter(Boolean).join(' · ');
  }

  function renderChange(r) {
    const s = r.stats || {};
    $('#statFiles').textContent = s.files_reviewed || 0;
    const project = !r.base_ref;
    $('#statAdded').textContent = project ? `${s.lines_added || 0}` : `+${s.lines_added || 0}`;
    $('#statAdded').nextElementSibling.textContent = project ? 'lines reviewed' : 'lines added';
    $('#statRemoved').parentElement.hidden = project;
    $('#statRemoved').textContent = `−${s.lines_removed || 0}`;
    const extra = [];
    if (s.files_skipped) extra.push(`${s.files_skipped} skipped`);
    if (s.files_failed) extra.push(`${s.files_failed} failed`);
    if (s.cached_files) extra.push(`${s.cached_files} from cache`);
    $('#changeFoot').textContent = `${r.base_ref ? `compared with ${r.base_ref}` : 'whole project'}${extra.length ? ` · ${extra.join(' · ')}` : ''}`;
  }

  function severityCounts(r) {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const f of r.findings) if (!isHidden(f) && counts[f.severity] !== undefined) counts[f.severity] += 1;
    return counts;
  }

  function renderSeverity(r) {
    const counts = severityCounts(r);
    const box = clear($('#sevCounts'));
    const bar = clear($('#sevBar'));
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    for (const s of SEVERITIES) {
      const only = state.filters.sev.size === 1 && state.filters.sev.has(s);
      box.append(el('button', {
        class: `sev-count${only ? ' active' : ''}`, title: `Show only ${s.toLowerCase()} issues`,
        onclick: () => { state.filters.sev = only ? new Set(SEVERITIES) : new Set([s]); syncFilters(); },
      }, el('b', { class: `c-${s}`, text: counts[s] }), el('span', { text: sevLabel(s) })));
      if (total && counts[s]) bar.append(el('i', { class: `b-${s}`, style: { width: `${(100 * counts[s]) / total}%` } }));
    }
  }

  function renderSummary(r) {
    show($('#summaryCard'), Boolean(r.summary));
    $('#summaryText').textContent = r.summary || '';
    $('#modelLabel').textContent = r.model ? `by ${r.model}` : '';
  }

  // ------------------------------------------------------------------ filters
  function renderCategoryOptions(r) {
    const cats = [...new Set(r.findings.map((f) => f.category))].sort();
    const sel = $('#catFilter');
    clear(sel).append(el('option', { value: '', text: 'All categories' }), ...cats.map((c) => el('option', { value: c, text: CATEGORY_LABEL[c] || c })));
    sel.value = cats.includes(state.filters.cat) ? state.filters.cat : '';
    renderSevChips();
  }

  function renderSevChips() {
    const counts = state.result ? severityCounts(state.result) : {};
    const box = clear($('#sevFilter'));
    for (const s of SEVERITIES) {
      const on = state.filters.sev.has(s);
      box.append(el('button', {
        class: 'chip', 'aria-pressed': on ? 'true' : 'false', title: `${on ? 'Hide' : 'Show'} ${s.toLowerCase()}`,
        onclick: () => { if (on) state.filters.sev.delete(s); else state.filters.sev.add(s); syncFilters(); },
      }, el('i', { class: `b-${s}` }), `${sevLabel(s)} ${counts[s] ?? ''}`));
    }
  }

  function resetFilters(render = true) {
    state.filters = { sev: new Set(SEVERITIES), cat: '', q: '', fixOnly: false, showHidden: false, file: '' };
    $('#searchInput').value = '';
    $('#fixOnly').checked = false;
    $('#showHidden').checked = false;
    if (render) syncFilters();
  }

  function syncFilters() {
    $('#catFilter').value = state.filters.cat;
    renderSeverity(state.result);
    renderSevChips();
    renderFindings();
    renderFiles(state.result);
  }

  let searchTimer = null;
  $('#searchInput').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = e.target.value.trim().toLowerCase(); renderFindings(); }, 150);
  });
  $('#catFilter').addEventListener('change', (e) => { state.filters.cat = e.target.value; syncFilters(); });
  $('#fixOnly').addEventListener('change', (e) => { state.filters.fixOnly = e.target.checked; renderFindings(); });
  $('#showHidden').addEventListener('change', (e) => { state.filters.showHidden = e.target.checked; renderFindings(); });
  $('#clearFilters').addEventListener('click', () => resetFilters(true));

  function matches(f) {
    const flt = state.filters;
    if (!flt.showHidden && isHidden(f)) return false;
    if (!flt.sev.has(f.severity)) return false;
    if (flt.cat && f.category !== flt.cat) return false;
    if (flt.file && f.file_path !== flt.file) return false;
    if (flt.fixOnly && !f.fix) return false;
    if (flt.q && !`${f.title} ${f.file_path} ${f.explanation}`.toLowerCase().includes(flt.q)) return false;
    return true;
  }

  // ------------------------------------------------------------------ issue list
  function renderFindings() {
    const r = state.result;
    const list = clear($('#findingList'));
    if (!r) return;
    const visible = r.findings.filter(matches);
    const hiddenCount = r.findings.filter(isHidden).length;
    $('#hiddenCount').textContent = hiddenCount ? `(${hiddenCount})` : '';
    $('#findingCount').textContent = visible.length === r.findings.length ? r.findings.length : `${visible.length} of ${r.findings.length}`;

    if (!visible.length) {
      const msg = r.findings.length ? 'No issues match these filters.' : 'The AI found no issues in the changed code.';
      list.append(el('div', { class: 'list-empty' }, msg, r.findings.length ? el('div', null,
        el('button', { class: 'link-btn small', text: 'Clear filters', onclick: () => resetFilters(true) })) : null));
      return;
    }
    const groups = new Map();
    for (const f of visible) {
      if (!groups.has(f.file_path)) groups.set(f.file_path, []);
      groups.get(f.file_path).push(f);
    }
    const ordered = [...groups.entries()].sort((a, b) => {
      const wa = Math.max(...a[1].map((f) => SEV_RANK[f.severity]));
      const wb = Math.max(...b[1].map((f) => SEV_RANK[f.severity]));
      return wb - wa || b[1].length - a[1].length || a[0].localeCompare(b[0]);
    });
    ordered.forEach(([file, items], gi) => {
      items.sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.line - b.line);
      const open = state.openFiles.has(file) || (state.openFiles.size === 0 && gi < 10) || items.some((f) => f.fingerprint === state.selected);
      const group = el('div', { class: `file-group${open ? ' open' : ''}` });
      const head = el('button', {
        class: 'file-head', 'aria-expanded': open ? 'true' : 'false',
        onclick: () => {
          const now = !group.classList.contains('open');
          group.classList.toggle('open', now);
          head.setAttribute('aria-expanded', String(now));
          if (now) state.openFiles.add(file); else state.openFiles.delete(file);
        },
      }, icon('chevron'), el('span', { class: 'path', title: file }, el('bdi', { text: file })), el('span', { class: 'count', text: items.length }));
      const body = el('div', { class: 'file-items' }, items.map(findingRow));
      group.append(head, body);
      list.append(group);
    });
  }

  function findingRow(f) {
    const sub = [el('span', { class: 'line', text: `L${lineRange(f)}` }), el('span', { text: CATEGORY_LABEL[f.category] || f.category })];
    if (f.fix) sub.push(el('span', { class: 'tag new' }, icon('sparkle'), 'fix'));
    if (f.suppressed) sub.push(el('span', { class: 'tag', text: 'ignored' }));
    return el('button', {
      class: `finding${state.selected === f.fingerprint ? ' selected' : ''}${isHidden(f) ? ' muted-item' : ''}`,
      role: 'option', 'aria-selected': state.selected === f.fingerprint ? 'true' : 'false', dataset: { fp: f.fingerprint },
      onclick: () => selectFinding(f),
    }, el('span', { class: `sev b-${f.severity}`, text: f.severity === 'CRITICAL' ? 'CRIT' : f.severity }),
    el('span', { style: { minWidth: 0 } }, el('div', { class: 'msg', text: f.title }), el('div', { class: 'sub' }, sub)));
  }

  function selectFinding(f) {
    state.selected = f.fingerprint;
    document.querySelectorAll('.finding.selected').forEach((n) => { n.classList.remove('selected'); n.setAttribute('aria-selected', 'false'); });
    const row = document.querySelector(`.finding[data-fp="${CSS.escape(f.fingerprint)}"]`);
    if (row) { row.classList.add('selected'); row.setAttribute('aria-selected', 'true'); }
    renderDetail(f);
    if (window.innerWidth <= 1180) $('#detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  document.addEventListener('keydown', (e) => {
    if (!state.result || e.target.closest('input, select, textarea, dialog')) return;
    if (e.key !== 'j' && e.key !== 'k') return;
    const rows = [...document.querySelectorAll('.file-group.open .finding')];
    if (!rows.length) return;
    const idx = rows.findIndex((r) => r.dataset.fp === state.selected);
    const next = rows[Math.max(0, Math.min(rows.length - 1, idx + (e.key === 'j' ? 1 : -1)))];
    const f = state.result.findings.find((x) => x.fingerprint === next.dataset.fp);
    if (f) { selectFinding(f); next.scrollIntoView({ block: 'nearest' }); }
  });

  // ------------------------------------------------------------------ detail panel
  function highlightLine(text, language) {
    const lang = HLJS_LANG[language];
    if (window.hljs && lang && window.hljs.getLanguage(lang)) {
      try { return window.hljs.highlight(text, { language: lang, ignoreIllegals: true }).value; } catch (e) { /* plain */ }
    }
    return null;
  }

  function codeRow(cls, ln, mark, text, language) {
    const code = el('td', { class: 'hljs' });
    const html = highlightLine(text, language);
    if (html !== null) code.innerHTML = html; // highlight.js output is escaped
    else code.textContent = text;
    return el('tr', { class: cls }, el('td', { class: 'ln', text: ln }), el('td', { class: 'mk', text: mark }), code);
  }

  function codeView(f) {
    if (!f.context) return null;
    const table = el('table');
    const start = f.context_start || f.line;
    const end = f.end_line || f.line;
    f.context.split('\n').forEach((line, i) => {
      const n = start + i;
      const hl = n >= f.line && n <= end;
      table.append(codeRow(hl ? 'hl' : '', n, n === f.line ? '›' : '', line, f.language));
    });
    return el('div', { class: 'code' }, table);
  }

  function lineDiff(a, b) {
    const n = a.length;
    const m = b.length;
    if (n * m > 250000) return null;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i -= 1) {
      for (let j = m - 1; j >= 0; j -= 1) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
    const out = [];
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) { out.push({ t: ' ', s: a[i], ln: i }); i += 1; j += 1; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ t: '-', s: a[i], ln: i }); i += 1; }
      else { out.push({ t: '+', s: b[j] }); j += 1; }
    }
    while (i < n) { out.push({ t: '-', s: a[i], ln: i }); i += 1; }
    while (j < m) { out.push({ t: '+', s: b[j] }); j += 1; }
    return out;
  }

  function diffView(f) {
    // context holds exactly the lines the fix replaces (line..end_line)
    const original = (f.context || '').split('\n');
    const fixed = f.fix.replace(/\s+$/, '').split('\n');
    const ops = f.context ? lineDiff(original, fixed) : null;
    const table = el('table');
    if (!ops) fixed.forEach((line) => table.append(codeRow('add', '', '+', line, f.language)));
    else {
      ops.forEach((op) => {
        const ln = op.ln !== undefined ? (f.context_start || f.line) + op.ln : '';
        table.append(codeRow(op.t === '+' ? 'add' : op.t === '-' ? 'del' : '', op.t === '+' ? '' : ln, op.t === ' ' ? '' : op.t, op.s, f.language));
      });
    }
    return el('div', { class: 'code' }, table);
  }

  async function copyText(text, label) {
    try { await navigator.clipboard.writeText(text); toast(`${label} copied`); }
    catch (e) { toast('Copy failed: your browser blocked clipboard access', 'error'); }
  }

  function renderDetail(f) {
    const body = $('#detailBody');
    show($('#detailEmpty'), !f);
    show(body, Boolean(f));
    clear(body);
    if (!f) return;
    const conf = Math.round((f.confidence || 0) * 100);
    body.append(el('div', { class: 'detail-tags' },
      el('span', { class: `sev b-${f.severity}`, text: f.severity }),
      el('span', { class: 'tag', text: CATEGORY_LABEL[f.category] || f.category }),
      el('span', { class: 'conf' }, 'AI confidence', el('span', { class: 'conf-bar' }, el('i', { style: { width: `${conf}%` } })), `${conf}%`)));
    body.append(el('h3', { class: 'detail-title', text: f.title }));
    const location = `${f.file_path}:${lineRange(f)}`;
    body.append(el('div', { class: 'detail-meta' }, el('span', { class: 'mono', text: location }),
      el('button', { class: 'link-btn small', onclick: () => copyText(location, 'Location') }, icon('copy'), 'Copy location')));
    if (f.suppressed) body.append(el('div', { class: 'note', text: `Ignored: ${f.suppressed}` }));
    if (f.explanation) body.append(el('div', { class: 'ai-box' }, el('div', { text: f.explanation })));

    if (f.fix) {
      body.append(el('div', { class: 'detail-section' }, el('h3', null, 'Suggested fix', el('span', { class: 'spacer' }),
        el('button', { class: 'link-btn small', onclick: () => copyText(f.fix, 'Fix') }, icon('copy'), 'Copy fix')), diffView(f)));
    } else {
      const code = codeView(f);
      if (code) body.append(el('div', { class: 'detail-section' }, el('h3', { text: 'Code' }), code));
    }

    const actions = el('div', { class: 'detail-actions' });
    const userSuppressed = f.suppressed && /^(marked false positive|ignored)/.test(f.suppressed);
    if (userSuppressed) {
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => unsuppress(f) }, icon('undo'), 'Restore issue'));
    } else if (!f.suppressed) {
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => askSuppress(f, 'false_positive') }, icon('flag'), 'False positive'));
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => askSuppress(f, 'ignore') }, icon('eye-off'), 'Ignore'));
    } else {
      actions.append(el('span', { class: 'muted small', text: 'Ignored by a "reviewer: ignore" comment in the code.' }));
    }
    body.append(actions);
  }

  // ------------------------------------------------------------------ ignoring issues
  function askSuppress(f, kind) {
    state.suppressTarget = { f, kind };
    $('#suppressTitle').textContent = kind === 'false_positive' ? 'Mark as false positive' : 'Ignore this issue';
    $('#suppressForm').reset();
    $('#suppressModal').returnValue = '';
    $('#suppressModal').showModal();
  }

  $('#suppressModal').addEventListener('close', async () => {
    const target = state.suppressTarget;
    state.suppressTarget = null;
    if ($('#suppressModal').returnValue !== 'ok' || !target) return;
    const reason = $('#suppressForm').elements.reason.value;
    await applyRescore(api('POST', `/api/projects/${state.project.id}/suppressions`,
      { fingerprint: target.f.fingerprint, kind: target.kind, reason }),
    target.kind === 'false_positive' ? 'Marked as false positive' : 'Issue ignored');
  });

  function unsuppress(f) {
    applyRescore(api('DELETE', `/api/projects/${state.project.id}/suppressions/${encodeURIComponent(f.fingerprint)}`), 'Issue restored');
  }

  async function applyRescore(promise, message) {
    try {
      const scan = await promise;
      const before = state.result.verdict_label;
      state.scan = scan;
      state.result = scan.result;
      renderResult();
      toast(before !== state.result.verdict_label ? `${message}. Verdict is now "${state.result.verdict_label}".` : message);
      loadProjects();
    } catch (e) { toast(e.message, 'error'); }
  }

  // ------------------------------------------------------------------ files
  function renderFiles(r) {
    if (!r) return;
    const box = clear($('#filesTable'));
    box.append(...['File', 'Status', 'Lines', 'Issues', 'Notes'].map((h, i) => el('div', { class: `h${i === 2 ? ' opt' : ''}`, text: h })));
    const s = r.stats || {};
    $('#filesSummary').textContent = `${s.files_reviewed || 0} reviewed${s.files_skipped ? `, ${s.files_skipped} skipped` : ''}${s.files_failed ? `, ${s.files_failed} failed` : ''}`;
    for (const f of r.files) {
      const dot = f.status === 'reviewed' ? 'dot-pass' : f.status === 'error' ? 'dot-fail' : 'dot-none';
      const active = state.filters.file === f.path;
      box.append(
        el('button', {
          class: `file-link${active ? ' active' : ''}`, title: f.status === 'reviewed' ? 'Show only issues in this file' : f.path,
          onclick: () => { if (f.status !== 'reviewed') return; state.filters.file = active ? '' : f.path; syncFilters(); },
        }, el('span', { class: `dot ${dot}` }), el('bdi', { text: f.path })),
        el('div', { text: f.status }),
        el('div', { class: 'opt', text: `+${f.lines_added}` }),
        el('div', { text: f.status === 'reviewed' ? f.issues : '' }),
        el('div', { class: 'muted', text: f.message || (f.cached ? 'from cache' : '') }));
    }
  }

  // ------------------------------------------------------------------ project modal
  const projectForm = $('#projectForm');
  let editingId = null;

  function updateSourceHints() {
    const github = projectForm.elements.source_type.value === 'github';
    $('#pathLabel').textContent = github ? 'Repository URL' : 'Folder path';
    projectForm.elements.path_or_url.placeholder = github ? 'https://github.com/owner/repo' : 'C:\\Projects\\my-app';
    $('#pathHint').textContent = github
      ? 'The repository is cloned so its branches can be compared.'
      : 'A folder inside an allowed location (your home folder by default). It must be a git repository to review changes since a branch.';
  }
  projectForm.querySelectorAll('input[name="source_type"]').forEach((r) => r.addEventListener('change', updateSourceHints));
  document.querySelectorAll('[data-close]').forEach((btn) => btn.addEventListener('click', () => btn.closest('dialog').close('cancel')));

  function openProjectModal(project) {
    editingId = project ? project.id : null;
    projectForm.reset();
    show($('#projectError'), false);
    $('#projectModalTitle').textContent = project ? 'Project settings' : 'Add project';
    show($('#deleteProjectBtn'), Boolean(project));
    show($('#sourceField'), !project);
    projectForm.elements.path_or_url.disabled = Boolean(project);
    if (project) {
      for (const key of ['name', 'path_or_url', 'base_ref']) projectForm.elements[key].value = project[key] || '';
      projectForm.elements.source_type.value = project.source_type;
    }
    updateSourceHints();
    $('#projectModal').showModal();
    projectForm.elements.name.focus();
  }

  $('#addProjectBtn').addEventListener('click', () => openProjectModal(null));
  $('#welcomeAdd').addEventListener('click', () => openProjectModal(null));
  $('#settingsBtn').addEventListener('click', () => openProjectModal(state.project));

  projectForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(projectForm).entries());
    const errorBox = $('#projectError');
    if (!data.name || (!editingId && !data.path_or_url)) {
      errorBox.textContent = 'Name and path are required.';
      show(errorBox, true);
      return;
    }
    $('#saveProjectBtn').disabled = true;
    try {
      const project = editingId
        ? await api('PATCH', `/api/projects/${editingId}`, { name: data.name, base_ref: data.base_ref })
        : await api('POST', '/api/projects', data);
      $('#projectModal').close();
      await loadProjects();
      toast(editingId ? 'Project saved' : 'Project added');
      if (editingId) { state.project = state.projects.find((p) => p.id === project.id); renderTopbar(); } else selectProject(project.id);
    } catch (err) {
      errorBox.textContent = err.message;
      show(errorBox, true);
    } finally {
      $('#saveProjectBtn').disabled = false;
    }
  });

  $('#deleteProjectBtn').addEventListener('click', async () => {
    if (!editingId || !window.confirm('Delete this project and its review history? This cannot be undone.')) return;
    try {
      await api('DELETE', `/api/projects/${editingId}`);
      $('#projectModal').close();
      toast('Project deleted');
      state.project = null;
      await loadProjects();
      route();
    } catch (err) { toast(err.message, 'error'); }
  });

  // ------------------------------------------------------------------ start
  function route() {
    const m = /^#\/p\/([\w-]+)/.exec(window.location.hash);
    const target = (m && state.projects.find((p) => p.id === m[1])) || state.projects[0];
    if (target) selectProject(target.id);
    else { state.project = null; renderTopbar(); showView('welcome'); }
  }

  async function init() {
    applyTheme();
    loadAiStatus();
    await loadProjects();
    route();
  }

  init();
})();
