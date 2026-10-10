/* Code Reviewer dashboard.
 * All text from scans (messages, code, AI output) is inserted with textContent,
 * never innerHTML, so a scanned repository can't inject script into this page.
 * The only innerHTML use is highlight.js output, which escapes its input. */
(() => {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const STAGES = [
    { key: 'prepare', label: 'Prepare', match: ['queued', 'clone', 'discover', 'diff'] },
    { key: 'scan', label: 'Run scanners', match: ['scan'] },
    { key: 'process', label: 'Merge findings', match: ['process'] },
    { key: 'ai', label: 'AI review', match: ['ai'] },
    { key: 'gates', label: 'Quality gates', match: ['gates', 'done', 'end'] },
  ];
  const GATE_FILTER = {
    build: { cat: 'build' }, tests: { cat: 'tests' }, coverage_new: { cat: 'tests' }, coverage_overall: { cat: 'tests' },
    secrets: { cat: 'secrets' }, sast: { cat: 'sast' }, dependencies: { cat: 'dependencies' }, lint: { cat: 'lint' },
    types: { cat: 'types' }, complexity: { cat: 'complexity' }, duplication: { cat: 'duplication' }, size: { cat: 'size' },
    debug_leftovers: { cat: 'debug' }, sonarqube: { tool: 'SonarQube' },
  };
  const CATEGORY_LABEL = {
    build: 'Build', tests: 'Tests', secrets: 'Secrets', sast: 'Security (SAST)', dependencies: 'Dependencies', lint: 'Lint',
    types: 'Types', complexity: 'Complexity', size: 'Size', duplication: 'Duplication', debug: 'Debug leftovers',
    ai: 'AI review', external: 'External',
  };
  const HLJS_LANG = { python: 'python', javascript: 'javascript', typescript: 'typescript', java: 'java', csharp: 'csharp',
    go: 'go', ruby: 'ruby', php: 'php', rust: 'rust', c: 'c', cpp: 'cpp', kotlin: 'kotlin', swift: 'swift', scala: 'scala' };

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

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  const show = (node, on = true) => { node.hidden = !on; };
  const effSev = (f) => f.ai_severity || f.severity;
  const isHidden = (f) => Boolean(f.suppressed) || f.ai_dismissed || !f.is_new;
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

  function timeAgo(iso) {
    if (!iso) return '';
    const secs = (Date.now() - new Date(iso).getTime()) / 1000;
    if (secs < 60) return 'just now';
    if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
    if (secs < 86400) return `${Math.round(secs / 3600)} h ago`;
    return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }

  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

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
    setTimeout(() => node.remove(), type === 'error' ? 7000 : 3500);
  }

  // ------------------------------------------------------------------ state
  const state = {
    projects: [],
    project: null,
    scan: null,
    result: null,
    history: [],
    selected: null,
    filters: { sev: new Set(['CRITICAL', 'HIGH', 'MEDIUM']), tool: '', cat: '', q: '', aiOnly: false, showHidden: false, gate: null },
    openFiles: new Set(),
    limit: 150,
    stream: null,
    pollTimer: null,
    suppressTarget: null,
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
    if (state.result) renderCharts();
  }

  $('#themeBtn').addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('cr-theme', next); } catch (e) { /* storage unavailable */ }
    applyTheme();
  });
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);

  // ------------------------------------------------------------------ sidebar
  function openSidebar(on) {
    $('#sidebar').classList.toggle('open', on);
    show($('#scrim'), on);
  }
  $('#openSidebar').addEventListener('click', () => openSidebar(true));
  $('#closeSidebar').addEventListener('click', () => openSidebar(false));
  $('#scrim').addEventListener('click', () => openSidebar(false));

  async function loadProjects() {
    try {
      state.projects = await api('GET', '/api/projects');
    } catch (e) {
      toast(e.message, 'error');
      return;
    }
    renderProjects();
  }

  function verdictDot(p) {
    if (p.running_scan) return 'dot dot-running';
    return { FAIL: 'dot dot-fail', WARN: 'dot dot-warn', PASS: 'dot dot-pass' }[p.last_verdict] || 'dot dot-none';
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
        class: `project${active ? ' active' : ''}`, 'aria-current': active ? 'page' : null,
        title: p.path_or_url, onclick: () => { selectProject(p.id); openSidebar(false); },
      },
      el('span', { class: verdictDot(p) }),
      el('span', { style: { minWidth: 0 } },
        el('div', { class: 'project-name', text: p.name }),
        el('div', { class: 'project-sub', text: p.last_scan ? timeAgo(p.last_scan) : (p.source_type === 'github' ? 'GitHub' : 'Local folder') })),
      el('span', { class: 'project-score', text: p.last_score !== null && p.last_score !== undefined ? p.last_score : '' })));
    }
  }

  // ------------------------------------------------------------------ project selection
  function renderTopbar() {
    const p = state.project;
    const meta = clear($('#projectMeta'));
    $('#projectName').textContent = p ? p.name : 'Welcome';
    show($('#runGroup'), Boolean(p));
    show($('#settingsBtn'), Boolean(p));
    show($('#pdfBtn'), Boolean(p && state.scan && state.scan.status === 'done'));
    if (!p) return;
    meta.append(el('span', { title: p.path_or_url }, icon(p.source_type === 'github' ? 'github' : 'folder'),
      p.path_or_url.length > 60 ? `…${p.path_or_url.slice(-58)}` : p.path_or_url));
    const base = state.result && state.result.base_ref;
    meta.append(el('span', null, icon('branch'), base ? `changes since ${base}` : 'whole project'));
    if (state.scan && state.scan.finished_at) meta.append(el('span', null, `scanned ${timeAgo(state.scan.finished_at)}`));
    $('#scanBaseRef').value = p.base_ref || '';
  }

  async function selectProject(id) {
    stopWatching();
    const p = state.projects.find((x) => x.id === id);
    if (!p) return;
    state.project = p;
    state.scan = null;
    state.result = null;
    state.selected = null;
    state.openFiles.clear();
    resetFilters(false);
    try { history.replaceState(null, '', `#/p/${id}`); } catch (e) { /* ignore */ }
    renderProjects();
    renderTopbar();
    showView('loading');
    await loadLatest();
  }

  function showView(view) {
    show($('#welcome'), view === 'welcome');
    show($('#noScan'), view === 'noscan');
    show($('#progressCard'), view === 'progress');
    show($('#results'), view === 'results');
    if (view !== 'results' && view !== 'error') show($('#errorCard'), false);
  }

  async function loadLatest() {
    const p = state.project;
    let data;
    try {
      data = await api('GET', `/api/projects/${p.id}/latest`);
    } catch (e) {
      toast(e.message, 'error');
      return;
    }
    if (state.project !== p) return;
    const scan = data.scan;
    if (!scan) { state.scan = null; renderTopbar(); showView('noscan'); return; }
    if (scan.status === 'running') { watchScan(scan.id); return; }
    if (scan.status === 'error') {
      state.scan = scan;
      renderTopbar();
      showView('noscan');
      show($('#errorCard'), true);
      $('#errorText').textContent = scan.error || 'Unknown error';
      return;
    }
    state.scan = scan;
    state.result = scan.result;
    try { state.history = await api('GET', `/api/projects/${p.id}/history`); } catch (e) { state.history = []; }
    renderTopbar();
    showView('results');
    renderResult();
  }

  // ------------------------------------------------------------------ scanning
  async function runScan(options) {
    const p = state.project;
    if (!p) return;
    const body = options || {};
    $('#runBtn').disabled = true;
    try {
      const { scan_id: scanId } = await api('POST', `/api/projects/${p.id}/scans`, body);
      toast('Scan started');
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

  const progress = { stage: 'prepare', tools: new Map() };

  function renderProgress(message) {
    const idx = STAGES.findIndex((s) => s.key === progress.stage);
    const stepper = clear($('#stepper'));
    STAGES.forEach((s, i) => {
      stepper.append(el('li', { class: i < idx ? 'done' : i === idx ? 'active' : '', text: s.label }));
    });
    if (message) $('#progressMsg').textContent = message;
    const grid = clear($('#toolGrid'));
    for (const [name, t] of progress.tools) {
      const label = t.status === 'running' ? 'running…' : t.status === 'ran' ? `${plural(t.findings || 0, 'finding')}` : t.status;
      grid.append(el('div', { class: `tool-pill ${t.status}`, title: t.message || '' },
        el('span', { class: 'dot' }), el('span', { class: 'name', text: name }), el('span', { class: 'st', text: label })));
    }
  }

  function handleEvent(event) {
    const stage = STAGES.find((s) => s.match.includes(event.stage));
    if (stage) progress.stage = stage.key;
    if (event.tool) {
      progress.tools.set(event.tool, { status: event.status, message: event.message, findings: event.findings });
    }
    renderProgress(event.message && !event.tool ? event.message : null);
    if (event.stage === 'end') {
      stopWatching();
      if (state.project && state.project.running_scan) state.project.running_scan = null;
      if (event.status === 'error') toast(`Scan failed: ${event.message || 'see details'}`, 'error');
      else toast(`Scan finished: ${event.verdict || 'done'}`);
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
    progress.tools = new Map();
    $('#progressTitle').textContent = 'Scanning…';
    $('#progressMsg').textContent = 'Starting';
    renderProgress();
    showView('progress');
    show($('#pdfBtn'), false);
    if (window.EventSource) {
      const es = new EventSource(`/api/scans/${scanId}/events`);
      state.stream = es;
      es.onmessage = (msg) => { try { handleEvent(JSON.parse(msg.data)); } catch (e) { console.error(e); } };
      es.onerror = () => { // fall back to polling if the stream drops
        if (!state.stream) return;
        es.close();
        state.stream = null;
        pollScan(scanId);
      };
    } else {
      pollScan(scanId);
    }
  }

  function pollScan(scanId) {
    state.pollTimer = setInterval(async () => {
      try {
        const scan = await api('GET', `/api/scans/${scanId}`);
        if (scan.status !== 'running') handleEvent({ stage: 'end', status: scan.status, verdict: scan.verdict, message: scan.error });
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
    runScan({ base_ref: $('#scanBaseRef').value.trim(), use_ai: $('#scanUseAi').checked });
  });
  $('#pdfBtn').addEventListener('click', () => {
    if (state.scan) window.open(`/api/scans/${state.scan.id}/report.pdf`, '_blank', 'noopener');
  });

  // ------------------------------------------------------------------ results
  function renderResult() {
    const r = state.result;
    if (!r) return;
    renderVerdict(r);
    renderHealth(r);
    renderSeverity(r);
    renderGates(r);
    renderCharts();
    renderFilterOptions(r);
    renderFindings();
    renderScanLog(r);
    const still = state.selected && r.findings.find((f) => f.fingerprint === state.selected);
    if (still) renderDetail(still); else { state.selected = null; renderDetail(null); }
  }

  function renderVerdict(r) {
    const card = $('#verdictCard');
    card.className = `card verdict-card v-${r.verdict}`;
    $('#verdictValue').textContent = r.verdict;
    $('#verdictReason').textContent = r.verdict_reason;
    const s = r.stats || {};
    const parts = [`${plural(s.findings_counted || 0, 'finding')} counted`];
    if (s.suppressed) parts.push(`${s.suppressed} ignored`);
    if (s.ai_dismissed) parts.push(`${s.ai_dismissed} dismissed by AI`);
    if (s.baseline) parts.push(`${s.baseline} in baseline`);
    if (s.changed_files !== null && s.changed_files !== undefined) parts.push(`${plural(s.changed_files, 'changed file')}`);
    $('#verdictFoot').textContent = parts.join(' · ');
  }

  function renderHealth(r) {
    const h = r.health || {};
    const score = Number(h.score || 0);
    $('#scoreValue').textContent = score;
    $('#gradeValue').textContent = `grade ${h.grade || '—'}`;
    const ring = $('#ringValue');
    ring.style.strokeDashoffset = String(314.16 * (1 - score / 100));
    ring.style.stroke = score >= 80 ? cssVar('--pass') : score >= 60 ? cssVar('--warn') : cssVar('--fail');
    const prev = state.history.filter((x) => x.id !== state.scan.id && x.score !== null).slice(-1)[0];
    const delta = $('#scoreDelta');
    if (prev) {
      const d = score - prev.score;
      delta.className = `delta ${d > 0 ? 'up' : d < 0 ? 'down' : 'same'}`;
      delta.textContent = d === 0 ? 'No change since last scan' : `${d > 0 ? '▲' : '▼'} ${Math.abs(d)} since last scan`;
    } else {
      delta.className = 'delta same';
      delta.textContent = 'First scan';
    }
    const notes = (h.notes || []).join('; ');
    $('#densityText').textContent = `${h.density ?? 0} weighted findings per 1,000 lines${notes ? ` · ${notes}` : ''}`;
  }

  function severityCounts(r) {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const f of r.findings) if (!isHidden(f)) counts[effSev(f)] += 1;
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
        class: `sev-count${only ? ' active' : ''}`, title: `Show only ${s.toLowerCase()} findings`,
        onclick: () => { state.filters.sev = only ? new Set(['CRITICAL', 'HIGH', 'MEDIUM']) : new Set([s]); syncFilters(); },
      }, el('b', { class: `c-${s}`, text: counts[s] }), el('span', { text: s === 'CRITICAL' ? 'Crit' : s.charAt(0) + s.slice(1).toLowerCase() })));
      if (total && counts[s]) bar.append(el('i', { class: `b-${s}`, style: { width: `${(100 * counts[s]) / total}%` } }));
    }
  }

  function gateIcon(g) {
    if (g.status === 'passed') return 'check';
    if (g.status === 'failed') return 'alert';
    return 'skip';
  }

  function renderGates(r) {
    const box = clear($('#gates'));
    for (const g of r.gates) {
      const filter = GATE_FILTER[g.key];
      const active = state.filters.gate === g.key;
      const lines = [];
      lines.push(`${g.status.toUpperCase()} · ${g.severity === 'blocker' ? 'blocker' : 'warning'} gate`);
      if (g.actual) lines.push(`Actual: ${g.actual}`);
      if (g.threshold) lines.push(`Threshold: ${g.threshold}`);
      if (g.details) lines.push(g.details);
      if (g.tools && g.tools.length) lines.push(`Tools: ${g.tools.join(', ')}`);
      if (g.top_files && g.top_files.length) lines.push(`Top files: ${g.top_files.map((t) => `${t.file} (${t.count})`).join(', ')}`);
      const tip = el('span', { class: 'tip', role: 'tooltip' });
      lines.forEach((line, i) => { if (i) tip.append(el('br')); tip.append(line); });
      box.append(el('button', {
        class: `gate g-${g.status} ${g.severity}${active ? ' active' : ''}`,
        'aria-pressed': active ? 'true' : 'false', 'aria-label': `${g.name}: ${lines.join('. ')}`,
        onclick: () => {
          if (!filter) return;
          if (active) { state.filters.gate = null; state.filters.cat = ''; state.filters.tool = ''; }
          else {
            state.filters.gate = g.key;
            state.filters.cat = filter.cat || '';
            state.filters.tool = filter.tool || '';
            state.filters.sev = new Set(SEVERITIES);
          }
          syncFilters();
        },
      }, icon(gateIcon(g)), g.name, g.actual && g.status !== 'skipped' ? el('small', { text: g.actual }) : null, tip));
    }
  }

  // Small dependency-free SVG charts, coloured from the theme's CSS variables.
  function svgEl(tag, attrs, text) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function chartEmpty(box, message) {
    clear(box).append(el('div', { class: 'chart-empty', text: message }));
  }

  function renderTrendChart(box) {
    const hist = state.history.filter((h) => h.score !== null && h.score !== undefined);
    if (hist.length < 2) { chartEmpty(box, hist.length ? 'Run another scan to see the trend.' : 'No history yet.'); return; }
    const W = 560; const H = 190; const L = 34; const R = 14; const T = 12; const B = 28;
    const x = (i) => L + (i * (W - L - R)) / (hist.length - 1);
    const y = (v) => T + ((100 - v) * (H - T - B)) / 100;
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img',
      'aria-label': `Health score over the last ${hist.length} scans, latest ${hist[hist.length - 1].score}` });
    for (const v of [0, 25, 50, 75, 100]) {
      svg.append(svgEl('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid' }));
      svg.append(svgEl('text', { x: L - 8, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, String(v)));
    }
    const pts = hist.map((h, i) => `${x(i)},${y(h.score)}`).join(' ');
    svg.append(svgEl('polygon', { points: `${x(0)},${y(0)} ${pts} ${x(hist.length - 1)},${y(0)}`, class: 'area' }));
    svg.append(svgEl('polyline', { points: pts, class: 'line' }));
    const fmt = (h) => new Date(h.finished_at || h.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    const labelEvery = Math.ceil(hist.length / 6);
    hist.forEach((h, i) => {
      const dot = svgEl('circle', { cx: x(i), cy: y(h.score), r: 4.5, class: `pt v-${h.verdict || 'NONE'}` });
      dot.append(svgEl('title', {}, `${fmt(h)}: score ${h.score} (${h.verdict})`));
      svg.append(dot);
      if (i % labelEvery === 0 || i === hist.length - 1) {
        svg.append(svgEl('text', { x: x(i), y: H - 8, 'text-anchor': i === 0 ? 'start' : i === hist.length - 1 ? 'end' : 'middle', class: 'tick' }, fmt(h)));
      }
    });
    clear(box).append(svg);
  }

  function renderToolChart(box) {
    const counts = {};
    for (const f of state.result.findings) if (!isHidden(f)) counts[f.tool] = (counts[f.tool] || 0) + 1;
    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 7);
    if (!entries.length) { chartEmpty(box, 'No findings to chart.'); return; }
    const W = 560; const row = 24; const L = 130; const R = 40; const H = entries.length * row + 8;
    const max = Math.max(...entries.map((e) => e[1]));
    const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Findings by tool' });
    entries.forEach(([tool, n], i) => {
      const yy = 4 + i * row;
      const w = Math.max(3, ((W - L - R) * n) / max);
      svg.append(svgEl('text', { x: L - 10, y: yy + 15, 'text-anchor': 'end', class: 'label' }, tool.length > 18 ? `${tool.slice(0, 17)}…` : tool));
      const bar = svgEl('rect', { x: L, y: yy + 3, width: w, height: row - 8, rx: 4, class: 'bar' });
      bar.append(svgEl('title', {}, `${tool}: ${n}`));
      svg.append(bar);
      svg.append(svgEl('text', { x: L + w + 6, y: yy + 15, class: 'value' }, String(n)));
    });
    clear(box).append(svg);
  }

  function renderCharts() {
    if (!state.result) return;
    renderTrendChart($('#trendChart'));
    renderToolChart($('#toolChart'));
  }

  // ------------------------------------------------------------------ filters
  function renderFilterOptions(r) {
    const tools = [...new Set(r.findings.map((f) => f.tool))].sort();
    const cats = [...new Set(r.findings.map((f) => f.category))].sort();
    const toolSel = $('#toolFilter');
    const catSel = $('#catFilter');
    clear(toolSel).append(el('option', { value: '', text: 'All tools' }), ...tools.map((t) => el('option', { value: t, text: t })));
    clear(catSel).append(el('option', { value: '', text: 'All categories' }), ...cats.map((c) => el('option', { value: c, text: CATEGORY_LABEL[c] || c })));
    toolSel.value = tools.includes(state.filters.tool) ? state.filters.tool : '';
    catSel.value = cats.includes(state.filters.cat) ? state.filters.cat : '';
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
      }, el('i', { class: `b-${s}` }), `${s === 'CRITICAL' ? 'Crit' : s.charAt(0) + s.slice(1).toLowerCase()} ${counts[s] ?? ''}`));
    }
  }

  function resetFilters(render = true) {
    state.filters = { sev: new Set(['CRITICAL', 'HIGH', 'MEDIUM']), tool: '', cat: '', q: '', aiOnly: false, showHidden: false, gate: null };
    $('#searchInput').value = '';
    $('#aiOnly').checked = false;
    $('#showHidden').checked = false;
    state.limit = 150;
    if (render) syncFilters();
  }

  function syncFilters() {
    $('#toolFilter').value = state.filters.tool;
    $('#catFilter').value = state.filters.cat;
    state.limit = 150;
    renderSeverity(state.result);
    renderSevChips();
    renderGates(state.result);
    renderFindings();
  }

  let searchTimer = null;
  $('#searchInput').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.filters.q = e.target.value.trim().toLowerCase(); state.limit = 150; renderFindings(); }, 150);
  });
  $('#toolFilter').addEventListener('change', (e) => { state.filters.tool = e.target.value; state.filters.gate = null; syncFilters(); });
  $('#catFilter').addEventListener('change', (e) => { state.filters.cat = e.target.value; state.filters.gate = null; syncFilters(); });
  $('#aiOnly').addEventListener('change', (e) => { state.filters.aiOnly = e.target.checked; renderFindings(); });
  $('#showHidden').addEventListener('change', (e) => { state.filters.showHidden = e.target.checked; renderFindings(); });
  $('#clearFilters').addEventListener('click', () => resetFilters(true));

  function matches(f) {
    const flt = state.filters;
    if (!flt.showHidden && isHidden(f)) return false;
    if (!flt.sev.has(effSev(f))) return false;
    if (flt.tool && f.tool !== flt.tool && !(f.tools || []).includes(flt.tool)) return false;
    if (flt.cat && f.category !== flt.cat) return false;
    if (flt.aiOnly && f.ai_verdict !== 'TRUE_POSITIVE') return false;
    if (flt.q) {
      const hay = `${f.message} ${f.file_path} ${f.rule_id} ${f.tool}`.toLowerCase();
      if (!hay.includes(flt.q)) return false;
    }
    return true;
  }

  // ------------------------------------------------------------------ findings list
  function renderFindings() {
    const r = state.result;
    const list = clear($('#findingList'));
    if (!r) return;
    const visible = r.findings.filter(matches);
    const hiddenCount = r.findings.filter(isHidden).length;
    $('#hiddenCount').textContent = hiddenCount ? `(${hiddenCount})` : '';
    $('#findingCount').textContent = visible.length === r.findings.length ? r.findings.length : `${visible.length} of ${r.findings.length}`;
    const s = r.stats || {};
    $('#baselineBtn').textContent = s.baseline ? 'Clear baseline' : 'Set baseline';

    if (!visible.length) {
      const msg = r.findings.length ? 'No findings match these filters.' : 'No findings. Clean code!';
      list.append(el('div', { class: 'list-empty' }, msg, r.findings.length ? el('div', null,
        el('button', { class: 'link-btn small', text: 'Clear filters', onclick: () => resetFilters(true) })) : null));
      return;
    }

    const groups = new Map();
    for (const f of visible) {
      const key = f.file_path || '(project)';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }
    const ordered = [...groups.entries()].sort((a, b) => {
      const wa = Math.max(...a[1].map((f) => SEV_RANK[effSev(f)]));
      const wb = Math.max(...b[1].map((f) => SEV_RANK[effSev(f)]));
      return wb - wa || b[1].length - a[1].length || a[0].localeCompare(b[0]);
    });

    let shown = 0;
    ordered.forEach(([file, items], gi) => {
      if (shown >= state.limit) return;
      items.sort((a, b) => SEV_RANK[effSev(b)] - SEV_RANK[effSev(a)] || a.line - b.line);
      const open = state.openFiles.has(file) || (state.openFiles.size === 0 && gi < 8) ||
        items.some((f) => f.fingerprint === state.selected);
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
      const body = el('div', { class: 'file-items' });
      for (const f of items) {
        if (shown >= state.limit) break;
        shown += 1;
        body.append(findingRow(f));
      }
      group.append(head, body);
      list.append(group);
    });
    if (visible.length > shown) {
      list.append(el('button', { class: 'btn btn-ghost btn-sm more-btn', text: `Show ${Math.min(150, visible.length - shown)} more of ${visible.length - shown}`,
        onclick: () => { state.limit += 150; renderFindings(); } }));
    }
  }

  function aiTag(f) {
    if (!f.ai_verdict) return null;
    const map = { TRUE_POSITIVE: ['ai-tp', 'AI: real issue'], FALSE_POSITIVE: ['ai-fp', 'AI: false positive'], UNSURE: ['ai-unsure', 'AI: unsure'] };
    const [cls, label] = map[f.ai_verdict] || map.UNSURE;
    return el('span', { class: `tag ${cls}` }, icon('sparkle'), label);
  }

  function findingRow(f) {
    const sev = effSev(f);
    const sub = [el('span', { class: 'line', text: f.line ? `L${f.line}` : '' }), el('span', { text: (f.tools || [f.tool]).join(' + ') }),
      el('span', { text: f.rule_id.length > 40 ? `${f.rule_id.slice(0, 38)}…` : f.rule_id })];
    if (f.suppressed) sub.push(el('span', { class: 'tag', text: 'ignored' }));
    if (f.ai_dismissed) sub.push(el('span', { class: 'tag ai-fp', text: 'dismissed' }));
    if (!f.is_new) sub.push(el('span', { class: 'tag', text: 'baseline' }));
    const tag = aiTag(f);
    if (tag && !f.ai_dismissed) sub.push(tag);
    return el('button', {
      class: `finding${state.selected === f.fingerprint ? ' selected' : ''}${isHidden(f) ? ' muted-item' : ''}`,
      role: 'option', 'aria-selected': state.selected === f.fingerprint ? 'true' : 'false', dataset: { fp: f.fingerprint },
      onclick: () => selectFinding(f),
    }, el('span', { class: `sev b-${sev}`, text: sev === 'CRITICAL' ? 'CRIT' : sev }),
    el('span', { style: { minWidth: 0 } }, el('div', { class: 'msg', text: f.message }), el('div', { class: 'sub' }, sub)));
  }

  function selectFinding(f) {
    state.selected = f.fingerprint;
    document.querySelectorAll('.finding.selected').forEach((n) => { n.classList.remove('selected'); n.setAttribute('aria-selected', 'false'); });
    const row = document.querySelector(`.finding[data-fp="${CSS.escape(f.fingerprint)}"]`);
    if (row) { row.classList.add('selected'); row.setAttribute('aria-selected', 'true'); }
    renderDetail(f);
    if (window.innerWidth <= 1180) $('#detail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // keyboard: j / k to move through findings
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
      try { return window.hljs.highlight(text, { language: lang, ignoreIllegals: true }).value; } catch (e) { /* fall through */ }
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
    const table = el('table');
    if (f.context) {
      const start = f.context_start || 1;
      f.context.split('\n').forEach((line, i) => {
        const n = start + i;
        const hl = n === f.line || (f.end_line && n > f.line && n <= f.end_line && f.end_line - f.line < 6);
        table.append(codeRow(hl ? 'hl' : '', n, n === f.line ? '›' : '', line, f.language));
      });
    } else if (f.code_snippet) {
      f.code_snippet.split('\n').forEach((line, i) => table.append(codeRow(i === 0 ? 'hl' : '', f.line ? f.line + i : '', '', line, f.language)));
    } else {
      return null;
    }
    return el('div', { class: 'code' }, table);
  }

  // Line diff (longest common subsequence) between the original code and the AI fix.
  function lineDiff(a, b) {
    const n = a.length;
    const m = b.length;
    if (n * m > 250000) return null;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i -= 1) {
      for (let j = m - 1; j >= 0; j -= 1) {
        dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
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
    const original = (f.context || '').split('\n');
    const fixed = f.ai_fix.replace(/\s+$/, '').split('\n');
    let ops = f.context ? lineDiff(original, fixed) : null;
    // If the AI returned only a fragment rather than the whole span, a diff would show
    // everything as deleted; show the replacement on its own instead.
    if (ops) {
      const common = ops.filter((op) => op.t === ' ').length;
      if (common < Math.max(1, original.length * 0.4)) ops = null;
    }
    const table = el('table');
    if (!ops) {
      fixed.forEach((line) => table.append(codeRow('', '', '', line, f.language)));
    } else {
      // show changed lines with 3 lines of context around them
      const keep = new Set();
      ops.forEach((op, idx) => { if (op.t !== ' ') for (let k = idx - 3; k <= idx + 3; k += 1) keep.add(k); });
      let gap = false;
      ops.forEach((op, idx) => {
        if (!keep.has(idx)) { if (!gap) { table.append(el('tr', null, el('td', { class: 'ln', text: '⋯' }), el('td'), el('td'))); gap = true; } return; }
        gap = false;
        const ln = op.ln !== undefined ? (f.context_start || 1) + op.ln : '';
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
    const sev = effSev(f);
    const tags = [el('span', { class: `sev b-${sev}`, text: sev })];
    if (f.ai_severity && f.ai_severity !== f.severity) tags.push(el('span', { class: 'tag', text: `scanner said ${f.severity}` }));
    tags.push(el('span', { class: 'tag', text: CATEGORY_LABEL[f.category] || f.category }));
    if (!f.is_new) tags.push(el('span', { class: 'tag', text: 'baseline' }));
    const at = aiTag(f);
    if (at) tags.push(at);
    body.append(el('div', { class: 'detail-tags' }, tags));
    body.append(el('h3', { class: 'detail-title', text: f.message }));

    const meta = el('div', { class: 'detail-meta' });
    const location = f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ''}` : '';
    if (location) meta.append(el('span', { class: 'mono', text: location }));
    meta.append(el('span', { text: `${(f.tools || [f.tool]).join(' + ')} · ${f.rule_id}` }));
    if (f.confidence) meta.append(el('span', { text: `scanner confidence: ${String(f.confidence).toLowerCase()}` }));
    if (f.url && /^https?:\/\//.test(f.url)) meta.append(el('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer', text: 'Rule docs ↗' }));
    body.append(meta);

    if (f.suppressed) body.append(el('div', { class: 'note', text: `Ignored: ${f.suppressed}` }));
    if (f.ai_dismissed) body.append(el('div', { class: 'note', text: 'The AI judged this a false positive with high confidence, so it does not count towards the verdict.' }));
    const also = (f.extra && f.extra.also_reported) || [];
    if (also.length) {
      body.append(el('div', { class: 'detail-section' }, el('h3', { text: 'Also reported as' }),
        el('ul', { class: 'also' }, also.map((a) => el('li', { text: `${a.tool} ${a.rule_id}: ${a.message}` })))));
    }
    if (f.category === 'dependencies' && f.extra) {
      const e = f.extra;
      body.append(el('div', { class: 'note' + (e.fixed ? '' : ' warn') },
        `${e.package || 'package'} ${e.installed || ''} → ${e.fixed ? `upgrade to ${e.fixed}` : 'no fixed version published yet'}`));
    }

    const code = codeView(f);
    if (code) {
      body.append(el('div', { class: 'detail-section' }, el('h3', null, 'Code', el('span', { class: 'spacer' }),
        location ? el('button', { class: 'link-btn small', onclick: () => copyText(location, 'Location') }, icon('copy'), 'Copy location') : null), code));
    }

    if (f.ai_verdict || f.ai_explanation) {
      const conf = typeof f.ai_confidence === 'number' ? Math.round(f.ai_confidence * 100) : null;
      const box = el('div', { class: 'ai-box' },
        el('div', { class: 'ai-head' }, aiTag(f) || el('span', { class: 'tag' }, icon('sparkle'), 'AI review'),
          conf !== null ? el('span', { class: 'conf' }, 'confidence', el('span', { class: 'conf-bar' }, el('i', { style: { width: `${conf}%` } })), `${conf}%`) : null),
        el('div', { text: f.ai_explanation || '' }));
      body.append(el('div', { class: 'detail-section' }, el('h3', { text: 'AI assessment' }), box));
    }

    if (f.ai_fix) {
      body.append(el('div', { class: 'detail-section' }, el('h3', null, 'Suggested fix', el('span', { class: 'spacer' }),
        el('button', { class: 'link-btn small', onclick: () => copyText(f.ai_fix, 'Fix') }, icon('copy'), 'Copy fix')), diffView(f)));
    }

    const actions = el('div', { class: 'detail-actions' });
    const userSuppressed = f.suppressed && /^(marked false positive|ignored)/.test(f.suppressed);
    if (userSuppressed) {
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => unsuppress(f) }, icon('undo'), 'Restore finding'));
    } else if (!f.suppressed) {
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => askSuppress(f, 'false_positive') }, icon('flag'), 'False positive'));
      actions.append(el('button', { class: 'btn btn-ghost btn-sm', onclick: () => askSuppress(f, 'ignore') }, icon('eye-off'), 'Ignore'));
    } else {
      actions.append(el('span', { class: 'muted small', text: 'Ignored by a comment in the code. Remove the "reviewer: ignore" comment to restore it.' }));
    }
    body.append(actions);
  }

  // ------------------------------------------------------------------ suppressions & baseline
  function askSuppress(f, kind) {
    state.suppressTarget = { f, kind };
    $('#suppressTitle').textContent = kind === 'false_positive' ? 'Mark as false positive' : 'Ignore this finding';
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
    target.kind === 'false_positive' ? 'Marked as false positive' : 'Finding ignored');
  });

  function unsuppress(f) {
    applyRescore(api('DELETE', `/api/projects/${state.project.id}/suppressions/${encodeURIComponent(f.fingerprint)}`), 'Finding restored');
  }

  async function applyRescore(promise, message) {
    try {
      const scan = await promise;
      const before = state.result.verdict;
      state.scan = scan;
      state.result = scan.result;
      renderResult();
      toast(before !== state.result.verdict ? `${message}. Verdict is now ${state.result.verdict}.` : message);
      loadProjects();
    } catch (e) {
      toast(e.message, 'error');
    }
  }

  $('#baselineBtn').addEventListener('click', () => {
    const has = state.result && state.result.stats && state.result.stats.baseline;
    if (has) {
      applyRescore(api('DELETE', `/api/projects/${state.project.id}/baseline`), 'Baseline cleared');
    } else if (window.confirm('Treat every current finding as existing debt? Only new issues will count from now on.')) {
      applyRescore(api('POST', `/api/projects/${state.project.id}/baseline`), 'Baseline set: only new findings count now');
    }
  });

  // ------------------------------------------------------------------ scan log
  function renderScanLog(r) {
    const box = clear($('#scanLog'));
    box.append(...['Tool', 'Status', 'Findings', 'Notes', 'Time'].map((h, i) => el('div', { class: `h${i === 2 || i === 4 ? ' opt' : ''}`, text: h })));
    const ran = r.scans.filter((s) => s.status === 'ran').length;
    const missing = r.scans.filter((s) => s.status !== 'ran' && !s.not_applicable).length;
    $('#scanLogSummary').textContent = `${ran} ran${missing ? `, ${missing} missing or failed` : ''}`;
    for (const s of r.scans) {
      const dot = s.status === 'ran' ? 'dot-pass' : s.status === 'error' ? 'dot-fail' : s.not_applicable ? 'dot-none' : 'dot-skip';
      box.append(el('div', { style: { fontWeight: 600 } }, el('span', { class: `dot ${dot}`, style: { marginRight: '8px' } }), s.tool),
        el('div', { text: s.not_applicable ? 'not needed' : s.status }),
        el('div', { class: 'opt', text: s.finding_count ?? '' }),
        el('div', { class: 'muted', text: s.message || '' }),
        el('div', { class: 'opt muted', text: s.duration_seconds ? `${s.duration_seconds}s` : '' }));
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
      ? 'Public repos work as is. Tests of cloned repos are not run unless you allow it in quality-gates.yml.'
      : 'Must be inside an allowed folder (your home folder by default).';
  }
  projectForm.querySelectorAll('input[name="source_type"]').forEach((r) => r.addEventListener('change', updateSourceHints));

  function openProjectModal(project) {
    editingId = project ? project.id : null;
    projectForm.reset();
    show($('#projectError'), false);
    $('#sonarTestResult').textContent = '';
    $('#projectModalTitle').textContent = project ? 'Project settings' : 'Add project';
    show($('#deleteProjectBtn'), Boolean(project));
    show($('#sourceField'), !project);
    projectForm.elements.path_or_url.disabled = Boolean(project);
    if (project) {
      for (const key of ['name', 'path_or_url', 'base_ref', 'sonar_host', 'sonar_project_key']) projectForm.elements[key].value = project[key] || '';
      projectForm.elements.source_type.value = project.source_type;
      projectForm.elements.sonar_token.placeholder = project.has_sonar_token ? 'Saved. Leave empty to keep it' : 'Paste a token';
    }
    updateSourceHints();
    $('#projectModal').showModal();
    projectForm.elements.name.focus();
  }

  $('#addProjectBtn').addEventListener('click', () => openProjectModal(null));
  $('#welcomeAdd').addEventListener('click', () => openProjectModal(null));
  $('#settingsBtn').addEventListener('click', () => openProjectModal(state.project));

  document.querySelectorAll('[data-close]').forEach((btn) => btn.addEventListener('click', () => btn.closest('dialog').close('cancel')));

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
      let project;
      if (editingId) {
        const { name, base_ref: baseRef, sonar_host: host, sonar_token: token, sonar_project_key: key } = data;
        project = await api('PATCH', `/api/projects/${editingId}`, { name, base_ref: baseRef, sonar_host: host, sonar_token: token, sonar_project_key: key });
      } else {
        project = await api('POST', '/api/projects', data);
      }
      $('#projectModal').close();
      await loadProjects();
      toast(editingId ? 'Project saved' : 'Project added');
      if (editingId) { state.project = state.projects.find((p) => p.id === project.id); renderTopbar(); }
      else selectProject(project.id);
    } catch (err) {
      errorBox.textContent = err.message;
      show(errorBox, true);
    } finally {
      $('#saveProjectBtn').disabled = false;
    }
  });

  $('#deleteProjectBtn').addEventListener('click', async () => {
    if (!editingId || !window.confirm('Delete this project and its scan history? This cannot be undone.')) return;
    try {
      await api('DELETE', `/api/projects/${editingId}`);
      $('#projectModal').close();
      toast('Project deleted');
      state.project = null;
      await loadProjects();
      route();
    } catch (err) { toast(err.message, 'error'); }
  });

  $('#sonarTestBtn').addEventListener('click', async () => {
    const f = projectForm.elements;
    const out = $('#sonarTestResult');
    out.textContent = 'Testing…';
    try {
      const res = await api('POST', '/api/sonar/test', { host: f.sonar_host.value, token: f.sonar_token.value, project_key: f.sonar_project_key.value, project_id: editingId });
      out.textContent = res.ok ? `Connected. Quality gate: ${res.status}` : `Failed: ${res.error}`;
      out.style.color = res.ok ? cssVar('--pass') : cssVar('--fail');
    } catch (err) { out.textContent = err.message; out.style.color = cssVar('--fail'); }
  });

  // ------------------------------------------------------------------ tools modal
  $('#toolsBtn').addEventListener('click', async () => {
    const list = clear($('#toolsList'));
    list.append(el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' }));
    $('#toolsModal').showModal();
    try {
      const tools = await api('GET', '/api/tools');
      clear(list);
      for (const t of tools) {
        list.append(el('div', { class: 'tool-row' }, el('span', { class: `dot ${t.installed ? 'dot-pass' : 'dot-skip'}` }),
          el('strong', { text: t.name }), el('span', { class: 'p', title: t.path || t.hint || '', text: t.installed ? t.path : `Not available: ${t.hint}` })));
      }
    } catch (err) { clear(list).append(el('div', { class: 'form-error', text: err.message })); }
  });

  // ------------------------------------------------------------------ start
  function route() {
    const m = /^#\/p\/([\w-]+)/.exec(window.location.hash);
    const fromHash = m && state.projects.find((p) => p.id === m[1]);
    const target = fromHash || state.projects[0];
    if (target) selectProject(target.id);
    else { state.project = null; renderTopbar(); showView('welcome'); }
  }

  async function init() {
    applyTheme();
    await loadProjects();
    route();
  }

  init();
})();
