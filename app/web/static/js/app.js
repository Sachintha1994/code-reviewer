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
    filters: { sev: new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']), cat: '', q: '', fixOnly: false, showHidden: false, file: '', newOnly: false },
    openFiles: new Set(), stream: null, pollTimer: null, suppressTarget: null, ai: null,
    latestId: null, viewingOld: false, history: [],
  };
  const fmt = (n) => Number(n || 0).toLocaleString();

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
    renderUsage();
  }

  function renderUsage() {
    const ai = state.ai;
    show($('#usage'), Boolean(ai && ai.available));
    if (!ai || !ai.available) return;
    const used = ai.requests_24h || 0;
    const limit = ai.daily_request_limit || 0;
    $('#usageCount').textContent = limit ? `${fmt(used)} / ${fmt(limit)}` : fmt(used);
    show($('#usageMeter'), limit > 0);
    if (limit) {
      const pct = Math.min(100, (100 * used) / limit);
      $('#usageBar').style.width = `${pct}%`;
      $('#usageMeter').className = `meter${pct >= 100 ? ' full' : pct >= 75 ? ' high' : ''}`;
    }
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
        el('div', { class: 'project-sub', text: `${p.source_type === 'zip' ? 'ZIP upload' : p.base_ref ? `vs ${p.base_ref}` : 'whole project'}${p.last_scan ? ` · ${timeAgo(p.last_scan)}` : ''}` }))));
    }
  }

  // ------------------------------------------------------------------ project selection
  function renderTopbar() {
    const p = state.project;
    const meta = clear($('#projectMeta'));
    $('#projectName').textContent = p ? p.name : 'Welcome';
    show($('#runGroup'), Boolean(p));
    show($('#settingsBtn'), Boolean(p));
    show($('#exportGroup'), Boolean(p && state.result));
    if (!p) return;
    const srcIcon = { github: 'github', zip: 'layers' }[p.source_type] || 'folder';
    show($('#runOptionsBtn'), p.source_type !== 'zip');   // a ZIP is always reviewed whole
    meta.append(el('span', { title: p.path_or_url }, icon(srcIcon),
      p.path_or_url.length > 60 ? `…${p.path_or_url.slice(-58)}` : p.path_or_url));
    const ref = state.result ? state.result.base_ref : p.base_ref;
    meta.append(el('span', null, icon('branch'), ref ? `changes since ${ref}` : 'whole project'));
    if (state.scan && state.scan.finished_at) meta.append(el('span', null, icon('clock'), `reviewed ${timeAgo(state.scan.finished_at)}`));
    const sel = state.result && state.result.stats && state.result.stats.selection;
    if (sel && sel.length) meta.append(el('span', { title: `Reviewed only:\n${sel.join('\n')}` }, icon('folder'), sel.length === 1 ? `only ${sel[0]}` : 'selected files only'));
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
    Object.assign(state, { project: p, scan: null, result: null, selected: null, latestId: null, viewingOld: false, history: [] });
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
    if (!state.project || state.project.id !== p.id) return;
    const scan = data.scan;
    state.scan = scan;
    state.result = null;
    state.viewingOld = false;
    state.latestId = scan && scan.status === 'done' ? scan.id : null;
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
    loadHistory();
  }

  async function loadHistory() {
    const p = state.project;
    try { state.history = await api('GET', `/api/projects/${p.id}/history`); } catch (e) { state.history = []; }
    if (state.project && state.project.id === p.id) renderTrend();
  }

  async function openScan(id) {
    if (state.scan && state.scan.id === id) return;
    if (id === state.latestId) { loadLatest(); return; }
    let scan;
    try { scan = await api('GET', `/api/scans/${id}`); } catch (e) { toast(e.message, 'error'); return; }
    if (!scan.result || !scan.result.files) { toast('That review was made by an older version and can\'t be shown.', 'error'); return; }
    Object.assign(state, { scan, result: scan.result, viewingOld: true, selected: null });
    renderTopbar();
    showView('results');
    renderResult();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
  $('#backToLatest').addEventListener('click', () => loadLatest());

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
      loadAiStatus();
      loadProjects().then(() => {
        if (state.project) state.project = state.projects.find((x) => x.id === state.project.id) || state.project;
        renderProjects();
        if (state.project) loadLatest();
      });
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
    show($('#exportGroup'), false);
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
    if (!pop.hidden) { $('#scanBaseRef').focus(); refreshEstimates(); }
  });

  // ------------------------------------------------------------------ request estimates
  function estimateText(est) {
    if (!est.files) return 'Nothing to review.';
    return `${plural(est.files, 'file')} · ${fmt(est.lines)} lines · about ${plural(est.requests, 'AI request')}`;
  }

  function quotaWarning(requests) {
    const ai = state.ai;
    if (!ai || !ai.daily_request_limit) return '';
    const left = ai.daily_request_limit - (ai.requests_24h || 0);
    return requests > left ? ` (more than the ${Math.max(0, left)} left today; it will stop and continue on the next run)` : '';
  }

  async function estimate(body) {
    return api('POST', `/api/projects/${state.project.id}/estimate`, body);
  }

  let estTimer = null;
  let estSeq = 0;
  function refreshEstimates() {
    clearTimeout(estTimer);
    const ref = $('#scanBaseRef').value.trim();
    const seq = ++estSeq;
    $('#estChanges').textContent = ref ? 'Estimating…' : 'Enter a branch to compare with.';
    $('#estWhole').textContent = 'Estimating…';
    estTimer = setTimeout(async () => {
      const jobs = [estimate({ whole_project: true }).then((e) => {
        if (seq === estSeq) $('#estWhole').textContent = estimateText(e) + quotaWarning(e.requests);
      }).catch((e) => { if (seq === estSeq) $('#estWhole').textContent = e.message; })];
      if (ref) {
        jobs.push(estimate({ base_ref: ref }).then((e) => {
          if (seq === estSeq) $('#estChanges').textContent = estimateText(e) + quotaWarning(e.requests);
        }).catch((e) => { if (seq === estSeq) $('#estChanges').textContent = e.message; }));
      }
      await Promise.all(jobs);
    }, 350);
  }
  $('#scanBaseRef').addEventListener('input', refreshEstimates);
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
  $('#runChoose').addEventListener('click', () => {
    $('#runOptions').hidden = true;
    const ref = state.project.source_type === 'zip' ? '' : $('#scanBaseRef').value.trim();
    openSelect(ref);
  });
  // ------------------------------------------------------------------ export
  function togglePopover(pop, btn, on) {
    pop.hidden = !on;
    btn.setAttribute('aria-expanded', String(on));
  }
  $('#exportBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    togglePopover($('#exportMenu'), $('#exportBtn'), $('#exportMenu').hidden);
  });
  document.addEventListener('click', (e) => {
    const pop = $('#exportMenu');
    if (!pop.hidden && !pop.contains(e.target)) togglePopover(pop, $('#exportBtn'), false);
  });

  async function download(url) {
    const res = await fetch(url);
    if (!res.ok) {
      let msg = `Export failed (${res.status})`;
      try { msg = (await res.json()).detail || msg; } catch (e) { /* not JSON */ }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const name = (/filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '') || [])[1] || 'review';
    const link = el('a', { href: URL.createObjectURL(blob), download: name });
    document.body.append(link);
    link.click();
    setTimeout(() => { URL.revokeObjectURL(link.href); link.remove(); }, 1000);
    return res;
  }

  document.querySelectorAll('[data-export]').forEach((btn) => btn.addEventListener('click', async () => {
    togglePopover($('#exportMenu'), $('#exportBtn'), false);
    if (!state.scan) return;
    const kind = btn.dataset.export;
    if (kind === 'pdf') { window.open(`/api/scans/${state.scan.id}/report.pdf`, '_blank', 'noopener'); return; }
    const ignored = $('#exportIgnored').checked ? '?ignored=true' : '';
    try {
      const res = await download(`/api/scans/${state.scan.id}/export/${kind}${ignored}`);
      if (kind === 'patch') {
        const applied = Number(res.headers.get('X-Fixes-Applied') || 0);
        const skipped = Number(res.headers.get('X-Fixes-Skipped') || 0);
        toast(applied ? `Patch has ${plural(applied, 'fix')}${skipped ? `; ${skipped} left out because the code changed or they overlap` : ''}. Apply with: git apply --3way`
          : 'No fixes could be applied: the code changed since the review, or no issue has a fix.', applied ? '' : 'error');
      } else toast('Export downloaded');
    } catch (e) { toast(e.message, 'error'); }
  }));

  // ------------------------------------------------------------------ results
  function renderResult() {
    const r = state.result;
    if (!r) return;
    renderVerdict(r);
    renderChange(r);
    renderSeverity(r);
    renderSummary(r);
    renderBanner();
    renderCompare(r);
    renderTrend();
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
    if (s.selection && s.selection.length) extra.unshift('selected files only');
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

  function renderBanner() {
    show($('#oldBanner'), state.viewingOld);
    if (state.viewingOld && state.scan) {
      const when = new Date(state.scan.finished_at || state.scan.started_at);
      $('#oldBannerText').textContent = `You're looking at an older review, from ${when.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}. Ignoring issues works on the latest review only.`;
    }
  }

  // ------------------------------------------------------------------ comparison and trend
  function renderCompare(r) {
    const cmp = r.comparison;
    const card = $('#compareCard');
    clear($('#fixedList'));
    show($('#fixedList'), false);
    $('#cmpFixed').classList.remove('active');
    show($('#newOnlyLabel'), Boolean(cmp));
    if (!cmp) {
      card.classList.add('no-compare');
      $('#cmpNewCount').textContent = '–';
      $('#cmpFixedCount').textContent = '–';
      $('#cmpOpenCount').textContent = '–';
      $('#compareFoot').textContent = 'This is the first review of this project. The next one will show what is new and what got fixed.';
      return;
    }
    card.classList.remove('no-compare');
    const live = r.findings.filter((f) => !isHidden(f));
    const fresh = live.filter((f) => f.is_new).length;
    $('#cmpNewCount').textContent = fresh;
    $('#cmpFixedCount').textContent = cmp.fixed.length;
    $('#cmpOpenCount').textContent = live.length - fresh;
    $('#cmpNew').classList.toggle('active', state.filters.newOnly);
    $('#cmpNew').disabled = !fresh;
    $('#cmpFixed').disabled = !cmp.fixed.length;
    const prev = cmp.previous_finished_at ? timeAgo(cmp.previous_finished_at) : 'before';
    $('#compareFoot').textContent = `Compared with the review from ${prev} (${plural(cmp.previous_issues || 0, 'issue')}).`;
    const list = $('#fixedList');
    for (const f of cmp.fixed.slice(0, 200)) {
      list.append(el('div', { class: 'fixed-item' }, el('span', { class: `sev b-${f.severity}`, text: f.severity === 'CRITICAL' ? 'CRIT' : f.severity }),
        el('span', { class: 'fixed-title', text: f.title }), el('span', { class: 'mono muted', text: `${f.file_path}:${f.line}` })));
    }
  }

  $('#cmpNew').addEventListener('click', () => {
    state.filters.newOnly = !state.filters.newOnly;
    $('#newOnly').checked = state.filters.newOnly;
    $('#cmpNew').classList.toggle('active', state.filters.newOnly);
    renderFindings();
    if (state.filters.newOnly) $('#findingList').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
  $('#cmpFixed').addEventListener('click', () => {
    const list = $('#fixedList');
    show(list, list.hidden);
    $('#cmpFixed').classList.toggle('active', !list.hidden);
  });

  function svg(tag, attrs, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return node;
  }

  function renderTrend() {
    const box = clear($('#trendChart'));
    const hist = state.history || [];
    if (hist.length < 2) {
      box.append(el('div', { class: 'chart-empty', text: hist.length ? 'Run another review to start the trend.' : 'No finished reviews yet.' }));
      return;
    }
    const W = 560; const H = 170; const L = 34; const R = 14; const T = 14; const B = 26;
    const max = Math.max(4, ...hist.map((h) => h.issues || 0));
    const step = hist.length > 1 ? (W - L - R) / (hist.length - 1) : 0;
    const x = (i) => L + i * step;
    const y = (v) => T + (H - T - B) * (1 - v / max);
    const chart = svg('svg', { viewBox: `0 0 ${W} ${H}`, class: 'chart', role: 'img', 'aria-label': 'Number of issues in each review' });
    [0, 0.5, 1].forEach((t) => {
      const v = Math.round(max * t);
      chart.append(svg('line', { x1: L, x2: W - R, y1: y(v), y2: y(v), class: 'grid' }),
        svg('text', { x: L - 8, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, v));
    });
    const pts = hist.map((h, i) => `${x(i)},${y(h.issues || 0)}`);
    chart.append(svg('path', { d: `M${x(0)},${y(0)} L${pts.join(' L')} L${x(hist.length - 1)},${y(0)} Z`, class: 'area' }),
      svg('path', { d: `M${pts.join(' L')}`, class: 'line' }));
    const day = (iso) => new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
    chart.append(svg('text', { x: x(0), y: H - 6, 'text-anchor': 'start', class: 'tick' }, day(hist[0].finished_at)),
      svg('text', { x: x(hist.length - 1), y: H - 6, 'text-anchor': 'end', class: 'tick' }, day(hist[hist.length - 1].finished_at)));
    hist.forEach((h, i) => {
      const current = state.scan && state.scan.id === h.id;
      const sev = h.by_severity || {};
      const tip = `${new Date(h.finished_at).toLocaleString()}\n${h.verdict_label || h.verdict}: ${plural(h.issues || 0, 'issue')}`
        + ` (${sev.CRITICAL || 0} critical, ${sev.HIGH || 0} high)\n${h.base_ref ? `changes since ${h.base_ref}` : 'whole project'}`
        + `${h.selection ? ', selected files only' : ''}`;
      const g = svg('g', { class: 'pt-hit', tabindex: '0', role: 'button', 'aria-label': tip.replace(/\n/g, '. ') },
        svg('title', null, tip),
        svg('circle', { cx: x(i), cy: y(h.issues || 0), r: 12, class: 'hit' }),
        svg('circle', { cx: x(i), cy: y(h.issues || 0), r: current ? 6.5 : 4.5,
          class: `pt v-${h.verdict}${current ? ' current' : ''}${h.selection ? ' partial' : ''}` }));
      g.addEventListener('click', () => openScan(h.id));
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openScan(h.id); } });
      chart.append(g);
    });
    box.append(chart);
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
    state.filters = { sev: new Set(SEVERITIES), cat: '', q: '', fixOnly: false, showHidden: false, file: '', newOnly: false };
    $('#searchInput').value = '';
    $('#newOnly').checked = false;
    $('#cmpNew').classList.remove('active');
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
  $('#newOnly').addEventListener('change', (e) => {
    state.filters.newOnly = e.target.checked;
    $('#cmpNew').classList.toggle('active', e.target.checked);
    renderFindings();
  });
  $('#showHidden').addEventListener('change', (e) => { state.filters.showHidden = e.target.checked; renderFindings(); });
  $('#clearFilters').addEventListener('click', () => resetFilters(true));

  function matches(f) {
    const flt = state.filters;
    if (!flt.showHidden && isHidden(f)) return false;
    if (!flt.sev.has(f.severity)) return false;
    if (flt.cat && f.category !== flt.cat) return false;
    if (flt.file && f.file_path !== flt.file) return false;
    if (flt.fixOnly && !f.fix) return false;
    if (flt.newOnly && !f.is_new) return false;
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
      const msg = r.findings.length ? 'No issues match these filters.' : `The AI found no issues in the ${r.base_ref ? 'changed code' : 'project'}.`;
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
    if (f.is_new && state.result && state.result.comparison) sub.push(el('span', { class: 'tag fresh', text: 'new' }));
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
    if (f.is_new && state.result.comparison) body.append(el('div', { class: 'note fresh-note', text: 'New since the previous review.' }));
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
    if (state.viewingOld) {
      actions.append(el('span', { class: 'muted small', text: 'Open the latest review to ignore or restore issues.' }));
    } else if (userSuppressed) {
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
      loadHistory();
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

  // ------------------------------------------------------------------ choose files
  const sel = { files: [], byPath: new Map(), root: null, chosen: new Set(), open: new Set(), base: '', q: '' };

  function buildTree(files) {
    const root = { name: '', path: '', dirs: new Map(), files: [] };
    for (const f of files) {
      const parts = f.path.split('/');
      let node = root;
      parts.slice(0, -1).forEach((part, i) => {
        if (!node.dirs.has(part)) node.dirs.set(part, { name: part, path: parts.slice(0, i + 1).join('/'), dirs: new Map(), files: [] });
        node = node.dirs.get(part);
      });
      node.files.push(f);
    }
    // collapse single-child folder chains (src/main/java/com/acme → one row)
    const squash = (node) => {
      for (const [key, child] of [...node.dirs]) {
        let c = child;
        while (c.files.length === 0 && c.dirs.size === 1) {
          const only = [...c.dirs.values()][0];
          c = { ...only, name: `${c.name}/${only.name}` };
        }
        node.dirs.set(key, c);
        squash(c);
      }
    };
    squash(root);
    const tally = (node) => {
      node.all = [...node.files.filter((f) => f.reviewable)];
      node.lines = node.all.reduce((a, f) => a + f.lines, 0);
      for (const d of node.dirs.values()) { tally(d); node.all.push(...d.all); node.lines += d.lines; }
    };
    tally(root);
    return root;
  }

  function folderState(node) {
    let on = 0;
    for (const f of node.all) if (sel.chosen.has(f.path)) on += 1;
    return on === 0 ? 'none' : on === node.all.length ? 'all' : 'some';
  }

  function checkbox(stateName, onChange, disabled) {
    const box = el('input', { type: 'checkbox', disabled: disabled || null, tabindex: '-1' });
    box.checked = stateName === 'all';
    box.indeterminate = stateName === 'some';
    box.addEventListener('change', onChange);
    return box;
  }

  function fileRow(f, depth, showPath) {
    const on = sel.chosen.has(f.path);
    return el('label', { class: `tree-row file${f.reviewable ? '' : ' disabled'}`, style: { paddingLeft: `${8 + depth * 18}px` }, title: f.note || f.path },
      checkbox(on ? 'all' : 'none', (e) => { if (e.target.checked) sel.chosen.add(f.path); else sel.chosen.delete(f.path); afterSelect(); }, !f.reviewable),
      icon('file'), el('span', { class: 'tree-name' }, el('bdi', { text: showPath ? f.path : f.path.split('/').pop() })),
      el('span', { class: 'tree-meta', text: f.reviewable ? `${fmt(f.lines)} lines` : (f.note || 'skipped') }));
  }

  function folderRows(node, depth, out) {
    const dirs = [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name));
    for (const d of dirs) {
      const open = sel.open.has(d.path);
      const st = folderState(d);
      const row = el('div', { class: `tree-row folder${open ? ' open' : ''}`, style: { paddingLeft: `${8 + depth * 18}px` }, role: 'treeitem', 'aria-expanded': String(open) },
        el('button', { type: 'button', class: 'tree-toggle', 'aria-label': open ? 'Collapse' : 'Expand',
          onclick: () => { if (open) sel.open.delete(d.path); else sel.open.add(d.path); renderTree(); } }, icon('chevron')),
        checkbox(st, (e) => { for (const f of d.all) { if (e.target.checked) sel.chosen.add(f.path); else sel.chosen.delete(f.path); } afterSelect(); }, !d.all.length),
        icon('folder'),
        el('button', { type: 'button', class: 'tree-name link', onclick: () => { if (open) sel.open.delete(d.path); else sel.open.add(d.path); renderTree(); } }, el('bdi', { text: d.name })),
        el('span', { class: 'tree-meta', text: `${plural(d.all.length, 'file')} · ${fmt(d.lines)} lines` }));
      out.push(row);
      if (open) folderRows(d, depth + 1, out);
    }
    for (const f of [...node.files].sort((a, b) => a.path.localeCompare(b.path))) out.push(fileRow(f, depth, false));
  }

  function renderTree() {
    const box = clear($('#tree'));
    if (!sel.root) return;
    const rows = [];
    if (sel.q) {
      const hits = sel.files.filter((f) => f.path.toLowerCase().includes(sel.q));
      hits.slice(0, 400).forEach((f) => rows.push(fileRow(f, 0, true)));
      if (!hits.length) rows.push(el('div', { class: 'list-empty', text: 'No files match.' }));
      if (hits.length > 400) rows.push(el('div', { class: 'muted small tree-more', text: `${hits.length - 400} more; narrow the filter.` }));
    } else folderRows(sel.root, 0, rows);
    box.append(...rows);
  }

  // smallest list of paths that covers the selection: whole folders where possible
  function compactSelection() {
    const out = [];
    const walk = (node) => {
      const st = folderState(node);
      if (st === 'none') return;
      if (st === 'all' && node.path) { out.push(node.path); return; }
      for (const d of node.dirs.values()) walk(d);
      for (const f of node.files) if (sel.chosen.has(f.path)) out.push(f.path);
    };
    walk(sel.root);
    return out;
  }

  let selTimer = null;
  let selSeq = 0;
  function afterSelect() {
    renderTree();
    const total = sel.root ? sel.root.all.length : 0;
    const n = sel.chosen.size;
    $('#selectRun').disabled = n === 0;
    $('#selectRun').lastChild.textContent = n === total ? 'Review all' : `Review ${plural(n, 'file')}`;
    const box = $('#selectEstimate');
    if (!n) { box.textContent = 'Nothing selected.'; return; }
    box.textContent = `${plural(n, 'file')} selected · estimating…`;
    clearTimeout(selTimer);
    const seq = ++selSeq;
    selTimer = setTimeout(async () => {
      try {
        const est = await estimate({ base_ref: sel.base || null, whole_project: !sel.base, paths: n === total ? [] : compactSelection() });
        if (seq === selSeq) box.textContent = estimateText(est) + quotaWarning(est.requests);
      } catch (e) { if (seq === selSeq) box.textContent = e.message; }
    }, 400);
  }

  async function openSelect(base) {
    const p = state.project;
    Object.assign(sel, { files: [], root: null, base, q: '' });
    sel.chosen = new Set();
    sel.open = new Set();
    $('#selectSearch').value = '';
    $('#selectScope').textContent = base ? `Files changed since ${base}` : 'Whole project';
    clear($('#tree')).append(el('div', { class: 'list-empty' }, el('div', { class: 'spinner' }), 'Listing files…'));
    $('#selectEstimate').textContent = '';
    $('#selectRun').disabled = true;
    $('#selectModal').showModal();
    let data;
    try {
      data = await api('GET', `/api/projects/${p.id}/files?${new URLSearchParams(base ? { base_ref: base } : { whole_project: 'true' })}`);
    } catch (e) {
      clear($('#tree')).append(el('div', { class: 'form-error', text: e.message }));
      return;
    }
    if (!state.project || state.project.id !== p.id) return;
    sel.files = data.files;
    sel.byPath = new Map(data.files.map((f) => [f.path, f]));
    sel.root = buildTree(data.files);
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(`cr-sel-${p.id}`) || 'null'); } catch (e) { /* storage unavailable */ }
    const inSaved = (path) => saved.some((s2) => path === s2 || path.startsWith(`${s2}/`));
    for (const f of data.files) if (f.reviewable && (!saved || !saved.length || inSaved(f.path))) sel.chosen.add(f.path);
    if (!sel.chosen.size) for (const f of data.files) if (f.reviewable) sel.chosen.add(f.path);
    // open the first levels so the structure is visible
    const openTop = (node, depth) => { for (const d of node.dirs.values()) { if (depth < 2) { sel.open.add(d.path); openTop(d, depth + 1); } } };
    openTop(sel.root, 0);
    if (!data.files.length) {
      clear($('#tree')).append(el('div', { class: 'list-empty', text: base ? `Nothing changed since ${base}.` : 'No reviewable files found.' }));
      return;
    }
    afterSelect();
  }

  let selSearchTimer = null;
  $('#selectSearch').addEventListener('input', (e) => {
    clearTimeout(selSearchTimer);
    selSearchTimer = setTimeout(() => { sel.q = e.target.value.trim().toLowerCase(); renderTree(); }, 120);
  });
  $('#selectAll').addEventListener('click', () => {
    const pool = sel.q ? sel.files.filter((f) => f.path.toLowerCase().includes(sel.q)) : sel.files;
    for (const f of pool) if (f.reviewable) sel.chosen.add(f.path);
    afterSelect();
  });
  $('#selectNone').addEventListener('click', () => {
    if (sel.q) { for (const f of sel.files) if (f.path.toLowerCase().includes(sel.q)) sel.chosen.delete(f.path); } else sel.chosen.clear();
    afterSelect();
  });
  $('#selectForm').addEventListener('submit', (e) => {
    e.preventDefault();
    if (!sel.chosen.size || !sel.root) return;
    const all = sel.chosen.size === sel.root.all.length;
    const paths = all ? [] : compactSelection();
    try { localStorage.setItem(`cr-sel-${state.project.id}`, JSON.stringify(paths)); } catch (err) { /* storage unavailable */ }
    $('#selectModal').close();
    runScan({ base_ref: sel.base || null, whole_project: !sel.base, paths });
  });

  // ------------------------------------------------------------------ AI settings
  const settingsForm = $('#settingsForm');
  const NUMBER_FIELDS = ['max_lines_per_request', 'max_workers', 'max_files', 'whole_file_up_to', 'context_lines', 'daily_request_limit'];
  let settingsData = null;

  function fillProviders() {
    const select = clear($('#setProvider'));
    const keys = settingsData.keys || {};
    const name = { gemini: 'Gemini', groq: 'Groq', openai: 'OpenAI', ollama: 'Ollama (local)' };
    select.append(el('option', { value: '', text: 'Automatic (from the key in .env)' }));
    for (const p of ['gemini', 'groq', 'openai', 'ollama']) {
      const note = p === 'ollama' ? '' : keys[p] ? ' · key found' : ' · no key in .env';
      select.append(el('option', { value: p, text: `${name[p]}${note}` }));
    }
  }

  function updateModelPlaceholder() {
    const provider = $('#setProvider').value || (state.ai && state.ai.provider) || '';
    const model = (settingsData.default_models || {})[provider];
    $('#setModel').placeholder = model ? `default: ${model}` : 'provider default';
  }

  function fillSettings(data) {
    settingsData = data;
    const v = data.values;
    fillProviders();
    const f = settingsForm.elements;
    f.provider.value = v.provider || '';
    f.model.value = v.model || '';
    f.focus.value = (v.focus || []).join('\n');
    f.min_confidence.value = v.min_confidence ?? 0.5;
    $('#confOut').textContent = `${Math.round(100 * Number(f.min_confidence.value))}%`;
    f.summary.checked = v.summary !== false;
    for (const k of NUMBER_FIELDS) f[k].value = v[k] ?? 0;
    f.exclude.value = (v.exclude || []).join('\n');
    $('#settingsFile').textContent = data.customized.length
      ? `Changed from reviewer.yml: ${data.customized.join(', ')}. Saved in ${data.file}.`
      : 'Using the values from reviewer.yml.';
    updateModelPlaceholder();
  }

  async function openSettings() {
    show($('#settingsError'), false);
    $('#testAiResult').textContent = '';
    try { fillSettings(await api('GET', '/api/settings')); } catch (e) { toast(e.message, 'error'); return; }
    $('#settingsModal').showModal();
  }
  $('#aiSettingsBtn').addEventListener('click', () => { openSidebar(false); openSettings(); });
  $('#setProvider').addEventListener('change', updateModelPlaceholder);
  settingsForm.elements.min_confidence.addEventListener('input', (e) => { $('#confOut').textContent = `${Math.round(100 * Number(e.target.value))}%`; });

  settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = settingsForm.elements;
    const lines = (text) => text.split('\n').map((x) => x.trim()).filter(Boolean);
    const body = {
      provider: f.provider.value, model: f.model.value.trim(), focus: lines(f.focus.value),
      min_confidence: Number(f.min_confidence.value), summary: f.summary.checked, exclude: lines(f.exclude.value),
    };
    for (const k of NUMBER_FIELDS) body[k] = Number(f[k].value || 0);
    $('#saveSettingsBtn').disabled = true;
    try {
      const data = await api('PUT', '/api/settings', body);
      state.ai = data.ai;
      $('#settingsModal').close();
      toast('Settings saved');
      loadAiStatus();
    } catch (err) {
      $('#settingsError').textContent = err.message;
      show($('#settingsError'), true);
    } finally { $('#saveSettingsBtn').disabled = false; }
  });

  $('#resetSettingsBtn').addEventListener('click', async () => {
    if (!window.confirm('Go back to the values in reviewer.yml? Your saved settings will be removed.')) return;
    try {
      const data = await api('DELETE', '/api/settings');
      fillSettings(data);
      toast('Settings reset to reviewer.yml');
      loadAiStatus();
    } catch (err) { toast(err.message, 'error'); }
  });

  $('#testAiBtn').addEventListener('click', async () => {
    const out = $('#testAiResult');
    out.className = 'small';
    out.textContent = 'Testing…';
    $('#testAiBtn').disabled = true;
    try {
      const res = await api('POST', '/api/ai/test');
      out.className = `small ${res.ok ? 'ok-text' : 'err-text'}`;
      out.textContent = res.ok ? `${res.label} works (${res.message})` : `${res.label}: ${res.message}`;
      loadAiStatus();
    } catch (err) {
      out.className = 'small err-text';
      out.textContent = err.message;
    } finally { $('#testAiBtn').disabled = false; }
  });

  // ------------------------------------------------------------------ project modal
  const projectForm = $('#projectForm');
  let editingId = null;

  function updateSourceHints() {
    const type = projectForm.elements.source_type.value;
    const zip = type === 'zip';
    const editingZip = Boolean(editingId) && state.project && state.project.source_type === 'zip';
    show($('#pathField'), !zip && !editingZip);
    show($('#branchField'), !zip && !editingZip);
    show($('#zipField'), zip || editingZip);
    $('#zipLabel').textContent = editingZip ? 'Upload a new version (optional)' : 'ZIP of the code';
    const github = type === 'github';
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
    const rulesCount = project ? (project.rules || '').split('\n').filter((x) => x.trim()).length : 0;
    $('#rulesCount').textContent = rulesCount ? `(${rulesCount})` : '';
    $('#rulesSection').open = rulesCount > 0;
    if (project) {
      for (const key of ['name', 'path_or_url', 'base_ref', 'rules', 'extra_exclude']) projectForm.elements[key].value = project[key] || '';
      projectForm.elements.source_type.value = project.source_type;
    }
    $('#saveProjectBtn').textContent = 'Save project';
    updateSourceHints();
    $('#projectModal').showModal();
    projectForm.elements.name.focus();
  }

  $('#addProjectBtn').addEventListener('click', () => openProjectModal(null));
  $('#welcomeAdd').addEventListener('click', () => openProjectModal(null));
  $('#settingsBtn').addEventListener('click', () => openProjectModal(state.project));

  // Upload with progress (fetch can't report upload progress).
  function uploadForm(url, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(Math.round((100 * e.loaded) / e.total)); };
      xhr.upload.onload = () => onProgress(100);
      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText); } catch (err) { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else {
          const detail = data && data.detail;
          reject(new Error(Array.isArray(detail) ? detail.map((d) => d.msg).join('; ') : detail || `Upload failed (${xhr.status})`));
        }
      };
      xhr.onerror = () => reject(new Error('Upload failed: the server could not be reached'));
      xhr.send(formData);
    });
  }

  projectForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(projectForm).entries());
    const zipFile = projectForm.elements.zip_file.files[0] || null;
    const isZip = data.source_type === 'zip' || (editingId && state.project && state.project.source_type === 'zip');
    const errorBox = $('#projectError');
    const saveBtn = $('#saveProjectBtn');
    show(errorBox, false);
    if (!data.name || (!editingId && !isZip && !data.path_or_url) || (!editingId && isZip && !zipFile)) {
      errorBox.textContent = isZip ? 'Give the project a name and choose a ZIP file.' : 'Name and path are required.';
      show(errorBox, true);
      return;
    }
    if (zipFile && !/\.zip$/i.test(zipFile.name)) {
      errorBox.textContent = 'Choose a .zip file.';
      show(errorBox, true);
      return;
    }
    saveBtn.disabled = true;
    const progressText = (pct) => { saveBtn.textContent = pct < 100 ? `Uploading ${pct}%` : 'Unpacking…'; };
    try {
      let project;
      if (!editingId && isZip) {
        const form = new FormData();
        form.append('name', data.name);
        form.append('file', zipFile);
        project = await uploadForm('/api/projects/zip', form, progressText);
        if (data.rules || data.extra_exclude) {
          project = await api('PATCH', `/api/projects/${project.id}`, { rules: data.rules, extra_exclude: data.extra_exclude });
        }
      } else if (editingId) {
        if (isZip && zipFile) {
          const form = new FormData();
          form.append('file', zipFile);
          await uploadForm(`/api/projects/${editingId}/zip`, form, progressText);
        }
        const patch = { name: data.name, rules: data.rules, extra_exclude: data.extra_exclude };
        if (!isZip) patch.base_ref = data.base_ref;
        project = await api('PATCH', `/api/projects/${editingId}`, patch);
      } else {
        project = await api('POST', '/api/projects', data);
      }
      $('#projectModal').close();
      await loadProjects();
      toast(editingId ? (zipFile ? 'New version uploaded' : 'Project saved') : 'Project added');
      if (editingId) { state.project = state.projects.find((p) => p.id === project.id); renderTopbar(); } else selectProject(project.id);
    } catch (err) {
      errorBox.textContent = err.message;
      show(errorBox, true);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save project';
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
