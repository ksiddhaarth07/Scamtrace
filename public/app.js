/* ScamTrace frontend — app.js
 *
 * All analysis runs locally (localAnalyze).  When window.SCAMTRACE_API is
 * set the app also tries the backend for /analyze, /reports and /signals.
 * No URLs are fetched, resolved, or opened.
 */

'use strict';

// ── Config ────────────────────────────────────────────────────────────────
const API = (window.SCAMTRACE_API || '').replace(/\/$/, '');
const PAGE_SIZE = 10;

// ── State ─────────────────────────────────────────────────────────────────
let activeKind = 'url';          // current tab
let signalPage = 0;              // current page index
let allSignals  = [];            // full filtered list
let rawSignals  = [];            // unfiltered signals from seed or API
let modToken    = null;          // moderator session token (memory only)

// ── Helpers ───────────────────────────────────────────────────────────────
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function toast(msg, kind = 'info') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast ${kind}`;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), 4000);
}

async function apiRequest(path, body, extraHeaders = {}) {
  if (!API) return null;
  const opts = {
    method: body ? 'POST' : 'GET',
    headers: { ...(body ? {'content-type': 'application/json'} : {}), ...extraHeaders },
    body: body ? JSON.stringify(body) : undefined,
  };
  const r = await fetch(API + path, opts);
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${r.status}`);
  }
  return r.json();
}

// ── Local analysis (runs even without API) ────────────────────────────────
// Mirrors the Python analysis.py rules so the demo works fully offline.

const URL_SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','ow.ly','is.gd','buff.ly',
  'adf.ly','goo.gl','rb.gy','cutt.ly','shorturl.at','tiny.cc',
]);
const SUSPICIOUS_TLDS = ['.top','.click','.xyz','.loan','.win','.gq','.tk','.cf','.ml','.ga','.work'];
const BRANDS = ['paypal','amazon','netflix','apple','google','microsoft','facebook','instagram',
  'whatsapp','fedex','dhl','ups','usps','hmrc','irs','visa','mastercard','barclays','hsbc',
  'lloyds','natwest','santander','chase','wellsfargo','bankofamerica'];
const URGENCY_RE = /\b(urgent|immediately|right away|act now|expires?|deadline|limited time|last chance|within 24 hours?|within 48 hours?|suspended|locked|blocked|compromised|unauthorized|verify now|confirm (your|details|identity|account)|click here now|respond immediately|warning|alert|your account)\b/i;
const PAYMENT_RE = /\b(fee|payment|pay (a |the )?small|transfer|wire|bitcoin|crypto|gift card|voucher|redelivery|customs charge|release fee|admin fee|prize|winner|won|reward|claim (your|a|the)|refund|cashback|lottery|inheritance|advance fee|investment|guaranteed return)\b/ig;
const CRED_RE = /\b(password|passcode|pin|ssn|social security|date of birth|credit card|debit card|card number|cvv|sort code|bank account|routing number|login|sign in|verify identity)\b/i;
const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;
const PHONE_RE = /(?<!\w)\+?[0-9][\d ()\-]{7,}[0-9](?!\w)/;

function extractDomain(raw) {
  try {
    const url = new URL(raw.includes('://') ? raw : 'https://' + raw);
    return url.hostname.replace(/^www\./, '').toLowerCase();
  } catch { return null; }
}

function isPunycode(domain) {
  return domain.split('.').some(l => l.startsWith('xn--'));
}

function localAnalyze(value, kind) {
  const lower = value.toLowerCase();
  const signals = [];
  let score = 0;

  // ── URL-specific ──────────────────────────────────────────────────────
  const urlMatch = /https?:\/\/\S+/i.exec(value);
  if (urlMatch || kind === 'url') {
    const raw = urlMatch ? urlMatch[0] : value;
    const domain = extractDomain(raw);
    if (domain) {
      signals.push('Contains a web link (not opened or fetched).');
      score += 5;

      if (URL_SHORTENERS.has(domain)) {
        signals.push('Uses a URL shortener — the final destination is hidden.'); score += 40;
      }
      if (isPunycode(domain)) {
        signals.push('Domain uses punycode encoding — may be a homoglyph lookalike.'); score += 30;
      }
      if (/[^\x00-\x7F]/.test(domain)) {
        signals.push('Domain contains non-ASCII characters that may imitate familiar letters.'); score += 35;
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        signals.push('URL uses a raw IP address instead of a domain name.'); score += 40;
      }
      if (SUSPICIOUS_TLDS.some(t => domain.endsWith(t))) {
        signals.push('Domain ends with a TLD commonly associated with scam infrastructure.'); score += 20;
      }
      const domParts = domain.split('.');
      const registrableRoot = domParts.length >= 2 ? domParts[domParts.length - 2] : domain;
      for (const brand of BRANDS) {
        if (domain.includes(brand) && !registrableRoot.includes(brand)) {
          signals.push('A brand name appears in the URL but the registrable domain is unrelated — a common impersonation pattern.'); score += 35; break;
        }
      }
      if (domParts.length >= 5) { signals.push('URL has an unusually large number of subdomain levels.'); score += 15; }
      const firstLabel = domParts[0];
      if (domParts.length >= 3 && firstLabel.length >= 12 && (firstLabel.length >= 16 || (/[0-9]/.test(firstLabel) && /[a-z]/i.test(firstLabel)))) {
        signals.push('Subdomain appears long and randomly generated.'); score += 15;
      }
      if (/secure|verify|update|login|signin|account|validate|confirm/.test(domain)) {
        signals.push('Security-sounding words appear in the domain name.'); score += 20;
      }
    }
  }

  // ── Content-level ─────────────────────────────────────────────────────
  if (URGENCY_RE.test(lower)) { signals.push('Contains urgency or account-pressure language.'); score += 20; }

  const paymentMatches = [...lower.matchAll(PAYMENT_RE)];
  const uniquePayment = new Set(paymentMatches.map(m => m[0]));
  if (uniquePayment.size >= 4) { signals.push('Mentions fees, payments, prizes, or refunds — common scam lures.'); score += 45; }
  else if (uniquePayment.size >= 2) { signals.push('Mentions fees, payments, prizes, or refunds — common scam lures.'); score += 30; }
  else if (uniquePayment.size >= 1) { signals.push('Mentions fees, payments, prizes, or refunds — common scam lures.'); score += 20; }

  if (CRED_RE.test(lower)) { signals.push('Asks for credentials or sensitive personal information.'); score += 30; }

  for (const brand of BRANDS) {
    if (lower.includes(brand)) {
      signals.push('Mentions a recognizable brand name — verify the sender through that brand\'s official website.'); score += 20; break;
    }
  }

  const urlCount = (value.match(/https?:\/\//g) || []).length;
  if (urlCount >= 3) { signals.push('Contains multiple links — unusual for legitimate messages.'); score += 15; }

  if (EMAIL_RE.test(value) || PHONE_RE.test(value)) { signals.push('The text may contain personal contact information — avoid submitting personal details.'); score += 10; }

  // ── Score → risk ──────────────────────────────────────────────────────
  score = Math.min(score, 100);
  const risk = score >= 45 ? 'High' : score >= 20 ? 'Medium' : 'Low';

  if (!signals.length) {
    signals.push('No common scam patterns detected. This does not confirm the content is safe.');
  }

  const advice = risk === 'High'
    ? 'Do not click links, provide information, or make payments. Contact the organization through its official website or phone number only.'
    : risk === 'Medium'
      ? 'Treat with caution. Verify the sender independently through the organization\'s official contact details — not through any link or number in this message.'
      : 'No strong risk signals found. Still verify the sender through official channels if anything feels off.';

  return {
    risk, score, signals, advice,
    source: 'local-heuristic',
    disclaimer: 'This is a heuristic screen — no link was opened or fetched. A low-risk result does not confirm safety. Always verify through official channels.',
  };
}

// ── Render analysis result ────────────────────────────────────────────────
function showAnalysis(r) {
  const out = $('#analysis-result');
  out.classList.remove('hidden', 'high', 'medium', 'safe', 'loading');
  out.classList.add(r.risk === 'High' ? 'high' : r.risk === 'Medium' ? 'medium' : 'safe');

  const sourceNote = r.source === 'local-heuristic'
    ? '<span class="notice demo" style="display:inline-flex;gap:6px;padding:4px 8px;font-size:11px;border-radius:4px;margin-bottom:10px;">◈ Local heuristic — no network request made</span>'
    : '';

  out.innerHTML = `
    ${sourceNote}
    <div class="result-header">
      <span class="risk-badge ${esc(r.risk)}">${esc(r.risk)} RISK</span>
      <span style="font-size:12px;color:var(--text3);">Score: ${esc(r.score)}/100</span>
    </div>
    <ul>${(r.signals || []).map(s => `<li>${esc(s)}</li>`).join('')}</ul>
    ${r.advice ? `<div class="result-advice">💡 ${esc(r.advice)}</div>` : ''}
    <div class="result-disclaimer">${esc(r.disclaimer || '')}</div>
  `;
}

// ── Analyze form ──────────────────────────────────────────────────────────
$('#analyze-form').addEventListener('submit', async e => {
  e.preventDefault();
  const value = $('#analyze-input').value.trim();
  const errEl = $('#analyze-error');

  if (!value) {
    errEl.textContent = 'Enter a URL or message to analyze.';
    errEl.classList.add('visible');
    $('#analyze-input').setAttribute('aria-invalid', 'true');
    return;
  }
  errEl.classList.remove('visible');
  $('#analyze-input').removeAttribute('aria-invalid');

  if (value.length > 2000) {
    errEl.textContent = 'Input must be 2,000 characters or fewer.';
    errEl.classList.add('visible');
    return;
  }

  const out = $('#analysis-result');
  const btn = $('#analyze-btn');
  out.classList.remove('hidden', 'high', 'medium', 'safe');
  out.classList.add('loading');
  out.innerHTML = '<div class="skeleton" style="height:80px"></div>';
  btn.disabled = true;
  btn.textContent = 'Analyzing…';

  try {
    let result = null;
    if (API) {
      result = await apiRequest('/analyze', { kind: activeKind, input: value })
                      .catch(() => null);
    }
    showAnalysis(result || localAnalyze(value, activeKind));
  } catch {
    out.innerHTML = '<strong>Analysis temporarily unavailable.</strong><br>Your text was not saved. Try again in a moment.';
    out.classList.remove('loading');
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Analyze signal <span>→</span>';
    out.classList.remove('loading');
  }
});

// ── Tab switching ─────────────────────────────────────────────────────────
$$('.tab').forEach(b => b.addEventListener('click', () => {
  $$('.tab').forEach(x => { x.classList.remove('active'); x.setAttribute('aria-selected','false'); });
  b.classList.add('active');
  b.setAttribute('aria-selected', 'true');
  activeKind = b.dataset.kind;
  const label = $('#input-label');
  const input = $('#analyze-input');
  label.textContent = activeKind === 'url' ? 'SUSPICIOUS URL' : 'SUSPICIOUS MESSAGE';
  input.placeholder = activeKind === 'url'
    ? 'https://something-doesnt-feel-right.com'
    : 'Paste the message here — remove private details first.';
  $('#analysis-result').classList.add('hidden');
  input.focus();
}));

// ── Example buttons ───────────────────────────────────────────────────────
$$('[data-example]').forEach(b => b.addEventListener('click', () => {
  const isUrl = b.dataset.example === 'url';
  document.querySelector(`.tab[data-kind="${isUrl ? 'url' : 'message'}"]`).click();
  $('#analyze-input').value = isUrl
    ? 'https://secure-parcel-track.example/fee?ref=48291'
    : 'URGENT: Your bank account has been locked. Verify immediately at http://bank-secure-login.xyz or access will be suspended within 24 hours.';
  $('#analyze-input').focus();
  // Auto-submit so the demo flow is smooth.
  setTimeout(() => $('#analyze-form').dispatchEvent(new Event('submit', {bubbles:true,cancelable:true})), 100);
}));

// ── Character counter ─────────────────────────────────────────────────────
$('#analyze-input').addEventListener('input', () => {
  const len = $('#analyze-input').value.length;
  const counter = $('#analyze-char-count');
  counter.textContent = `${len} / 2000`;
  counter.className = 'char-counter' + (len > 1800 ? ' warn' : '') + (len > 2000 ? ' error' : '');
});
$('#report-detail').addEventListener('input', () => {
  const len = $('#report-detail').value.length;
  const counter = $('#report-char-count');
  counter.textContent = `${len} / 1000`;
  counter.className = 'char-counter' + (len > 800 ? ' warn' : '') + (len > 1000 ? ' error' : '');
});

// ── Report form ───────────────────────────────────────────────────────────
$('#report-form').addEventListener('submit', async e => {
  e.preventDefault();
  const description = $('#report-detail').value.trim();
  const category = $('#report-type').value;
  const errEl = $('#report-error');
  const resultEl = $('#report-result');
  const btn = $('#report-btn');

  errEl.classList.remove('visible');
  resultEl.classList.add('hidden');

  if (!description) {
    errEl.textContent = 'Describe the scam before submitting.';
    errEl.classList.add('visible');
    $('#report-detail').setAttribute('aria-invalid','true');
    return;
  }
  if (description.length > 1000) {
    errEl.textContent = 'Description must be 1,000 characters or fewer.';
    errEl.classList.add('visible');
    return;
  }
  $('#report-detail').removeAttribute('aria-invalid');

  btn.disabled = true;
  btn.textContent = 'Submitting…';

  try {
    if (API) {
      const saved = await apiRequest('/reports', { category, description });
      resultEl.className = 'report-success';
      resultEl.innerHTML = `
        <strong>Report received — thank you.</strong><br>
        Your report is stored privately and excluded from the public feed until a moderator reviews it.
        It will be automatically deleted after 90 days.<br>
        <small>Reference: ${esc(saved.reference || '')}</small>
      `;
    } else {
      resultEl.className = 'report-success local';
      resultEl.innerHTML = `
        <strong>Demo mode — no report was sent or saved.</strong><br>
        Connect the ScamTrace API to submit a private report.
        In a live deployment your report would be stored privately
        and reviewed before any indicator becomes public.
      `;
    }
    resultEl.classList.remove('hidden');
    $('#report-detail').value = '';
    $('#report-char-count').textContent = '0 / 1000';
    toast(API ? 'Report received for private review.' : 'Demo only — no data was sent.', API ? 'success' : 'info');
  } catch (err) {
    resultEl.className = 'report-success error';
    resultEl.innerHTML = `<strong>Could not submit right now.</strong><br>${esc(err.message || 'Please try again.')}`;
    resultEl.classList.remove('hidden');
    toast('Submission failed. Please try again.', 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Submit report <span>→</span>';
  }
});

// ── Signal feed / table ───────────────────────────────────────────────────
function applyFilters() {
  const q = ($('#search-input').value || '').trim().toLowerCase();
  const sev = $('#filter-severity').value;
  allSignals = rawSignals.filter(x =>
    (sev === 'all' || x.risk === sev) &&
    (!q || [x.indicator, x.type, x.summary, x.reviewStatus].join(' ').toLowerCase().includes(q))
  );
  signalPage = 0;
  renderTable();
}

function renderTable() {
  const start = signalPage * PAGE_SIZE;
  const page  = allSignals.slice(start, start + PAGE_SIZE);
  const tbody = $('#threat-rows');

  if (!page.length) {
    tbody.innerHTML = '';
    $('#empty-state').classList.remove('hidden');
  } else {
    $('#empty-state').classList.add('hidden');
    tbody.innerHTML = page.map(x => `
      <tr tabindex="0" aria-label="${esc(x.indicator)} — ${esc(x.risk)} risk">
        <td><span class="indicator"><i class="type-icon">${typeIcon(x.type)}</i>${esc(x.indicator)}</span></td>
        <td>${esc(x.type)}</td>
        <td><span class="risk ${esc(x.risk)}">${esc(x.risk)}</span></td>
        <td>${esc(x.firstSeen || x.seen || '—')}</td>
        <td>${esc(x.reportCount || x.reports || '—')}</td>
        <td><span class="status">● &nbsp;${esc(x.reviewStatus || x.status || '—')}</span>${x.confidence === 'Sample' ? '<span class="sample-badge">SAMPLE</span>' : ''}</td>
      </tr>
    `).join('');
  }

  $('#showing-count').textContent = page.length;
  $('#total-count').textContent = allSignals.length;

  // Pagination buttons.
  const totalPages = Math.ceil(allSignals.length / PAGE_SIZE);
  renderPagination(totalPages);
}

function typeIcon(type) {
  if (!type) return '◉';
  const t = type.toLowerCase();
  if (t.includes('url')) return '↗';
  if (t.includes('sms') || t.includes('text')) return '▤';
  if (t.includes('email')) return '✉';
  if (t.includes('payment')) return '◈';
  return '◉';
}

function renderPagination(totalPages) {
  const container = $('#pagination');
  if (!container) return;
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  let html = '';
  if (signalPage > 0) html += `<button class="page-btn" data-page="${signalPage - 1}" aria-label="Previous page">← Prev</button>`;
  for (let i = 0; i < totalPages; i++) {
    html += `<button class="page-btn${i === signalPage ? ' active' : ''}" data-page="${i}" aria-label="Page ${i + 1}" aria-current="${i === signalPage ? 'page' : 'false'}">${i + 1}</button>`;
  }
  if (signalPage < totalPages - 1) html += `<button class="page-btn" data-page="${signalPage + 1}" aria-label="Next page">Next →</button>`;
  container.innerHTML = html;

  container.querySelectorAll('[data-page]').forEach(btn => {
    btn.addEventListener('click', () => {
      signalPage = parseInt(btn.dataset.page, 10);
      renderTable();
      $('#signals').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  });
}

$('#search-input').addEventListener('input', applyFilters);
$('#filter-severity').addEventListener('change', applyFilters);

async function loadSignals() {
  let data = null;
  if (API) {
    data = await apiRequest('/signals').catch(() => null);
  }

  if (data?.items?.length) {
    rawSignals = data.items;
    if (data.notice) {
      $('#feed-notice').textContent = data.notice;
      $('#feed-notice').classList.remove('hidden');
    }
  } else {
    // Show seed data with clear SAMPLE labelling (defined in constants below).
    rawSignals = SEED_DATA;
  }

  applyFilters();
  $('#showing-count').textContent = Math.min(PAGE_SIZE, rawSignals.length);
  $('#total-count').textContent = rawSignals.length;
}

// Synthetic seed data — clearly labelled SAMPLE, not real threat intelligence.
const SEED_DATA = [
  { indicator: 'secure-parcel-track.example', type: 'URL', risk: 'High', firstSeen: '2026-11-01', reportCount: 38, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Fake parcel tracking domain — synthetic demo data.' },
  { indicator: '"Account locked" bank impersonation SMS', type: 'SMS pattern', risk: 'High', firstSeen: '2026-11-08', reportCount: 24, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Template SMS claiming online banking is locked — synthetic demo data.' },
  { indicator: 'claim-reward-2026.example', type: 'URL', risk: 'High', firstSeen: '2026-11-10', reportCount: 19, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Prize-claim domain with suspicious TLD — synthetic demo data.' },
  { indicator: 'QuickLoan Pro brand impersonation', type: 'Impersonation', risk: 'Medium', firstSeen: '2026-11-11', reportCount: 12, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Fabricated lender brand soliciting upfront fees — synthetic demo data.' },
  { indicator: '"Package held — pay redelivery fee" email', type: 'Email pattern', risk: 'Medium', firstSeen: '2026-11-09', reportCount: 9, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Delivery-lure email requesting a small redelivery fee — synthetic demo data.' },
  { indicator: 'Crypto recovery advance fee scheme', type: 'Payment fraud', risk: 'High', firstSeen: '2026-11-07', reportCount: 7, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Advance fee fraud claiming to recover lost crypto — synthetic demo data.' },
  { indicator: 'marketplace-payment-help.example', type: 'URL', risk: 'Medium', firstSeen: '2026-11-08', reportCount: 5, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Domain mimicking a marketplace payment portal — synthetic demo data.' },
  { indicator: '"Your refund is ready" phishing SMS', type: 'SMS pattern', risk: 'Low', firstSeen: '2026-11-06', reportCount: 3, reviewStatus: 'Sample', confidence: 'Sample', summary: 'Tax refund lure SMS — synthetic demo data.' },
];

// ── Moderation panel ──────────────────────────────────────────────────────
const modPanel = $('#mod-panel');

$('#mod-login-form')?.addEventListener('submit', async e => {
  e.preventDefault();
  const tokenInput = $('#mod-token-input');
  const token = tokenInput.value.trim();
  if (!token) return;
  if (!API) {
    document.querySelector('#mod-panel .notice').innerHTML =
      '⚠ No API configured. Connect a deployed ScamTrace API to use the moderation console.';
    return;
  }
  // Verify token with a dry-run GET.
  try {
    await apiRequest('/moderate', null, { 'x-mod-token': token });
    modToken = token;
    tokenInput.value = '';
    document.getElementById('mod-auth-section').classList.add('hidden');
    document.getElementById('mod-reports-section').classList.remove('hidden');
    loadModReports();
  } catch (err) {
    document.getElementById('mod-auth-error').textContent =
      err.message === 'HTTP 401' ? 'Incorrect token.' : `Error: ${err.message}`;
    document.getElementById('mod-auth-error').classList.add('visible');
  }
});

async function loadModReports() {
  if (!API || !modToken) return;
  const container = $('#mod-report-list');
  container.innerHTML = '<div class="skeleton" style="height:60px;margin-bottom:8px"></div>'.repeat(3);
  try {
    const data = await apiRequest('/moderate', null, { 'x-mod-token': modToken });
    if (!data.reports?.length) {
      container.innerHTML = '<p class="muted">No pending reports.</p>';
      return;
    }
    container.innerHTML = data.reports.map(r => `
      <div class="mod-report-card" data-pk="${esc(r.pk)}">
        <div><strong>${esc(r.category)}</strong> <small style="color:var(--text3)">#${esc(r.referenceId?.slice(0,8) || '')}</small></div>
        <p class="mod-description">${esc(r.description || 'No description available.')}</p>
        <div style="font-size:12px;color:var(--text3)">Received ${new Date((r.createdAt||0)*1000).toLocaleString()}</div>
        <div class="mod-actions">
          <button class="mod-btn approve" data-action="approve">✓ Mark reviewed</button>
          <button class="mod-btn dismiss" data-action="dismiss">✕ Dismiss</button>
          <button class="mod-btn promote" data-action="promote-open">⬆ Promote…</button>
        </div>
        <div class="mod-promote-form hidden" style="margin-top:8px;display:flex;flex-direction:column;gap:6px">
          <input class="promote-indicator" placeholder="Indicator value (URL, pattern…)" style="font-size:13px">
          <select class="promote-type" style="font-size:13px">
            <option>URL</option><option>SMS pattern</option><option>Email pattern</option>
            <option>Impersonation</option><option>Payment fraud</option>
          </select>
          <select class="promote-risk" style="font-size:13px">
            <option value="High">High risk</option><option value="Medium">Medium risk</option><option value="Low">Low risk</option>
          </select>
          <button class="mod-btn promote" data-action="promote-submit">Submit promotion</button>
        </div>
      </div>
    `).join('');

    // Bind action buttons.
    container.querySelectorAll('.mod-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const card = btn.closest('.mod-report-card');
        const pk = card.dataset.pk;
        const action = btn.dataset.action;

        if (action === 'promote-open') {
          card.querySelector('.mod-promote-form').classList.toggle('hidden');
          return;
        }

        let body = { pk, action: action === 'promote-submit' ? 'promote' : action };
        if (action === 'promote-submit') {
          body.indicator = card.querySelector('.promote-indicator').value.trim();
          body.indicatorType = card.querySelector('.promote-type').value;
          body.risk = card.querySelector('.promote-risk').value;
        }

        btn.disabled = true;
        try {
          await apiRequest('/moderate', body, { 'x-mod-token': modToken });
          card.style.opacity = '0.4';
          card.querySelectorAll('button').forEach(b => b.disabled = true);
          toast('Action applied.', 'success');
        } catch (err) {
          toast(`Action failed: ${err.message}`, 'error');
          btn.disabled = false;
        }
      });
    });
  } catch (err) {
    container.innerHTML = `<p class="muted" style="color:var(--high)">Could not load reports: ${esc(err.message)}</p>`;
  }
}

// ── Nav / section scroll ──────────────────────────────────────────────────
$$('.nav[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const target = document.querySelector(a.getAttribute('href'));
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    $$('.nav').forEach(x => { x.classList.remove('active'); });
    a.classList.add('active');
  });
});

// Update active nav based on the section nearest the reading line.
const setActiveNav = id => {
  $$('.nav').forEach(x => {
    const active = x.getAttribute('href') === `#${id}`;
    x.classList.toggle('active', active);
    if (active) x.setAttribute('aria-current', 'page');
    else x.removeAttribute('aria-current');
  });
};
const observer = new IntersectionObserver(entries => {
  const visible = entries.filter(entry => entry.isIntersecting)
    .sort((a, b) => Math.abs(a.boundingClientRect.top) - Math.abs(b.boundingClientRect.top));
  if (visible.length) setActiveNav(visible[0].target.id);
}, { rootMargin: '-18% 0px -70% 0px', threshold: 0 });
['analyze','reports','signals','moderation'].forEach(id => {
  const el = document.getElementById(id);
  if (el) observer.observe(el);
});
window.addEventListener('scroll', () => {
  if (window.scrollY < 90) setActiveNav('overview');
}, { passive: true });
if (window.scrollY < 90) setActiveNav('overview');

// ── Init ──────────────────────────────────────────────────────────────────
loadSignals();
