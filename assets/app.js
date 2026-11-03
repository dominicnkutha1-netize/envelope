import {
  parseFields,
  analyse,
  toReport,
  decodeWords,
  registrableDomain,
} from './headers.js';
import { SAMPLES } from './samples.js';

const rawInput = document.getElementById('raw');
const analyseButton = document.getElementById('analyse');
const clearButton = document.getElementById('clear');
const result = document.getElementById('result');
const sampleButtons = [...document.querySelectorAll('button.sample')];

const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function formatTime(ms) {
  if (ms === null) return '—';
  const date = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
}

function formatDelay(ms) {
  if (ms === null) return '—';
  const sign = ms < 0 ? '−' : '+';
  const total = Math.abs(Math.round(ms / 1000));
  if (total < 60) return `${sign}${total}s`;
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes < 60) return `${sign}${minutes}m ${String(seconds).padStart(2, '0')}s`;
  const hours = Math.floor(minutes / 60);
  return `${sign}${hours}h ${String(minutes % 60).padStart(2, '0')}m`;
}

/** A date in a header is only ever as trustworthy as the header itself. */
function formatHeaderDate(value) {
  if (!value) return '—';
  const parsed = Date.parse(String(value).replace(/\([^)]*\)/g, ' ').trim());
  if (Number.isNaN(parsed)) return value;
  return `${value}  ·  ${formatTime(parsed)}`;
}

function identityRow(label, address, extra = '') {
  if (!address || !address.address) {
    return `<dt>${label}</dt><dd class="muted">not present</dd>`;
  }
  const name = address.name
    ? `<span class="display-name">${escapeHtml(address.name)}</span>`
    : '';
  return `<dt>${label}</dt><dd>${escapeHtml(address.address)}${extra}${name}</dd>`;
}

function sameSiteLabel(a, b) {
  if (!a || !b) return '';
  return registrableDomain(a) === registrableDomain(b)
    ? ''
    : ` <span class="mismatch">different site</span>`;
}

function renderIdentity(result_) {
  const { from, returnPath, replyTo, subject, date, messageId } = result_;
  return `
    <div class="identity">
      <dl>
        ${identityRow('From', from)}
        ${identityRow('Return-Path', returnPath, sameSiteLabel(returnPath.domain, from.domain))}
        ${identityRow('Reply-To', replyTo, sameSiteLabel(replyTo.domain, from.domain))}
        <dt>Subject</dt><dd>${subject ? escapeHtml(subject) : '<span class="muted">not present</span>'}</dd>
        <dt>Date</dt><dd>${date ? escapeHtml(formatHeaderDate(date)) : '<span class="muted">not present</span>'}</dd>
        <dt>Message-ID</dt><dd>${messageId ? escapeHtml(messageId) : '<span class="muted">not present</span>'}</dd>
      </dl>
    </div>`;
}

function renderSignals(signals) {
  const rows = signals
    .map(
      (entry) => `
      <div class="signal" data-level="${entry.level}">
        <span class="level">${entry.level === 'bad' ? 'finding' : entry.level === 'warn' ? 'warning' : entry.level === 'ok' ? 'passed' : 'note'}</span>
        <div>
          <p class="title">${escapeHtml(entry.title)}</p>
          <p class="detail">${escapeHtml(entry.detail)}</p>
        </div>
      </div>`
    )
    .join('');

  return `<div class="signals"><h3>Findings</h3>${rows}</div>`;
}

function renderHops(hops) {
  if (!hops.length) {
    return `<div class="hops"><h3>Delivery path</h3>
      <p class="detail">No <code>Received</code> headers were found, so there is no route to show.</p></div>`;
  }

  const rows = hops
    .map((hop) => {
      const backwards = hop.delayMs !== null && hop.delayMs < -60000;
      const slow = hop.delayMs !== null && hop.delayMs >= 5 * 60 * 1000;
      const delayClass = backwards ? 'backwards' : slow ? 'slow' : '';
      const delayText = hop.delayMs === null ? '—' : formatDelay(hop.delayMs);
      const delayNote = backwards ? ' backwards' : slow ? ' slow' : '';
      return `
        <tr>
          <td class="num">${hop.hop}</td>
          <td>${escapeHtml(hop.from || '?')}</td>
          <td>${escapeHtml(hop.by || '?')}${hop.ip ? `<br><span class="stamp">${escapeHtml(hop.ip)}</span>` : ''}</td>
          <td class="delay ${delayClass}">${delayText}${delayNote}</td>
          <td><span class="stamp">${escapeHtml(formatTime(hop.at))}</span></td>
        </tr>`;
    })
    .join('');

  return `
    <div class="hops">
      <h3>Delivery path <span class="stamp">oldest first</span></h3>
      <table class="path">
        <thead>
          <tr><th>#</th><th>From</th><th>By</th><th>Since previous</th><th>Time (UTC)</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderRawFields(fields) {
  const rows = fields
    .map(
      (field) => `
      <tr>
        <td class="name">${escapeHtml(field.name)}</td>
        <td>${escapeHtml(decodeWords(field.value))}</td>
      </tr>`
    )
    .join('');

  return `
    <details class="raw-fields">
      <summary>Every parsed field (${fields.length})</summary>
      <table>
        <thead><tr><th>Header</th><th>Value</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </details>`;
}

function verdictCopy(verdict, counts, hopsCount, fieldsCount) {
  if (verdict === 'suspicious') {
    const hard = counts.bad;
    return {
      title: 'Treat this as suspicious',
      body: `${hard} hard finding${hard === 1 ? '' : 's'} and ${counts.warn} warning${counts.warn === 1 ? '' : 's'}. ` +
        `Check the sender through a channel you already trust before acting on anything in the message.`,
    };
  }
  if (verdict === 'mixed') {
    return {
      title: 'Worth reading before you trust it',
      body: `No check failed outright, but ${counts.warn} warning${counts.warn === 1 ? '' : 's'} ` +
        `need a human decision. Each one is explained below, including the ones that are usually innocent.`,
    };
  }
  return {
    title: 'Everything recorded here agrees',
    body: `Every authentication check the receiving server recorded passed, and the addresses point at the same site. ` +
      `That is not a guarantee: ${fieldsCount} fields and ${hopsCount} hop${hopsCount === 1 ? '' : 's'} is all this page can see.`,
  };
}

/**
 * Copying is two attempts deep on purpose: `navigator.clipboard` is blocked in
 * some embedded and headless browsers, and the summary is the one part of this
 * page a user needs to move somewhere else.
 */
async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the legacy path.
    }
  }

  try {
    const helper = document.createElement('textarea');
    helper.value = text;
    helper.setAttribute('readonly', '');
    helper.style.position = 'fixed';
    helper.style.top = '-1000px';
    document.body.appendChild(helper);
    helper.select();
    const copied = document.execCommand('copy');
    helper.remove();
    return copied;
  } catch {
    return false;
  }
}

/** If the clipboard is unavailable entirely, put the text on screen instead of failing silently. */
function showReportOnScreen(report) {
  const existing = document.getElementById('report-fallback');
  if (existing) {
    existing.focus();
    existing.select();
    return;
  }

  const area = document.createElement('textarea');
  area.id = 'report-fallback';
  area.className = 'report-fallback';
  area.readOnly = true;
  area.rows = 12;
  area.value = report;
  area.setAttribute('aria-label', 'Plain-text report, select and copy manually');

  result.appendChild(area);
  area.focus();
  area.select();
}

function render(result_, fields) {
  const { signals, counts, verdict, hops } = result_;
  const copy = verdictCopy(verdict, counts, hops.length, fields.length);
  const report = toReport(result_);

  result.innerHTML = `
    <div class="verdict" data-verdict="${verdict}">
      <span class="stamp">${verdict}</span>
      <div>
        <h2>${escapeHtml(copy.title)}</h2>
        <p>${escapeHtml(copy.body)}</p>
      </div>
    </div>
    ${renderIdentity(result_)}
    ${renderSignals(signals)}
    ${renderHops(hops)}
    ${renderRawFields(fields)}
    <div class="result-actions">
      <button type="button" class="ghost" id="copy-report">Copy summary</button>
      <span class="copy-note">Plain text, for a ticket or a report.</span>
    </div>`;

  const copyButton = document.getElementById('copy-report');
  const copyNote = copyButton.nextElementSibling;

  copyButton.addEventListener('click', async () => {
    if (await copyText(report)) {
      copyButton.textContent = 'Copied';
      setTimeout(() => {
        copyButton.textContent = 'Copy summary';
      }, 1600);
      return;
    }

    copyButton.textContent = 'Select the text below';
    copyNote.textContent = 'The clipboard is blocked here. The report is below — press Ctrl+C to copy it.';
    showReportOnScreen(report);
  });
}

function renderError(message) {
  result.innerHTML = `
    <div class="empty">
      <h2>Nothing to analyse</h2>
      <p>${escapeHtml(message)}</p>
      <p class="empty-note">Paste the raw headers, or load one of the synthetic examples on the left.</p>
    </div>`;
}

function run() {
  const raw = rawInput.value;
  const fields = parseFields(raw);

  if (fields.length === 0) {
    renderError('No header fields were found in what you pasted.');
    return;
  }

  // A header block with one plausible line is almost always a partial paste.
  const hasFrom = fields.some((field) => field.lower === 'from');
  if (!hasFrom && fields.length < 4) {
    renderError('That looks like a partial paste — there is no From header. Copy the full header block.');
    return;
  }

  result.setAttribute('aria-busy', 'true');
  const analysis = analyse(fields);
  render(analysis, fields);
  result.setAttribute('aria-busy', 'false');
}

analyseButton.addEventListener('click', run);
clearButton.addEventListener('click', () => {
  rawInput.value = '';
  rawInput.focus();
  result.innerHTML = `
    <div class="empty">
      <h2>Nothing analysed yet</h2>
      <p>Paste headers on the left, or load one of the two synthetic examples.</p>
      <p class="empty-note">Both examples are invented messages using reserved IP ranges and
        example domains: one is the shape of a forged bank email, the other is a correctly
        authenticated newsletter.</p>
    </div>`;
});

rawInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    run();
  }
});

// Pasting headers and then having to click a button is a wasted click.
rawInput.addEventListener('paste', () => setTimeout(run, 50));

for (const button of sampleButtons) {
  button.addEventListener('click', () => {
    const sample = SAMPLES.find((entry) => entry.id === button.dataset.sample);
    if (!sample) return;
    rawInput.value = sample.text;
    run();
    result.scrollIntoView({ block: 'start', behavior: 'smooth' });
  });
}

// A deep link is handy in a ticket: ?sample=suspicious
const requested = new URLSearchParams(location.search).get('sample');
if (requested) {
  const sample = SAMPLES.find((entry) => entry.id === requested);
  if (sample) {
    rawInput.value = sample.text;
    run();
  }
}
