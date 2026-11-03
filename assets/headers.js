/**
 * Email header parsing and analysis.
 *
 * Deliberately free of DOM and network code: this is the part with the edge
 * cases, so it has to be testable in node with nothing mocked.
 *
 * Nothing here validates a signature or contacts a DNS server. It reads what
 * the receiving mail server already recorded, and reports the disagreements
 * that matter. See the README for what that cannot tell you.
 */

/** Suffixes with more than one label, so `mail.bank.co.za` is compared as
 *  `bank.co.za` and not `co.za`. Not the Public Suffix List — a short list of
 *  the ones that actually show up in mail. Documented as a limitation. */
export const MULTI_LABEL_SUFFIXES = [
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za', 'web.za', 'edu.za',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'co.in', 'co.il', 'co.ke', 'co.zw', 'co.bw', 'co.na',
  'com.br', 'com.mx', 'com.ar', 'com.sg', 'com.hk', 'com.tr',
];

const HEADER_FIELD = /^([!-9;-~]+):\s*(.*)$/;

export function normaliseNewlines(raw) {
  return String(raw ?? '').replace(/\r\n?/g, '\n');
}

/** The header block ends at the first empty line. Everything after is body. */
export function splitMessage(raw) {
  const text = normaliseNewlines(raw);
  const boundary = text.indexOf('\n\n');
  if (boundary === -1) return { headerText: text, bodyText: '' };
  return { headerText: text.slice(0, boundary), bodyText: text.slice(boundary + 2) };
}

/**
 * RFC 5322 folding: a line break followed by whitespace continues the previous
 * header. Received headers are almost always folded mid-address or mid-date,
 * so unfolding is not optional — an unfolded parse would cut the timestamp off
 * and report every hop as having no date.
 */
export function unfold(headerText) {
  return normaliseNewlines(headerText).replace(/\n[ \t]+/g, ' ');
}

/** Ordered header fields. Duplicates are kept: Received and
 *  Authentication-Results both legitimately appear more than once. */
export function parseFields(raw) {
  const { headerText } = splitMessage(raw);
  const fields = [];
  for (const line of unfold(headerText).split('\n')) {
    if (!line.trim()) continue;
    // A pasted body line (no colon) is skipped rather than treated as an error.
    const match = line.match(HEADER_FIELD);
    if (!match) continue;
    fields.push({ name: match[1], value: match[2].trim(), lower: match[1].toLowerCase() });
  }
  return fields;
}

export function all(fields, name) {
  const key = name.toLowerCase();
  return fields.filter((field) => field.lower === key).map((field) => field.value);
}

export function first(fields, name) {
  const values = all(fields, name);
  return values.length ? values[0] : '';
}

/** Decode RFC 2047 encoded-words: =?UTF-8?B?...?= and =?UTF-8?Q?...?= */
export function decodeWords(value) {
  return String(value ?? '').replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (whole, charset, encoding, text) => {
    try {
      let bytes;
      if (encoding.toUpperCase() === 'B') {
        const binary = atob(text.replace(/\s+/g, ''));
        bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      } else {
        const source = text.replace(/_/g, ' ');
        const out = [];
        for (let i = 0; i < source.length; i += 1) {
          if (source[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(source.slice(i + 1, i + 3))) {
            out.push(parseInt(source.slice(i + 1, i + 3), 16));
            i += 2;
          } else {
            out.push(source.charCodeAt(i));
          }
        }
        bytes = Uint8Array.from(out);
      }
      const decoder = new TextDecoder(charset.toLowerCase(), { fatal: false });
      return decoder.decode(bytes);
    } catch {
      return whole; // Unknown charset: show it rather than hide it.
    }
  });
}

/** One address. Handles `"Name" <a@b>`, `Name <a@b>`, `<a@b>` and `a@b`. */
export function parseAddress(value) {
  const text = decodeWords(value).trim();
  const angle = text.match(/^(.*)<([^<>]+)>\s*$/);
  const address = (angle ? angle[2] : text).trim().replace(/^mailto:/i, '');
  // Trim before stripping quotes: the name sits between the quote and the
  // space before `<`, so an anchored `$` would miss it.
  const name = (angle ? angle[1] : '').trim().replace(/^["']+|["']+$/g, '').trim();
  const at = address.lastIndexOf('@');
  const domain = at === -1 ? '' : address.slice(at + 1).trim().toLowerCase().replace(/[).,;>]+$/, '');
  return { name, address, domain, valid: at > 0 && domain.length > 0 };
}

/** Dates in headers are RFC 5322 with optional parenthetical timezone names. */
export function parseDate(value) {
  const cleaned = String(value ?? '')
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return null;
  const ms = Date.parse(cleaned);
  return Number.isNaN(ms) ? null : ms;
}

/** One Received header: the structural bits plus its timestamp. */
export function parseReceived(value) {
  const text = unfold(value).replace(/\s+/g, ' ').trim();
  const semicolon = text.lastIndexOf(';');
  const head = semicolon === -1 ? text : text.slice(0, semicolon);
  const dateText = semicolon === -1 ? '' : text.slice(semicolon + 1).trim();
  const grab = (pattern) => {
    const match = head.match(pattern);
    return match ? match[1] : '';
  };
  const ip = head.match(/\[([0-9a-fA-F:.]+)\]/);

  return {
    from: grab(/\bfrom\s+([^\s(;]+)/i),
    by: grab(/\bby\s+([^\s(;]+)/i),
    with: grab(/\bwith\s+([^\s(;]+)/i),
    id: grab(/\bid\s+([^\s(;]+)/i),
    forAddress: grab(/\bfor\s+<?([^\s>;]+)>?/i),
    ip: ip ? ip[1] : '',
    dateText,
    at: parseDate(dateText),
  };
}

/**
 * Received headers are written newest-first, so the last one in the header
 * block is the hop that first saw the message. Reverse for delivery order:
 * hop 1 is the sender's server, the last hop is the one that handed it to you.
 */
export function buildHops(fields) {
  const received = all(fields, 'received')
    .map(parseReceived)
    .filter((hop) => hop.from || hop.by || hop.dateText);

  const delivery = received.slice().reverse();

  return delivery.map((hop, index) => {
    const previous = index === 0 ? null : delivery[index - 1].at;
    const delayMs = hop.at !== null && previous !== null ? hop.at - previous : null;
    return { ...hop, hop: index + 1, delayMs };
  });
}

/**
 * Authentication-Results is added by the receiving server. There can be several
 * (one per hop that checked); the first is the most recent, which is the one
 * that decided where the message went.
 */
export function parseAuthResults(fields) {
  return all(fields, 'authentication-results').map((value) => {
    const text = unfold(value).replace(/\s+/g, ' ').trim();
    const by = text.split(';')[0].trim();
    const grab = (pattern) => {
      const match = text.match(pattern);
      return match ? match[1].toLowerCase() : '';
    };
    const dkim = [...text.matchAll(/dkim=(\w+)([^;]*)/gi)].map((match) => {
      const methods = match[2] || '';
      const identity = methods.match(/header\.i=@?([^\s;]+)/i);
      return {
        result: match[1].toLowerCase(),
        domain: identity ? identity[1].replace(/[;,]+$/, '').toLowerCase() : '',
      };
    });

    return {
      by,
      spf: grab(/\bspf=(\w+)/i),
      dkim,
      dmarc: grab(/\bdmarc=(\w+)/i),
      fromDomain: grab(/header\.from=([^\s;]+)/i),
    };
  });
}

/** Naive eTLD+1: `mail.example.co.za` and `example.co.za` are the same site. */
export function registrableDomain(host) {
  const value = String(host ?? '').toLowerCase().replace(/\.+$/, '').trim();
  if (!value || !value.includes('.')) return value;

  for (const suffix of MULTI_LABEL_SUFFIXES) {
    if (value === suffix) return value;
    if (value.endsWith(`.${suffix}`)) {
      const label = value.slice(0, -(suffix.length + 1)).split('.').pop();
      return `${label}.${suffix}`;
    }
  }

  return value.split('.').slice(-2).join('.');
}

export function sameSite(a, b) {
  return Boolean(a) && Boolean(b) && registrableDomain(a) === registrableDomain(b);
}

const LEVEL_ORDER = { bad: 0, warn: 1, info: 2, ok: 3 };

function signal(level, title, detail) {
  return { level, title, detail };
}

/**
 * The verdict. Every signal is something a person can check themselves, and the
 * wording says what it means rather than scoring the message out of ten: a
 * "pass" here is a report from the receiving server, not a guarantee.
 */
export function analyse(fields) {
  const signals = [];
  const from = parseAddress(first(fields, 'from'));
  const replyTo = parseAddress(first(fields, 'reply-to'));
  const returnPath = parseAddress(first(fields, 'return-path'));
  const sender = parseAddress(first(fields, 'sender'));
  const messageId = first(fields, 'message-id');
  const dateHeader = first(fields, 'date');
  const auth = parseAuthResults(fields);
  const hops = buildHops(fields);
  const latest = auth[0];

  if (!from.address) {
    signals.push(
      signal('bad', 'No From header', 'Without a From address there is nothing to check the rest of the message against. The headers may be incomplete.')
    );
  }

  if (!latest) {
    signals.push(
      signal(
        'warn',
        'No Authentication-Results',
        'The receiving server did not record SPF, DKIM or DMARC results. Either the message predates the check, the headers were trimmed, or the server does not add them. Absence is not proof of a problem, but it means nothing was verified here.'
      )
    );
  } else {
    // `softfail` and `neutral` are "not proven, not a hard no". Only `fail`,
    // `permerror` and `temperror` are treated as strong negative signals.
    const level = (result) => {
      if (result === 'pass') return 'ok';
      if (!result || result === 'none' || result === 'neutral' || result === 'softfail') return 'warn';
      return 'bad';
    };

    if (latest.spf) {
      signals.push(
        signal(
          level(latest.spf),
          `SPF ${latest.spf}`,
          latest.spf === 'pass'
            ? 'The sending server was allowed to send mail for the envelope domain.'
            : `The sending server was not authorised for the envelope domain. ${latest.spf === 'softfail' ? 'A soft failure usually means the domain is in transition, or somebody is sending as it.' : 'A hard failure on a real message is a strong signal.'}`
        )
      );
    }

    if (latest.dkim.length === 0) {
      signals.push(
        signal('warn', 'No DKIM result', 'No DKIM signature was verified. Unsigned mail is common for small senders, and also for forged mail.')
      );
    } else {
      for (const entry of latest.dkim) {
        const detail =
          entry.result === 'pass'
            ? 'The signature matched the message body, so it was not altered after signing.'
            : entry.result === 'none'
              ? 'No signature was presented for this message. Unsigned mail is common for small senders, and also for forged mail.'
              : 'The signature did not verify. Either the body changed in transit or the signature was never valid.';
        signals.push(signal(level(entry.result), `DKIM ${entry.result}${entry.domain ? ` (${entry.domain})` : ''}`, detail));
      }
    }

    if (latest.dmarc) {
      signals.push(
        signal(
          level(latest.dmarc),
          `DMARC ${latest.dmarc}`,
          latest.dmarc === 'pass'
            ? `A domain-aligned method passed for ${latest.fromDomain || 'the From domain'}.`
            : `No aligned SPF or DKIM result for ${latest.fromDomain || 'the From domain'}. This is the check that catches a spoofed From address, so a failure matters even if SPF passed for some other domain.`
        )
      );
    }
  }

  if (from.domain && returnPath.domain && !sameSite(from.domain, returnPath.domain)) {
    signals.push(
      signal(
        'warn',
        'From and Return-Path are different sites',
        `The message claims to be from ${registrableDomain(from.domain)} but bounces go to ${registrableDomain(returnPath.domain)}. Bulk senders do this legitimately through a bounce domain; spoofed mail does it because it has no choice.`
      )
    );
  }

  if (replyTo.address && from.domain && !sameSite(replyTo.domain, from.domain)) {
    signals.push(
      signal(
        'warn',
        'Replies would go to a different site',
        `Reply-To is ${replyTo.address}. Replies would leave the From domain (${registrableDomain(from.domain)}) and go to ${registrableDomain(replyTo.domain)}. Marketing lists do this on purpose; it is also how a conversation is quietly redirected.`
      )
    );
  }

  if (from.name) {
    const embedded = parseAddress(from.name);
    if (embedded.valid && embedded.domain && !sameSite(embedded.domain, from.domain)) {
      signals.push(
        signal(
          'bad',
          'The display name contains a different address',
          `The sender shows as “${from.name}” but the actual address is ${from.address}. Mail clients usually show the display name, so look at the angle brackets.`
        )
      );
    }
  }

  if (from.domain && (/(^|\.)xn--/i.test(from.domain) || /[^\x00-\x7F]/.test(from.domain))) {
    signals.push(
      signal(
        'warn',
        'The From domain is internationalised',
        `${from.domain} uses non-ASCII characters or punycode (xn--). That is legitimate for many domains, and it is also how a lookalike character is used to imitate a brand. Compare it character by character.`
      )
    );
  }

  if (sender.address && from.address && !sameSite(sender.domain, from.domain)) {
    signals.push(
      signal('info', 'Sender differs from From', `Sender is ${sender.address}. It is the address the message is attributed to on behalf of the From author, so a difference is not automatically wrong.`)
    );
  }

  const dateValue = parseDate(dateHeader);
  if (dateValue !== null && hops.length) {
    const last = hops[hops.length - 1].at;
    if (last !== null && last - dateValue > 10 * 60 * 1000) {
      signals.push(
        signal('warn', 'The Date header predates delivery', `Date says ${new Date(dateValue).toISOString()} but the last server saw it at ${new Date(last).toISOString()}. That gap is either a slow queue or an invented date.`)
      );
    }
  }

  if (hops.length === 0) {
    signals.push(
      signal('warn', 'No Received headers', 'No delivery hops were recorded. If this message was actually delivered, that is unusual: every server that handles it normally adds one.')
    );
  } else if (hops.some((hop) => hop.delayMs !== null && hop.delayMs < -60 * 1000)) {
    signals.push(
      signal('warn', 'The hop timestamps are not in order', 'At least one server recorded a time earlier than the server before it. That is clock drift, or a hand-edited header.')
    );
  }

  const messageIdDomain = (messageId.match(/@([^>\s]+)>?\s*$/) || [])[1];
  if (messageIdDomain && from.domain && !sameSite(messageIdDomain, from.domain)) {
    signals.push(
      signal('info', 'Message-ID belongs to a different site', `The Message-ID was generated on ${registrableDomain(messageIdDomain)}, not ${registrableDomain(from.domain)}. Normal when a mailing service sends on someone's behalf.`)
    );
  }

  const origin = hops[0];
  if (origin && origin.from && from.domain && !sameSite(origin.from, from.domain)) {
    signals.push(
      signal('info', 'The first hop is not in the From domain', `The oldest Received header names ${origin.from}. Senders using an email service send from the service's servers, so this is expected rather than alarming on its own.`)
    );
  }

  signals.sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level]);

  const counts = { bad: 0, warn: 0, info: 0, ok: 0 };
  for (const entry of signals) counts[entry.level] += 1;

  return {
    signals,
    counts,
    verdict: counts.bad > 0 ? 'suspicious' : counts.warn > 0 ? 'mixed' : 'consistent',
    from,
    replyTo,
    returnPath,
    sender,
    auth,
    hops,
    subject: decodeWords(first(fields, 'subject')),
    date: dateHeader,
    messageId,
  };
}

/** Plain text for a ticket. Screenshots do not paste into ticket comments. */
export function toReport(result) {
  const lines = [];
  lines.push('EMAIL HEADER SUMMARY');
  lines.push('====================');
  lines.push('');
  lines.push(`Verdict: ${result.verdict.toUpperCase()} (${result.counts.bad} bad, ${result.counts.warn} warnings, ${result.counts.ok} passed)`);
  lines.push('');
  lines.push(`From:        ${result.from.address || '(none)'}${result.from.name ? `  (${result.from.name})` : ''}`);
  lines.push(`Return-Path: ${result.returnPath.address || '(none)'}`);
  lines.push(`Reply-To:    ${result.replyTo.address || '(none)'}`);
  lines.push(`Subject:     ${result.subject || '(none)'}`);
  lines.push(`Date:        ${result.date || '(none)'}`);
  lines.push(`Message-ID:  ${result.messageId || '(none)'}`);
  lines.push('');

  if (result.auth.length) {
    lines.push('AUTHENTICATION');
    const latest = result.auth[0];
    lines.push(`  SPF:   ${latest.spf || 'not recorded'}`);
    lines.push(`  DKIM:  ${latest.dkim.length ? latest.dkim.map((d) => `${d.result}${d.domain ? ` (${d.domain})` : ''}`).join(', ') : 'not recorded'}`);
    lines.push(`  DMARC: ${latest.dmarc || 'not recorded'}`);
    lines.push(`  Checked by: ${latest.by || 'unknown'}`);
    lines.push('');
  }

  if (result.hops.length) {
    lines.push('DELIVERY PATH (oldest first)');
    for (const hop of result.hops) {
      const delay = hop.delayMs === null ? '' : `  +${(hop.delayMs / 1000).toFixed(1)}s`;
      lines.push(`  ${hop.hop}. ${hop.from || '?'} -> ${hop.by || '?'}${hop.ip ? ` [${hop.ip}]` : ''}${delay}`);
      if (hop.dateText) lines.push(`     ${hop.dateText}`);
    }
    lines.push('');
  }

  lines.push('FINDINGS');
  // The same words the page shows, so a pasted report and a screenshot agree.
  const label = { bad: 'FINDING', warn: 'WARNING', ok: 'PASSED', info: 'NOTE' };
  for (const entry of result.signals) {
    lines.push(`  [${label[entry.level] ?? entry.level.toUpperCase()}] ${entry.title}`);
    lines.push(`      ${entry.detail}`);
  }
  lines.push('');
  lines.push('Report generated in the browser. Nothing was uploaded.');
  return lines.join('\n');
}
