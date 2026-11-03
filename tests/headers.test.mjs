import test from 'node:test';
import assert from 'node:assert/strict';

import {
  splitMessage,
  unfold,
  parseFields,
  all,
  first,
  decodeWords,
  parseAddress,
  parseDate,
  parseReceived,
  buildHops,
  parseAuthResults,
  registrableDomain,
  sameSite,
  analyse,
  toReport,
} from '../assets/headers.js';

import { SUSPICIOUS, CLEAN } from '../assets/samples.js';

const fieldsOf = (raw) => parseFields(raw);

test('splitMessage divides headers from body at the first blank line', () => {
  const { headerText, bodyText } = splitMessage('From: a@b.com\r\nSubject: Hi\r\n\r\nBody here');
  assert.equal(headerText, 'From: a@b.com\nSubject: Hi');
  assert.equal(bodyText, 'Body here');
});

test('splitMessage keeps a bodyless paste intact', () => {
  const { headerText, bodyText } = splitMessage('From: a@b.com\nSubject: Hi');
  assert.equal(headerText, 'From: a@b.com\nSubject: Hi');
  assert.equal(bodyText, '');
});

test('unfold joins continuations, including tab-indented ones', () => {
  const folded = 'Received: from a.example\n\tby b.example\n  with ESMTP; Tue, 03 Nov 2026 07:00:00 +0200';
  assert.equal(
    unfold(folded),
    'Received: from a.example by b.example with ESMTP; Tue, 03 Nov 2026 07:00:00 +0200'
  );
});

test('parseFields preserves order and duplicates', () => {
  const fields = fieldsOf(
    'Return-Path: <a@b.com>\nReceived: from one\nReceived: from two\nFrom: x@y.com\n\nbody'
  );
  assert.deepEqual(
    fields.map((field) => field.name),
    ['Return-Path', 'Received', 'Received', 'From']
  );
  assert.equal(all(fields, 'received').length, 2);
  assert.equal(first(fields, 'from'), 'x@y.com');
});

test('parseFields skips the body and junk lines instead of throwing', () => {
  const fields = fieldsOf('From: a@b.com\nthis is not a header\nSubject: Hi\n\nBody: not a header');
  assert.deepEqual(fields.map((field) => field.name), ['From', 'Subject']);
});

test('decodeWords decodes base64 encoded-words', () => {
  // "Urgent" in base64
  assert.equal(decodeWords('=?UTF-8?B?VXJnZW50?='), 'Urgent');
});

test('decodeWords decodes quoted-printable encoded-words', () => {
  assert.equal(decodeWords('=?UTF-8?Q?Urgent:_your_account?='), 'Urgent: your account');
});

test('decodeWords leaves an unknown charset visible rather than eating it', () => {
  const value = '=?x-no-such-charset?B?SGk=?=';
  assert.equal(decodeWords(value), value);
});

test('parseAddress handles name, angle brackets, bare address and mailto', () => {
  assert.deepEqual(parseAddress('"Example Weekly" <news@example.org>'), {
    name: 'Example Weekly',
    address: 'news@example.org',
    domain: 'example.org',
    valid: true,
  });
  assert.equal(parseAddress('news@example.org').domain, 'example.org');
  assert.equal(parseAddress('<a@b.co.za>').domain, 'b.co.za');
  assert.equal(parseAddress('mailto:a@b.com').address, 'a@b.com');
  assert.equal(parseAddress('').valid, false);
});

test('parseAddress decodes an encoded display name', () => {
  const parsed = parseAddress('=?UTF-8?Q?Mzanzi_Bank?= <alerts@example.com>');
  assert.equal(parsed.name, 'Mzanzi Bank');
  assert.equal(parsed.address, 'alerts@example.com');
});

test('parseDate reads RFC 5322 with an offset and ignores the timezone comment', () => {
  const ms = parseDate('Tue, 03 Nov 2026 07:42:11 -0800 (PST)');
  assert.equal(new Date(ms).toISOString(), '2026-11-03T15:42:11.000Z');
});

test('parseDate returns null for nonsense instead of NaN', () => {
  assert.equal(parseDate('not a date'), null);
  assert.equal(parseDate(''), null);
});

test('parseReceived pulls out the structural fields and the timestamp', () => {
  const hop = parseReceived(
    'from mx.corp-mail.example (mx.corp-mail.example [203.0.113.44]) by mx.google.com with ESMTPS id x12abc for <you@example.com>; Tue, 03 Nov 2026 07:42:11 -0800 (PST)'
  );
  assert.equal(hop.from, 'mx.corp-mail.example');
  assert.equal(hop.by, 'mx.google.com');
  assert.equal(hop.with, 'ESMTPS');
  assert.equal(hop.ip, '203.0.113.44');
  assert.equal(hop.forAddress, 'you@example.com');
  assert.equal(new Date(hop.at).toISOString(), '2026-11-03T15:42:11.000Z');
});

test('parseReceived stays usable without a timestamp', () => {
  const hop = parseReceived('from a.example by b.example with SMTP');
  assert.equal(hop.from, 'a.example');
  assert.equal(hop.at, null);
});

test('buildHops reverses the headers into delivery order', () => {
  const hops = buildHops(fieldsOf(SUSPICIOUS));
  assert.equal(hops.length, 3);
  assert.equal(hops[0].from, 'localhost');
  assert.equal(hops[2].by, 'mx.google.com');
});

test('buildHops reports the delay between consecutive hops', () => {
  const hops = buildHops(fieldsOf(SUSPICIOUS));
  assert.equal(hops[0].delayMs, null, 'the first hop has nothing to compare against');
  assert.equal(hops[1].delayMs, 6000);
  assert.equal(hops[2].delayMs, 13000);
});

test('buildHops marks a clock that runs backwards as a negative delay', () => {
  const raw = [
    'Received: from b.example by c.example; Tue, 03 Nov 2026 10:00:00 +0000',
    'Received: from a.example by b.example; Tue, 03 Nov 2026 11:00:00 +0000',
  ].join('\n');
  const hops = buildHops(fieldsOf(raw));
  assert.equal(hops[1].delayMs, -3600000);
});

test('parseAuthResults reads spf, dkim and dmarc from the receiver report', () => {
  const [auth] = parseAuthResults(fieldsOf(CLEAN));
  assert.equal(auth.spf, 'pass');
  assert.equal(auth.dmarc, 'pass');
  assert.equal(auth.fromDomain, 'example.org');
  assert.equal(auth.dkim.length, 1);
  assert.equal(auth.dkim[0].result, 'pass');
  assert.equal(auth.dkim[0].domain, 'example.org');
});

test('parseAuthResults handles a message with no authentication header', () => {
  assert.deepEqual(parseAuthResults(fieldsOf('From: a@b.com')), []);
});

test('registrableDomain collapses subdomains and knows two-label suffixes', () => {
  assert.equal(registrableDomain('mail.example.co.za'), 'example.co.za');
  assert.equal(registrableDomain('example.co.za'), 'example.co.za');
  assert.equal(registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(registrableDomain('localhost'), 'localhost');
  assert.equal(registrableDomain(''), '');
});

test('sameSite treats a bounce domain and the sending domain as one site', () => {
  assert.equal(sameSite('news.example.org', 'example.org'), true);
  assert.equal(sameSite('example.org', 'example.com'), false);
  assert.equal(sameSite('', 'example.com'), false);
});

test('a forged bank email comes out as suspicious, with the reason named', () => {
  const result = analyse(fieldsOf(SUSPICIOUS));

  assert.equal(result.verdict, 'suspicious');
  assert.ok(result.counts.bad >= 2);

  const titles = result.signals.map((entry) => entry.title);
  assert.ok(titles.includes('DMARC fail'), 'DMARC failure is the headline');
  assert.ok(
    titles.includes('The display name contains a different address'),
    'the address hidden in the display name is called out'
  );
  assert.ok(titles.some((title) => title.startsWith('From and Return-Path')));
});

test('the forged sample decodes its subject rather than showing encoded text', () => {
  const result = analyse(fieldsOf(SUSPICIOUS));
  assert.equal(result.subject, 'Urgent: your account is suspended');
});

test('a correctly authenticated newsletter comes out consistent', () => {
  const result = analyse(fieldsOf(CLEAN));
  assert.equal(result.verdict, 'consistent');
  assert.equal(result.counts.bad, 0);
  assert.equal(result.counts.warn, 0);

  const titles = result.signals.map((entry) => entry.title);
  assert.ok(titles.includes('SPF pass'));
  assert.ok(titles.includes('DMARC pass'));
  assert.ok(titles.includes('DKIM pass (example.org)'));
});

test('the newsletter is not flagged for a different bounce domain in the same site', () => {
  const result = analyse(fieldsOf(CLEAN));
  const titles = result.signals.map((entry) => entry.title);
  assert.equal(titles.some((title) => title.startsWith('From and Return-Path')), false);
});

test('a partially pasted header is caught before it is trusted', () => {
  const result = analyse(fieldsOf('Subject: hello'));
  assert.equal(result.from.valid, false);
  assert.equal(result.verdict, 'suspicious');
  assert.ok(result.signals.some((entry) => entry.title === 'No From header'));
});

test('a message with no Received headers is reported as such', () => {
  const result = analyse(fieldsOf('From: a@example.com\nSubject: hi'));
  assert.equal(result.hops.length, 0);
  assert.ok(result.signals.some((entry) => entry.title === 'No Received headers'));
});

test('punycode in the From domain is flagged', () => {
  const raw = 'From: Bank <security@xn--mzanzi-bank-9dd.example>\nSubject: hi';
  const result = analyse(fieldsOf(raw));
  assert.ok(result.signals.some((entry) => entry.title === 'The From domain is internationalised'));
});

test('toReport produces a plain-text summary with the route and findings', () => {
  const report = toReport(analyse(fieldsOf(SUSPICIOUS)));
  assert.match(report, /EMAIL HEADER SUMMARY/);
  assert.match(report, /Verdict: SUSPICIOUS/);
  assert.match(report, /DELIVERY PATH \(oldest first\)/);
  assert.match(report, /\[FINDING\] DMARC fail/);
  assert.match(report, /Nothing was uploaded/);
});

test('an empty paste does not throw', () => {
  const result = analyse([]);
  assert.equal(result.from.valid, false);
  assert.equal(result.hops.length, 0);
  assert.ok(Array.isArray(result.signals));
});
