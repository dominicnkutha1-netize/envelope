/**
 * Two synthetic header sets, used by the page and by the tests.
 *
 * Every IP is from a documentation range (RFC 5737) and every domain is
 * reserved or invented. The first sample is the pattern of a forged bank
 * email; the second is what a boring, correctly authenticated newsletter
 * looks like. Neither is a real message, and neither is meant to be.
 */

export const SUSPICIOUS = `Return-Path: <bounce@mailer-relay-7x2.example>
Received: from mx.corp-mail.example (mx.corp-mail.example [203.0.113.44])
	by mx.google.com with ESMTPS id x12abc
	for <you@example.com>
	; Tue, 03 Nov 2026 07:42:11 -0800 (PST)
Received: from smtp-relay.example ([198.51.100.23])
	by mx.corp-mail.example with ESMTP id r7
	; Tue, 03 Nov 2026 17:41:58 +0200
Received: from localhost (unknown [10.0.0.5])
	by smtp-relay.example with ESMTPA id q1
	; Tue, 03 Nov 2026 17:41:52 +0200
Authentication-Results: mx.google.com;
	spf=softfail (google.com: domain of transitioning bounce@mailer-relay-7x2.example does not designate 203.0.113.44 as permitted sender) smtp.mailfrom=mailer-relay-7x2.example;
	dkim=none;
	dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=mzanzi-secure.example
From: "security@mzanzi-bank.co.za" <alerts@mzanzi-secure.example>
Reply-To: "Mzanzi Support" <helpdesk@mzanzi-secure.example>
To: you@example.com
Subject: =?UTF-8?Q?Urgent:_your_account_is_suspended?=
Date: Tue, 03 Nov 2026 17:41:49 +0200 (SAST)
Message-ID: <20261103174149.7f3c@mailer-relay-7x2.example>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>Your account has been suspended. Verify now.</p></body></html>`;

export const CLEAN = `Return-Path: <bounce@news.example.org>
Received: from mail-io1-f52.google.com (mail-io1-f52.google.com [192.0.2.25])
	by mx.google.com with SMTPS id abc.123
	for <you@example.com>
	; Tue, 03 Nov 2026 08:15:03 -0800 (PST)
Received: from dispatch.example.org (dispatch.example.org [192.0.2.10])
	by mail-io1-f52.google.com with ESMTPS id def.456
	; Tue, 03 Nov 2026 16:15:01 +0000
Authentication-Results: mx.google.com;
	spf=pass (google.com: domain of bounce@news.example.org designates 192.0.2.10 as permitted sender) smtp.mailfrom=news.example.org;
	dkim=pass header.i=@example.org header.s=sel2026 header.b=XyZ123;
	dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.org
From: "Example Weekly" <news@example.org>
Reply-To: news@example.org
To: you@example.com
Subject: What changed in DNS this week
Date: Tue, 03 Nov 2026 16:15:00 +0000
Message-ID: <20261103161500.9a1b@dispatch.example.org>
List-Unsubscribe: <https://example.org/unsubscribe>, <mailto:leave@example.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

This week: the resolver comparison tool, and why TTLs disagree.`;

export const SAMPLES = [
  { id: 'suspicious', label: 'Forged bank email', text: SUSPICIOUS },
  { id: 'clean', label: 'Legitimate newsletter', text: CLEAN },
];
