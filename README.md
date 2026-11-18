# Apex Shield

Scans files, APKs and URLs for known malware. ClamAV for signatures, YARA for patterns.

**Status: not built, and it cannot live where the rest of the suite lives.**

## The constraint that shapes it

ClamAV keeps a signature database that is hundreds of megabytes and changes daily. YARA
needs files on a real filesystem. Neither can run in a Cloudflare Worker, which has no
disk, a CPU time limit and no long-lived process. Supabase Edge Functions are no better.

So Shield needs **the machine you already run for `Automation`** — the VPS behind the
Cloudflare Tunnel — with ClamAV installed there and a queue in front of it. The Worker
would hand over a file reference, the VPS would pull the object from B2, scan it, and write
the verdict back.

## Honest expectations

- ClamAV catches **known** malware. A freshly built APK that nobody has seen is not in the
  database, so "clean" means "nothing known", not "safe".
- For APKs, the useful checks are static ones a scanner can do cheaply: which permissions
  it asks for, whether it is signed, whether the signature matches the previous version,
  and whether it came from outside a store.
- Google Play Protect already does this on your phone, with vastly more data. Shield is
  worth building only for files that never touch a store.
- For URLs, Google Safe Browsing has a free API with quota. Reimplementing that from
  scratch would be worse than useless.

## What you need to do

1. The VPS (or an old laptop) that will hold the ClamAV database.
2. A Safe Browsing API key, which is free.

## First three steps

1. ClamAV on the VPS, scanning one local file, before any of this touches the suite.
2. A Worker route that accepts an object key and returns "pending" — the queue.
3. APK static analysis first, because it is the part that needs no signature database.
