# Apex Shield

Scans files, APKs and URLs for known malware. ClamAV for signatures, YARA for patterns.

**Status: the console is built and runs entirely in the tab; the scanner is still a VPS
service that does not exist yet.**

```
index.html            shell and markup
styles.css            charcoal / green / cyan theme
core.js               helpers, tab routing, network state (loaded first)
apk.js                zip, binary AndroidManifest.xml and signing-block parsing
app.js                console logic: file triage, APK view, setup checklist
manifest.webmanifest  PWA manifest
sw.js                 offline service worker
_headers              CSP and friends for a static host
icons/                generated PNG icons (any + maskable)
```

Deploy is a static file copy. There is nothing to compile and no server of our own.

## What the console actually does

**File triage** — drop any file and it is hashed (SHA-256 and MD5), typed from its magic
bytes, and measured for entropy. A SHA-256 seen before in this browser is remembered, so a
"same name, different bytes" swap is visible. Every file also gets the exact `clamscan`
command to run where the signature database lives.

**APK static analysis** — reads the zip central directory, inflates `AndroidManifest.xml`,
and decodes the compiled binary XML (string pool, resource map, attributes) to report the
package, version, min/target SDK, every declared permission grouped by risk, and the flags
that matter: `debuggable`, `allowBackup`, `usesCleartextTraffic`. It also detects the v1
(JAR), v2 and v3 APK Signing Block schemes and names the signer files in `META-INF`.

**Setup** — the queue contract, the ClamAV/VPS commands and the Safe Browsing request, with
a checklist that persists, so a half-built Shield still tells you where it stopped.

Nothing is uploaded, and there is no code path that could: the file never leaves the tab.

## The constraint that shapes it

ClamAV keeps a signature database that is hundreds of megabytes and changes daily. YARA
needs files on a real filesystem. Neither can run in a Cloudflare Worker, which has no
disk, a CPU time limit and no long-lived process. Supabase Edge Functions are no better.

So Shield needs **the machine you already run for `Automation`** — the VPS behind the
Cloudflare Tunnel — with ClamAV installed there and a queue in front of it. The Worker
would hand over a file reference, the VPS would pull the object from B2, scan it, and write
the verdict back. That is the contract in the Setup tab, and it is not written yet.

## Honest expectations

- ClamAV catches **known** malware. A freshly built APK that nobody has seen is not in the
  database, so "clean" means "nothing known", not "safe".
- Permissions alone are not a finding. A torch app wants the camera; a messaging app wants
  SMS. The console groups them by risk so the list is readable, not so it can accuse.
- Signature detection here reports the **scheme**, not trust in the certificate chain.
- Google Play Protect already does this on your phone, with vastly more data. Shield is
  worth building only for files that never touch a store.
- For URLs, Google Safe Browsing has a free API with quota. Reimplementing that from
  scratch would be worse than useless.

## What you need to do

1. The VPS (or an old laptop) that will hold the ClamAV database.
2. A Safe Browsing API key, which is free. It belongs in the Worker's secrets, never here.

## Next steps

1. ClamAV on the VPS, scanning one local file, before any of this touches the suite.
2. A Worker route that accepts an object key and returns "pending" — the queue.
3. APK static analysis — **done**, in this console. The server side only has to accept the
   queue entry now.
