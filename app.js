/* Apex-Shield — console logic.
   Loaded after core.js (helpers, tabs) and apk.js (zip + manifest parsing).
   Everything reads a local File object. There is no upload path in here. */

'use strict';

const HISTORY_KEY = 'shield-history-v1';
const CHECK_KEY = 'shield-checklist-v1';

/* --------------------------------------------------------------- formatting */

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '?';
  if (bytes < 1024) return bytes + ' B';
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return value.toFixed(value >= 10 ? 0 : 1) + ' ' + units[i];
}

function permissionInfo(name) {
  const key = String(name || '').replace('android.permission.', '').toUpperCase();
  const table = {
    CAMERA: ['caution', 'Camera access: the app can capture without a further prompt once granted.'],
    RECORD_AUDIO: ['danger', 'Microphone: records audio, including in the background.'],
    ACCESS_FINE_LOCATION: ['danger', 'Precise location, and often in the background too.'],
    ACCESS_COARSE_LOCATION: ['caution', 'Approximate location.'],
    ACCESS_BACKGROUND_LOCATION: ['danger', 'Location while the app is not in use.'],
    READ_SMS: ['danger', 'Reads every SMS: the usual vector for one-time code theft.'],
    RECEIVE_SMS: ['danger', 'Intercepts incoming SMS, including one-time codes.'],
    SEND_SMS: ['danger', 'Sends SMS, potentially to premium numbers.'],
    READ_CONTACTS: ['danger', 'Reads the address book.'],
    WRITE_CONTACTS: ['caution', 'Modifies the address book.'],
    READ_CALL_LOG: ['danger', 'Reads call history.'],
    CALL_PHONE: ['danger', 'Places calls without a confirmation step.'],
    READ_PHONE_STATE: ['caution', 'Device and SIM identifiers.'],
    READ_PHONE_NUMBERS: ['caution', 'Reads the phone number.'],
    READ_EXTERNAL_STORAGE: ['caution', 'Reads shared storage.'],
    WRITE_EXTERNAL_STORAGE: ['caution', 'Writes shared storage.'],
    MANAGE_EXTERNAL_STORAGE: ['danger', 'All-files access: the whole shared store.'],
    QUERY_ALL_PACKAGES: ['caution', 'Enumerates every installed app.'],
    SYSTEM_ALERT_WINDOW: ['danger', 'Draws over other apps: the standard overlay-phishing primitive.'],
    REQUEST_INSTALL_PACKAGES: ['danger', 'Can prompt the user to install another APK.'],
    BIND_ACCESSIBILITY_SERVICE: ['danger', 'Accessibility: reads the screen and acts as the user.'],
    BIND_DEVICE_ADMIN: ['danger', 'Device administrator.'],
    PACKAGE_USAGE_STATS: ['caution', 'App usage history.'],
    REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: ['caution', 'Asks to be exempt from battery limits.'],
    INTERNET: ['normal', 'Network access. Most apps need it.'],
    ACCESS_NETWORK_STATE: ['normal', 'Reads connectivity state.'],
    POST_NOTIFICATIONS: ['normal', 'Shows notifications.'],
    VIBRATE: ['normal', 'Haptics.'],
    WAKE_LOCK: ['normal', 'Keeps the CPU awake.'],
    FOREGROUND_SERVICE: ['normal', 'Runs a foreground service.'],
    RECEIVE_BOOT_COMPLETED: ['normal', 'Starts at boot.'],
    USE_BIOMETRIC: ['normal', 'Biometric unlock.'],
  };
  const hit = table[key];
  if (hit) return { level: hit[0], why: hit[1] };
  return { level: 'normal', why: 'Not in the curated list. Read the docs before assuming it is harmless.' };
}

const LEVEL_ORDER = { danger: 0, caution: 1, normal: 2 };

/* ---------------------------------------------------------------- kv helpers */

function fillKv(list, rows) {
  list.textContent = '';
  rows.forEach(([key, value, strong]) => {
    list.appendChild(el('dt', null, key));
    list.appendChild(el('dd', strong ? 'mono-strong' : null, value));
  });
}

function verdict(kind, title, body) {
  const box = el('div', 'verdict ' + kind);
  box.appendChild(el('strong', null, title));
  box.appendChild(el('span', null, body));
  return box;
}

/* ------------------------------------------------------------------- history */

function readHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '{}') || {};
  } catch {
    return {};
  }
}

function rememberFile(record) {
  const history = readHistory();
  const previous = history[record.sha256];
  history[record.sha256] = {
    name: previous ? previous.name : record.name,
    size: record.size,
    first: previous ? previous.first : new Date().toISOString(),
    seen: (previous ? previous.seen : 0) + 1,
  };
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {
    /* private mode: history just does not persist */
  }
  return previous;
}

/* -------------------------------------------------------------- file triage */

function setClamCommand(name) {
  const box = $('clamCmd');
  if (!box) return;
  const safe = name ? name.replace(/[^\w.\- ]+/g, '_') : '<path-to-file>';
  box.textContent = 'clamscan --infected --recursive --log=shield.log "' + safe + '"';
}

async function handleFile(file) {
  if (!file) return;
  const out = $('fileOut');
  const box = $('fileVerdict');
  const hint = $('fileHint');
  const zone = $('dropZone');

  out.hidden = false;
  out.textContent = '';
  setClamCommand(file.name);
  zone.classList.add('loaded');
  hint.textContent = 'Reading ' + file.name + ' locally…';

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch {
    hint.textContent = 'The browser refused to read that file.';
    return;
  }

  const type = detectFileType(buffer);
  const sha256 = await sha256Hex(buffer);
  const md5 = md5Hex(buffer);
  const entropy = entropyOf(buffer);

  fillKv(out, [
    ['Name', file.name, true],
    ['Size', formatBytes(buffer.byteLength) + ' (' + buffer.byteLength.toLocaleString() + ' bytes)'],
    ['Type', type.label],
    ['SHA-256', sha256 || 'unavailable without HTTPS', true],
    ['MD5', md5, true],
    ['Entropy', entropy.toFixed(2) + ' bits/byte' + (entropy > 7.2 ? ' · packed or encrypted' : '')],
  ]);

  box.hidden = false;
  box.textContent = '';

  if (type.note) {
    box.appendChild(el('p', 'hint', type.note));
  }

  if (sha256) {
    const previous = rememberFile({ sha256, name: file.name, size: buffer.byteLength });
    box.appendChild(
      el(
        'p',
        'hint',
        previous
          ? 'Seen here ' + previous.seen + '× before, first as "' + previous.name + '" on ' + new Date(previous.first).toLocaleDateString() + '.'
          : 'First time this exact hash has been seen in this browser.'
      )
    );
  }

  box.appendChild(
    el(
      'p',
      'hint',
      'A hash identifies the file, not its intent. Run the ClamAV command below on the machine that holds the signature database.'
    )
  );

  // A zip with an Android manifest is an APK: offer the deeper read instead of
  // making the user guess which tab to use.
  if (type.label === 'ZIP container') {
    const zip = readZipDirectory(buffer);
    if (zip && zip.entries.some((e) => e.name === 'AndroidManifest.xml')) {
      const row = el('div', 'row');
      const open = el('button', 'btn', 'Analyse as APK');
      open.type = 'button';
      open.addEventListener('click', () => {
        showPanel('apk');
        handleApk(file);
      });
      row.appendChild(open);
      box.appendChild(row);
    }
  }

  hint.textContent = 'Hashes and structure computed in this tab. Nothing was uploaded.';
}

/* ------------------------------------------------------------ apk analysis */

function signatureChips(apk) {
  const wrap = $('apkFlags');
  wrap.textContent = '';

  const chip = (label, state) => el('span', 'flag ' + state, label);

  wrap.appendChild(chip('v1 ' + (apk.v1.present ? 'present' : 'absent'), apk.v1.present ? 'good' : 'on'));
  wrap.appendChild(chip('v2 ' + (apk.v2 ? 'present' : 'absent'), apk.v2 ? 'good' : 'on'));
  wrap.appendChild(chip('v3 ' + (apk.v3 ? 'present' : 'absent'), apk.v3 ? 'good' : 'on'));

  const flags = apk.flags || {};
  wrap.appendChild(chip('debuggable ' + (flags.debuggable === true ? 'true' : flags.debuggable === false ? 'false' : 'unset'), flags.debuggable === true ? 'bad' : flags.debuggable === false ? 'good' : ''));
  wrap.appendChild(chip('allowBackup ' + (flags.allowBackup === true ? 'true' : flags.allowBackup === false ? 'false' : 'unset'), flags.allowBackup === true ? 'on' : flags.allowBackup === false ? 'good' : ''));
  wrap.appendChild(chip('cleartext ' + (flags.cleartext === true ? 'allowed' : flags.cleartext === false ? 'blocked' : 'unset'), flags.cleartext === true ? 'on' : flags.cleartext === false ? 'good' : ''));
  wrap.appendChild(chip(apk.dexFiles + ' dex · ' + apk.nativeLibs + ' native', ''));
}

function permissionList(apk) {
  const list = $('permList');
  const count = $('permCount');
  list.textContent = '';

  const sorted = apk.permissions
    .map((name) => ({ name, ...permissionInfo(name) }))
    .sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || a.name.localeCompare(b.name));

  const dangers = sorted.filter((p) => p.level === 'danger').length;
  count.textContent = sorted.length
    ? sorted.length + ' · ' + dangers + ' dangerous'
    : 'none declared';
  count.className = 'badge ' + (dangers ? 'bad' : sorted.length ? 'warn' : 'ok');

  if (!sorted.length) {
    list.appendChild(el('li', 'empty', 'This manifest declares no permissions.'));
    return;
  }

  sorted.forEach((perm) => {
    const row = el('li', 'perm ' + perm.level);
    row.appendChild(el('span', 'pname', perm.name.replace('android.permission.', '')));
    row.appendChild(el('span', 'badge ' + (perm.level === 'danger' ? 'bad' : perm.level === 'caution' ? 'warn' : 'ok'), perm.level));
    row.appendChild(el('span', 'pwhy', perm.why));
    list.appendChild(row);
  });
}

async function handleApk(file) {
  if (!file) return;
  const out = $('apkOut');
  const hint = $('apkHint');
  const zone = $('apkZone');

  out.hidden = false;
  out.textContent = '';
  zone.classList.add('loaded');
  hint.textContent = 'Reading ' + file.name + '…';
  hint.classList.remove('bad');

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch {
    hint.textContent = 'The browser refused to read that file.';
    hint.classList.add('bad');
    return;
  }

  let apk;
  try {
    apk = await analyseApk(buffer, buffer.byteLength);
  } catch (e) {
    hint.textContent = 'Could not analyse this file: ' + e.message + '.';
    hint.classList.add('bad');
    $('permList').textContent = '';
    $('permList').appendChild(el('li', 'empty', 'No manifest could be read.'));
    $('permCount').textContent = 'unreadable';
    $('permCount').className = 'badge bad';
    $('apkFlags').textContent = '';
    return;
  }

  const version = [apk.versionName, apk.versionCode ? '(' + apk.versionCode + ')' : '']
    .filter(Boolean)
    .join(' ');

  fillKv(out, [
    ['Package', apk.package || 'not declared', true],
    ['Version', version || 'not declared'],
    ['Min SDK', apk.minSdk === null || apk.minSdk === undefined ? 'unset' : String(apk.minSdk)],
    ['Target SDK', apk.targetSdk === null || apk.targetSdk === undefined ? 'unset' : String(apk.targetSdk)],
    ['Manifest', apk.binaryManifest ? 'compiled binary XML' : 'plain text XML'],
    ['Signatures', apk.schemes.length ? apk.schemes.join(', ') : apk.v1.present ? 'v1 only (JAR signing)' : 'none found'],
    ['Signer files', apk.certFiles.length ? apk.certFiles.join(', ') : 'none in META-INF'],
    ['Entries', apk.entries + ' zip entries'],
    ['SHA-256', apk.sha256 || 'unavailable without HTTPS', true],
  ]);

  signatureChips(apk);
  permissionList(apk);

  const notes = [];
  if (apk.flags && apk.flags.debuggable === true) notes.push('debuggable: a debugger can attach to the running app.');
  if (apk.flags && apk.flags.allowBackup === true) notes.push('allowBackup: app data can be extracted with adb.');
  if (apk.flags && apk.flags.cleartext === true) notes.push('cleartext traffic allowed.');
  if (!apk.v2 && !apk.v3) notes.push('no v2/v3 signature: only the older JAR signature covers this file.');
  if (!apk.v1.present && !apk.v2 && !apk.v3) notes.push('unsigned: nothing binds this file to a publisher.');

  hint.classList.remove('bad');
  hint.textContent = notes.length
    ? 'Flags worth reading: ' + notes.join(' ')
    : 'No manifest flags stood out. That is not a clean verdict: only a signature database can give one.';
}

/* ----------------------------------------------------------------- checklist */

const CHECKLIST = [
  'ClamAV installed on the VPS, `freshclam` run once',
  'One local file scanned from the shell with `clamscan`',
  'Worker route accepts an object key and returns `pending`',
  'VPS service pulls from B2, scans, writes the verdict back',
];

function readChecks() {
  try {
    return JSON.parse(localStorage.getItem(CHECK_KEY) || '[]') || [];
  } catch {
    return [];
  }
}

function renderQueue() {
  const list = $('checklist');
  const badge = $('readyCount');
  if (!list) return;
  const done = readChecks();
  list.textContent = '';

  CHECKLIST.forEach((label, i) => {
    const row = el('li', done.includes(i) ? 'done' : '');
    const box = el('span', 'box');
    box.setAttribute('role', 'checkbox');
    box.setAttribute('tabindex', '0');
    box.setAttribute('aria-checked', done.includes(i) ? 'true' : 'false');
    const toggle = () => {
      const current = readChecks();
      const next = current.includes(i) ? current.filter((x) => x !== i) : current.concat(i);
      try {
        localStorage.setItem(CHECK_KEY, JSON.stringify(next));
      } catch {
        /* ignore */
      }
      renderQueue();
    };
    box.addEventListener('click', toggle);
    box.addEventListener('keydown', (event) => {
      if (event.key === ' ' || event.key === 'Enter') {
        event.preventDefault();
        toggle();
      }
    });

    row.appendChild(box);
    row.appendChild(el('span', 'label', label));
    row.appendChild(el('span', 'badge ' + (done.includes(i) ? 'ok' : ''), done.includes(i) ? 'done' : 'todo'));
    list.appendChild(row);
  });

  if (badge) {
    badge.textContent = done.length + ' of ' + CHECKLIST.length;
    badge.className = 'badge ' + (done.length === CHECKLIST.length ? 'ok' : done.length ? 'warn' : '');
  }
}

/* -------------------------------------------------------------------- wiring */

function wireDrop(zoneId, inputId, handler) {
  const zone = $(zoneId);
  const input = $(inputId);
  if (!zone || !input) return;

  input.addEventListener('change', () => {
    if (input.files && input.files[0]) handler(input.files[0]);
    input.value = '';
  });

  ['dragenter', 'dragover'].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.add('over');
    });
  });

  ['dragleave', 'drop'].forEach((name) => {
    zone.addEventListener(name, (event) => {
      event.preventDefault();
      zone.classList.remove('over');
    });
  });

  zone.addEventListener('drop', (event) => {
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) handler(file);
  });
}

function boot() {
  wireDrop('dropZone', 'fileInput', handleFile);
  wireDrop('apkZone', 'apkInput', handleApk);

  const clear = $('clearFile');
  if (clear) {
    clear.addEventListener('click', () => {
      const out = $('fileOut');
      const box = $('fileVerdict');
      if (out) {
        out.textContent = '';
        out.hidden = true;
      }
      if (box) {
        box.textContent = '';
        box.hidden = true;
      }
      const zone = $('dropZone');
      if (zone) zone.classList.remove('loaded');
      const hint = $('fileHint');
      if (hint) hint.textContent = 'Hashes, magic bytes and archive layout are computed in this tab. That is all a browser can honestly do.';
      setClamCommand('');
    });
  }

  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const node = $(btn.dataset.copy);
      copy(node ? node.textContent : '', 'Copied');
    });
  });

  renderQueue();

  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('sw.js').catch(() => {
      toast('Offline shell unavailable in this browser');
    });
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
