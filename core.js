/* Apex-Shield shared helpers. Loaded first: $, el, toast, copy, tab routing,
   and the network badge. Every module builds on these, so nothing else defines
   them twice. */

'use strict';

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

let toastTimer = null;

function toast(message) {
  const box = $('toast');
  if (!box) return;
  box.textContent = message;
  box.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove('show'), 1900);
}

async function copy(text, okMessage) {
  if (!text) {
    toast('Nothing to copy');
    return false;
  }
  try {
    await navigator.clipboard.writeText(text);
    toast(okMessage || 'Copied');
    return true;
  } catch {
    // Clipboard permission is refused outside a user gesture or on insecure
    // origins; select the text instead of pretending it worked.
    toast('Clipboard blocked: select the text and copy manually');
    return false;
  }
}

/* ------------------------------------------------------------------- panels */

const PANELS = ['file', 'apk', 'queue'];

function showPanel(name) {
  if (!PANELS.includes(name)) return;
  PANELS.forEach((p) => {
    const panel = $('panel-' + p);
    if (panel) panel.hidden = p !== name;
  });
  document.querySelectorAll('.tab').forEach((tab) => {
    const on = tab.dataset.panel === name;
    tab.classList.toggle('active', on);
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  document.body.dataset.panel = name;
  if (name === 'queue' && typeof renderQueue === 'function') renderQueue();
}

function paintNet() {
  const dot = $('netStatus');
  const label = $('netLabel');
  if (!dot || !label) return;
  const online = navigator.onLine;
  dot.classList.toggle('offline', !online);
  label.textContent = online ? 'ONLINE' : 'OFFLINE';
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => showPanel(tab.dataset.panel));
  });

  document.querySelectorAll('.tab').forEach((tab, i) => {
    tab.title = 'Press ' + (i + 1);
  });

  document.addEventListener('keydown', (event) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return;
    const tag = (event.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
    const index = Number(event.key) - 1;
    if (index >= 0 && index < PANELS.length) showPanel(PANELS[index]);
  });

  window.addEventListener('online', paintNet);
  window.addEventListener('offline', paintNet);
  paintNet();
});
