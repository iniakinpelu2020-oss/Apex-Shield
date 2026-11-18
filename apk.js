/* Apex-Shield — file format layer.
   Reads a zip central directory, decodes the compiled AndroidManifest.xml
   (binary XML), and looks for the APK signing schemes. All of it runs on an
   ArrayBuffer in this tab; nothing is inflated from a remote service. */

'use strict';

const ascii = (bytes) => String.fromCharCode(...bytes);
const u64 = (view, at) => view.getUint32(at, true) + view.getUint32(at + 4, true) * 0x100000000;

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const SIG_XML = 0x00080003;
const SIG_STRING_POOL = 0x0001;
const SIG_RESOURCE_MAP = 0x0180;
const SIG_START_ELEMENT = 0x0102;

/* ------------------------------------------------------------------- hashes */

function hexOf(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(buffer) {
  if (!window.crypto || !crypto.subtle) return null;
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return hexOf(digest);
}

function md5Hex(buffer) {
  // Local MD5 so a file can be matched against public hash lists without
  // WebCrypto (which has no MD5). Small implementation, byte-accurate.
  const bytes = new Uint8Array(buffer);
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) * 64);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const pv = new DataView(padded.buffer);
  pv.setUint32(padded.length - 8, bitLen >>> 0, true);
  pv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let at = 0; at < padded.length; at += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = pv.getUint32(at + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + (((F << S[i]) | (F >>> (32 - S[i]))) >>> 0)) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0].map((w) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, w, true);
    return hexOf(b.buffer);
  }).join('');
}

function entropyOf(buffer) {
  const bytes = new Uint8Array(buffer, 0, Math.min(buffer.byteLength, 1 << 20));
  if (!bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let bits = 0;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / bytes.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/* ---------------------------------------------------------------------- zip */

function findEocd(view) {
  const len = view.byteLength;
  const stop = Math.max(0, len - 66000);
  for (let at = len - 22; at >= stop; at--) {
    if (view.getUint32(at, true) === SIG_EOCD) return at;
  }
  return -1;
}

function readZipDirectory(buffer) {
  const view = new DataView(buffer);
  const eocd = findEocd(view);
  if (eocd < 0) return null;

  const count = view.getUint16(eocd + 10, true);
  let at = view.getUint32(eocd + 16, true);
  if (at === 0xffffffff) return null; // zip64: out of scope, say so upstream

  const entries = [];
  for (let i = 0; i < count; i++) {
    if (at + 46 > view.byteLength || view.getUint32(at, true) !== SIG_CENTRAL) break;
    const nameLen = view.getUint16(at + 28, true);
    const extraLen = view.getUint16(at + 30, true);
    const commentLen = view.getUint16(at + 32, true);
    const name = new TextDecoder().decode(new Uint8Array(buffer, at + 46, nameLen));
    entries.push({
      name,
      method: view.getUint16(at + 10, true),
      compressed: view.getUint32(at + 20, true),
      size: view.getUint32(at + 24, true),
      offset: view.getUint32(at + 42, true),
    });
    at += 46 + nameLen + extraLen + commentLen;
  }
  return { entries, cdOffset: view.getUint32(eocd + 16, true) };
}

async function readZipEntry(buffer, entry) {
  const view = new DataView(buffer);
  if (view.getUint32(entry.offset, true) !== SIG_LOCAL) throw new Error('bad local header');
  const nameLen = view.getUint16(entry.offset + 26, true);
  const extraLen = view.getUint16(entry.offset + 28, true);
  const start = entry.offset + 30 + nameLen + extraLen;
  const slice = buffer.slice(start, start + entry.compressed);

  if (entry.method === 0) return slice;
  if (entry.method !== 8) throw new Error('compression method ' + entry.method + ' is not supported');
  if (typeof DecompressionStream === 'undefined') throw new Error('this browser cannot inflate deflate-raw');

  const stream = new Blob([slice]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return await new Response(stream).arrayBuffer();
}

/* --------------------------------------------------------------- binary xml */

function readPoolString(bytes, at, utf8) {
  if (utf8) {
    // A UTF-8 pool stores two lengths: UTF-16 code units, then UTF-8 bytes.
    let units = bytes[at++];
    if (units & 0x80) { units = ((units & 0x7f) << 8) | bytes[at++]; }
    let size = bytes[at++];
    if (size & 0x80) { size = ((size & 0x7f) << 8) | bytes[at++]; }
    return new TextDecoder().decode(bytes.subarray(at, at + size));
  }
  let len = bytes[at] | (bytes[at + 1] << 8);
  at += 2;
  if (len & 0x8000) {
    len = ((len & 0x7fff) << 16) | (bytes[at] | (bytes[at + 1] << 8));
    at += 2;
  }
  return new TextDecoder('utf-16le').decode(bytes.subarray(at, at + len * 2));
}

function parseStringPool(view, at) {
  const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  const headerSize = view.getUint16(at + 2, true);
  const count = view.getUint32(at + 8, true);
  const flags = view.getUint32(at + 16, true);
  const stringsStart = view.getUint32(at + 20, true);
  const utf8 = (flags & 0x100) !== 0;
  const base = at + stringsStart;

  const strings = [];
  for (let i = 0; i < count; i++) {
    const offset = view.getUint32(at + headerSize + i * 4, true);
    strings.push(readPoolString(bytes, base + offset, utf8));
  }
  return strings;
}

function attrValue(view, strings, attrAt) {
  const rawIndex = view.getUint32(attrAt + 8, true);
  if (rawIndex !== 0xffffffff && strings[rawIndex] !== undefined) return strings[rawIndex];
  const type = view.getUint8(attrAt + 15);
  const data = view.getUint32(attrAt + 16, true);
  if (type === 0x03) return strings[data] !== undefined ? strings[data] : String(data);
  if (type === 0x12) return data !== 0;
  if (type === 0x10 || type === 0x11) return data;
  return data;
}

/* Attribute resource IDs, so a manifest that carries the resource map is read
   by ID and one that does not is read by name. Android does the same. */
const RID = {
  NAME: 0x01010003,
  DEBUGGABLE: 0x0101000f,
  MIN_SDK: 0x0101020c,
  VERSION_CODE: 0x0101021b,
  VERSION_NAME: 0x0101021c,
  TARGET_SDK: 0x01010270,
  ALLOW_BACKUP: 0x01010280,
  CLEARTEXT: 0x010104ec,
  EXTRACT_NATIVE: 0x010104ea,
};

function parseBinaryXml(buffer) {
  const view = new DataView(buffer);
  const out = {
    package: '',
    versionName: '',
    versionCode: null,
    minSdk: null,
    targetSdk: null,
    permissions: [],
    flags: {},
    elements: 0,
  };
  let strings = [];
  let resIds = [];
  let at = 8;

  while (at + 8 <= view.byteLength) {
    const type = view.getUint16(at, true);
    const headerSize = view.getUint16(at + 2, true);
    const size = view.getUint32(at + 4, true);
    if (size <= 0 || at + size > view.byteLength) break;

    if (type === SIG_STRING_POOL) {
      strings = parseStringPool(view, at);
    } else if (type === SIG_RESOURCE_MAP) {
      resIds = [];
      for (let i = headerSize; at + i + 4 <= at + size; i += 4) resIds.push(view.getUint32(at + i, true));
    } else if (type === SIG_START_ELEMENT) {
      const base = at + headerSize;
      const nameIdx = view.getUint32(base + 4, true);
      const attrStart = view.getUint16(base + 8, true);
      const attrSize = view.getUint16(base + 10, true);
      const attrCount = view.getUint16(base + 12, true);
      const tag = strings[nameIdx] || '';
      out.elements++;

      const attrs = {};
      for (let i = 0; i < attrCount; i++) {
        const attrAt = base + attrStart + i * attrSize;
        if (attrAt + 20 > at + size) break;
        const aNameIdx = view.getUint32(attrAt + 4, true);
        // A resource-map slot of 0 means "this name carries no resource id",
        // which is the normal case for plain attributes such as package=.
        const resId = resIds[aNameIdx] || undefined;
        const key = resId !== undefined ? '#' + resId.toString(16) : strings[aNameIdx];
        attrs[key] = { name: strings[aNameIdx] || key, value: attrValue(view, strings, attrAt) };
      }

      const pick = (rid, fallback) => {
        const byId = attrs['#' + rid.toString(16)];
        if (byId) return byId.value;
        const byName = attrs[fallback];
        return byName ? byName.value : undefined;
      };

      if (tag === 'manifest') {
        if (attrs.package && typeof attrs.package.value === 'string') out.package = attrs.package.value;
        const vName = pick(RID.VERSION_NAME, 'versionName');
        if (vName !== undefined) out.versionName = String(vName);
        const vCode = pick(RID.VERSION_CODE, 'versionCode');
        if (vCode !== undefined) out.versionCode = vCode;
      } else if (tag === 'uses-sdk') {
        const min = pick(RID.MIN_SDK, 'minSdkVersion');
        const target = pick(RID.TARGET_SDK, 'targetSdkVersion');
        if (min !== undefined) out.minSdk = min;
        if (target !== undefined) out.targetSdk = target;
      } else if (tag === 'uses-permission' || tag === 'uses-permission-sdk-23') {
        const name = pick(RID.NAME, 'name');
        if (typeof name === 'string' && name && !out.permissions.includes(name)) out.permissions.push(name);
      } else if (tag === 'application') {
        out.flags.debuggable = pick(RID.DEBUGGABLE, 'debuggable');
        out.flags.allowBackup = pick(RID.ALLOW_BACKUP, 'allowBackup');
        out.flags.cleartext = pick(RID.CLEARTEXT, 'usesCleartextTraffic');
        out.flags.extractNative = pick(RID.EXTRACT_NATIVE, 'extractNativeLibs');
      }
    }
    at += size;
  }

  if (!out.elements) throw new Error('no XML elements found');
  return out;
}

function parseTextManifest(buffer) {
  // Some tools ship an uncompiled manifest. Read it rather than failing.
  const text = new TextDecoder().decode(buffer);
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const manifest = doc.querySelector('manifest');
  if (!manifest) throw new Error('manifest root missing');
  const android = 'http://schemas.android.com/apk/res/android';
  const get = (node, name) => node.getAttributeNS(android, name);

  const permissions = [...doc.querySelectorAll('uses-permission, uses-permission-sdk-23')]
    .map((n) => get(n, 'name'))
    .filter(Boolean);
  const application = doc.querySelector('application');
  const sdk = doc.querySelector('uses-sdk');

  return {
    package: manifest.getAttribute('package') || '',
    versionName: manifest.getAttributeNS(android, 'versionName') || '',
    versionCode: Number(manifest.getAttributeNS(android, 'versionCode')) || null,
    minSdk: sdk ? get(sdk, 'minSdkVersion') : null,
    targetSdk: sdk ? get(sdk, 'targetSdkVersion') : null,
    permissions: [...new Set(permissions)],
    flags: {
      debuggable: application ? get(application, 'debuggable') === 'true' : undefined,
      allowBackup: application ? get(application, 'allowBackup') === 'true' : undefined,
      cleartext: application ? get(application, 'usesCleartextTraffic') === 'true' : undefined,
      extractNative: application ? get(application, 'extractNativeLibs') : undefined,
    },
    elements: doc.querySelectorAll('*').length,
  };
}

/* ---------------------------------------------------------- signing schemes */

const APK_SIG_IDS = { 0x7109871a: 'v2', 0xf05368c0: 'v3', 0x1b93ad61: 'v3.1', 0x6dff800d: 'source stamp' };

function readSigningBlock(buffer, cdOffset) {
  const view = new DataView(buffer);
  if (cdOffset < 32 || cdOffset > view.byteLength) return { schemes: [], pairs: [] };
  const marker = new Uint8Array(buffer, cdOffset - 16, 16);
  if (ascii(marker) !== 'APK Sig Block 42') return { schemes: [], pairs: [] };

  const size = u64(view, cdOffset - 24);
  const start = cdOffset - size - 8;
  if (start < 0) return { schemes: [], pairs: [] };

  const schemes = [];
  const pairs = [];
  let at = start + 8;
  const end = cdOffset - 24;
  let guard = 0;
  while (at + 12 <= end && guard++ < 64) {
    const len = u64(view, at);
    if (len < 4) break;
    const id = view.getUint32(at + 8, true);
    pairs.push(id >>> 0);
    if (APK_SIG_IDS[id]) schemes.push(APK_SIG_IDS[id]);
    at += 8 + len;
  }
  return { schemes: [...new Set(schemes)], pairs };
}

/* ------------------------------------------------------------------- entry */

function detectFileType(bytes) {
  const b = new Uint8Array(bytes, 0, Math.min(bytes.byteLength, 16));
  const starts = (sig, offset = 0) => sig.every((v, i) => b[offset + i] === v);
  const text = (s, offset = 0) => b[offset] === s.charCodeAt(0);

  if (starts([0x50, 0x4b, 0x03, 0x04])) return { label: 'ZIP container', note: 'APK, JAR, DOCX, or a plain archive: the entry list decides.' };
  if (starts([0x4d, 0x5a])) return { label: 'Windows PE (MZ)', note: 'Executable or DLL. Never run it to find out more.' };
  if (starts([0x7f, 0x45, 0x4c, 0x46])) return { label: 'ELF binary', note: 'Linux/Android native executable or shared object.' };
  if (starts([0x25, 0x50, 0x44, 0x46])) return { label: 'PDF document', note: 'Scripts and embedded files live inside the object streams.' };
  if (starts([0xd0, 0xcf, 0x11, 0xe0])) return { label: 'OLE compound file', note: 'Legacy Office document or MSI installer.' };
  if (starts([0x52, 0x61, 0x72, 0x21])) return { label: 'RAR archive' };
  if (starts([0x37, 0x7a, 0xbc, 0xaf])) return { label: '7-Zip archive' };
  if (starts([0x1f, 0x8b])) return { label: 'gzip stream' };
  if (starts([0x64, 0x65, 0x78, 0x0a])) return { label: 'Android DEX bytecode', note: 'Pull the manifest and permissions from the APK, not this.' };
  if (starts([0xfe, 0xed, 0xfa, 0xce]) || starts([0xcf, 0xfa, 0xed, 0xfe])) return { label: 'Mach-O binary' };
  if (starts([0xca, 0xfe, 0xba, 0xbe]) && b[6] < 0x41) return { label: 'Java class file' };
  if (text('#') && text('!', 1)) return { label: 'Script', note: 'Shebang line: read it before anything executes it.' };
  return { label: 'Unrecognised', note: 'No known magic bytes. That is a fact about the header, not a verdict.' };
}

async function analyseApk(buffer, fileSize) {
  const zip = readZipDirectory(buffer);
  if (!zip) throw new Error('not a readable zip (or it is zip64)');

  const manifestEntry = zip.entries.find((e) => e.name === 'AndroidManifest.xml');
  if (!manifestEntry) throw new Error('no AndroidManifest.xml: this is a zip, not an APK');

  const raw = await readZipEntry(buffer, manifestEntry);
  const view = new DataView(raw);
  const binary = raw.byteLength > 8 && view.getUint32(0, true) === SIG_XML;
  const manifest = binary ? parseBinaryXml(raw) : parseTextManifest(raw);

  const certFiles = zip.entries
    .filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name))
    .map((e) => e.name);
  const hasManifestMf = zip.entries.some((e) => e.name === 'META-INF/MANIFEST.MF');
  const signing = readSigningBlock(buffer, zip.cdOffset);
  const dex = zip.entries.filter((e) => /^classes\d*\.dex$/.test(e.name)).length;
  const nativeLibs = zip.entries.filter((e) => /^lib\/[^/]+\/.+\.so$/.test(e.name)).length;

  return {
    ...manifest,
    binaryManifest: binary,
    isApk: true,
    entries: zip.entries.length,
    dexFiles: dex,
    nativeLibs,
    certFiles,
    v1: { present: certFiles.length > 0 || hasManifestMf, certFiles, manifestMf: hasManifestMf },
    v2: signing.schemes.includes('v2'),
    v3: signing.schemes.includes('v3') || signing.schemes.includes('v3.1'),
    schemes: signing.schemes,
    fileSize,
    sha256: await sha256Hex(buffer),
    md5: md5Hex(buffer),
    entropy: entropyOf(buffer),
  };
}
