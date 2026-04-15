// JavaScript deobfuscation harness for ACE3.
//
// Usage: node harness.js <input_path> <output_path>
//
// Two-stage pipeline:
//   1. Static pass — webcrack resolves string-table indirection, constant-
//      folds JSFuck-style expressions, beautifies, and prunes dead code.
//      Uses a node:vm-backed custom sandbox so we don't pull in the
//      isolated-vm native addon.
//   2. Dynamic pass — runs the cleaned source inside a node:vm sandbox
//      with stubbed browser and Acrobat globals. Every read and write the
//      script performs against those globals is recorded via Proxy traps.
//
// The reconstructed pseudo-JS trace is written to <output_path>, and a
// JSON status report is printed to stdout. Webcrack is optional: if it's
// unavailable (missing dependency, crash), we fall back to the raw source
// and continue with the dynamic pass so the module still produces output.

import fs from 'node:fs';
import vm from 'node:vm';

const [, , INPUT_PATH, OUTPUT_PATH] = process.argv;
if (!INPUT_PATH || !OUTPUT_PATH) {
  process.stdout.write(JSON.stringify({ status: 'error', error: 'usage: harness.js <input> <output>' }));
  process.exit(2);
}

let SRC = fs.readFileSync(INPUT_PATH, 'utf8');
// status values:
//   "skipped"                   — webcrack not available / not tried
//   "applied"                   — webcrack ran and materially changed source
//   "applied (cosmetic only)"   — webcrack ran but deltas are < 2% of size,
//                                 meaning the tail block is unlikely to reveal
//                                 anything new to an analyst
//   "failed: <reason>"          — webcrack threw
let webcrackStatus = 'skipped';
let webcrackError = null;

// ---------------------------------------------------------------------------
// Stage 1 — webcrack static pre-pass
// ---------------------------------------------------------------------------
try {
  const { webcrack } = await import('webcrack');
  // Pass a custom sandbox so webcrack runs the obfuscator's string-decoder
  // function through node:vm instead of isolated-vm. isolated-vm needs a
  // native C++ build which we don't want in the scanner image. Our dynamic
  // stage runs in vm anyway, so pulling in a second sandbox runtime buys
  // nothing.
  const nodeVmSandbox = async (code) => {
    const ctx = vm.createContext({});
    return vm.runInContext(code, ctx, { timeout: 10000 });
  };
  const result = await webcrack(SRC, {
    sandbox: nodeVmSandbox,
    jsx: false,
    unpack: false,
    mangle: false,
  });
  if (result && typeof result.code === 'string' && result.code.length > 0) {
    // Classify: did webcrack change anything meaningful, or just reformat /
    // constant-fold a few tokens? Compare whitespace-stripped lengths — if
    // the relative delta is under 2%, the tail block is unlikely to help
    // an analyst (webcrack hit a JSFuck-only or eval-wrapped sample where
    // the sandbox does the real work) and we should say so in the header.
    const rawCompact = SRC.replace(/\s+/g, '');
    const newCompact = result.code.replace(/\s+/g, '');
    const delta = Math.abs(newCompact.length - rawCompact.length) / Math.max(rawCompact.length, 1);
    webcrackStatus = (delta < 0.02) ? 'applied (cosmetic only)' : 'applied';
    SRC = result.code;
  }
} catch (e) {
  webcrackError = e && (e.message || String(e));
  webcrackStatus = `failed: ${webcrackError}`;
}

// ---------------------------------------------------------------------------
// Stage 2 — dynamic sandbox
// ---------------------------------------------------------------------------
const events = [];
const secondaryScripts = [];

function safeStringify(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'function') {
    try {
      // String(value) hits the recorder Proxy's toString trap (returning
      // `[label]` for our wrappers) or calls Function.prototype.toString on a
      // real user-written function (returning its source). That lets us
      // surface cleartext function bodies the malware author actually wrote
      // while still rendering recorders as readable labels.
      const src = String(value);
      if (src.startsWith('[') && src.endsWith(']')) return src;
      if (src.includes('[native code]')) return '[native function]';
      if (src.length > 2048) {
        return JSON.stringify(src.slice(0, 2048) + '…[truncated]');
      }
      return src;
    } catch (_) {
      return '[function]';
    }
  }
  try {
    return JSON.stringify(value);
  } catch (_) {
    try { return String(value); } catch (__) { return '[unserializable]'; }
  }
}

function recorder(label) {
  const target = function () {};
  return new Proxy(target, {
    get(_t, prop) {
      if (typeof prop === 'symbol') {
        if (prop === Symbol.toPrimitive) return () => `[${label}]`;
        if (prop === Symbol.iterator) return undefined;
        return undefined;
      }
      if (prop === 'toString' || prop === 'valueOf') return () => `[${label}]`;
      if (prop === 'then') return undefined; // don't look like a thenable
      events.push({ kind: 'get', label, prop: String(prop) });
      return recorder(`${label}.${String(prop)}`);
    },
    set(_t, prop, value) {
      events.push({ kind: 'set', label, prop: String(prop), value: safeStringify(value) });
      return true;
    },
    apply(_t, _thisArg, args) {
      events.push({ kind: 'call', label, args: args.map(safeStringify) });
      return recorder(`${label}()`);
    },
    construct(_t, args) {
      events.push({ kind: 'new', label, args: args.map(safeStringify) });
      return recorder(`new ${label}()`);
    },
    has() { return true; },
  });
}

const sandbox = {
  console: {
    log: (...a) => events.push({ kind: 'console.log', args: a.map(safeStringify) }),
    warn: (...a) => events.push({ kind: 'console.warn', args: a.map(safeStringify) }),
    error: (...a) => events.push({ kind: 'console.error', args: a.map(safeStringify) }),
    info: (...a) => events.push({ kind: 'console.info', args: a.map(safeStringify) }),
    debug: () => {},
  },
  atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
  btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
  setTimeout: (fn, _ms, ...rest) => {
    if (typeof fn === 'string') {
      secondaryScripts.push({ kind: 'setTimeout', body: fn });
    } else if (typeof fn === 'function') {
      try { fn.apply(null, rest); } catch (e) { events.push({ kind: 'setTimeout.error', error: String(e) }); }
    }
    return 0;
  },
  setInterval: () => 0,
  setImmediate: (fn) => {
    if (typeof fn === 'function') {
      try { fn(); } catch (e) { events.push({ kind: 'setImmediate.error', error: String(e) }); }
    }
    return 0;
  },
  clearTimeout: () => {},
  clearInterval: () => {},
  queueMicrotask: (fn) => { try { fn(); } catch (_) {} },
};

// Browser globals — each one is its own recorder so events are labeled
// clearly (e.g. "document.createElement.src = ...").
for (const name of [
  // DOM / BOM
  'window', 'document', 'location', 'navigator', 'top', 'self', 'parent',
  'frames', 'frameElement', 'screen', 'history', 'localStorage',
  'sessionStorage', 'fetch', 'XMLHttpRequest', 'WebSocket', 'crypto',
  'indexedDB', 'performance', 'Image', 'Audio', 'HTMLElement', 'Element',
  'Node', 'MutationObserver', 'alert', 'prompt', 'confirm',
  // Adobe Acrobat / PDF JavaScript — top-level objects plus commonly used
  // "this.*" methods that PDF scripts dereference as unqualified names after
  // obfuscation (e.g. `this[a0_0x471eff(0x128)]()` resolving to `getField`)
  'app', 'util', 'SOAP', 'color', 'event', 'global', 'xfa',
  'Collab', 'Doc', 'Field', 'Net', 'identity', 'security', 'spell', 'media',
  'getField', 'getTemplate', 'info', 'numPages', 'pageNum', 'path', 'URL',
  'submitForm', 'mailForm', 'mailDoc', 'closeDoc', 'exportDataObject',
  'resetForm', 'addScript', 'syncAnnotScan', 'importDataObject',
  'calculateNow', 'addAnnot', 'getAnnot', 'getAnnots', 'getOCGs',
  'getPageBox', 'getPageNthWord', 'getPageNthWordQuads', 'getPageNumWords',
  'getURL', 'print', 'setAction',
]) {
  sandbox[name] = recorder(name);
}
sandbox.globalThis = sandbox;

let runError = null;
try {
  vm.createContext(sandbox);
  vm.runInContext(SRC, sandbox, { timeout: 5000, displayErrors: true });
} catch (e) {
  runError = e && (e.stack || e.message || String(e));
}

// Re-run any secondary scripts the sample revealed (Function ctor bodies,
// setTimeout string handlers, etc.) so their global writes get recorded too.
const alreadyRun = new Set();
for (let i = 0; i < secondaryScripts.length; i++) {
  const entry = secondaryScripts[i];
  if (alreadyRun.has(entry.body)) continue;
  alreadyRun.add(entry.body);
  events.push({ kind: 'secondary.start', source: entry.kind });
  try {
    vm.runInContext(entry.body, sandbox, { timeout: 5000, displayErrors: true });
  } catch (e) {
    events.push({ kind: 'secondary.error', error: e && (e.message || String(e)) });
  }
}

// Emit a deobfuscated pseudo-JS file: one line per significant event.
// Downstream URL extraction just needs the string values to be visible in
// plaintext, so we render them as JS-ish assignments.
const lines = [];
lines.push('// ACE3 javascript deobfuscator — reconstructed from sandbox trace');
lines.push(`// source: ${INPUT_PATH}`);
lines.push(`// webcrack static pass: ${webcrackStatus}`);
lines.push('');
for (const ev of events) {
  if (ev.kind === 'set') {
    lines.push(`${ev.label}.${ev.prop} = ${ev.value};`);
  } else if (ev.kind === 'call') {
    lines.push(`${ev.label}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'new') {
    lines.push(`new ${ev.label}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'console.log' || ev.kind === 'console.warn' || ev.kind === 'console.error' || ev.kind === 'console.info') {
    lines.push(`${ev.kind}(${(ev.args || []).join(', ')});`);
  } else if (ev.kind === 'secondary.start') {
    lines.push(`// --- secondary payload (${ev.source}) ---`);
  } else if (ev.kind === 'secondary.error') {
    lines.push(`// secondary error: ${ev.error}`);
  }
}
if (secondaryScripts.length) {
  lines.push('');
  lines.push('// Raw secondary script bodies:');
  for (const entry of secondaryScripts) {
    lines.push(`// [${entry.kind}]`);
    lines.push(entry.body);
    lines.push('');
  }
}
// Also emit the webcracked source (or raw source if webcrack skipped) at the
// tail of the output, wrapped in an `if (false)` block so it doesn't fight
// with the trace lines above if anyone tries to lint-check the file. This
// gives downstream URL/IOC extractors the full deobfuscated body to scan, not
// just the events we captured through the recorder.
lines.push('');
lines.push('// --- deobfuscated source (post-webcrack) ---');
lines.push('if (false) {');
lines.push(SRC);
lines.push('}');
if (runError) {
  lines.push('');
  lines.push(`// run error: ${runError}`);
}

fs.writeFileSync(OUTPUT_PATH, lines.join('\n') + '\n', 'utf8');

process.stdout.write(JSON.stringify({
  status: runError ? 'error_during_run' : 'ok',
  event_count: events.length,
  secondary_script_count: secondaryScripts.length,
  error: runError,
  webcrack_status: webcrackStatus,
  webcrack_error: webcrackError,
}));
