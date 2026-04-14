// JavaScript deobfuscation harness for ACE3.
//
// Usage: node js_deobfuscator.js <input_path> <output_path>
//
// Runs the input script inside a node vm sandbox with stubbed browser
// globals. Every read and write the script performs against those globals
// is recorded via Proxy traps. At the end, the recorded events are written
// to <output_path> as a pseudo-JS listing that downstream ACE modules can
// URL-extract from, and a JSON status report is printed to stdout.

'use strict';

const fs = require('fs');
const vm = require('vm');

const [, , INPUT_PATH, OUTPUT_PATH] = process.argv;
if (!INPUT_PATH || !OUTPUT_PATH) {
  process.stdout.write(JSON.stringify({ status: 'error', error: 'usage: js_deobfuscator.js <input> <output>' }));
  process.exit(2);
}

const SRC = fs.readFileSync(INPUT_PATH, 'utf8');
const events = [];
const secondaryScripts = [];

function safeStringify(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return String(value);
  if (t === 'function') return '[function]';
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
  'window', 'document', 'location', 'navigator', 'top', 'self', 'parent',
  'frames', 'frameElement', 'screen', 'history', 'localStorage',
  'sessionStorage', 'fetch', 'XMLHttpRequest', 'WebSocket', 'crypto',
  'indexedDB', 'performance', 'Image', 'Audio', 'HTMLElement', 'Element',
  'Node', 'MutationObserver', 'alert', 'prompt', 'confirm',
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
}));
