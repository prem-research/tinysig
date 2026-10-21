// Build first: cargo build -p trustbase-sigstore --example wasm_smoke --target wasm32-unknown-unknown --release
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

const path = process.argv[2] ?? 'target/wasm32-unknown-unknown/release/examples/wasm_smoke.wasm';
const module = await WebAssembly.compile(readFileSync(path));
assert.deepEqual(WebAssembly.Module.imports(module), [], 'the verifier must not need host imports');
const instance = await WebAssembly.instantiate(module);
assert.equal(instance.exports.check(), 1, 'real CI verification and tamper rejection must pass in Wasm');
console.log('WebAssembly verification passed; no host imports.');
