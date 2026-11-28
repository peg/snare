#!/usr/bin/env node
import { constants } from "node:fs";
import { open, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const API = "https://api.cloudflare.com/client/v4";
const BULK = 100;
const MAX_KEYS = 200000;
const MAX_BYTES = 64 * 1024 * 1024;
const TIMEOUT = 30000;
const PREFIXES = new Set(["device", "webhook", "owner", "event", "evr", "rl", "dedup"]);
const NAMESPACE = /^[0-9a-f]{32}$/;

export class ExportError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function fail(code) { throw new ExportError(code); }

async function call(fetchImpl, token, path, init = {}) {
  for (let attempt = 0; ; attempt++) {
    const response = await fetchImpl(`${API}${path}`, {
      ...init, signal: AbortSignal.timeout(TIMEOUT), headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers },
    });
    if (response.status === 429 && attempt < 5) {
      const wait = Number(response.headers.get("retry-after")) || 2 ** attempt;
      await new Promise(done => setTimeout(done, Math.min(wait, 30) * 1000));
      continue;
    }
    let body;
    try { body = await response.json(); } catch { fail(`HTTP_${response.status}`); }
    if (!response.ok || body.success === false) fail(`HTTP_${response.status}`);
    return body;
  }
}

export async function exportNamespace({ accountId, namespaceId, token, fetchImpl = fetch }) {
  if (!/^[0-9a-f]{32}$/.test(accountId ?? "") || !NAMESPACE.test(namespaceId ?? "") || !token) fail("INVALID_CONFIGURATION");
  const base = `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}`;
  const names = [];
  const expiry = new Map();
  let cursor = "";
  do {
    const query = new URLSearchParams({ limit: "1000", ...(cursor ? { cursor } : {}) });
    const page = await call(fetchImpl, token, `${base}/keys?${query}`);
    for (const key of page.result) {
      names.push(key.name);
      if (key.expiration) expiry.set(key.name, key.expiration * 1000);
    }
    if (names.length > MAX_KEYS) fail("TOO_MANY_KEYS");
    cursor = page.result_info?.cursor || "";
  } while (cursor);

  const entries = [];
  let bytes = 0;
  let expired = 0;
  for (let i = 0; i < names.length; i += BULK) {
    const keys = names.slice(i, i + BULK);
    const page = await call(fetchImpl, token, `${base}/bulk/get`, { method: "POST", body: JSON.stringify({ keys, type: "text" }) });
    for (const name of keys) {
      const value = page.result?.values?.[name];
      if (typeof value !== "string") {
        if ((expiry.get(name) ?? Infinity) <= Date.now()) { expired++; continue; }
        fail("INCONSISTENT_SNAPSHOT");
      }
      bytes += Buffer.byteLength(name) + Buffer.byteLength(value);
      if (bytes > MAX_BYTES) fail("BACKUP_TOO_LARGE");
      entries.push({ name, value });
    }
  }
  const counts = {};
  for (const { name } of entries) {
    const [head] = name.split(":", 1);
    const prefix = PREFIXES.has(head) ? head : "other";
    counts[prefix] = (counts[prefix] ?? 0) + 1;
  }
  return { entries, counts: { total: entries.length, byPrefix: counts, ...(expired ? { expired } : {}) } };
}

export async function exportToFile(options, outputPath) {
  if (!outputPath) fail("INVALID_PATHS");
  const output = await open(outputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await output.chmod(0o600);
    const { entries, counts } = await exportNamespace(options);
    await output.writeFile(JSON.stringify(entries), "utf8");
    await output.sync();
    await output.close();
    return counts;
  } catch (error) {
    await output.close().catch(() => {});
    await unlink(outputPath).catch(() => {});
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) fail("USAGE_NAMESPACE_ID_OUTPUT_JSON");
    const counts = await exportToFile({
      accountId: process.env.CLOUDFLARE_ACCOUNT_ID, namespaceId: process.argv[2], token: process.env.CLOUDFLARE_API_TOKEN,
    }, process.argv[3]);
    process.stdout.write(`${JSON.stringify(counts)}\n`);
  } catch (error) {
    const code = error instanceof ExportError ? error.code : error?.code === "EEXIST" ? "OUTPUT_EXISTS" : "IO_ERROR";
    process.stderr.write(`Export failed: ${code}. Existing output was not changed; remove any partial output before retrying.\n`);
    process.exitCode = 1;
  }
}
