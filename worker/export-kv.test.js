import { describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportNamespace, exportToFile } from "./scripts/export-kv.mjs";

const OPTIONS = { accountId: "a".repeat(32), namespaceId: "b".repeat(32), token: "synthetic" };

function api(values, { drop = [] } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push(init.method ?? "GET");
    if (url.includes("/keys")) return Response.json({ success: true, result: Object.keys(values).map(name => ({ name })), result_info: {} });
    const { keys } = JSON.parse(init.body);
    return Response.json({ success: true, result: { values: Object.fromEntries(keys.filter(k => !drop.includes(k)).map(k => [k, values[k]])) } });
  };
  return { fetchImpl, calls };
}

describe("KV export", () => {
  it("only reads, and fails closed when a listed key vanishes mid-export", async () => {
    const values = { "device:a": "{\"secret_hash\":\"x\"}", "webhook:tok_00000001": "{}" };
    const ok = api(values);
    expect((await exportNamespace({ ...OPTIONS, fetchImpl: ok.fetchImpl })).counts).toEqual({ total: 2, byPrefix: { device: 1, webhook: 1 } });
    expect(new Set(ok.calls)).toEqual(new Set(["GET", "POST"]));
    await expect(exportNamespace({ ...OPTIONS, fetchImpl: api(values, { drop: ["device:a"] }).fetchImpl }))
      .rejects.toMatchObject({ code: "INCONSISTENT_SNAPSHOT" });
    await expect(exportNamespace({ ...OPTIONS, accountId: "nope", fetchImpl: ok.fetchImpl })).rejects.toMatchObject({ code: "INVALID_CONFIGURATION" });
  });

  it("writes a private file and never overwrites an existing one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "snare-export-"));
    try {
      const output = join(dir, "backup.json");
      const { fetchImpl } = api({ "device:a": "{\"secret_hash\":\"x\"}" });
      await exportToFile({ ...OPTIONS, fetchImpl }, output);
      expect((await stat(output)).mode & 0o777).toBe(0o600);
      expect(JSON.parse(await readFile(output, "utf8"))).toEqual([{ name: "device:a", value: "{\"secret_hash\":\"x\"}" }]);
      await writeFile(output, "keep");
      await expect(exportToFile({ ...OPTIONS, fetchImpl }, output)).rejects.toMatchObject({ code: "EEXIST" });
      expect(await readFile(output, "utf8")).toBe("keep");
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
