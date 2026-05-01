import { describe, it, expect } from "vitest";
import { CANARY_TYPES, shouldFilter, resolveWebhooks, SCANNER_ORGS } from "./index.js";

// ─── Token pattern validation ────────────────────────────────────────────────
// The worker uses this regex for canary callback matching:
//   /^\/c\/([a-zA-Z0-9_-]{8,80})(\/.*)?$/
const TOKEN_RE = /^[a-zA-Z0-9_-]{8,80}$/;

describe("token pattern validation", () => {
  it("accepts valid alphanumeric+dash tokens (8-80 chars)", () => {
    expect(TOKEN_RE.test("agent-01-abc123def456")).toBe(true);
  });

  it("accepts snare-test tokens", () => {
    expect(TOKEN_RE.test("snare-test-abc123")).toBe(true);
  });

  it("accepts tokens with underscores", () => {
    expect(TOKEN_RE.test("my_token_12345678")).toBe(true);
  });

  it("accepts exactly 8 characters", () => {
    expect(TOKEN_RE.test("abcd1234")).toBe(true);
  });

  it("accepts exactly 80 characters", () => {
    expect(TOKEN_RE.test("a".repeat(80))).toBe(true);
  });

  it("rejects empty string", () => {
    expect(TOKEN_RE.test("")).toBe(false);
  });

  it("rejects too-short tokens (< 8 chars)", () => {
    expect(TOKEN_RE.test("ab")).toBe(false);
    expect(TOKEN_RE.test("abcdefg")).toBe(false); // 7 chars
  });

  it("rejects tokens longer than 80 chars", () => {
    expect(TOKEN_RE.test("a".repeat(81))).toBe(false);
  });

  it("rejects tokens with invalid characters", () => {
    expect(TOKEN_RE.test("agent-01-abc!@#$")).toBe(false);
    expect(TOKEN_RE.test("token with spaces")).toBe(false);
    expect(TOKEN_RE.test("token.with.dots")).toBe(false);
  });

  it("accepts 'agent-01-' (9 chars, valid)", () => {
    // trailing dash is a valid character in [a-zA-Z0-9_-]
    expect(TOKEN_RE.test("agent-01-")).toBe(true);
  });
});

// ─── shouldFilter ────────────────────────────────────────────────────────────

function makeMeta(overrides = {}) {
  return {
    userAgent: "",
    asnOrg: "",
    sdkHints: { hasAwsSig: false, isPost: false },
    ...overrides,
  };
}

describe("shouldFilter", () => {
  describe("scanner ASN filtering (all canary types)", () => {
    it("filters known scanner ASN: Shodan", () => {
      expect(shouldFilter("generic", makeMeta({ asnOrg: "Shodan.io" }))).toBe(true);
    });

    it("filters known scanner ASN: Censys", () => {
      expect(shouldFilter("aws", makeMeta({ asnOrg: "Censys, Inc." }))).toBe(true);
    });

    it("filters known scanner ASN: Rapid7", () => {
      expect(shouldFilter("github", makeMeta({ asnOrg: "Rapid7" }))).toBe(true);
    });

    it("does not filter unknown ASN", () => {
      expect(shouldFilter("generic", makeMeta({ asnOrg: "Comcast Cable" }))).toBe(false);
    });
  });

  describe("aws canary type", () => {
    it("filters requests WITHOUT AWS4-HMAC-SHA256 signature", () => {
      expect(shouldFilter("aws", makeMeta({ asnOrg: "Comcast", sdkHints: { hasAwsSig: false } }))).toBe(true);
    });

    it("does NOT filter requests WITH AWS SDK signature", () => {
      expect(shouldFilter("aws", makeMeta({ asnOrg: "Comcast", sdkHints: { hasAwsSig: true } }))).toBe(false);
    });
  });

  describe("awsproc canary type", () => {
    it("filters browser-like UA without AWS sig", () => {
      expect(shouldFilter("awsproc", makeMeta({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        sdkHints: { hasAwsSig: false },
      }))).toBe(true);
    });

    it("does NOT filter browser-like UA WITH AWS sig", () => {
      expect(shouldFilter("awsproc", makeMeta({
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        sdkHints: { hasAwsSig: true },
      }))).toBe(false);
    });

    it("does NOT filter non-browser UA (e.g. curl)", () => {
      expect(shouldFilter("awsproc", makeMeta({
        userAgent: "curl/7.68.0",
        sdkHints: { hasAwsSig: false },
      }))).toBe(false);
    });
  });

  describe("gcp canary type", () => {
    it("filters non-POST requests (crawlers)", () => {
      expect(shouldFilter("gcp", makeMeta({ sdkHints: { isPost: false } }))).toBe(true);
    });

    it("does NOT filter POST requests", () => {
      expect(shouldFilter("gcp", makeMeta({ sdkHints: { isPost: true } }))).toBe(false);
    });
  });

  describe("default/other types", () => {
    for (const type of ["github", "openai", "anthropic", "ssh", "k8s", "npm", "mcp", "pypi", "stripe", "generic"]) {
      it(`does NOT filter '${type}' with unknown ASN`, () => {
        expect(shouldFilter(type, makeMeta({ asnOrg: "Some ISP" }))).toBe(false);
      });
    }
  });
});

// ─── CANARY_TYPES completeness ───────────────────────────────────────────────

describe("CANARY_TYPES completeness", () => {
  const EXPECTED_TYPES = [
    "aws", "awsproc", "gcp", "github", "stripe", "openai", "anthropic",
    "ssh", "k8s", "npm", "mcp", "pypi", "docker", "generic",
    "huggingface", "azure", "git", "terraform",
  ];

  it("has all 18 expected canary types", () => {
    for (const t of EXPECTED_TYPES) {
      expect(CANARY_TYPES).toHaveProperty(t);
    }
  });

  it("each type has emoji, color, and name", () => {
    for (const [key, val] of Object.entries(CANARY_TYPES)) {
      expect(val).toHaveProperty("emoji");
      expect(val).toHaveProperty("color");
      expect(val).toHaveProperty("name");
      expect(typeof val.color).toBe("number");
      expect(typeof val.name).toBe("string");
    }
  });
});

// ─── resolveWebhooks ─────────────────────────────────────────────────────────

describe("resolveWebhooks", () => {
  it("returns registered=true for a registered token", async () => {
    const mockKV = {
      get: async (key) => {
        if (key === "webhook:my-token-123") {
          return JSON.stringify({
            webhook_url: "https://discord.com/api/webhooks/123/abc",
            canary_type: "aws",
            label: "prod-key",
            device_id: "dev-abc",
          });
        }
        return null;
      },
    };

    const result = await resolveWebhooks("my-token-123", { SNARE_KV: mockKV });
    expect(result.registered).toBe(true);
    expect(result.meta.canaryType).toBe("aws");
    expect(result.meta.label).toBe("prod-key");
    expect(result.webhooks).toEqual(["https://discord.com/api/webhooks/123/abc"]);
  });

  it("returns registered=false for an unregistered token", async () => {
    const mockKV = {
      get: async () => null,
    };

    const result = await resolveWebhooks("unknown-token-xyz", { SNARE_KV: mockKV });
    expect(result.registered).toBe(false);
    expect(result.webhooks).toEqual([]);
    expect(result.meta).toEqual({});
  });

  it("falls back to global WEBHOOK_URLS when per-token uses 'use-global'", async () => {
    const mockKV = {
      get: async () => JSON.stringify({
        webhook_url: "use-global",
        canary_type: "github",
        label: null,
        device_id: "dev-x",
      }),
    };

    const result = await resolveWebhooks("some-token-456", {
      SNARE_KV: mockKV,
      WEBHOOK_URLS: "https://hooks.slack.com/services/a/b/c,https://discord.com/api/webhooks/1/2",
    });
    expect(result.registered).toBe(true);
    expect(result.webhooks).toEqual([
      "https://hooks.slack.com/services/a/b/c",
      "https://discord.com/api/webhooks/1/2",
    ]);
  });

  it("returns empty webhooks when no KV is configured", async () => {
    const result = await resolveWebhooks("any-token-789", {});
    expect(result.registered).toBe(false);
    expect(result.webhooks).toEqual([]);
  });
});
