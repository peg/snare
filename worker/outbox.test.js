import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { D1Store } from "./store.js";
import { createDeliveryMessage } from "./delivery.js";
import { consumeQueue, dispatchOutbox } from "./outbox.js";
import { resolveWebhooks, forwardAlert } from "./index.js";
import { SQLiteD1 } from "./test-support/sqlite.js";

const NOW = Date.parse("2026-09-11T12:00:00Z");
const DAY = 86400000;
const TOKEN = "outbox-token-12345678";
const OWNER = "outbox-owner";
const DESTINATION = "https://receiver.example/PRIVATE-DESTINATION";
const hooks = { resolveWebhooks, forwardAlert };
const databases = [];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
});
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  vi.restoreAllMocks();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function fixture() {
  const db = new SQLiteD1();
  databases.push(db);
  const store = new D1Store(db);
  await store.createDevice(OWNER, "a".repeat(64));
  const registration = { device_id: OWNER, webhook_url: DESTINATION, canary_type: "generic", label: "test destination" };
  expect(await store.registerToken(TOKEN, registration)).toBe("registered");
  const event = {
    id: crypto.randomUUID(), token: TOKEN, device_id: OWNER, token_revision: 1,
    timestamp: new Date(NOW).toISOString(), classification: "activity", notification_suppressed: null,
    method: "POST", path: `/c/${TOKEN}/original-evidence`, userAgent: "curl/fixture", ip: "192.0.2.2",
    sdkHints: { hasAwsSig: false, isPost: true }, is_test: false,
  };
  const message = await createDeliveryMessage(DESTINATION, event, {
    deviceId: OWNER, canaryType: "generic", label: registration.label,
  }, { tokenRevision: 1 });
  expect(await store.saveEvent(event, [message])).toBe(true);
  const queued = [];
  const env = {
    SNARE_DB: db, WEBHOOK_ALLOWED_DOMAINS: "receiver.example",
    WEBHOOK_DELIVERY_QUEUE: { send: vi.fn(async body => { queued.push(body); }) },
  };
  return { db, store, env, event, message, queued, registration };
}

function notification(message) {
  return { body: structuredClone(message), ack: vi.fn(), retry: vi.fn() };
}

async function consume(env, message) {
  const item = notification(message);
  await consumeQueue({ messages: [item] }, env, hooks);
  return item;
}

async function addEvents(store, original, count) {
  const messages = [];
  for (let i = 0; i < count; i++) {
    const event = { ...original, id: crypto.randomUUID(), timestamp: new Date(Date.now()).toISOString() };
    const message = await createDeliveryMessage(DESTINATION, event, {
      deviceId: OWNER, canaryType: "generic", label: "test destination",
    }, { tokenRevision: 1 });
    expect(await store.saveEvent(event, [message])).toBe(true);
    messages.push(message);
  }
  return messages;
}

describe("durable publication and recovery", () => {
  it("allows only one concurrent publisher to send a pending delivery", async () => {
    const { env, queued, store, message } = await fixture();
    await Promise.all([dispatchOutbox(env, hooks), dispatchOutbox(env, hooks), dispatchOutbox(env, hooks)]);
    expect(queued).toHaveLength(1);
    expect(queued[0].delivery_id).toBe(message.delivery_id);
    expect((await store.getDelivery(message.delivery_id)).state).toBe("enqueued");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("retains failed enqueues durably and recovers them on a later dispatcher invocation", async () => {
    const { env, store, db, message } = await fixture();
    env.WEBHOOK_DELIVERY_QUEUE.send.mockRejectedValueOnce(new Error("temporary queue failure"));
    await dispatchOutbox(env, hooks);
    let record = await store.getDelivery(message.delivery_id);
    expect(record.state).toBe("pending");
    expect(record.lease_token).toBeNull();
    expect(record.next_attempt_at).toBeGreaterThan(NOW);
    expect(db.count("events")).toBe(1);
    expect(db.count("deliveries")).toBe(1);
    vi.setSystemTime(record.next_attempt_at);
    await dispatchOutbox(env, hooks);
    record = await store.getDelivery(message.delivery_id);
    expect(record.state).toBe("enqueued");
    expect(env.WEBHOOK_DELIVERY_QUEUE.send).toHaveBeenCalledTimes(2);
    expect(env.WEBHOOK_DELIVERY_QUEUE.send.mock.calls.map(call => call[0].delivery_id))
      .toEqual([message.delivery_id, message.delivery_id]);
  });

  it("recovers a lost queue message with its original delivery ID", async () => {
    const { env, store, message, queued } = await fixture();
    await dispatchOutbox(env, hooks);
    vi.setSystemTime((await store.getDelivery(message.delivery_id)).next_attempt_at);
    await dispatchOutbox(env, hooks);
    expect(queued).toHaveLength(2);
    expect(queued[0].delivery_id).toBe(queued[1].delivery_id);
    const item = await consume(env, queued[1]);
    expect(item.ack).toHaveBeenCalledOnce();
    expect((await store.getDelivery(message.delivery_id)).state).toBe("delivered");
  });

  it("preserves pending delivery during an identical registration repair", async () => {
    const { env, store, message, registration } = await fixture();
    expect(await store.registerToken(TOKEN, { ...registration, registered_at: new Date(NOW + 1000).toISOString() })).toBe("registered");
    expect((await store.getToken(TOKEN)).revision).toBe(1);
    expect((await store.getDelivery(message.delivery_id)).state).toBe("pending");
    await dispatchOutbox(env, hooks);
    await consume(env, message);
    expect(fetch).toHaveBeenCalledOnce();
  });
});

describe("consumer status, bounded retries, and identity", () => {
  it("acknowledges 2xx, records receipt, and never resends a completed duplicate", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    const first = await consume(env, message);
    expect(first.ack).toHaveBeenCalledOnce();
    expect(first.retry).not.toHaveBeenCalled();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "delivered", attempts: 1, error_code: null });
    expect(fetch).toHaveBeenCalledOnce();
    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe(DESTINATION);
    expect(options.redirect).toBe("manual");
    expect(options.headers["x-snare-delivery-id"]).toBe(message.delivery_id);
    expect(options.headers["x-snare-event-id"]).toBe(message.event.id);
    expect((await consume(env, message)).ack).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledOnce();
    expect((await store.getEvents(TOKEN))[0].deliveries[0].state).toBe("delivered");
  });

  it("serializes simultaneous consumers using a lease", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    const first = notification(message);
    const second = notification(message);
    await Promise.all([
      consumeQueue({ messages: [first] }, env, hooks),
      consumeQueue({ messages: [second] }, env, hooks),
    ]);
    expect(fetch).toHaveBeenCalledOnce();
    expect((await store.getDelivery(message.delivery_id)).state).toBe("delivered");
    expect(first.ack.mock.calls.length + second.ack.mock.calls.length).toBeGreaterThanOrEqual(1);
  });

  it.each([408, 425, 429, 500, 503])("retries HTTP %s and later records success under the same ID", async status => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    fetch.mockResolvedValueOnce(new Response(null, { status, headers: { "retry-after": "99999999" } }));
    const first = await consume(env, message);
    expect(first.ack).not.toHaveBeenCalled();
    expect(first.retry).toHaveBeenCalledWith({ delaySeconds: 3600 });
    const pending = await store.getDelivery(message.delivery_id);
    expect(pending).toMatchObject({ state: "pending", attempts: 1, error_code: `http_${status}` });
    expect(pending.next_attempt_at).toBe(NOW + 3600000);
    vi.setSystemTime(pending.next_attempt_at);
    const second = await consume(env, message);
    expect(second.ack).toHaveBeenCalledOnce();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "delivered", attempts: 2 });
    expect(fetch.mock.calls.map(call => call[1].headers["x-snare-delivery-id"]))
      .toEqual([message.delivery_id, message.delivery_id]);
  });

  it("uses a five-second outbound timeout and leaves a retryable durable record", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    const timeout = vi.spyOn(AbortSignal, "timeout").mockImplementation(() => AbortSignal.abort(new DOMException("fixture timeout", "TimeoutError")));
    fetch.mockImplementation(async (_url, options) => options.signal.throwIfAborted());
    const item = await consume(env, message);
    expect(timeout).toHaveBeenCalledWith(5000);
    expect(item.retry).toHaveBeenCalledOnce();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "pending", attempts: 1, error_code: "network_failure" });
  });

  it.each([400, 401, 403, 404, 410, 302])("terminates HTTP %s without following redirects or retrying", async status => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    fetch.mockResolvedValueOnce(new Response(null, { status, headers: { location: "https://unapproved.invalid/private" } }));
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(item.retry).not.toHaveBeenCalled();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", attempts: 1, error_code: `http_${status}` });
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0][1].redirect).toBe("manual");
  });

  it("stops after five failed attempts and retains terminal failure for event readers", async () => {
    const { env, store, message, db } = await fixture();
    await dispatchOutbox(env, hooks);
    fetch.mockImplementation(async () => { throw new Error(`network error with ${DESTINATION}`); });
    for (let i = 1; i <= 5; i++) {
      const item = await consume(env, message);
      const state = await store.getDelivery(message.delivery_id);
      expect(state.attempts).toBe(i);
      if (i < 5) { expect(item.retry).toHaveBeenCalledOnce(); vi.setSystemTime(state.next_attempt_at); }
      else { expect(item.ack).toHaveBeenCalledOnce(); expect(state.state).toBe("failed"); }
    }
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(db.count("delivery_attempts")).toBe(5);
    const evidence = await store.getEvents(TOKEN);
    expect(evidence[0].deliveries[0]).toMatchObject({ state: "failed", attempts: 5, error_code: "network_failure" });
    expect(JSON.stringify(evidence)).not.toContain(DESTINATION);
  });

  it("reserves sends before fetch so lost completion writes cannot reset the five-attempt bound", async () => {
    const { env, store, message, db } = await fixture();
    await dispatchOutbox(env, hooks);
    // Simulate a process losing storage after the remote receiver accepted each
    // request. No completion state survives, but its pre-send reservation does.
    const finish = vi.spyOn(D1Store.prototype, "finishDelivery").mockRejectedValue(new Error("fixture storage unavailable"));
    for (let attempt = 1; attempt <= 5; attempt++) {
      const item = await consume(env, message);
      const record = await store.getDelivery(message.delivery_id);
      expect(item.retry).toHaveBeenCalledWith({ delaySeconds: 60 });
      expect(record.attempts).toBe(attempt);
      vi.setSystemTime(record.lease_until);
    }
    finish.mockRestore();
    const recovered = await consume(env, message);
    expect(recovered.ack).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(db.count("delivery_attempts")).toBe(5);
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", attempts: 5 });
  });

  it("uses persisted evidence when a queue body is tampered with", async () => {
    const { env, message } = await fixture();
    await dispatchOutbox(env, hooks);
    const changed = structuredClone(message);
    changed.event.path = "/attacker-replacement";
    changed.meta.label = "attacker replacement";
    const item = await consume(env, changed);
    expect(item.ack).toHaveBeenCalledOnce();
    const payload = JSON.parse(fetch.mock.calls[0][1].body);
    expect(payload.request.path).toBe(message.event.path);
    expect(fetch.mock.calls[0][1].body).not.toContain("attacker replacement");
  });
});

describe("cancellation, expiry, and operation budgets", () => {
  it.each(["revoked", "destination changed"])("cancels %s registration without outbound traffic", async reason => {
    const { env, store, message, registration } = await fixture();
    await dispatchOutbox(env, hooks);
    if (reason === "revoked") await store.revokeToken(TOKEN, OWNER);
    else await store.registerToken(TOKEN, { ...registration, webhook_url: "https://receiver.example/NEW-DESTINATION" });
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect((await store.getDelivery(message.delivery_id)).state).toBe("cancelled");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("revalidates the current destination allowlist before delivering queued work", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    env.WEBHOOK_ALLOWED_DOMAINS = "";
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "cancelled", error_code: "destination_changed" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("makes 24-hour expiry terminal and visible even when the consumer runs before Cron", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    vi.setSystemTime(NOW + DAY);
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(item.retry).not.toHaveBeenCalled();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", error_code: "delivery_expired" });
    expect((await store.getEvents(TOKEN))[0].deliveries[0].state).toBe("failed");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("makes queue expiry visible during reconciliation even when no message returns", async () => {
    const { env, store, message } = await fixture();
    await dispatchOutbox(env, hooks);
    vi.setSystemTime(NOW + DAY);
    await dispatchOutbox(env, hooks);
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", error_code: "delivery_expired" });
    expect(env.WEBHOOK_DELIVERY_QUEUE.send).toHaveBeenCalledOnce();
  });

  it("expires the consumed delivery even when an earlier expired backlog exceeds the cleanup batch", async () => {
    const { env, store, db, event, message } = await fixture();
    vi.setSystemTime(NOW - 1000);
    await addEvents(new D1Store(db, { dailyEventsPerDevice: 500 }), event, 120);
    vi.setSystemTime(NOW + DAY);
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", error_code: "delivery_expired" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds queue publisher work under the D1 Free per-invocation query allowance", async () => {
    const { env, db, store, event, queued } = await fixture();
    await addEvents(store, event, 20);
    db.resetQueryCount();
    await dispatchOutbox(env, hooks);
    expect(queued).toHaveLength(15);
    expect(db.queryCount).toBeLessThanOrEqual(50);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds direct dispatcher work under the D1 Free per-invocation query allowance", async () => {
    const { env, db, store, event } = await fixture();
    delete env.WEBHOOK_DELIVERY_QUEUE;
    await addEvents(store, event, 10);
    db.resetQueryCount();
    await dispatchOutbox(env, hooks);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(db.queryCount).toBeLessThanOrEqual(50);
  });

  it("defers excess queue batch messages while processing five within the query allowance", async () => {
    const { env, db, store, event, message } = await fixture();
    const items = [message, ...await addEvents(store, event, 6)].map(notification);
    db.resetQueryCount();
    await consumeQueue({ messages: items }, env, hooks);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(db.queryCount).toBeLessThanOrEqual(50);
    for (const item of items.slice(0, 5)) expect(item.ack).toHaveBeenCalledOnce();
    for (const item of items.slice(5)) {
      expect(item.ack).not.toHaveBeenCalled();
      expect(item.retry).toHaveBeenCalledWith({ delaySeconds: 60 });
    }
  });

  it("enforces outbound allowance before fetch and does not add more attempt rows after exhaustion", async () => {
    const { env, store, db, message } = await fixture();
    const insert = db.sqlite.prepare("INSERT INTO delivery_attempts(attempt_id, device_id, admission_day, admitted_at) VALUES (?, ?, ?, ?)");
    for (let i = 0; i < 200; i++) insert.run(`attempt-${i}`, OWNER, Math.floor(NOW / DAY), NOW);
    await dispatchOutbox(env, hooks);
    const item = await consume(env, message);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(await store.getDelivery(message.delivery_id)).toMatchObject({ state: "failed", error_code: "delivery_budget_exhausted" });
    expect(db.count("delivery_attempts")).toBe(200);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects malformed queue messages without sending or touching valid event evidence", async () => {
    const { env, db, message } = await fixture();
    const bad = { ...message, request_body: "must not be accepted" };
    const item = await consume(env, bad);
    expect(item.ack).toHaveBeenCalledOnce();
    expect(item.retry).not.toHaveBeenCalled();
    expect(db.count("events")).toBe(1);
    expect(db.count("delivery_attempts")).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
  });
});
