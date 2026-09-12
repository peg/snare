import { describe, expect, it } from "vitest";
import { createDeliveryMessage, DELIVERY_SCHEMA } from "./delivery.js";

describe("durable webhook delivery contract", () => {
  it("creates a deterministic v1 envelope without serializing the destination", async () => {
    const destination = "https://hooks.slack.com/services/T000/B000/secret";
    const message = await createDeliveryMessage(
      destination,
      {
        token: "agent-prod-12345678",
        device_id: "dev-12345678",
        is_test: false,
        timestamp: "2026-07-30T00:00:00.000Z",
        ip: "203.0.113.10",
        method: "GET",
        sdkHints: {
          isPost: false,
          hasAwsSig: true,
          authorization: "must never be queued",
        },
        body: "must never be queued",
        authorization: "must never be queued",
      },
      {
        canaryType: "awsproc",
        label: "agent-prod-admin",
        deviceId: "dev-12345678",
        webhookURL: destination,
        deviceSecret: "must never be queued",
      },
      {
        deliveryId: "00000000-0000-4000-8000-000000000000",
        queuedAt: "2026-07-30T00:00:01.000Z",
      },
    );

    expect(message).toMatchObject({
      schema: DELIVERY_SCHEMA,
      delivery_id: "00000000-0000-4000-8000-000000000000",
      queued_at: "2026-07-30T00:00:01.000Z",
      destination_id: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
      event: {
        token: "agent-prod-12345678",
        device_id: "dev-12345678",
        is_test: false,
        timestamp: "2026-07-30T00:00:00.000Z",
        ip: "203.0.113.10",
        method: "GET",
        sdkHints: {
          hasAwsSig: true,
          isPost: false,
        },
      },
      meta: {
        canaryType: "awsproc",
        label: "agent-prod-admin",
        deviceId: "dev-12345678",
      },
    });

    const serialized = JSON.stringify(message);
    expect(serialized).not.toContain(destination);
    expect(serialized).not.toContain("must never be queued");
    expect(message.event).not.toHaveProperty("body");
    expect(message.event).not.toHaveProperty("authorization");
    expect(message.event.sdkHints).not.toHaveProperty("authorization");
    expect(message.meta).not.toHaveProperty("webhookURL");
    expect(message.meta).not.toHaveProperty("deviceSecret");
  });

  it("uses stable destination identities and unique default delivery IDs", async () => {
    const destination = "https://example.com/snare-webhook/secret";
    const first = await createDeliveryMessage(destination, {});
    const second = await createDeliveryMessage(destination, {});

    expect(first.destination_id).toBe(second.destination_id);
    expect(first.delivery_id).not.toBe(second.delivery_id);
    expect(first.delivery_id).toMatch(/^[0-9a-f-]{36}$/);

    const withFragment = await createDeliveryMessage(
      `${destination}#not-sent-over-http`,
      {},
    );
    expect(withFragment.destination_id).toBe(first.destination_id);
  });

  it("rejects non-HTTPS destinations", async () => {
    await expect(
      createDeliveryMessage("http://example.com/webhook", {}),
    ).rejects.toThrow("webhook destination must use https without credentials");
  });

  it("rejects destinations containing URL credentials", async () => {
    await expect(
      createDeliveryMessage("https://user:secret@example.com/webhook", {}),
    ).rejects.toThrow("webhook destination must use https without credentials");
  });
});
