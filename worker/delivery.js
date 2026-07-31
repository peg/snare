const DELIVERY_SCHEMA = "snare.webhook-delivery.v1";

const EVENT_FIELDS = [
  "token",
  "device_id",
  "is_test",
  "timestamp",
  "ip",
  "userAgent",
  "method",
  "path",
  "country",
  "city",
  "asn",
  "asnOrg",
  "botScore",
];

const META_FIELDS = ["canaryType", "label", "deviceId"];

const SDK_HINT_FIELDS = [
  "amzSdkRequest",
  "amzTarget",
  "contentType",
  "hasAwsSig",
  "isPost",
];

function pickFields(source, fields) {
  const picked = {};
  for (const field of fields) {
    if (source?.[field] !== undefined) picked[field] = source[field];
  }
  return picked;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Build the privacy-bounded v1 message used by durable webhook delivery.
 *
 * This module is deliberately not connected to the callback path yet. The
 * activation change will validate the destination against the outbound policy,
 * enqueue this message, and resolve the destination again in the consumer.
 */
async function createDeliveryMessage(
  destinationURL,
  event,
  meta = {},
  { deliveryId = crypto.randomUUID(), queuedAt = new Date().toISOString() } = {},
) {
  const destination = new URL(destinationURL);
  if (
    destination.protocol !== "https:" ||
    destination.username ||
    destination.password
  ) {
    throw new Error("webhook destination must use https without credentials");
  }
  destination.hash = "";

  const queuedEvent = pickFields(event, EVENT_FIELDS);
  if (event?.sdkHints !== undefined) {
    queuedEvent.sdkHints = pickFields(event.sdkHints, SDK_HINT_FIELDS);
  }

  return {
    schema: DELIVERY_SCHEMA,
    delivery_id: deliveryId,
    queued_at: queuedAt,
    destination_id: `sha256:${await sha256Hex(destination.href)}`,
    event: queuedEvent,
    meta: pickFields(meta, META_FIELDS),
  };
}

export { createDeliveryMessage, DELIVERY_SCHEMA };
