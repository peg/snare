const DELIVERY_SCHEMA = "snare.webhook-delivery.v1";

const EVENT_FIELDS = [
  "id",
  "proof_id",
  "classification",
  "notification_suppressed",
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
    const value = source?.[field];
    // Never copy arrays or nested objects through a nominally scalar field.
    if (value === null || typeof value === "boolean") picked[field] = value;
    else if (typeof value === "number" && Number.isFinite(value)) picked[field] = value;
    else if (typeof value === "string") picked[field] = value.slice(0, field === "path" ? 1024 : 512);
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
 * The outbox persists this envelope before queue publication. Consumers resolve
 * the current destination again; neither the queue nor its logs contain URLs.
 */
async function createDeliveryMessage(
  destinationURL,
  event,
  meta = {},
  { deliveryId = crypto.randomUUID(), queuedAt = new Date().toISOString(), tokenRevision } = {},
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

  const message = {
    schema: DELIVERY_SCHEMA,
    delivery_id: deliveryId,
    queued_at: queuedAt,
    destination_id: `sha256:${await sha256Hex(destination.href)}`,
    event: queuedEvent,
    meta: pickFields(meta, META_FIELDS),
  };
  if (tokenRevision !== undefined) message.token_revision = tokenRevision;
  if (new TextEncoder().encode(JSON.stringify(message)).byteLength > 8192) throw new Error("delivery message too large");
  return message;
}

async function destinationIdentity(url) {
  const destination = new URL(url);
  destination.hash = "";
  return `sha256:${await sha256Hex(destination.href)}`;
}

// Validate at the storage and queue boundaries, even when a producer is ours.
// Consumers use the persisted envelope; queue content cannot replace evidence.
function validateDeliveryMessage(message) {
  const fail = () => { throw new Error("invalid delivery message"); };
  const object = value => value && typeof value === "object" && !Array.isArray(value);
  if (!object(message) || message.schema !== DELIVERY_SCHEMA) fail();
  if (Object.keys(message).some(key => !["schema", "delivery_id", "queued_at", "destination_id", "event", "meta", "token_revision"].includes(key))) fail();
  if (!/^[0-9a-f-]{36}$/.test(message.delivery_id || "") || !/^sha256:[0-9a-f]{64}$/.test(message.destination_id || "")) fail();
  if (typeof message.queued_at !== "string" || !Number.isFinite(Date.parse(message.queued_at))) fail();
  if (message.token_revision !== undefined && (!Number.isSafeInteger(message.token_revision) || message.token_revision < 1)) fail();
  if (!object(message.event) || !object(message.meta)) fail();
  if (Object.keys(message.event).some(key => ![...EVENT_FIELDS, "sdkHints"].includes(key))) fail();
  if (Object.keys(message.meta).some(key => !META_FIELDS.includes(key))) fail();
  const boundedText = (value, max = 512) => value === null ||
    (typeof value === "string" && new TextEncoder().encode(value).byteLength <= max);
  for (const [key, value] of Object.entries(message.event)) {
    if (key === "sdkHints") continue;
    if (key === "is_test") { if (typeof value !== "boolean") fail(); }
    else if (key === "asn" || key === "botScore") {
      if (value !== null && (!Number.isSafeInteger(value) || value < 0 || value > (key === "botScore" ? 100 : 0xffffffff))) fail();
    } else if (!boundedText(value, key === "path" ? 1024 : 512)) fail();
  }
  if (Object.values(message.meta).some(value => !boundedText(value))) fail();
  if (message.event.sdkHints !== undefined) {
    if (!object(message.event.sdkHints) || Object.keys(message.event.sdkHints).some(key => !SDK_HINT_FIELDS.includes(key))) fail();
    for (const [key, value] of Object.entries(message.event.sdkHints)) {
      if (["isPost", "hasAwsSig"].includes(key)) { if (typeof value !== "boolean") fail(); }
      else if (!boundedText(value)) fail();
    }
  }
  for (const key of ["id", "token"]) {
    if (typeof message.event[key] !== "string" || !/^[a-zA-Z0-9_-]{8,80}$/.test(message.event[key])) fail();
  }
  if (typeof message.event.device_id !== "string" || !/^[a-zA-Z0-9_-]{1,80}$/.test(message.event.device_id)) fail();
  if (message.event.proof_id != null && !/^[0-9a-f]{32}$/.test(message.event.proof_id)) fail();
  if (typeof message.event.timestamp !== "string" || !Number.isFinite(Date.parse(message.event.timestamp))) fail();
  if (new TextEncoder().encode(JSON.stringify(message)).byteLength > 8192) fail();
  return message;
}

export { createDeliveryMessage, DELIVERY_SCHEMA, destinationIdentity, validateDeliveryMessage };
