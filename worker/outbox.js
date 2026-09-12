import { D1Store } from "./store.js";
import { validateDeliveryMessage, destinationIdentity } from "./delivery.js";

const MAX_ATTEMPTS = 5;
const MAX_AGE = 24 * 60 * 60 * 1000;

function storeFor(env) { return new D1Store(env.SNARE_DB); }

function retryDelay(attempt, requested) {
  return Math.min(3600, Math.max(5, Number(requested) || Math.min(900, 15 * 2 ** Math.min(attempt, 6))));
}

async function consumeDelivery(id, env, hooks, notification = null) {
  const store = storeFor(env);
  const now = Date.now();
  const current = await store.getDelivery(id);
  if (!current || ["delivered", "failed", "cancelled"].includes(current.state)) {
    notification?.ack();
    return;
  }
  if (now - current.created_at >= MAX_AGE) {
    await store.expireDelivery(id, now);
    notification?.ack();
    return;
  }
  const record = await store.claimDelivery(id, now);
  if (!record) { notification?.retry({ delaySeconds: 30 }); return; }
  const lease = record.lease_token;
  const attempts = record.attempts + 1;
  const finish = (state, error = null, next = now) => store.finishDelivery(id, state, attempts, next, error, lease);
  try {
    const message = validateDeliveryMessage(record.message);
    if (now - Date.parse(message.queued_at) >= MAX_AGE || attempts > MAX_ATTEMPTS) {
      await finish("failed", "delivery_expired");
      notification?.ack();
      return;
    }
    const registration = await hooks.resolveWebhooks(message.event.token, env);
    if (!registration.registered || registration.meta.deviceId !== message.event.device_id ||
        registration.revision !== message.token_revision) {
      await finish("cancelled", "registration_changed");
      notification?.ack();
      return;
    }
    let destination;
    for (const url of registration.webhooks) {
      if (await destinationIdentity(url) === message.destination_id) { destination = url; break; }
    }
    if (!destination) {
      await finish("cancelled", "destination_changed");
      notification?.ack();
      return;
    }
    if (!await store.reserveDeliveryAttempt(id, lease, now, MAX_ATTEMPTS)) {
      await finish("failed", "delivery_budget_exhausted");
      notification?.ack();
      return;
    }
    await hooks.forwardAlert(destination, message.event, message.meta, env, { deliveryId: id });
    await finish("delivered");
    notification?.ack();
  } catch (error) {
    // Never persist/log a thrown URL, request payload, or third-party error text.
    const status = Number(error.status) || 0;
    const transient = !status || [408, 425, 429].includes(status) || status >= 500;
    if (!transient || attempts >= MAX_ATTEMPTS) {
      await finish("failed", status ? `http_${status}` : "network_failure");
      notification?.ack();
    } else {
      const delay = retryDelay(attempts, error.retryAfter);
      await finish("pending", status ? `http_${status}` : "network_failure", Date.now() + delay * 1000);
      notification?.retry({ delaySeconds: delay });
    }
  }
}

async function dispatchOutbox(env, hooks) {
  if (!env.SNARE_DB) return;
  const store = storeFor(env);
  // D1 Free permits 50 queries per invocation. Leave room for event admission,
  // lease/budget operations, expiry, and scheduled cleanup.
  const records = await store.dueDeliveries(Date.now(), env.WEBHOOK_DELIVERY_QUEUE ? 15 : 5);
  for (const candidate of records) {
    if (!env.WEBHOOK_DELIVERY_QUEUE) {
      // Optional owner-hosted mode: the same durable outbox retries via Cron.
      await consumeDelivery(candidate.delivery_id, env, hooks);
      continue;
    }
    const record = await store.claimEnqueue(candidate.delivery_id, Date.now());
    if (!record) continue;
    try {
      const message = validateDeliveryMessage(record.message);
      await env.WEBHOOK_DELIVERY_QUEUE.send(message);
      await store.markEnqueued(record.delivery_id, Date.now(), record.lease_token);
    } catch {
      await store.releaseEnqueue(record.delivery_id, Date.now(), record.lease_token);
      console.error("DELIVERY_ENQUEUE_FAILED");
    }
  }
}

async function consumeQueue(batch, env, hooks) {
  if (!env.SNARE_DB) throw new Error("queue delivery requires transactional storage");
  for (const [index, notification] of batch.messages.entries()) {
    // Also bound unexpected batches independently of deployment configuration.
    if (index >= 5) { notification.retry({ delaySeconds: 60 }); continue; }
    try {
      const message = validateDeliveryMessage(notification.body);
      await consumeDelivery(message.delivery_id, env, hooks, notification);
    } catch {
      // Schema errors are terminal. Infrastructure errors must remain retryable.
      try { validateDeliveryMessage(notification.body); }
      catch { notification.ack(); console.error("DELIVERY_MESSAGE_REJECTED"); continue; }
      notification.retry({ delaySeconds: 60 });
      console.error("DELIVERY_STORAGE_UNAVAILABLE");
    }
  }
}

export { consumeDelivery, consumeQueue, dispatchOutbox, retryDelay };
