# Streaming Resource Protection and Denial-of-Service Defense

## 1. Concurrency and Rate Controls

Real-time streaming channels can consume memory and connection file descriptors if left uncontrolled. SnareSight enforces strict, multi-layered bounds:

| Boundary | Default Limit | Enforcement Mechanism | Failure Response |
| :--- | :--- | :--- | :--- |
| **Global Concurrent Streams** | 50 connections | `StreamManager.active_count` | HTTP 429 Too Many Requests |
| **Per-User Concurrent Streams** | 5 connections | `StreamManager.user_connections` | HTTP 429 Too Many Requests |
| **Subscriber Queue Depth** | 100 messages | `asyncio.Queue(maxsize=100)` | Client terminated (`queue_full`) |
| **Replay Batch Limit** | 500 events | Query `limit(500)` in replay | Replay capped; further catch-up on subsequent cursor |

## 2. Slow-Client Eviction Strategy

A slow client (e.g. over a throttled mobile link or stalled browser tab) must never impair platform throughput or memory availability:

1. When `EventPublisher.publish()` attempts to push an event to a subscriber:
   - It checks `subscriber.is_full()`.
   - If the queue has reached 100 unprocessed messages, it does **not** block or wait.
   - It marks the subscriber as inactive (`subscriber.is_active = False`) with reason `queue_full`.
   - The subscriber is purged from the registry, freeing resources.
   - The disconnection is logged and recorded in `metrics_collector.stream_queue_drops`.

2. The main ingestion pipeline continues without interruption, guaranteeing that slow consumers do not impact ingestion latency.

