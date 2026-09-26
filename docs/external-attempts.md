# External attempts — experimental host-local API

This additive implementation is a review candidate, not an enabled dispatcher or
an accepted platform architecture. `hermes_cli.kanban_db_external.ExternalAttempts`
is the native authority: explicit SQLite connection, board identity, epoch and
tenant. Its mutations use the native transaction/event machinery. No remote
HTTP listener, model tool, installer, daemon or credential provisioning is added.

## Contract v1

An operator registers a dedicated Ed25519 public key with immutable agent/key IDs,
finite expiry and capability allowlist. Rotation requires a new identity;
revocation cannot be undone. Private keys never enter the native DB. A registered
key is not a profile name or a transport bearer credential. All signed messages,
including duplicate retries, must pass current revocation/expiry checks.

`prepare_task` freezes scope/capabilities and marks `execution_backend=external_agent`.
`offer` durably creates an external attempt and assignment outbox entry. The
operator supplies an authorization reference; this API does not independently
resolve that reference to human approval. Only trusted host code may call it.

Messages bind protocol version, board/epoch, tenant, task/revision, attempt,
agent/key, message ID, sequence, kind, payload hash and reported timestamp.
Sorted compact ASCII-escaped JSON (UTF-8), no floats, 16-level nesting and 64 KiB
bounds define signing bytes. Timestamps are informational, never lease authority.
Native receive atomically authenticates, checks ownership/dependencies, transitions
the attempt/task, appends an event, and persists both receipt and outbox. Exact
replay returns the original receipt; conflicting IDs, sequence gaps, stale epochs,
foreign identities and task fences fail closed.

Lifecycle: offered → accepted → running → review → operator-reviewed done.
Progress/heartbeat do not release ownership. Blocked, yield and cancellation are
explicit states. Cancellation requests await signed acknowledgement with tool
shutdown/no-in-flight declaration. Even yielded/cancelled attempts remain held:
there is deliberately no automatic reassignment API. Result needs criterion-linked
evidence, tests, artifacts and risks, and cannot mark done itself. Review is a
trusted operator operation, not proof of an independent review merely because
its reviewer string differs from the worker ID.

Local profile mutation/claim/reclaim/reap paths exclude external ownership;
external tasks never acquire fake PIDs. Board transfer is refused for boards with
external tasks. `rotate_epoch` invalidates old messages and holds unresolved work;
restore requires coherent DB/outbox/journal recovery and explicit reconciliation.

External dependency edges are frozen: both hard-delete APIs refuse to delete a
local prerequisite of an external task, including an archived prerequisite.
Archival is not accepted completion; offer, start, result and review still require
Done parents. No reconciliation/removal API is supplied in v1. Swarm idempotency
cannot reuse an external task as a local planning root or synthesize a local run.

Wire v1 supports only unset or `local-only` completion contracts. `prepare_task`
rejects PR/repository contracts rather than substituting reviewer prose for the
native PR acceptance gate. `review` also rejects these contracts on tasks prepared
by older versions, leaving task/attempt ownership unchanged for reconciliation.

## Cancellation racing with pending messages

If cancellation commits first, a valid next-sequence `accept`, `start`,
`heartbeat`, `progress`, `blocked`, `result` or `yield` is consumed atomically with a
receipt/outbox entry and an `external_message_rejected` event. The receipt has
`outcome=rejected`, `rejection_reason=cancel_requested`, and
`state=cancel_requested`. All existing identity/sequence bindings and the SHA-256
`message_digest` of the canonical original message remain mandatory. The legacy
`accepted_kind` field binds the original kind; it is **not** an authorization.

This path changes only the attempt sequence, not task execution state, start time,
heartbeat, result or dependencies. Payload validation still applies. Execution
prerequisites do not block this rejection: no start or completion is authorized.
The worker must authenticate the controller receipt, match its exact pending
message and clear that pending message before sending `cancel_ack` at the next
sequence. A rejection receipt must never grant start permission or prove shutdown.

Authentication, revocation/expiry, epoch/tenant/task/attempt fences, state coherence,
next sequence and schema validity are prerequisites. Invalid inputs still raise
`ProtocolError` without consuming sequence or emitting a reconciliation receipt.
`ExternalAttempts.rejection_error` exposes that exact exception class to adapters;
operational/storage failures are not permanent rejections and must remain retryable.

If the worker message committed first, exact retry returns its original accepted
receipt (the absence of `outcome` retains the v1 accepted meaning), not a later
rejection. A committed result remains in Review; a committed yield remains
Yielded. Neither can be overwritten by cancellation. If cancellation wins over
yield, its shutdown declaration is still validated but the rejection does not
release ownership: a separate next-sequence `cancel_ack` with a valid shutdown
declaration is required. `cancel_ack` is never a rejection-receipt kind: it is
accepted only in `cancel_requested`, and its exact receipt replays after cancellation
settles. A second cancellation of a requested/terminal attempt fails closed.
Rejected receipts likewise replay unchanged after reconnect, later
`cancel_ack`, or uncertain delivery, provided current identity/fences still pass.
Revocation/expiry rejects even previously committed receipts. Receipt/outbox failure
rolls back sequence, event and receipt together; no blind pending-message discard
or automatic ownership release is permitted.

## Verification

```sh
scripts/run_tests.sh tests/hermes_cli/test_kanban_external.py -j 1
scripts/run_tests.sh tests/hermes_cli/test_kanban*.py tests/plugins/test_kanban*.py tests/tools/test_kanban*.py -j 4
```

Use the repository's isolated runner, never a safety-environment bypass. The tests
use generated keys and temporary native databases, cover auth/replay,
revocation/expiry, tenant/home isolation, local-dispatch exclusion, cancellation,
fencing, rollback and concurrent duplicate receipt serialization. Cancellation
coverage derives a both-orderings matrix from every supported transition (including
all yield source states and `cancel_ack`), plus shutdown-declaration rejection,
no execution mutation, dependency drift,
reconnect/duplicate replay, publication failure rollback, next-sequence stop
acknowledgement and negative authentication/schema/fence cases. The broader
Kanban suite also exercises legacy migrations and local execution compatibility.

## Remaining acceptance gates

- Independent security/architecture review of this host-local API and wire v1.
- Supported key custody, approved enrollment/rotation and operator authentication.
- Integration of a real runner with cancellation, shutdown evidence and receipt
  consumption; this change executes no external work.
- A dedicated, least-privilege transport identity is separate from signing identity;
  remote platform access controls require their own authorized acceptance tests.
- No TTL failover, automatic reassignment, lost-journal restart, or live rollout.
