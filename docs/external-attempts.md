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

## Verification

Run the repository test runner against `tests/hermes_cli/test_kanban_external.py`.
The tests use generated keys and temporary native databases, cover auth/replay,
revocation/expiry, tenant/home isolation, local-dispatch exclusion, cancellation,
fencing, rollback and concurrent duplicate receipt serialization. The broader
Kanban suite also exercises legacy migrations and local execution compatibility.

## Remaining acceptance gates

- Independent security/architecture review of this host-local API and wire v1.
- Supported key custody, approved enrollment/rotation and operator authentication.
- Integration of a real runner with cancellation, shutdown evidence and receipt
  consumption; this change executes no external work.
- A dedicated, least-privilege transport identity is separate from signing identity;
  remote platform access controls require their own authorized acceptance tests.
- No TTL failover, automatic reassignment, lost-journal restart, or live rollout.
