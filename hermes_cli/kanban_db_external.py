"""Opt-in, host-local API for authenticated external Kanban attempts.

Transport adapters are untrusted couriers, not execution authorities. Only signed
messages reach receive(); provisioning/offering/review are operator-only Python
APIs, deliberately not exposed through the model toolset or an HTTP endpoint.
SQLite is local to the controller. No PID, TTL, or remote silence releases work.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hermes_cli.kanban_db_connect import write_txn

PROTOCOL_VERSION = 1
MAX_BYTES = 65536
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MESSAGE_FIELDS = frozenset({
    'protocol_version', 'board_id', 'board_epoch', 'tenant', 'task_id',
    'task_revision', 'attempt_id', 'agent_id', 'key_id', 'message_id',
    'sequence', 'kind', 'payload', 'payload_hash', 'reported_at',
})
TRANSITIONS = {
    ('offered', 'accept'): 'accepted',
    ('accepted', 'start'): 'running',
    ('running', 'progress'): 'running',
    ('running', 'heartbeat'): 'running',
    ('running', 'blocked'): 'blocked',
    ('blocked', 'heartbeat'): 'blocked',
    ('running', 'result'): 'review',
    ('blocked', 'result'): 'review',
    ('offered', 'yield'): 'yielded',
    ('accepted', 'yield'): 'yielded',
    ('running', 'yield'): 'yielded',
    ('blocked', 'yield'): 'yielded',
    ('cancel_requested', 'cancel_ack'): 'cancelled',
}
TASK_STATUS = {'offered': 'ready', 'accepted': 'ready', 'running': 'running',
               'review': 'review', 'done': 'done'}


class ProtocolError(ValueError):
    """A bounded, non-secret protocol or ownership error."""


def identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ProtocolError('invalid identifier')
    return value


def canonical(value):
    """Wire v1: UTF-8, sorted keys, ASCII escapes, no floats or ambiguous keys."""
    def check(item, depth=0):
        if depth > 16:
            raise ProtocolError('payload nesting limit')
        if item is None or type(item) in (str, bool, int):
            return
        if isinstance(item, list):
            for member in item:
                check(member, depth + 1)
            return
        if isinstance(item, dict) and all(isinstance(k, str) for k in item):
            for member in item.values():
                check(member, depth + 1)
            return
        raise ProtocolError('unsupported JSON value')
    check(value)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > MAX_BYTES:
        raise ProtocolError('payload size limit')
    return raw


def sign_message(message, private_key):
    return {'message': message, 'signature': private_key.sign(canonical(message)).hex()}


def verify_message(envelope, public_hex):
    if not isinstance(envelope, dict) or set(envelope) != {'message', 'signature'}:
        raise ProtocolError('invalid envelope')
    try:
        raw = canonical(envelope['message'])
        signature = bytes.fromhex(envelope['signature'])
        if len(signature) != 64:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, raw)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ProtocolError('signature rejected') from exc
    return envelope['message']


def require_local_task(conn, task_id):
    """Local mutation helpers must not override external ownership, even force."""
    row = conn.execute('SELECT execution_backend FROM tasks WHERE id = ?', (task_id,)).fetchone()
    if row and row[0] != 'local_profile':
        raise ProtocolError('external task requires external-attempt API')


def require_deletable_task(conn, task_id):
    """Check under the delete transaction; external dependency edges are frozen."""
    require_local_task(conn, task_id)
    if conn.execute(
        "SELECT 1 FROM task_links l JOIN tasks c ON c.id=l.child_id "
        "WHERE l.parent_id=? AND c.execution_backend!='local_profile' LIMIT 1",
        (task_id,),
    ).fetchone():
        raise ProtocolError('task has external dependents; deletion requires reconciliation')


def _require_supported_completion_contract(task):
    # PR acceptance is tied to local run/publication evidence, which wire v1
    # cannot provide. Operator review text is not a substitute for that gate.
    if task['completion_contract'] not in (None, '', 'local-only'):
        raise ProtocolError('external execution does not support this completion contract')


def initialize_schema(conn):
    """Additive migration; called only by the normal native connection initializer."""
    statements = (
        '''CREATE TABLE IF NOT EXISTS external_board (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), board_id TEXT NOT NULL,
            epoch TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS external_workers (
            tenant TEXT NOT NULL, agent_id TEXT NOT NULL, key_id TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE, capabilities TEXT NOT NULL, expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(tenant, agent_id), UNIQUE(tenant, key_id))''',
        '''CREATE TABLE IF NOT EXISTS external_tasks (
            task_id TEXT PRIMARY KEY REFERENCES tasks(id), tenant TEXT NOT NULL,
            scope TEXT NOT NULL, capabilities TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS external_attempts (
            attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
            tenant TEXT NOT NULL, agent_id TEXT NOT NULL, epoch TEXT NOT NULL,
            state TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0,
            offer_key TEXT NOT NULL, offer_hash TEXT NOT NULL, assignment TEXT NOT NULL,
            UNIQUE(tenant, offer_key))''',
        '''CREATE TABLE IF NOT EXISTS external_receipts (
            tenant TEXT NOT NULL, message_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
            digest TEXT NOT NULL, receipt TEXT NOT NULL, message TEXT NOT NULL,
            PRIMARY KEY(tenant, message_id))''',
        '''CREATE TABLE IF NOT EXISTS external_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
            delivery_key TEXT NOT NULL UNIQUE, document TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS external_rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL,
            received_at INTEGER NOT NULL, digest TEXT NOT NULL, reason TEXT NOT NULL)''',
    )
    with write_txn(conn, allow_nested=True):
        for statement in statements:
            conn.execute(statement)


class ExternalAttempts:
    """Explicit connection and tenant binding; never resolves a global profile.

    Constructor verifies the durable board identity. The operator must bind the
    correct local DB before giving an instance to a transport adapter. Possession
    of this Python object is operator authority, not a remotely issued capability.
    """
    # Adapters may quarantine permanent protocol failures, never storage faults.
    rejection_error = ProtocolError

    def __init__(self, conn, *, board_id, tenant):
        self.conn = conn
        self.board_id = identifier(board_id)
        self.tenant = identifier(tenant)
        with write_txn(conn):
            row = conn.execute('SELECT board_id FROM external_board WHERE singleton=1').fetchone()
            if row and row[0] != board_id:
                raise ProtocolError('board binding mismatch')
            conn.execute('INSERT OR IGNORE INTO external_board VALUES (1, ?, ?)', (board_id, str(uuid.uuid4())))

    @property
    def epoch(self):
        return self.conn.execute('SELECT epoch FROM external_board WHERE singleton=1').fetchone()[0]

    def _task(self, task_id):
        row = self.conn.execute('SELECT * FROM tasks WHERE id=? AND tenant=?', (task_id, self.tenant)).fetchone()
        if not row:
            raise ProtocolError('task not available')
        return row

    def _worker(self, agent_id):
        row = self.conn.execute('SELECT * FROM external_workers WHERE tenant=? AND agent_id=?',
                                (self.tenant, agent_id)).fetchone()
        if not row or row['revoked'] or row['expires_at'] <= int(time.time()):
            raise ProtocolError('worker unavailable or revoked')
        return row

    def register_worker(self, agent_id, key_id, public_key, capabilities, *, expires_at):
        """Explicit enrollment; cannot overwrite or resurrect a revoked identity."""
        identifier(agent_id)
        identifier(key_id)
        if type(expires_at) is not int or not int(time.time()) < expires_at <= int(time.time()) + 365 * 86400:
            raise ProtocolError('finite worker expiry within one year required')
        self._capabilities(capabilities)
        try:
            raw_key = bytes.fromhex(public_key)
            if public_key != raw_key.hex():
                raise ValueError()
            Ed25519PublicKey.from_public_bytes(raw_key)
        except (TypeError, ValueError) as exc:
            raise ProtocolError('invalid public key') from exc
        with write_txn(self.conn):
            prior = self.conn.execute('SELECT 1 FROM external_workers WHERE tenant=? AND agent_id=?',
                                      (self.tenant, agent_id)).fetchone()
            if prior:
                raise ProtocolError('identity already registered; use a new identity for rotation')
            self.conn.execute('INSERT INTO external_workers VALUES (?, ?, ?, ?, ?, ?, 0)',
                              (self.tenant, agent_id, key_id, public_key, canonical(capabilities).decode(), expires_at))

    def revoke_worker(self, agent_id):
        """Revocation rejects even duplicate messages; active work stays held."""
        with write_txn(self.conn):
            if self.conn.execute('UPDATE external_workers SET revoked=1 WHERE tenant=? AND agent_id=?',
                                 (self.tenant, agent_id)).rowcount != 1:
                raise ProtocolError('worker unavailable')
            for row in self.conn.execute('SELECT task_id FROM external_attempts WHERE tenant=? AND agent_id=?',
                                         (self.tenant, agent_id)).fetchall():
                self._event(row['task_id'], 'external_worker_revoked', {'agent_id': agent_id})

    @staticmethod
    def _capabilities(values):
        if not isinstance(values, list) or not values or len(values) > 32:
            raise ProtocolError('capabilities required')
        for value in values:
            identifier(value)

    def prepare_task(self, task_id, *, scope, capabilities):
        """Freeze a non-running task's execution specification as external-only."""
        self._capabilities(capabilities)
        if not isinstance(scope, dict) or not scope:
            raise ProtocolError('bounded scope required')
        from hermes_cli import kanban_db as kb
        with write_txn(self.conn):
            task = self._task(task_id)
            if task['execution_backend'] != 'local_profile' or task['status'] not in ('triage', 'todo', 'ready') or task['current_run_id']:
                raise ProtocolError('task not eligible for external preparation')
            if task['claim_lock'] or task['worker_pid'] or task['workflow_template_id']:
                raise ProtocolError('task has local execution context')
            _require_supported_completion_contract(task)
            self.conn.execute('INSERT INTO external_tasks VALUES (?, ?, ?, ?)',
                              (task_id, self.tenant, canonical(scope).decode(), canonical(capabilities).decode()))
            self.conn.execute("UPDATE tasks SET execution_backend='external_agent', assignee=NULL, status='ready', external_revision=1 WHERE id=?", (task_id,))
            kb._append_event(self.conn, task_id, 'external_prepared', {'scope': scope, 'capabilities': capabilities})

    def _event(self, task_id, kind, payload):
        from hermes_cli import kanban_db as kb
        kb._append_event(self.conn, task_id, kind, payload)

    def _publish(self, delivery_key, document):
        self.conn.execute('INSERT INTO external_outbox(tenant, delivery_key, document) VALUES (?, ?, ?)',
                          (self.tenant, delivery_key, canonical(document).decode()))

    def offer(self, task_id, agent_id, offer_key, *, authorization_ref):
        identifier(offer_key)
        identifier(authorization_ref)
        request_hash = hashlib.sha256(canonical([task_id, agent_id, authorization_ref])).hexdigest()
        with write_txn(self.conn):
            task = self._task(task_id)
            worker = self._worker(agent_id)
            prior = self.conn.execute('SELECT * FROM external_attempts WHERE tenant=? AND offer_key=?',
                                      (self.tenant, offer_key)).fetchone()
            if prior:
                if prior['offer_hash'] != request_hash or prior['epoch'] != self.epoch:
                    raise ProtocolError('offer replay conflict')
                return json.loads(prior['assignment'])
            if task['execution_backend'] != 'external_agent' or task['external_attempt_id'] or task['status'] != 'ready':
                raise ProtocolError('task already owned or not ready')
            # Archive is not accepted completion for an external dependency.
            if self.conn.execute("SELECT 1 FROM task_links l JOIN tasks p ON p.id=l.parent_id WHERE l.child_id=? AND p.status!='done'", (task_id,)).fetchone():
                raise ProtocolError('dependencies not accepted')
            spec = self.conn.execute('SELECT * FROM external_tasks WHERE task_id=? AND tenant=?', (task_id, self.tenant)).fetchone()
            if not set(json.loads(spec['capabilities'])).issubset(json.loads(worker['capabilities'])):
                raise ProtocolError('capability mismatch')
            attempt_id = str(uuid.uuid4())
            assignment = {'protocol_version': 1, 'kind': 'assignment', 'board_id': self.board_id,
                          'board_epoch': self.epoch, 'tenant': self.tenant, 'task_id': task_id,
                          'task_revision': task['external_revision'], 'attempt_id': attempt_id,
                          'agent_id': agent_id, 'authorization_ref': authorization_ref,
                          'scope': json.loads(spec['scope']), 'capabilities': json.loads(spec['capabilities']),
                          'state': 'offered'}
            self.conn.execute('INSERT INTO external_attempts VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)',
                              (attempt_id, task_id, self.tenant, agent_id, self.epoch, 'offered', offer_key,
                               request_hash, canonical(assignment).decode()))
            self.conn.execute("UPDATE tasks SET external_attempt_id=?, external_state='offered' WHERE id=?", (attempt_id, task_id))
            self._event(task_id, 'external_offered', assignment)
            self._publish('assignment:' + attempt_id, assignment)
            return assignment

    def _authenticate(self, envelope):
        if not isinstance(envelope, dict) or not isinstance(envelope.get('message'), dict):
            raise ProtocolError('invalid envelope')
        msg = envelope['message']
        if set(msg) != MESSAGE_FIELDS or type(msg['protocol_version']) is not int or msg['protocol_version'] != 1:
            raise ProtocolError('unsupported message schema')
        for field in ('board_id', 'board_epoch', 'tenant', 'task_id', 'attempt_id', 'agent_id', 'key_id', 'message_id'):
            identifier(msg[field])
        for field in ('sequence', 'task_revision', 'reported_at'):
            if type(msg[field]) is not int or not 0 <= msg[field] <= 2**53 - 1:
                raise ProtocolError('invalid sequence, revision or timestamp')
        if (msg['board_id'], msg['board_epoch'], msg['tenant']) != (self.board_id, self.epoch, self.tenant):
            raise ProtocolError('message scope mismatch')
        worker = self._worker(msg['agent_id'])
        if worker['key_id'] != msg['key_id']:
            raise ProtocolError('key binding mismatch')
        verify_message(envelope, worker['public_key'])
        if not isinstance(msg['payload'], dict):
            raise ProtocolError('invalid payload')
        if msg['payload_hash'] != hashlib.sha256(canonical(msg['payload'])).hexdigest():
            raise ProtocolError('payload hash mismatch')
        return msg

    def receive(self, envelope):
        """Atomic signature/revocation check, transition, event, receipt and outbox.

        Identical retries return the original durable receipt, not current state.
        Cancellation-overtaken valid messages consume sequence with a rejection
        receipt, never an execution transition. Other rejected input is recorded
        by digest only; raw hostile content is not logged.
        """
        digest = hashlib.sha256(canonical(envelope)).hexdigest()
        try:
            with write_txn(self.conn):
                return self._receive(envelope, digest)
        except ProtocolError as exc:
            with write_txn(self.conn):
                self.conn.execute('INSERT INTO external_rejections(tenant,received_at,digest,reason) VALUES (?,?,?,?)',
                                  (self.tenant, int(time.time()), digest, str(exc)))
            raise

    def _receive(self, envelope, digest):
        msg = self._authenticate(envelope)
        task = self._task(msg['task_id'])
        attempt = self.conn.execute('SELECT * FROM external_attempts WHERE attempt_id=? AND tenant=?',
                                    (msg['attempt_id'], self.tenant)).fetchone()
        if not attempt or (attempt['task_id'], attempt['agent_id'], attempt['epoch']) != (msg['task_id'], msg['agent_id'], self.epoch):
            raise ProtocolError('attempt binding mismatch')
        if task['external_attempt_id'] != msg['attempt_id'] or task['external_revision'] != msg['task_revision']:
            raise ProtocolError('task fence mismatch')
        prior = self.conn.execute('SELECT digest, receipt FROM external_receipts WHERE tenant=? AND message_id=?',
                                  (self.tenant, msg['message_id'])).fetchone()
        if prior:
            if prior['digest'] != digest:
                raise ProtocolError('conflicting replay')
            return json.loads(prior['receipt'])
        if not isinstance(msg['kind'], str):
            raise ProtocolError('invalid message kind')
        if task['external_state'] != attempt['state'] or task['execution_backend'] != 'external_agent':
            raise ProtocolError('attempt held for reconciliation')
        # Cancellation may overtake a worker's durably pending message. Consume
        # only authenticated, fenced, schema-valid next messages; never grant work.
        cancelled = attempt['state'] == 'cancel_requested' and msg['kind'] in (
            'accept', 'start', 'heartbeat', 'progress', 'blocked', 'result', 'yield')
        state = 'cancel_requested' if cancelled else TRANSITIONS.get((attempt['state'], msg['kind']))
        if state is None or msg['sequence'] != attempt['sequence'] + 1:
            raise ProtocolError('invalid transition or sequence')
        self._validate_payload(msg['kind'], msg['payload'])
        if not cancelled and msg['kind'] in ('start', 'result'):
            self._check_dependencies(task['id'])
        self.conn.execute('UPDATE external_attempts SET state=?, sequence=? WHERE attempt_id=?',
                          (state, msg['sequence'], msg['attempt_id']))
        now = int(time.time())
        if not cancelled:
            self.conn.execute('UPDATE tasks SET status=?, external_state=?, last_heartbeat_at=? WHERE id=?',
                              (TASK_STATUS.get(state, 'blocked'), state, now, task['id']))
            if msg['kind'] == 'start':
                self.conn.execute('UPDATE tasks SET started_at=COALESCE(started_at,?) WHERE id=?', (now, task['id']))
            if msg['kind'] == 'result':
                self.conn.execute('UPDATE tasks SET result=? WHERE id=?', (canonical(msg['payload']).decode(), task['id']))
        receipt = {**{k: msg[k] for k in ('protocol_version', 'board_id', 'board_epoch', 'tenant', 'task_id', 'task_revision', 'attempt_id', 'agent_id', 'message_id', 'sequence')},
                   'kind': 'receipt', 'accepted_kind': msg['kind'], 'state': state, 'received_at': now,
                   'message_digest': hashlib.sha256(canonical(msg)).hexdigest()}
        if cancelled:
            receipt.update(outcome='rejected', rejection_reason='cancel_requested')
        self.conn.execute('INSERT INTO external_receipts VALUES (?, ?, ?, ?, ?, ?)',
                          (self.tenant, msg['message_id'], msg['attempt_id'], digest,
                           canonical(receipt).decode(), canonical(msg).decode()))
        self._event(task['id'], 'external_message_rejected' if cancelled else 'external_' + msg['kind'], receipt)
        self._publish('receipt:' + self.tenant + ':' + msg['message_id'], receipt)
        return receipt

    @staticmethod
    def _validate_payload(kind, payload):
        if kind in ('accept', 'start', 'heartbeat'):
            if payload:
                raise ProtocolError('unexpected payload fields')
            return
        if kind in ('progress', 'blocked'):
            if set(payload) != {'checkpoint'} or not isinstance(payload['checkpoint'], str) or not payload['checkpoint'].strip():
                raise ProtocolError('checkpoint required')
            return
        required = {'checkpoint', 'tools_returned', 'in_flight_operations'}
        if kind == 'result':
            required |= {'criteria', 'tests', 'artifacts', 'risks'}
        if set(payload) != required or payload['tools_returned'] is not True or payload['in_flight_operations'] != []:
            raise ProtocolError('ownership release declaration required')
        if not isinstance(payload['checkpoint'], str) or not payload['checkpoint'].strip():
            raise ProtocolError('checkpoint required')
        if kind == 'result':
            for field in ('criteria', 'tests', 'artifacts', 'risks'):
                if not isinstance(payload[field], list):
                    raise ProtocolError('result evidence must be lists')
            if not payload['criteria'] or not payload['tests'] or not payload['artifacts']:
                raise ProtocolError('result evidence required')
            for criterion in payload['criteria']:
                if not isinstance(criterion, dict) or set(criterion) != {'criterion', 'evidence'} or not all(isinstance(v, str) and v.strip() for v in criterion.values()):
                    raise ProtocolError('criterion evidence required')

    def _check_dependencies(self, task_id):
        if self.conn.execute("SELECT 1 FROM task_links l JOIN tasks p ON p.id=l.parent_id WHERE l.child_id=? AND p.status!='done'", (task_id,)).fetchone():
            raise ProtocolError('dependencies not accepted')

    def cancel(self, task_id, *, reason):
        """Request only; no timeout release. Worker must send a signed cancel_ack."""
        identifier(reason)
        with write_txn(self.conn):
            task = self._task(task_id)
            if task['external_state'] not in ('offered', 'accepted', 'running', 'blocked'):
                raise ProtocolError('attempt cannot be cancelled')
            self.conn.execute("UPDATE external_attempts SET state='cancel_requested' WHERE attempt_id=?", (task['external_attempt_id'],))
            self.conn.execute("UPDATE tasks SET status='blocked', external_state='cancel_requested' WHERE id=?", (task_id,))
            document = {'protocol_version': 1, 'kind': 'cancel', 'board_id': self.board_id,
                        'board_epoch': self.epoch, 'tenant': self.tenant, 'task_id': task_id,
                        'attempt_id': task['external_attempt_id'], 'reason': reason}
            self._event(task_id, 'external_cancel_requested', document)
            self._publish('cancel:' + task['external_attempt_id'], document)

    def review(self, task_id, attempt_id, *, reviewer, evidence):
        """Independent operator approval includes verification of tool shutdown.

        A worker result alone never releases the ownership pointer or permits a
        second attempt. No automatic rerun/reassignment is provided in v1.
        """
        identifier(reviewer)
        if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 4096:
            raise ProtocolError('independent review evidence required')
        with write_txn(self.conn):
            task = self._task(task_id)
            attempt = self.conn.execute('SELECT * FROM external_attempts WHERE attempt_id=? AND tenant=?', (attempt_id, self.tenant)).fetchone()
            if not attempt or attempt['epoch'] != self.epoch or task['external_attempt_id'] != attempt_id or task['external_state'] != 'review' or reviewer == attempt['agent_id']:
                raise ProtocolError('review fence mismatch')
            self._check_dependencies(task_id)
            # Also fence already-prepared databases from older API versions.
            _require_supported_completion_contract(task)
            self.conn.execute("UPDATE tasks SET status='done', external_state='done', completed_at=? WHERE id=?", (int(time.time()), task_id))
            self.conn.execute("UPDATE external_attempts SET state='done' WHERE attempt_id=?", (attempt_id,))
            self._event(task_id, 'external_reviewed', {'attempt_id': attempt_id, 'reviewer': reviewer, 'evidence': evidence})

    def rotate_epoch(self):
        """Restore fence for the entire board; unresolved work is held, never reoffered."""
        with write_txn(self.conn):
            self.conn.execute('UPDATE external_board SET epoch=? WHERE singleton=1', (str(uuid.uuid4()),))
            self.conn.execute("UPDATE tasks SET status='blocked', external_state='reconciliation_required' WHERE execution_backend='external_agent' AND status!='done'")
        return self.epoch

    def pending_documents(self, after=0, limit=100):
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ProtocolError('invalid outbox range')
        return [dict(row) for row in self.conn.execute('SELECT * FROM external_outbox WHERE tenant=? AND id>? ORDER BY id LIMIT ?', (self.tenant, after, limit))]
