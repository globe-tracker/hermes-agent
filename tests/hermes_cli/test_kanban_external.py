"""Real temporary native databases; no dispatcher processes or remote services."""
import copy
import time
import hashlib
from pathlib import Path
from hermes_cli.kanban_db_external import canonical

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_connect import connect
from hermes_cli.kanban_db_external import ExternalAttempts, ProtocolError, sign_message


@pytest.fixture
def setup(tmp_path):
    conn = connect(tmp_path / 'board.db')
    api = ExternalAttempts(conn, board_id='test-board', tenant='test-tenant')
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    api.register_worker('worker', 'key-1', public, ['test'], expires_at=int(time.time()) + 3600)
    task = kb.create_task(conn, title='harmless fixture', tenant='test-tenant')
    api.prepare_task(task, scope={'repository': 'fixture'}, capabilities=['test'])
    assignment = api.offer(task, 'worker', 'offer-1', authorization_ref='fixture-authorization')
    yield conn, api, key, task, assignment
    conn.close()


def message(api, key, assignment, seq, message_kind, payload=None, **overrides):
    data = {**{k: assignment[k] for k in ('board_id', 'board_epoch', 'tenant', 'task_id', 'task_revision', 'attempt_id', 'agent_id')},
            'protocol_version': 1, 'key_id': 'key-1', 'message_id': f'message-{seq}',
            'sequence': seq, 'kind': message_kind, 'payload': payload or {}, 'reported_at': 100}
    data['payload_hash'] = hashlib.sha256(canonical(data['payload'])).hexdigest()
    data.update(overrides)
    return sign_message(data, key)


def test_native_lifecycle_and_local_fences(setup):
    conn, api, key, tid, assignment = setup
    assert kb.get_task(conn, tid).execution_backend == 'external_agent'
    assert kb.claim_task(conn, tid) is None
    for operation in (lambda: kb.reclaim_task(conn, tid), lambda: kb.complete_task(conn, tid, result='fake', force=True),
                      lambda: kb.archive_task(conn, tid), lambda: kb.edit_task(conn, tid, body='changed')):
        with pytest.raises(ProtocolError):
            operation()
    assert api.offer(tid, 'worker', 'offer-1', authorization_ref='fixture-authorization') == assignment
    accepted = message(api, key, assignment, 1, 'accept')
    assert api.receive(accepted) == api.receive(accepted)
    api.receive(message(api, key, assignment, 2, 'start'))
    assert kb.get_task(conn, tid).status == 'running'
    assert kb.get_task(conn, tid).worker_pid is None
    assert kb.release_stale_claims(conn) == 0
    from hermes_cli.kanban_db_dispatch import reconcile_orphaned_running, detect_stale_running
    assert reconcile_orphaned_running(conn) == []
    assert detect_stale_running(conn, stale_timeout_seconds=1) == []
    result = {'criteria': [{'criterion': 'fixture', 'evidence': 'commit:fixture'}], 'tests': ['fixture passed'],
              'artifacts': ['commit:fixture'], 'risks': [], 'checkpoint': 'finished',
              'tools_returned': True, 'in_flight_operations': []}
    receipt = api.receive(message(api, key, assignment, 3, 'result', result))
    assert receipt['state'] == 'review'
    assert kb.get_task(conn, tid).status == 'review'
    api.review(tid, assignment['attempt_id'], reviewer='independent', evidence='fixture reviewed')
    assert kb.get_task(conn, tid).status == 'done'
    local = kb.create_task(conn, title='local unchanged')
    assert kb.claim_task(conn, local) is not None


def test_security_replay_revocation_and_epoch(setup):
    conn, api, key, tid, a = setup
    for overrides in ({'tenant': 'foreign'}, {'board_id': 'foreign'}, {'board_epoch': 'old'},
                      {'attempt_id': 'foreign'}, {'agent_id': 'other'}, {'task_revision': 99},
                      {'sequence': 2}, {'kind': 'start'}):
        with pytest.raises(ProtocolError):
            api.receive(message(api, key, a, 1, 'accept', **overrides))
    good = message(api, key, a, 1, 'accept')
    forged = copy.deepcopy(good)
    forged['message']['payload'] = {'forged': True}
    with pytest.raises(ProtocolError):
        api.receive(forged)
    api.receive(good)
    with pytest.raises(ProtocolError):
        api.receive(message(api, key, a, 1, 'accept', {'altered': True}))
    api.revoke_worker('worker')
    with pytest.raises(ProtocolError):
        api.receive(good)
    with pytest.raises(ProtocolError):
        api.offer(tid, 'worker', 'offer-2', authorization_ref='fixture')
    api.rotate_epoch()
    with pytest.raises(ProtocolError):
        api.receive(good)
    assert kb.get_task(conn, tid).status == 'blocked'


def test_cancel_yield_expiry_and_uncertain_remote_effects(setup):
    conn, api, key, tid, a = setup
    api.receive(message(api, key, a, 1, 'accept'))
    api.receive(message(api, key, a, 2, 'start'))
    api.cancel(tid, reason='fixture-stop')
    with pytest.raises(ProtocolError):
        api.receive(message(api, key, a, 3, 'result', {'checkpoint': 'late'}))
    with pytest.raises(ProtocolError):
        api.receive(message(api, key, a, 3, 'cancel_ack', {
            'checkpoint': 'uncertain', 'tools_returned': True, 'in_flight_operations': ['uncertain']}))
    stopped = message(api, key, a, 3, 'cancel_ack', {
        'checkpoint': 'stopped', 'tools_returned': True, 'in_flight_operations': []})
    receipt = api.receive(stopped)
    assert receipt['state'] == 'cancelled'
    assert kb.get_task(conn, tid).status == 'blocked'
    with pytest.raises(ProtocolError):
        api.offer(tid, 'worker', 'second-offer', authorization_ref='fixture')
    # Expiry applies even to a previously authenticated idempotent replay.
    conn.execute('UPDATE external_workers SET expires_at=?', (int(time.time()) - 1,))
    with pytest.raises(ProtocolError):
        api.receive(stopped)


def test_atomicity_restart_tenant_and_database_isolation(setup, tmp_path):
    conn, api, key, tid, a = setup
    signed = message(api, key, a, 1, 'accept')
    # A receipt write failure rolls back task state, attempt, event and outbox.
    from unittest.mock import patch
    with patch.object(api, '_publish', side_effect=OSError('fixture disk full')):
        with pytest.raises(OSError):
            api.receive(signed)
    assert kb.get_task(conn, tid).external_state == 'offered'
    assert conn.execute('SELECT count(*) FROM external_receipts').fetchone()[0] == 0
    path = conn.execute('PRAGMA database_list').fetchone()[2]
    other_connection = connect(Path(path))
    try:
        reloaded = ExternalAttempts(other_connection, board_id='test-board', tenant='test-tenant')
        first = reloaded.receive(signed)
        assert first == api.receive(signed)
        foreign = ExternalAttempts(other_connection, board_id='test-board', tenant='foreign')
        with pytest.raises(ProtocolError):
            foreign.prepare_task(tid, scope={'fixture': True}, capabilities=['test'])
        with pytest.raises(ProtocolError):
            ExternalAttempts(other_connection, board_id='other-board', tenant='test-tenant')
    finally:
        other_connection.close()
    # Home/connection A -> B -> A: no module-level board/epoch/identity cache.
    conn_b = connect(tmp_path / 'home-b' / 'board.db')
    try:
        api_b = ExternalAttempts(conn_b, board_id='board-b', tenant='test-tenant')
        with pytest.raises(ProtocolError):
            api_b.receive(signed)
        assert api.receive(signed) == first
        assert conn_b.execute('SELECT count(*) FROM tasks').fetchone()[0] == 0
    finally:
        conn_b.close()


def test_independent_connections_serialize_duplicate_receive(setup):
    conn, api, key, tid, a = setup
    from concurrent.futures import ThreadPoolExecutor
    path = Path(conn.execute('PRAGMA database_list').fetchone()[2])
    signed = message(api, key, a, 1, 'accept')
    def receive():
        local = connect(path)
        try:
            return ExternalAttempts(local, board_id='test-board', tenant='test-tenant').receive(signed)
        finally:
            local.close()
    with ThreadPoolExecutor(max_workers=2) as workers:
        receipts = list(workers.map(lambda _: receive(), range(2)))
    assert receipts[0] == receipts[1]
    assert conn.execute('SELECT count(*) FROM external_receipts').fetchone()[0] == 1
    assert kb.get_task(conn, tid).external_state == 'accepted'


def _durable_state(conn):
    tables = ('tasks', 'task_links', 'task_runs', 'task_comments', 'task_events',
              'external_tasks', 'external_attempts', 'external_receipts', 'external_outbox')
    return {table: [tuple(row) for row in conn.execute(f'SELECT * FROM {table} ORDER BY rowid')]
            for table in tables}


def _result_payload():
    return {'criteria': [{'criterion': 'fixture', 'evidence': 'fixture evidence'}],
            'tests': ['fixture passed'], 'artifacts': ['fixture artifact'], 'risks': [],
            'checkpoint': 'finished', 'tools_returned': True, 'in_flight_operations': []}


@pytest.mark.parametrize('delete', [kb.delete_task, kb.delete_archived_task])
@pytest.mark.parametrize('phase', ['offer', 'start', 'review'])
def test_delete_preserves_external_prerequisite(setup, delete, phase):
    conn, api, key, _, _ = setup
    parent = kb.create_task(conn, title='local prerequisite', tenant='test-tenant')
    if phase != 'offer':
        assert kb.complete_task(conn, parent, result='accepted fixture')
    child = kb.create_task(conn, title='external dependent', tenant='test-tenant', parents=[parent])
    api.prepare_task(child, scope={'fixture': True}, capabilities=['test'])
    if phase != 'offer':
        assignment = api.offer(child, 'worker', 'dependent-offer', authorization_ref='fixture')
        api.receive(message(api, key, assignment, 1, 'accept'))
        if phase == 'review':
            api.receive(message(api, key, assignment, 2, 'start'))
            api.receive(message(api, key, assignment, 3, 'result', _result_payload()))
    assert kb.archive_task(conn, parent)
    before = _durable_state(conn)
    with pytest.raises(ProtocolError, match='external depend'):
        delete(conn, parent)
    assert _durable_state(conn) == before
    with pytest.raises(ProtocolError, match='dependencies not accepted'):
        if phase == 'offer':
            api.offer(child, 'worker', 'dependent-offer', authorization_ref='fixture')
        elif phase == 'start':
            api.receive(message(api, key, assignment, 2, 'start'))
        else:
            api.review(child, assignment['attempt_id'], reviewer='independent', evidence='fixture')
    assert _durable_state(conn) == before


@pytest.mark.parametrize('entry', ['swarm', 'inline'])
def test_swarm_cannot_activate_cancel_requested_external_root(setup, entry):
    from hermes_cli import kanban_swarm as swarm
    conn, api, _, _, _ = setup
    root = kb.create_task(conn, title='external root', tenant='test-tenant', idempotency_key='swarm-key')
    api.prepare_task(root, scope={'fixture': True}, capabilities=['test'])
    api.offer(root, 'worker', 'root-offer', authorization_ref='fixture')
    api.cancel(root, reason='fixture-stop')
    before = _durable_state(conn)
    with pytest.raises(ProtocolError, match='external task'):
        if entry == 'swarm':
            swarm.create_swarm(conn, goal='fixture',
                               workers=[swarm.SwarmWorkerSpec('local', 'worker', 'fixture')],
                               verifier_assignee='verifier', synthesizer_assignee='synthesizer',
                               tenant='test-tenant', idempotency_key='swarm-key')
        else:
            with kb.write_txn(conn):
                swarm._activate_root_inline(conn, root, summary='fixture', metadata={})
    assert _durable_state(conn) == before


@pytest.mark.parametrize('phase', ['prepare', 'review'])
def test_external_completion_contract_fails_closed(setup, phase):
    conn, api, key, tid, assignment = setup
    contract = 'https://github.com/fixture/repository/pull/1'
    if phase == 'prepare':
        tid = kb.create_task(conn, title='contract fixture', tenant='test-tenant', completion_contract=contract)
    else:
        api.receive(message(api, key, assignment, 1, 'accept'))
        api.receive(message(api, key, assignment, 2, 'start'))
        api.receive(message(api, key, assignment, 3, 'result', _result_payload()))
        # Model a DB prepared by the older API, which admitted these contracts.
        # No network acceptance lookup is needed: unsupported contracts fail closed.
        with kb.write_txn(conn):
            conn.execute('UPDATE tasks SET completion_contract=? WHERE id=?', (contract, tid))
    before = _durable_state(conn)
    with pytest.raises(ProtocolError, match='completion contract'):
        if phase == 'prepare':
            api.prepare_task(tid, scope={'fixture': True}, capabilities=['test'])
        else:
            api.review(tid, assignment['attempt_id'], reviewer='independent', evidence='cannot replace acceptance')
    assert kb.get_task(conn, tid).status != 'done'
    assert _durable_state(conn) == before


@pytest.mark.parametrize('kind', ['accept', 'start', 'heartbeat', 'progress', 'blocked', 'result', 'yield'])
def test_cancel_overtakes_message_without_execution_and_replays_after_restart(setup, kind):
    import json
    from concurrent.futures import ThreadPoolExecutor
    from unittest.mock import patch

    conn, api, key, tid, assignment = setup
    sequence = 1
    if kind != 'accept':
        api.receive(message(api, key, assignment, sequence, 'accept'))
        sequence += 1
    if kind not in ('accept', 'start'):
        api.receive(message(api, key, assignment, sequence, 'start'))
        sequence += 1
    payload = {'progress': {'checkpoint': 'progress'}, 'blocked': {'checkpoint': 'blocked'},
               'yield': {'checkpoint': 'stopped', 'tools_returned': True, 'in_flight_operations': []},
               'result': _result_payload()}.get(kind)
    pending = message(api, key, assignment, sequence, kind, payload)
    api.cancel(tid, reason='fixture-stop')
    # Dependency regression must not prevent rejecting a start/result: no work
    # is being authorized and the next cancel_ack must remain reachable.
    parent = kb.create_task(conn, title='unmet fixture dependency', tenant='test-tenant')
    with kb.write_txn(conn):
        conn.execute('INSERT INTO task_links(parent_id, child_id) VALUES (?, ?)', (parent, tid))
    before = _durable_state(conn)
    with patch.object(api, '_publish', side_effect=OSError('fixture disk full')):
        with pytest.raises(OSError):
            api.receive(pending)
    assert _durable_state(conn) == before

    path = Path(conn.execute('PRAGMA database_list').fetchone()[2])
    def receive_on_new_connection():
        fresh = connect(path)
        try:
            return ExternalAttempts(fresh, board_id=api.board_id, tenant=api.tenant).receive(pending)
        finally:
            fresh.close()
    with ThreadPoolExecutor(max_workers=2) as workers:
        receipts = list(workers.map(lambda _: receive_on_new_connection(), range(2)))
    receipt = receipts[0]
    assert receipt == receipts[1] == api.receive(pending)
    assert receipt['outcome'] == 'rejected'
    assert receipt['rejection_reason'] == receipt['state'] == 'cancel_requested'
    assert receipt['accepted_kind'] == kind  # Legacy name binds, never authorizes.
    assert receipt['message_digest'] == hashlib.sha256(canonical(pending['message'])).hexdigest()
    for field in ('board_id', 'board_epoch', 'tenant', 'task_id', 'task_revision',
                  'attempt_id', 'agent_id', 'message_id', 'sequence'):
        assert receipt[field] == pending['message'][field]
    after = _durable_state(conn)
    for table in ('tasks', 'task_links', 'task_runs', 'task_comments', 'external_tasks'):
        assert after[table] == before[table]
    for table in ('external_receipts', 'external_outbox', 'task_events'):
        assert len(after[table]) == len(before[table]) + 1
    attempt = conn.execute('SELECT state, sequence FROM external_attempts WHERE attempt_id=?',
                           (assignment['attempt_id'],)).fetchone()
    assert tuple(attempt) == ('cancel_requested', sequence)
    assert json.loads(api.pending_documents()[-1]['document']) == receipt
    altered = copy.deepcopy(pending['message'])
    altered['reported_at'] += 1
    with pytest.raises(ProtocolError, match='conflicting replay'):
        api.receive(sign_message(altered, key))
    assert _durable_state(conn) == after
    assert kb.claim_task(conn, tid) is None
    stopped = message(api, key, assignment, sequence + 1, 'cancel_ack', {
        'checkpoint': 'stopped', 'tools_returned': True, 'in_flight_operations': []})
    assert api.receive(stopped)['state'] == 'cancelled'
    assert api.receive(pending) == receipt
    api.revoke_worker('worker')
    with pytest.raises(ProtocolError):
        api.receive(pending)


@pytest.mark.parametrize('fault', ['signature', 'revoked', 'expired', 'epoch', 'attempt',
                                  'revision', 'sequence', 'payload', 'kind', 'conflict', 'held'])
def test_cancel_rejection_requires_authentication_fences_and_valid_message(setup, fault):
    conn, api, key, tid, assignment = setup
    committed = message(api, key, assignment, 1, 'accept')
    original = api.receive(committed)
    api.cancel(tid, reason='fixture-stop')
    assert api.receive(committed) == original
    overrides = {'epoch': {'board_epoch': 'old'}, 'attempt': {'attempt_id': 'other'},
                 'revision': {'task_revision': 99}, 'sequence': {'sequence': 3},
                 'kind': {'kind': 'unknown'}, 'conflict': {'message_id': 'message-1'}}.get(fault, {})
    pending = message(api, key, assignment, 2, 'start',
                      {'unexpected': True} if fault == 'payload' else None, **overrides)
    if fault == 'signature':
        pending = sign_message(pending['message'], Ed25519PrivateKey.generate())
    if fault == 'revoked':
        api.revoke_worker('worker')
    if fault == 'expired':
        conn.execute('UPDATE external_workers SET expires_at=?', (int(time.time()) - 1,))
    if fault == 'held':
        conn.execute("UPDATE tasks SET external_state='reconciliation_required' WHERE id=?", (tid,))
    before = _durable_state(conn)
    assert api.rejection_error is ProtocolError
    with pytest.raises(api.rejection_error):
        api.receive(pending)
    assert _durable_state(conn) == before
