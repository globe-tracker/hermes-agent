"""Exercise cancellation on every supported native transition, in both orders."""
import pytest
from hermes_cli import kanban_db as kb
from hermes_cli.kanban_db_external import ProtocolError, TRANSITIONS
from tests.hermes_cli.test_kanban_external import setup, message, _result_payload, _durable_state  # noqa: F401

STOP = {'checkpoint': 'stopped', 'tools_returned': True, 'in_flight_operations': []}
PATHS = {'offered': (), 'accepted': ('accept',), 'running': ('accept', 'start'),
         'blocked': ('accept', 'start', 'blocked'), 'cancel_requested': ('accept', 'start')}


def payload(kind):
    return {'blocked': {'checkpoint': 'blocked'}, 'progress': {'checkpoint': 'progress'},
            'result': _result_payload(), 'yield': STOP, 'cancel_ack': STOP}.get(kind)


@pytest.mark.parametrize('state,kind', list(TRANSITIONS))
@pytest.mark.parametrize('message_first', [False, True])
def test_every_transition_against_cancellation(setup, state, kind, message_first):
    conn, api, key, tid, assignment = setup
    seq = 1
    for prior in PATHS[state]:
        api.receive(message(api, key, assignment, seq, prior, payload(prior)))
        seq += 1
    if state == 'cancel_requested':
        api.cancel(tid, reason='fixture-stop')
    pending = message(api, key, assignment, seq, kind, payload(kind))
    original = api.receive(pending) if message_first else None
    if state == 'cancel_requested' or (message_first and kind in ('yield', 'result')):
        before = _durable_state(conn)
        with pytest.raises(ProtocolError):
            api.cancel(tid, reason='second-stop')
        assert _durable_state(conn) == before
    else:
        api.cancel(tid, reason='fixture-stop')
    receipt = api.receive(pending)
    assert api.receive(pending) == receipt
    if message_first:
        assert receipt == original
        assert receipt.get('outcome', 'accepted') == 'accepted'
    elif kind == 'cancel_ack':
        assert receipt['state'] == 'cancelled'
        assert receipt.get('outcome', 'accepted') == 'accepted'
    else:
        assert receipt['outcome'] == 'rejected'
        assert receipt['state'] == receipt['rejection_reason'] == 'cancel_requested'
    if kb.get_task(conn, tid).external_state == 'cancel_requested':
        # Neither a rejected yield nor an accepted pre-cancel message proves shutdown.
        bad = {**STOP, 'in_flight_operations': ['uncertain']}
        before = _durable_state(conn)
        with pytest.raises(ProtocolError):
            api.receive(message(api, key, assignment, seq + 1, 'cancel_ack', bad))
        assert _durable_state(conn) == before
        assert api.receive(message(api, key, assignment, seq + 1, 'cancel_ack', STOP))['state'] == 'cancelled'
    assert api.receive(pending) == receipt
    assert kb.claim_task(conn, tid) is None
    with pytest.raises(ProtocolError):
        api.offer(tid, 'worker', 'new-offer', authorization_ref='fixture')


@pytest.mark.parametrize('field,value', [('tools_returned', False), ('in_flight_operations', ['uncertain']), ('checkpoint', '')])
def test_cancelled_yield_keeps_shutdown_validation(setup, field, value):
    conn, api, key, tid, assignment = setup
    api.cancel(tid, reason='fixture-stop')
    before = _durable_state(conn)
    with pytest.raises(ProtocolError):
        api.receive(message(api, key, assignment, 1, 'yield', {**STOP, field: value}))
    assert _durable_state(conn) == before
