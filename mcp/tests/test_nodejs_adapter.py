"""Pruebas del adaptador Node.js NDJSON (Prompt Maestro §10.4 y §18)."""
import json
import unittest
from datetime import datetime, timezone

from adapters import nodejs

CAPTURED = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)


def line(**fields):
    base = {
        'schema_version': 1,
        'timestamp': '2026-11-22T01:02:03Z',
        'type': 'app.started',
    }
    base.update(fields)
    return json.dumps(base) + '\n'


class NodeAdapterTests(unittest.TestCase):
    def test_login_failed_and_success(self):
        failed = nodejs.adapt(line(
            type='auth.login_failed', user='maria', src_ip='192.168.122.1',
            request_id='req-1',
        ), CAPTURED)
        self.assertEqual(failed[0]['event_type'], 'auth.failed')
        self.assertEqual(failed[0]['username'], 'maria')
        self.assertEqual(failed[0]['attributes']['request_id'], 'req-1')
        self.assertEqual(failed[0]['timestamp_source'], 'producer_rfc3339')
        success = nodejs.adapt(line(
            type='auth.login_success', user='maria', src_ip='192.168.122.1',
        ), CAPTURED)
        self.assertEqual(success[0]['event_type'], 'auth.success')

    def test_login_without_minimums_downgrades_to_notice(self):
        events = nodejs.adapt(line(type='auth.login_failed', user='maria'), CAPTURED)
        self.assertEqual(events[0]['event_type'], 'system.notice')
        self.assertEqual(events[0]['username'], 'maria')

    def test_application_and_dependency_errors(self):
        for kind in ('app.error', 'dependency.error', 'db.error'):
            events = nodejs.adapt(line(type=kind, error_code='E_CONN'), CAPTURED)
            self.assertEqual(events[0]['event_type'], 'app.error', kind)
            self.assertEqual(events[0]['attributes']['error_code'], 'E_CONN')

    def test_denied_and_other_security_facts_are_notices(self):
        for kind in ('authz.denied', 'authz.forbidden_resource', 'rate_limited',
                     'session.created', 'validation.error', 'input.rejected'):
            events = nodejs.adapt(line(type=kind), CAPTURED)
            self.assertEqual(events[0]['event_type'], 'system.notice', kind)

    def test_db_operation_keeps_operation_attribute(self):
        events = nodejs.adapt(line(type='db.operation', operation='select'), CAPTURED)
        self.assertEqual(events[0]['attributes']['operation'], 'select')

    def test_invalid_json_and_unknown_type(self):
        self.assertEqual(nodejs.adapt('{"schema_version": 1, roto\n', CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(type='app.exploded'), CAPTURED), [])
        self.assertEqual(nodejs.adapt('texto libre de consola\n', CAPTURED), [])

    def test_missing_and_malformed_fields(self):
        no_ts = json.dumps({'schema_version': 1, 'type': 'app.started'}) + '\n'
        self.assertEqual(nodejs.adapt(no_ts, CAPTURED), [])
        no_schema = json.dumps({
            'timestamp': '2026-11-22T01:02:03Z', 'type': 'app.started',
        }) + '\n'
        self.assertEqual(nodejs.adapt(no_schema, CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(schema_version=2), CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(level='shouty'), CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(user='x' * 65), CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(request_id='r' * 65), CAPTURED), [])
        self.assertEqual(nodejs.adapt(line(src_ip='no-es-ip'), CAPTURED), [])
        unknown_key = json.loads(line())
        unknown_key['surprise'] = 1
        self.assertEqual(
            nodejs.adapt(json.dumps(unknown_key) + '\n', CAPTURED), []
        )

    def test_naive_timestamp_is_not_accepted(self):
        self.assertEqual(
            nodejs.adapt(line(timestamp='2026-11-22T01:02:03'), CAPTURED), []
        )


if __name__ == '__main__':
    unittest.main()
