from unittest import mock

from rest_framework.test import APIClient

from . import test_access_control as ac


class AuditCoverageTests(ac.AccessTestCase):
    """What the audit mixin reports about attacks, with the emit call mocked out."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch('audit.mixins.emit_audit_event')
        self.emit = patcher.start()
        self.addCleanup(patcher.stop)

    def events(self):
        return [call.kwargs for call in self.emit.call_args_list]

    def only_event(self):
        events = self.events()
        self.assertEqual(len(events), 1, events)
        return events[0]

    def test_denied_write_is_audited_as_denied_with_full_attribution(self):
        response = self.call('viewer_a', 'patch', 'pub_a', {'title': 'x'})
        self.assertEqual(response.status_code, 403)
        event = self.only_event()
        self.assertEqual(event['outcome'], 'denied')
        self.assertEqual(event['action'], 'document.update')
        self.assertEqual(event['actor'].pk, self.users['viewer_a'].pk)
        self.assertEqual(str(event['tenant_id']), str(self.tenants['a'].id))
        self.assertEqual(str(event['resource_id']), str(self.docs['pub_a'].id))
        self.assertEqual(event['metadata'], {
            'method': 'PATCH', 'path': self.url(self.docs['pub_a'].id), 'status': 403})

    def test_every_refused_write_is_audited_as_denied(self):
        cases = [(who, method, key)
                 for who in ('viewer_a', 'member_a')
                 for key in ('pub_a', 'int_a')
                 for method in ('put', 'patch', 'delete')]
        for who, method, key in cases:
            with self.subTest(who=who, method=method, doc=key):
                self.emit.reset_mock()
                response = self.call(who, method, key, self.body_for(method))
                self.assertEqual(response.status_code, 403)
                event = self.only_event()
                self.assertEqual(event['outcome'], 'denied')
                self.assertEqual(event['actor'].pk, self.users[who].pk)
        self.emit.reset_mock()
        self.assertEqual(self.call('viewer_a', 'post', data=ac.BODY).status_code, 403)
        event = self.only_event()
        self.assertEqual(event['action'], 'document.create')
        self.assertEqual(event['outcome'], 'denied')

    def test_cross_tenant_probe_is_attributed_to_the_attackers_own_tenant(self):
        """An attacker must never be able to write into the victim tenant's audit chain."""
        for method in ('get', 'put', 'patch', 'delete'):
            with self.subTest(method=method):
                self.emit.reset_mock()
                response = self.call('admin_a', method, 'pub_b', self.body_for(method))
                self.assertEqual(response.status_code, 404)
                event = self.only_event()
                self.assertEqual(str(event['tenant_id']), str(self.tenants['a'].id),
                                 "probe was recorded in the victim tenant's audit chain")
                self.assertEqual(event['actor'].pk, self.users['admin_a'].pk)
                self.assertNotEqual(event['outcome'], 'success')
                self.assertEqual(str(event['resource_id']), str(self.docs['pub_b'].id))

    def test_successful_actions_are_audited_with_the_right_verb(self):
        checks = [
            ('admin_a', 'get', None, None, 'document.list'),
            ('admin_a', 'get', 'pub_a', None, 'document.read'),
            ('admin_a', 'patch', 'pub_a', {'title': 'x'}, 'document.update'),
            ('admin_a', 'delete', 'int_a', None, 'document.delete'),
        ]
        for who, method, key, data, action in checks:
            with self.subTest(action=action):
                self.emit.reset_mock()
                response = self.call(who, method, key, data)
                self.assertLess(response.status_code, 400)
                event = self.only_event()
                self.assertEqual(event['action'], action)
                self.assertEqual(event['outcome'], 'success')
        self.emit.reset_mock()
        response = self.call('member_a', 'post', data={
            'title': 'new', 'content': 'x', 'sensitivity': 'INTERNAL'})
        self.assertEqual(response.status_code, 201)
        event = self.only_event()
        self.assertEqual(event['action'], 'document.create')
        self.assertEqual(str(event['resource_id']), str(response.data['id']))

    def test_audit_events_never_carry_request_or_document_content(self):
        marker = 'LEAK-MARKER-9f3a'
        self.call('admin_a', 'patch', 'pub_a', {'title': marker, 'content': marker})
        self.call('admin_a', 'get', 'pub_a')
        self.call('admin_a', 'get', 'conf_admin_a')  # body contains 'secret body of conf_admin_a'
        self.assertEqual(len(self.events()), 3)
        self.assertNotIn(marker, repr(self.events()))
        self.assertNotIn('secret body', repr(self.events()))
        for event in self.events():
            self.assertEqual(set(event['metadata']), {'method', 'path', 'status'})

    def test_audit_failure_does_not_break_the_request_fail_open_by_design(self):
        self.emit.side_effect = RuntimeError('broker down')
        with self.assertLogs('audit.mixins', level='ERROR'):
            response = self.call('admin_a', 'get', 'pub_a')
        self.assertEqual(response.status_code, 200)

    def test_known_gap_requests_rejected_by_the_middleware_are_not_audited(self):
        """Pins today's behaviour so changing it is a deliberate decision (see README)."""
        for header in (None, 'Bearer not.a.jwt'):
            with self.subTest(header=header):
                extra = {'HTTP_AUTHORIZATION': header} if header else {}
                response = APIClient().get(self.url(), **extra)
                self.assertEqual(response.status_code, 401)
        self.emit.assert_not_called()
