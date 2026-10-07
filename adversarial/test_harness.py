from django.db import connection
from django.urls import reverse
from rest_framework.test import APIClient

from .base import AdversarialTestCase


class HarnessSmokeTests(AdversarialTestCase):
    """If these fail, nothing else in the suite can be trusted."""

    def test_fixtures_exist(self):
        self.assertEqual(len(self.users), 6)
        self.assertEqual(len(self.docs), 8)

    def test_rls_enabled_and_forced_in_the_test_database(self):
        with connection.cursor() as cur:
            cur.execute(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('documents_document', 'audit_auditlog') ORDER BY relname"
            )
            rows = cur.fetchall()
        self.assertEqual(rows, [('audit_auditlog', True, True), ('documents_document', True, True)])

    def test_audit_table_has_both_immutability_triggers(self):
        with connection.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM pg_trigger "
                "WHERE tgrelid = 'audit_auditlog'::regclass AND NOT tgisinternal"
            )
            self.assertEqual(cur.fetchone()[0], 2)

    def test_login_flow_returns_tokens(self):
        response = self.login('admin_a')
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)

    def test_own_tenant_document_is_readable(self):
        url = reverse('document-detail', args=[self.docs['pub_a'].id])
        self.assertEqual(self.client_for('admin_a').get(url).status_code, 200)

    def test_other_tenant_document_is_hidden(self):
        url = reverse('document-detail', args=[self.docs['pub_b'].id])
        self.assertEqual(self.client_for('admin_a').get(url).status_code, 404)

    def test_unauthenticated_request_is_rejected(self):
        url = reverse('document-detail', args=[self.docs['pub_a'].id])
        self.assertEqual(APIClient().get(url).status_code, 401)
