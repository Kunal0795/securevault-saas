from django.db import connection
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken

from documents.models import Document
from tenants.middleware import TenantMiddleware

from .base import AdversarialTestCase


def current_tenant():
    """What the DB connection currently believes the tenant is (None = no context)."""
    with connection.cursor() as cur:
        cur.execute("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
        return cur.fetchone()[0]


class TenantContextLifetimeTests(AdversarialTestCase):
    """The tenant context must live exactly as long as one request.

    Nothing in a TestCase closes the connection between requests, which is the
    situation CONN_MAX_AGE > 0 or a connection pooler creates in production.
    The middleware is called directly with a probe in place of the view, so the
    test can see what the database believed at the moment the 'view' ran.
    """

    def setUp(self):
        super().setUp()
        self.seen = {}

        def probe(request):
            self.seen['tenant'] = current_tenant()
            self.seen['visible_docs'] = Document.objects.count()
            return HttpResponse('ok')

        self.middleware = TenantMiddleware(probe)
        self.factory = RequestFactory()

    def _tenant_request(self, username, path='/api/documents/'):
        self.seen.clear()
        token = RefreshToken.for_user(self.users[username]).access_token
        request = self.factory.get(path, HTTP_AUTHORIZATION=f'Bearer {token}')
        return self.middleware(request)

    def test_context_is_set_for_the_request_and_gone_after_it(self):
        self.assertIsNone(current_tenant())  # clean baseline
        response = self._tenant_request('admin_a')
        self.assertEqual(response.status_code, 200)
        # positive control: the "view" really ran under tenant A's context
        self.assertEqual(self.seen['tenant'], str(self.tenants['a'].id))
        self.assertEqual(self.seen['visible_docs'], 4)
        # the attack surface: nothing may be left on the connection afterwards
        self.assertIsNone(current_tenant(), "tenant context leaked past the end of the request")

    def test_exempt_paths_never_inherit_the_previous_requests_tenant(self):
        for path in ('/admin/', '/api/token/', '/api/token/refresh/'):
            with self.subTest(path=path):
                self._tenant_request('admin_a')  # leaves its context behind if the middleware leaks
                self.seen.clear()
                self.middleware(self.factory.get(path))
                self.assertIsNone(self.seen['tenant'], f"{path} ran under a stale tenant context")
                self.assertEqual(self.seen['visible_docs'], 0, f"{path} could read another tenant's rows")

    def test_back_to_back_requests_from_two_tenants_stay_isolated(self):
        """Regression guard through the full stack; should pass before and after the fix."""
        ids = {k: str(d.id) for k, d in self.docs.items()}
        a_ids = {v for k, v in ids.items() if k.endswith('_a')}
        b_ids = {v for k, v in ids.items() if k.endswith('_b')}
        for who, own, other in (('admin_a', a_ids, b_ids), ('admin_b', b_ids, a_ids), ('admin_a', a_ids, b_ids)):
            response = self.client_for(who).get(reverse('document-list'))
            self.assertEqual(response.status_code, 200)
            data = response.data
            items = data['results'] if isinstance(data, dict) else data
            returned = {str(item['id']) for item in items}
            self.assertTrue(returned, f"{who} saw nothing, so the check would be vacuous")
            self.assertTrue(returned <= own, f"{who} saw rows outside its own tenant")
            self.assertFalse(returned & other)
