import secrets

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import CustomUser
from documents.models import Document
from tenants.models import Tenant

ROLES = ('admin', 'member', 'viewer')


def set_tenant(tenant_id):
    """Transaction-local RLS tenant context, as TenantMiddleware sets per request.
    Pass None to clear it (RLS then matches no rows)."""
    with connection.cursor() as cur:
        cur.execute("SELECT set_config('app.current_tenant_id', %s, true)",
                    [str(tenant_id) if tenant_id else ''])


class AdversarialTestCase(TestCase):
    """Two tenants x three roles, with documents of every sensitivity.

    Plain TestCase on purpose: TransactionTestCase flushes with TRUNCATE,
    which the audit table's trigger blocks.
    """

    PASSWORD = secrets.token_urlsafe(16)  # throwaway, generated per run, never hardcoded

    @classmethod
    def setUpTestData(cls):
        cls.tenants = {
            'a': Tenant.objects.create(name='Tenant A', slug='tenant-a'),
            'b': Tenant.objects.create(name='Tenant B', slug='tenant-b'),
        }
        cls.users = {}
        for key, tenant in cls.tenants.items():
            for role in ROLES:
                name = f'{role}_{key}'
                cls.users[name] = CustomUser.objects.create_user(
                    username=name, password=cls.PASSWORD, tenant=tenant, role=role.upper()
                )
        cls.docs = {}
        for key, tenant in cls.tenants.items():
            admin, member = cls.users[f'admin_{key}'], cls.users[f'member_{key}']
            cls._make_doc(f'pub_{key}', tenant, admin, 'PUBLIC')
            cls._make_doc(f'int_{key}', tenant, admin, 'INTERNAL')
            cls._make_doc(f'conf_admin_{key}', tenant, admin, 'CONFIDENTIAL')
            cls._make_doc(f'conf_member_{key}', tenant, member, 'CONFIDENTIAL')
        set_tenant(None)

    @classmethod
    def _make_doc(cls, key, tenant, owner, sensitivity):
        set_tenant(tenant.id)  # FORCE RLS: inserts need the tenant context too
        cls.docs[key] = Document.objects.create(
            tenant=tenant, created_by=owner, title=key,
            content=f'secret body of {key}', sensitivity=sensitivity,
        )

    def setUp(self):
        cache.clear()  # the token-endpoint throttle counts per IP across tests otherwise

    def client_for(self, username):
        """Client carrying a genuine access token for a fixture user."""
        client = APIClient()
        token = RefreshToken.for_user(self.users[username]).access_token
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        return client

    def login(self, username, password=None):
        """The real login flow, through /api/token/."""
        return APIClient().post(
            '/api/token/',
            {'username': username, 'password': password or self.PASSWORD},
            format='json',
        )
