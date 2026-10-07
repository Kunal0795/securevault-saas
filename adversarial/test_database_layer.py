from django.db import DatabaseError, connection, transaction

from documents.models import Document

from .base import AdversarialTestCase, set_tenant


class DatabaseLayerTests(AdversarialTestCase):
    """Row-Level Security tested on its own, with every application-level filter out of the way."""

    def test_application_role_cannot_bypass_row_level_security(self):
        with connection.cursor() as cur:
            cur.execute("SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            name, is_super, bypass = cur.fetchone()
        self.assertFalse(is_super, f"{name} is a superuser: Postgres skips RLS for it entirely")
        self.assertFalse(bypass, f"{name} has BYPASSRLS: RLS is not enforced for it")

    def test_bare_queries_see_only_the_current_tenants_rows(self):
        for key in ('a', 'b'):
            set_tenant(self.tenants[key].id)
            self.assertEqual(Document.objects.count(), 4)
        set_tenant(self.tenants['a'].id)
        self.assertEqual(Document.objects.filter(tenant=self.tenants['b']).count(), 0)
        set_tenant(None)
        self.assertEqual(Document.objects.count(), 0, "no tenant context must mean no rows")

    def test_database_refuses_cross_tenant_writes_with_no_application_checks(self):
        victim = self.docs['pub_b']
        set_tenant(self.tenants['a'].id)
        self.assertEqual(Document.objects.filter(pk=victim.pk).update(title='hijacked'), 0)
        self.assertEqual(Document.objects.filter(pk=victim.pk).delete()[0], 0)
        with self.assertRaises(DatabaseError):
            with transaction.atomic():
                Document.objects.create(
                    tenant=self.tenants['b'], created_by=self.users['admin_b'],
                    title='planted', content='x')
        set_tenant(self.tenants['b'].id)
        self.assertEqual(Document.objects.get(pk=victim.pk).title, 'pub_b')
        self.assertFalse(Document.objects.filter(title='planted').exists())
