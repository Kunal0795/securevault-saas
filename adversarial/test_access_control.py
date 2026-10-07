import uuid

from django.test import Client
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from documents.models import Document

from .base import AdversarialTestCase, set_tenant

BODY = {'title': 'edited', 'content': 'edited body', 'sensitivity': 'PUBLIC'}


class AccessTestCase(AdversarialTestCase):
    """Helpers shared by the authorization suites. Fixture titles equal their keys."""

    def url(self, doc_id=None):
        if doc_id is None:
            return reverse('document-list')
        return reverse('document-detail', args=[doc_id])

    def call(self, who, method, doc=None, data=None):
        """Request as `who`. `doc` is a fixture key, a raw/UUID id, or None for the list route."""
        if isinstance(doc, str) and doc in self.docs:
            doc = self.docs[doc].id
        client, url = self.client_for(who), self.url(doc)
        if method == 'get':
            return client.get(url, data)
        if method == 'delete':
            return client.delete(url)
        return getattr(client, method)(url, data, format='json')

    @staticmethod
    def body_for(method):
        return BODY if method in ('put', 'patch') else None

    @staticmethod
    def ids(response):
        data = response.data['results'] if isinstance(response.data, dict) else response.data
        return {str(item['id']) for item in data}

    def doc_ids(self, *keys):
        return {str(self.docs[k].id) for k in keys}

    def make_member_doc(self, sensitivity='INTERNAL'):
        response = self.call('member_a', 'post', data={
            'title': 'member doc', 'content': 'x', 'sensitivity': sensitivity})
        self.assertEqual(response.status_code, 201)
        return response.data['id']

    def stored(self, key):
        """Read a fixture row straight from the DB, under that tenant's RLS context."""
        doc = self.docs[key]
        set_tenant(doc.tenant_id)
        return Document.objects.filter(pk=doc.pk).first()

    def assert_untouched(self, *keys):
        for key in keys:
            row = self.stored(key)
            self.assertIsNotNone(row, f"{key} was deleted")
            self.assertEqual(row.title, key, f"{key} was modified")


class AccessMatrixTests(AccessTestCase):
    """verify_matrix.sh, ported: role x sensitivity x ownership inside one tenant."""

    READ = [  # (user, document, expected status)
        ('admin_a', 'pub_a', 200), ('admin_a', 'int_a', 200),
        ('admin_a', 'conf_admin_a', 200), ('admin_a', 'conf_member_a', 200),
        ('member_a', 'pub_a', 200), ('member_a', 'int_a', 200),
        ('member_a', 'conf_admin_a', 404), ('member_a', 'conf_member_a', 200),
        ('viewer_a', 'pub_a', 200), ('viewer_a', 'int_a', 200),
        ('viewer_a', 'conf_admin_a', 404), ('viewer_a', 'conf_member_a', 404),
    ]
    VISIBLE = {
        'admin_a': ('pub_a', 'int_a', 'conf_admin_a', 'conf_member_a'),
        'member_a': ('pub_a', 'int_a', 'conf_member_a'),
        'viewer_a': ('pub_a', 'int_a'),
        'admin_b': ('pub_b', 'int_b', 'conf_admin_b', 'conf_member_b'),
        'member_b': ('pub_b', 'int_b', 'conf_member_b'),
        'viewer_b': ('pub_b', 'int_b'),
    }

    def test_detail_read_matrix(self):
        for who, key, expected in self.READ:
            with self.subTest(who=who, doc=key):
                self.assertEqual(self.call(who, 'get', key).status_code, expected)

    def test_list_returns_exactly_the_visible_set(self):
        for who, keys in self.VISIBLE.items():
            with self.subTest(who=who):
                response = self.call(who, 'get')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.ids(response), self.doc_ids(*keys))

    def test_create_permissions(self):
        body = {'title': 'probe', 'content': 'x', 'sensitivity': 'CONFIDENTIAL'}
        self.assertEqual(self.call('admin_a', 'post', data=body).status_code, 201)
        self.assertEqual(self.call('member_a', 'post', data=body).status_code, 201)
        self.assertEqual(self.call('viewer_a', 'post', data=body).status_code, 403)

    def test_permitted_updates_and_deletes_succeed(self):
        edit = {'title': 'edited'}
        mine = self.make_member_doc()
        self.assertEqual(self.call('admin_a', 'patch', mine, edit).status_code, 200)
        self.assertEqual(self.call('admin_a', 'patch', 'conf_member_a', edit).status_code, 200)
        self.assertEqual(self.call('member_a', 'patch', mine, edit).status_code, 200)
        self.assertEqual(self.call('member_a', 'delete', mine).status_code, 204)
        self.assertEqual(self.call('admin_a', 'get', mine).status_code, 404)  # really gone
        theirs = self.make_member_doc()
        self.assertEqual(self.call('admin_a', 'delete', theirs).status_code, 204)


class PrivilegeEscalationTests(AccessTestCase):

    def test_viewer_cannot_write_by_any_verb(self):
        for key in ('pub_a', 'int_a'):
            for method in ('put', 'patch', 'delete'):
                with self.subTest(doc=key, method=method):
                    response = self.call('viewer_a', method, key, self.body_for(method))
                    self.assertEqual(response.status_code, 403)
        self.assertEqual(self.call('viewer_a', 'post', data=BODY).status_code, 403)
        self.assert_untouched('pub_a', 'int_a')

    def test_member_cannot_modify_documents_they_do_not_own(self):
        for key in ('pub_a', 'int_a'):
            for method in ('put', 'patch', 'delete'):
                with self.subTest(doc=key, method=method):
                    response = self.call('member_a', method, key, self.body_for(method))
                    self.assertEqual(response.status_code, 403)
        self.assert_untouched('pub_a', 'int_a')

    def test_hidden_documents_cannot_be_modified_or_deleted(self):
        for method in ('put', 'patch', 'delete'):
            with self.subTest(who='member_a', method=method):
                response = self.call('member_a', method, 'conf_admin_a', self.body_for(method))
                self.assertEqual(response.status_code, 404)
            with self.subTest(who='viewer_a', method=method):
                # a viewer may be refused before the lookup (403) or after it (404): never 2xx
                for key in ('conf_admin_a', 'conf_member_a'):
                    response = self.call('viewer_a', method, key, self.body_for(method))
                    self.assertIn(response.status_code, (403, 404))
        self.assert_untouched('conf_admin_a', 'conf_member_a')

    def test_create_ignores_client_supplied_tenant_creator_and_id(self):
        victim = self.docs['pub_b']
        forged = {
            'title': 'forged', 'content': 'x', 'sensitivity': 'INTERNAL',
            'tenant': str(self.tenants['b'].id),
            'created_by': str(self.users['admin_b'].id),
            'id': str(victim.id),
        }
        response = self.call('member_a', 'post', data=forged)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(str(response.data['tenant']), str(self.tenants['a'].id))
        self.assertEqual(str(response.data['created_by']), str(self.users['member_a'].id))
        self.assertNotEqual(str(response.data['id']), str(victim.id))
        self.assert_untouched('pub_b')

    def test_patch_ignores_client_supplied_tenant_and_creator(self):
        doc_id = self.make_member_doc()
        before = self.call('member_a', 'get', doc_id).data
        response = self.call('member_a', 'patch', doc_id, {
            'title': 'tamper',
            'tenant': str(self.tenants['b'].id),
            'created_by': str(self.users['admin_b'].id),
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(str(response.data['tenant']), str(before['tenant']))
        self.assertEqual(str(response.data['created_by']), str(before['created_by']))

    def test_tenant_admin_role_grants_no_django_admin_access(self):
        for name in ('admin_a', 'member_a', 'viewer_a'):
            with self.subTest(user=name, credential='bearer token'):
                token = RefreshToken.for_user(self.users[name]).access_token
                response = APIClient().get('/admin/', HTTP_AUTHORIZATION=f'Bearer {token}')
                self.assertEqual(response.status_code, 302)
                self.assertIn('/admin/login/', response['Location'])
            with self.subTest(user=name, credential='session login'):
                client = Client()
                client.force_login(self.users[name])
                response = client.get('/admin/')
                self.assertEqual(response.status_code, 302)
                self.assertIn('/admin/login/', response['Location'])


class IDORTests(AccessTestCase):

    def test_other_tenant_and_nonexistent_documents_are_indistinguishable(self):
        ghost = uuid.uuid4()
        for key in ('pub_b', 'conf_admin_b'):
            for method in ('get', 'put', 'patch', 'delete'):
                with self.subTest(doc=key, method=method):
                    real = self.call('admin_a', method, key, self.body_for(method))
                    fake = self.call('admin_a', method, ghost, self.body_for(method))
                    self.assertEqual(real.status_code, 404)
                    self.assertEqual(fake.status_code, 404)
                    self.assertEqual(real.content, fake.content, "response body reveals existence")

    def test_hidden_confidential_and_nonexistent_documents_are_indistinguishable(self):
        ghost = uuid.uuid4()
        for who in ('member_a', 'viewer_a'):
            for method in ('get', 'put', 'patch', 'delete'):
                with self.subTest(who=who, method=method):
                    real = self.call(who, method, 'conf_admin_a', self.body_for(method))
                    fake = self.call(who, method, ghost, self.body_for(method))
                    self.assertNotEqual(real.status_code, 200)
                    self.assertEqual(real.status_code, fake.status_code)
                    self.assertEqual(real.content, fake.content, "response body reveals existence")

    def test_query_parameters_cannot_widen_visibility(self):
        tenant_b = str(self.tenants['b'].id)
        probes = [
            {'tenant': tenant_b}, {'tenant_id': tenant_b}, {'tenant__id': tenant_b},
            {'sensitivity': 'CONFIDENTIAL'},
            {'created_by': str(self.users['admin_a'].id)},
            {'id': str(self.docs['conf_admin_a'].id)},
            {'search': 'secret'}, {'ordering': '-created_at'},
            {'limit': 1000, 'page_size': 1000, 'page': 1},
        ]
        allowed = {
            'viewer_a': self.doc_ids('pub_a', 'int_a'),
            'member_a': self.doc_ids('pub_a', 'int_a', 'conf_member_a'),
            'admin_a': self.doc_ids('pub_a', 'int_a', 'conf_admin_a', 'conf_member_a'),
        }
        for who, expected in allowed.items():
            self.assertEqual(self.ids(self.call(who, 'get')), expected)  # baseline, not vacuous
            for params in probes:
                with self.subTest(who=who, params=params):
                    response = self.call(who, 'get', data=params)
                    self.assertIn(response.status_code, (200, 400, 404))
                    if response.status_code == 200:
                        self.assertTrue(self.ids(response) <= expected)

    def test_cross_tenant_writes_fail_and_leave_rows_intact(self):
        for attacker, victim_tenant in (('admin_a', 'b'), ('admin_b', 'a')):
            for key in [k for k in self.docs if k.endswith(f'_{victim_tenant}')]:
                for method in ('put', 'patch', 'delete'):
                    with self.subTest(attacker=attacker, doc=key, method=method):
                        response = self.call(attacker, method, key, self.body_for(method))
                        self.assertEqual(response.status_code, 404)
        self.assert_untouched(*self.docs)  # every fixture row, both tenants

    def test_malformed_ids_return_404_not_errors(self):
        client = self.client_for('admin_a')
        junk_ids = ('not-a-uuid', '1', '-1', '00000000-0000-0000-0000-000000000000',
                    '%27%20OR%20%271%27%3D%271')
        for junk in junk_ids:
            for method in ('get', 'patch', 'delete'):
                with self.subTest(id=junk, method=method):
                    response = getattr(client, method)(f'/api/documents/{junk}/')
                    self.assertEqual(response.status_code, 404)
                    self.assertNotIn(b'Traceback', response.content)
