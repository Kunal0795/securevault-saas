import ast
from pathlib import Path
from unittest import mock
from urllib.parse import quote

from django.conf import settings
from django.db import connection
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import CustomUser
from audit.hashing import GENESIS_HASH
from audit.models import AuditLog
from audit.tasks import write_audit_event
from documents.models import Document
from tenants.models import Tenant

from . import test_access_control as ac
from .base import set_tenant

PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE documents_document; --",
    '" OR ""="',
    "1; SELECT pg_sleep(10) --",
    "' UNION SELECT username, password, NULL FROM accounts_customuser --",
    "\\' OR 1=1 --",
    "'||(SELECT version())||'",
    "$$; SELECT 1; $$",
    "%27%20OR%201%3D1",
    "Robert'); DROP TABLE accounts_customuser;--",
]


class SQLInjectionTests(ac.AccessTestCase):

    def assert_schema_and_rows_intact(self, created_in_a=0):
        tables = connection.introspection.table_names()
        for table in ('documents_document', 'accounts_customuser', 'audit_auditlog', 'tenants_tenant'):
            self.assertIn(table, tables)
        self.assertEqual(CustomUser.objects.count(), 6)
        self.assertEqual(Tenant.objects.count(), 2)
        set_tenant(self.tenants['a'].id)
        self.assertEqual(Document.objects.count(), 4 + created_in_a)
        set_tenant(self.tenants['b'].id)
        self.assertEqual(Document.objects.count(), 4)

    def test_payloads_in_stored_fields_are_stored_as_inert_text(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                response = self.call('member_a', 'post', data={
                    'title': payload, 'content': payload, 'sensitivity': 'INTERNAL'})
                self.assertEqual(response.status_code, 201)
                fetched = self.call('member_a', 'get', response.data['id'])
                self.assertEqual(fetched.status_code, 200)
                self.assertEqual(fetched.data['title'], payload)
                self.assertEqual(fetched.data['content'], payload)
        self.assert_schema_and_rows_intact(created_in_a=len(PAYLOADS))

    def test_nul_bytes_are_rejected_cleanly(self):
        for field in ('title', 'content'):
            with self.subTest(field=field):
                body = {'title': 'ok', 'content': 'ok', 'sensitivity': 'INTERNAL'}
                body[field] = 'before\x00after'
                self.assertEqual(self.call('member_a', 'post', data=body).status_code, 400)

    def test_payloads_in_query_parameters_and_path_ids_are_inert(self):
        expected = self.doc_ids('pub_a', 'int_a', 'conf_admin_a', 'conf_member_a')
        params = ('search', 'ordering', 'sensitivity', 'tenant', 'created_by', 'id', 'title', 'page')
        client = self.client_for('admin_a')
        for payload in PAYLOADS:
            for param in params:
                with self.subTest(payload=payload, param=param):
                    response = self.call('admin_a', 'get', data={param: payload})
                    self.assertIn(response.status_code, (200, 400, 404))
                    if response.status_code == 200:
                        self.assertTrue(self.ids(response) <= expected)
            with self.subTest(payload=payload, where='path'):
                response = client.get('/api/documents/' + quote(payload, safe='') + '/')
                self.assertEqual(response.status_code, 404)
        self.assert_schema_and_rows_intact()

    def test_injection_in_choice_field_is_rejected(self):
        doc_id = self.make_member_doc()
        for payload in PAYLOADS + ['confidential', 'CONFIDENTIAL ', 'PUBLIC\n']:
            with self.subTest(payload=payload):
                created = self.call('member_a', 'post', data={
                    'title': 't', 'content': 'x', 'sensitivity': payload})
                self.assertEqual(created.status_code, 400)
                patched = self.call('member_a', 'patch', doc_id, {'sensitivity': payload})
                self.assertEqual(patched.status_code, 400)

    def test_login_with_injection_payloads_fails_cleanly(self):
        attempts = [{'username': p, 'password': p} for p in PAYLOADS]
        attempts += [
            {'username': "admin_a' --", 'password': 'x'},
            {'username': "admin_a' OR '1'='1", 'password': "' OR '1'='1"},
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},
            {'username': ['admin_a'], 'password': ['x']},
        ]
        for body in attempts:
            with self.subTest(body=body):
                response = APIClient().post(reverse('token_obtain_pair'), body, format='json')
                self.assertIn(response.status_code, (400, 401))
                self.assertNotIn('access', response.data)
        self.assert_schema_and_rows_intact()

    def test_injection_cannot_switch_the_rls_tenant_context(self):
        tenant_b = str(self.tenants['b'].id)
        hijacks = [
            f"x'; SELECT set_config('app.current_tenant_id', '{tenant_b}', false); --",
            f"x'; SET app.current_tenant_id = '{tenant_b}'; --",
            f"x'; SET LOCAL app.current_tenant_id = '{tenant_b}'; --",
            "x'); RESET app.current_tenant_id; --",
        ]
        tenant_b_ids = self.doc_ids('pub_b', 'int_b', 'conf_admin_b', 'conf_member_b')
        for payload in hijacks:
            with self.subTest(payload=payload):
                created = self.call('admin_a', 'post', data={
                    'title': payload, 'content': payload, 'sensitivity': 'PUBLIC'})
                self.assertEqual(created.status_code, 201)
                self.assertEqual(str(created.data['tenant']), str(self.tenants['a'].id))
                listing = self.call('admin_a', 'get', data={'search': payload, 'ordering': payload})
                if listing.status_code == 200:
                    self.assertFalse(self.ids(listing) & tenant_b_ids, "tenant B rows became visible")
                self.assertEqual(self.call('admin_a', 'get', 'pub_b').status_code, 404)
        self.assert_schema_and_rows_intact(created_in_a=len(hijacks))


# ---- static guard: no string-built SQL anywhere in the project ---------------

SQL_SINKS = {'execute', 'executemany', 'raw', 'RawSQL'}
SKIP_DIRS = {'venv', '.venv', 'env', 'migrations', 'node_modules', 'site-packages',
             '__pycache__', '.git'}


def unsafe_sql_calls(source):
    """Line numbers of SQL calls whose query is built at runtime instead of being a literal."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)
        if name == 'extra':  # QuerySet.extra() is discouraged outright
            lines.append(node.lineno)
        elif name in SQL_SINKS and node.args:
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                lines.append(node.lineno)
    return lines


class StaticSQLGuardTests(ac.AccessTestCase):

    def test_scanner_flags_string_built_sql_and_accepts_parameterized(self):
        bad = [
            'cur.execute(f"SELECT * FROM t WHERE id = {x}")',
            'cur.execute("SELECT * FROM t WHERE id = %s" % x)',
            'cur.execute("SELECT * FROM t WHERE id = " + x)',
            'cur.execute(sql)',
            'Model.objects.raw("SELECT " + col)',
            'qs.extra(where=["a = %s"], params=[x])',
        ]
        good = [
            'cur.execute("SELECT * FROM t WHERE id = %s", [x])',
            'Model.objects.raw("SELECT * FROM t WHERE id = %s", [x])',
            'cur.execute("SELECT set_config(\'a\', %s, true)", [x])',
        ]
        for source in bad:
            with self.subTest(source=source):
                self.assertTrue(unsafe_sql_calls(source), "scanner missed unsafe SQL")
        for source in good:
            with self.subTest(source=source):
                self.assertEqual(unsafe_sql_calls(source), [], "scanner flagged safe SQL")

    def test_codebase_contains_no_string_built_sql(self):
        root = Path(settings.BASE_DIR)
        offenders, scanned = [], 0
        for path in root.rglob('*.py'):
            if SKIP_DIRS & set(path.relative_to(root).parts):
                continue
            scanned += 1
            for line in unsafe_sql_calls(path.read_text(encoding='utf-8')):
                offenders.append(f'{path.relative_to(root)}:{line}')
        self.assertGreater(scanned, 15, "scanner saw too few files, so the check would be vacuous")
        self.assertEqual(offenders, [], "string-built SQL found")


# ---- second-order: attacker-controlled strings that reach the audit writer ----

class AuditInjectionEndToEndTests(ac.AccessTestCase):
    """Real path: request -> mixin -> emit -> on_commit -> write_audit_event -> AuditLog row."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch('audit.emit._publish',
                             side_effect=lambda event: write_audit_event(event))  # run the task inline
        patcher.start()
        self.addCleanup(patcher.stop)

    def chain(self, tenant_key):
        tenant = self.tenants[tenant_key]
        set_tenant(tenant.id)
        return list(AuditLog.objects.filter(tenant=tenant).order_by('sequence'))

    def assert_chain_is_linked(self, rows):
        self.assertEqual([r.sequence for r in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(rows[0].prev_hash, GENESIS_HASH)
        for previous, row in zip(rows, rows[1:]):
            self.assertEqual(row.prev_hash, previous.entry_hash)

    def test_hostile_user_agents_are_stored_as_inert_text_and_chain_stays_linked(self):
        agents = ["' OR '1'='1", "'; DROP TABLE audit_auditlog; --", 'x' * 1000, 'evil\x00agent']
        client = self.client_for('admin_a')
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            for agent in agents:
                response = client.get(self.url(self.docs['pub_a'].id), HTTP_USER_AGENT=agent)
                self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(callbacks), len(agents))
        rows = self.chain('a')
        self.assertEqual([r.user_agent for r in rows],
                         [a.replace('\x00', '\ufffd')[:256] for a in agents])
        self.assert_chain_is_linked(rows)
        self.assertEqual(self.chain('b'), [], "an attacker's events landed in another tenant's chain")
        self.assertIn('audit_auditlog', connection.introspection.table_names())

    def test_hostile_url_ids_are_stored_as_inert_text(self):
        junk = ["' OR '1'='1", "'; DROP TABLE documents_document; --", 'A' * 200]
        client = self.client_for('admin_a')
        with self.captureOnCommitCallbacks(execute=True):
            for item in junk:
                response = client.get('/api/documents/' + quote(item, safe='') + '/')
                self.assertEqual(response.status_code, 404)
        rows = self.chain('a')
        self.assertEqual([r.resource_id for r in rows], [item[:64] for item in junk])
        self.assertEqual({r.action for r in rows}, {'document.read'})
        self.assertEqual({r.outcome for r in rows}, {'failure'})
        self.assertEqual(rows[0].metadata['path'], '/api/documents/' + junk[0] + '/')
        self.assert_chain_is_linked(rows)
        self.assertIn('documents_document', connection.introspection.table_names())
