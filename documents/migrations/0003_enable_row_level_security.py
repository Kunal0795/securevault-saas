from django.db import migrations

POLICY = 'documents_tenant_isolation'
TENANT_MATCH = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid"

FORWARD = [
    "ALTER TABLE documents_document ENABLE ROW LEVEL SECURITY;",
    # FORCE: the table owner (our app role) is subject to the policy too
    "ALTER TABLE documents_document FORCE ROW LEVEL SECURITY;",
    f"DROP POLICY IF EXISTS {POLICY} ON documents_document;",
    f"CREATE POLICY {POLICY} ON documents_document "
    f"USING ({TENANT_MATCH}) WITH CHECK ({TENANT_MATCH});",
]

REVERSE = [
    f"DROP POLICY IF EXISTS {POLICY} ON documents_document;",
    "ALTER TABLE documents_document NO FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE documents_document DISABLE ROW LEVEL SECURITY;",
]


class Migration(migrations.Migration):

    dependencies = [
        ('documents', '0002_document_created_by_document_sensitivity'),
    ]

    operations = [
        migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE),
    ]
