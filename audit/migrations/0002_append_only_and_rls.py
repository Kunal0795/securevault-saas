from django.db import migrations

FORWARD = [
    # --- Layer 2: trigger blocks UPDATE / DELETE / TRUNCATE for everyone, superuser included ---
    """
    CREATE FUNCTION audit_auditlog_block_mutation() RETURNS trigger AS $fn$
    BEGIN
        RAISE EXCEPTION USING
            MESSAGE = 'audit_auditlog is append-only: ' || TG_OP || ' blocked',
            ERRCODE = 'insufficient_privilege';
    END;
    $fn$ LANGUAGE plpgsql;
    """,
    """
    CREATE TRIGGER audit_auditlog_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_auditlog
        FOR EACH ROW EXECUTE FUNCTION audit_auditlog_block_mutation();
    """,
    """
    CREATE TRIGGER audit_auditlog_no_truncate
        BEFORE TRUNCATE ON audit_auditlog
        FOR EACH STATEMENT EXECUTE FUNCTION audit_auditlog_block_mutation();
    """,
    # --- Layer 3: RLS. SELECT + INSERT policies only, so UPDATE/DELETE match zero rows ---
    "ALTER TABLE audit_auditlog ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_auditlog FORCE ROW LEVEL SECURITY;",
    """
    CREATE POLICY audit_tenant_select ON audit_auditlog FOR SELECT
        USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    """,
    """
    CREATE POLICY audit_tenant_insert ON audit_auditlog FOR INSERT
        WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
    """,
]

REVERSE = [
    "DROP POLICY audit_tenant_insert ON audit_auditlog;",
    "DROP POLICY audit_tenant_select ON audit_auditlog;",
    "ALTER TABLE audit_auditlog NO FORCE ROW LEVEL SECURITY;",
    "ALTER TABLE audit_auditlog DISABLE ROW LEVEL SECURITY;",
    "DROP TRIGGER audit_auditlog_no_truncate ON audit_auditlog;",
    "DROP TRIGGER audit_auditlog_no_update_delete ON audit_auditlog;",
    "DROP FUNCTION audit_auditlog_block_mutation();",
]


class Migration(migrations.Migration):

    dependencies = [
        ('audit', '0001_initial'),
    ]

    operations = [
        migrations.RunSQL(sql=FORWARD, reverse_sql=REVERSE),
    ]
