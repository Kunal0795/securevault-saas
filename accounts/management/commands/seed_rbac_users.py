import os

from django.core.management.base import BaseCommand, CommandError
from accounts.models import CustomUser
from tenants.models import Tenant


class Command(BaseCommand):
    help = "Seed non-superuser test users with roles across tenants A and B"

    def handle(self, *args, **options):
        password = os.environ.get("SV_TEST_PASSWORD")
        if not password:
            raise CommandError(
                "SV_TEST_PASSWORD is not set: export a local-only test password first."
            )

        tenant_a = Tenant.objects.get(id="5afd53de-3ba4-4506-ba69-d71b43cbc38e")
        tenant_b = Tenant.objects.get(id="3ca0886e-105b-48c7-8f3f-9a41336bfd4b")

        users_to_create = [
            ("admin_a", tenant_a, CustomUser.RoleChoices.ADMIN),
            ("member_a", tenant_a, CustomUser.RoleChoices.MEMBER),
            ("viewer_a", tenant_a, CustomUser.RoleChoices.VIEWER),
            ("admin_b", tenant_b, CustomUser.RoleChoices.ADMIN),
            ("member_b", tenant_b, CustomUser.RoleChoices.MEMBER),
            ("viewer_b", tenant_b, CustomUser.RoleChoices.VIEWER),
        ]

        for username, tenant, role in users_to_create:
            user, created = CustomUser.objects.get_or_create(
                username=username,
                defaults={"tenant": tenant, "role": role},
            )
            if created:
                user.set_password(password)
                user.save()
                self.stdout.write(self.style.SUCCESS(f"Created {username} ({role}, {tenant.name})"))
            else:
                self.stdout.write(self.style.WARNING(f"Skipped {username} — already exists"))