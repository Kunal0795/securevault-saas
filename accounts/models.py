# accounts/models.py
import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        'tenants.Tenant',
        on_delete=models.CASCADE,
        related_name='users',
        null=True,   # temporarily nullable — see note below
        blank=True,
    )

    def __str__(self):
        return f"{self.username} ({self.tenant.name if self.tenant else 'no tenant'})"