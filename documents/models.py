import uuid
from django.db import models
from tenants.models import Tenant


class Document(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    content = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class SensitivityChoices(models.TextChoices):
        PUBLIC = 'PUBLIC', 'Public'
        INTERNAL = 'INTERNAL', 'Internal'
        CONFIDENTIAL = 'CONFIDENTIAL', 'Confidential'

    created_by = models.ForeignKey(
        'accounts.CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='documents',
    )

    sensitivity = models.CharField(
        max_length=15,
        choices=SensitivityChoices.choices,
        default=SensitivityChoices.INTERNAL,
    )

    def __str__(self):
        return self.title