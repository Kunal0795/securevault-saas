from rest_framework import serializers
from .models import Document


class DocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ['id', 'title', 'content', 'tenant', 'created_by', 'created_at', 'sensitivity']
        read_only_fields = ['id', 'tenant', 'created_by', 'created_at']