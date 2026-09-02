#from django.shortcuts import render

from django.http import JsonResponse
from .models import Document


def list_documents(request):
    docs = Document.objects.all().values('id', 'title', 'tenant_id')
    return JsonResponse(list(docs), safe=False)
