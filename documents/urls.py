from django.urls import path
from . import views

urlpatterns = [
    path('documents/', views.list_documents, name='list_documents'),
]