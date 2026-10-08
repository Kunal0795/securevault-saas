import base64
import json

from django.urls import reverse
from rest_framework.test import APIClient

from .base import AdversarialTestCase


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


class JWTParserRobustnessTests(AdversarialTestCase):
    """Hostile token structure must produce a clean 401, never an unhandled exception (a 500)."""

    DEPTH = 100_000

    def hostile_tokens(self):
        payload = b64(json.dumps({'user_id': str(self.users['admin_a'].id)}).encode())
        signature = b64(b'x' * 32)
        return {
            'deeply nested header': f"{b64(b'[' * self.DEPTH + b']' * self.DEPTH)}.{payload}.{signature}",
            'header is not json': f"{b64(b'\xff\xfe not json')}.{payload}.{signature}",
            'oversized header segment': f"{'A' * 1_000_000}.{payload}.{signature}",
            'empty segments': '..',
        }

    def test_hostile_tokens_get_a_clean_401_on_the_api(self):
        url = reverse('document-list')
        for name, token in self.hostile_tokens().items():
            with self.subTest(token=name):
                response = APIClient().get(url, HTTP_AUTHORIZATION=f'Bearer {token}')
                self.assertEqual(response.status_code, 401)

    def test_hostile_tokens_get_a_clean_401_at_the_refresh_endpoint(self):
        for name, token in self.hostile_tokens().items():
            with self.subTest(token=name):
                response = APIClient().post(reverse('token_refresh'), {'refresh': token}, format='json')
                self.assertEqual(response.status_code, 401)
