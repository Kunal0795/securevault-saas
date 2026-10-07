import base64
import json
import time

import jwt
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import CustomUser
from tenants.models import Tenant

from .base import AdversarialTestCase

KEY = api_settings.SIGNING_KEY


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


class JWTTamperingTests(AdversarialTestCase):
    """Every forged, altered or misused token must be refused before it reaches data.

    test_positive_control proves the forging helpers can produce an ACCEPTED token,
    so the rejections below are real and not an artifact of a broken helper.
    """

    def setUp(self):
        super().setUp()
        self.url = reverse('document-list')

    # -- helpers -----------------------------------------------------------
    def valid_access(self, username='admin_a'):
        return str(RefreshToken.for_user(self.users[username]).access_token)

    def claims(self, username='admin_a'):
        return jwt.decode(self.valid_access(username), options={'verify_signature': False})

    def sign(self, claims, key=KEY, alg='HS256'):
        return jwt.encode(claims, key, algorithm=alg)

    def get_with(self, token, scheme='Bearer'):
        return APIClient().get(self.url, HTTP_AUTHORIZATION=f'{scheme} {token}')

    def assertRejected(self, response, status=401):
        self.assertEqual(response.status_code, status, response.content[:200])
        self.assertNotIn(b'secret body', response.content)

    # -- control -----------------------------------------------------------
    def test_positive_control_forge_helper_makes_acceptable_tokens(self):
        self.assertEqual(self.get_with(self.sign(self.claims())).status_code, 200)

    # -- signature attacks -------------------------------------------------
    def test_alg_none_token_is_rejected(self):
        payload = b64(json.dumps(self.claims()).encode())
        for alg in ('none', 'None', 'NONE', 'nOnE'):
            header = b64(json.dumps({'alg': alg, 'typ': 'JWT'}).encode())
            for token in (f'{header}.{payload}.', f'{header}.{payload}'):
                with self.subTest(alg=alg, token_tail=token[-6:]):
                    self.assertRejected(self.get_with(token))

    def test_token_signed_with_attacker_key_is_rejected(self):
        forged = self.sign(self.claims(), key='attacker-controlled-key-0123456789abcdef')
        self.assertRejected(self.get_with(forged))

    def test_algorithm_is_pinned_even_when_signed_with_the_real_key(self):
        for alg in ('HS384', 'HS512'):
            with self.subTest(alg=alg):
                self.assertRejected(self.get_with(self.sign(self.claims(), alg=alg)))

    def test_payload_tampering_invalidates_the_signature(self):
        head, body, sig = self.valid_access('member_a').split('.')
        for target in ('admin_a', 'admin_b'):  # privilege escalation, then cross-tenant
            with self.subTest(target=target):
                claims = json.loads(unb64(body))
                claims['user_id'] = str(self.users[target].id)
                forged = '.'.join([head, b64(json.dumps(claims).encode()), sig])
                self.assertRejected(self.get_with(forged))

    # -- claim attacks (validly signed, so only the claims are wrong) -------
    def test_expired_token_is_rejected(self):
        claims = self.claims()
        claims['exp'] = int(time.time()) - 60
        self.assertRejected(self.get_with(self.sign(claims)))

    def test_validly_signed_token_missing_a_required_claim_is_rejected(self):
        for missing in ('exp', 'jti', 'token_type', 'user_id'):
            with self.subTest(missing=missing):
                claims = self.claims()
                claims.pop(missing)
                self.assertRejected(self.get_with(self.sign(claims)))

    def test_injected_tenant_claim_does_not_change_the_tenant(self):
        claims = self.claims('admin_a')
        claims['tenant_id'] = claims['tenant'] = str(self.tenants['b'].id)
        response = self.get_with(self.sign(claims))
        self.assertEqual(response.status_code, 200)
        items = response.data['results'] if isinstance(response.data, dict) else response.data
        returned = {str(i['id']) for i in items}
        tenant_a = {str(d.id) for k, d in self.docs.items() if k.endswith('_a')}
        self.assertTrue(returned, "saw nothing, so the check would be vacuous")
        self.assertTrue(returned <= tenant_a, "a forged tenant claim changed which rows were visible")

    # -- token-type confusion ----------------------------------------------
    def test_refresh_token_cannot_be_used_as_access_token(self):
        refresh = str(RefreshToken.for_user(self.users['admin_a']))
        self.assertRejected(self.get_with(refresh))

    def test_access_token_cannot_be_used_at_the_refresh_endpoint(self):
        response = APIClient().post(
            reverse('token_refresh'), {'refresh': self.valid_access()}, format='json')
        self.assertEqual(response.status_code, 401)
        self.assertNotIn('access', response.data)

    # -- rotation / replay -------------------------------------------------
    def test_rotated_refresh_token_cannot_be_replayed(self):
        first = self.login('admin_a').data['refresh']
        refresh_url = reverse('token_refresh')
        client = APIClient()
        rotated = client.post(refresh_url, {'refresh': first}, format='json')
        self.assertEqual(rotated.status_code, 200)
        self.assertNotEqual(rotated.data['refresh'], first)
        replay = client.post(refresh_url, {'refresh': first}, format='json')
        self.assertEqual(replay.status_code, 401)
        self.assertNotIn('access', replay.data)

    # -- account / tenant state --------------------------------------------
    def test_deactivated_user_loses_access_immediately(self):
        client = self.client_for('member_a')
        self.assertEqual(client.get(self.url).status_code, 200)  # control: token was good
        CustomUser.objects.filter(username='member_a').update(is_active=False)
        self.assertRejected(client.get(self.url))

    def test_suspended_tenant_is_refused(self):
        client = self.client_for('admin_a')
        Tenant.objects.filter(pk=self.tenants['a'].pk).update(is_active=False)
        self.assertRejected(client.get(self.url), status=403)

    # -- header handling ---------------------------------------------------
    def test_malformed_authorization_headers_are_rejected(self):
        good = self.valid_access()
        cases = {
            'wrong scheme': f'Token {good}',
            'no scheme': good,
            'empty bearer': 'Bearer ',
            'extra part': f'Bearer {good} extra',
            'garbage': 'Bearer not.a.jwt',
            'two segments': f'Bearer {good.rsplit(".", 1)[0]}',
            'lowercase scheme': f'bearer {good}',
        }
        for name, value in cases.items():
            with self.subTest(case=name):
                self.assertRejected(APIClient().get(self.url, HTTP_AUTHORIZATION=value))
