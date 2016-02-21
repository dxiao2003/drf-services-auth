from uuid import uuid4

from django.conf.urls import patterns
from django.http import HttpResponse

from rest_framework import permissions, status
from rest_framework.test import APIRequestFactory, APIClient, APITestCase
from rest_framework.views import APIView
from rest_framework_jwt import utils
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings, DEFAULTS
from rest_framework_services_auth.authentication import \
    DynamicJSONWebTokenAuthentication
from rest_framework_services_auth.models import DynamicUser
from rest_framework_services_auth.utils import jwt_dynamic_user_payload_handler

User = get_user_model()

factory = APIRequestFactory()


class MockView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})

    def post(self, request):
        return HttpResponse({'a': 1, 'b': 2, 'c': 3})


urlpatterns = patterns(
    '',
    (r'^jwt/$', MockView.as_view(
     authentication_classes=[DynamicJSONWebTokenAuthentication])),
)


class DynamicJSONWebTokenAuthenticationTests(APITestCase):
    """JSON Web Token Authentication"""
    urls = 'tests.test_authentication'

    def setUp(self):
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.username = 'jpueblo'
        self.email = 'jpueblo@example.com'
        self.user = User.objects.create_user(self.username, self.email)
        DynamicUser.objects.create(user=self.user)

    def test_post_form_passing_jwt_auth(self):
        """
        Ensure POSTing form over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = jwt_dynamic_user_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(dynamic_user__id=payload['dynamic_user_id'])
        self.assertEqual(str(user.dynamic_user.id), payload['dynamic_user_id'])
        self.assertEqual(user.username, self.user.username)

    def test_post_json_passing_jwt_auth(self):
        """
        Ensure POSTing JSON over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = jwt_dynamic_user_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(dynamic_user__id=payload['dynamic_user_id'])
        self.assertEqual(str(user.dynamic_user.id), payload['dynamic_user_id'])
        self.assertEqual(user.username, self.user.username)

    def test_post_form_passing_jwt_auth_new_user(self):
        """
        Ensure POSTing form over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = jwt_dynamic_user_payload_handler(self.user)
        payload['dynamic_user_id'] = str(uuid4())
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(dynamic_user__id=payload['dynamic_user_id'])
        self.assertEqual(str(user.dynamic_user.id), payload['dynamic_user_id'])
        self.assertEqual(user.username, str(payload['dynamic_user_id']))

    def test_post_json_passing_jwt_auth_new_user(self):
        """
        Ensure POSTing JSON over JWT auth with correct credentials
        passes and does not require CSRF
        """
        payload = jwt_dynamic_user_payload_handler(self.user)
        payload['dynamic_user_id'] = str(uuid4())
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(dynamic_user__id=payload['dynamic_user_id'])
        self.assertEqual(str(user.dynamic_user.id), payload['dynamic_user_id'])
        self.assertEqual(user.username, str(payload['dynamic_user_id']))

    def test_post_form_failing_jwt_auth(self):
        """
        Ensure POSTing form over JWT auth without correct credentials fails
        """
        response = self.csrf_client.post('/jwt/', {'example': 'example'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_json_failing_jwt_auth(self):
        """
        Ensure POSTing json over JWT auth without correct credentials fails
        """
        response = self.csrf_client.post('/jwt/', {'example': 'example'},
                                         format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_no_jwt_header_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth without credentials fails
        """
        auth = 'JWT'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Invalid Authorization header. No credentials provided.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_invalid_jwt_header_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth without correct credentials fails
        """
        auth = 'JWT abc abc'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = ('Invalid Authorization header. Credentials string '
               'should not contain spaces.')

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_expired_token_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth with expired token fails
        """
        payload = jwt_dynamic_user_payload_handler(self.user)
        payload['exp'] = 1
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Signature has expired.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_invalid_token_failing_jwt_auth(self):
        """
        Ensure POSTing over JWT auth with invalid token fails
        """
        auth = 'JWT abc123'
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        msg = 'Error decoding signature.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'JWT realm="api"')

    def test_post_form_passing_jwt_invalid_payload(self):
        """
        Ensure POSTing json over JWT auth with invalid payload fails
        """
        payload = dict(email=None)
        token = utils.jwt_encode_handler(payload)

        auth = 'JWT {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'}, HTTP_AUTHORIZATION=auth)

        msg = 'Invalid payload.'

        self.assertEqual(response.data['detail'], msg)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_different_auth_header_prefix(self):
        """
        Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
        with correct credentials passes.
        """
        api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'

        payload = jwt_dynamic_user_payload_handler(self.user)
        token = utils.jwt_encode_handler(payload)

        auth = 'Bearer {0}'.format(token)
        response = self.csrf_client.post(
            '/jwt/', {'example': 'example'},
            HTTP_AUTHORIZATION=auth, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Restore original settings
        api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']

    def test_post_form_failing_jwt_auth_different_auth_header_prefix(self):
        """
        Ensure using a different setting for `JWT_AUTH_HEADER_PREFIX` and
        POSTing form over JWT auth without correct credentials fails and
        generated correct WWW-Authenticate header
        """
        api_settings.JWT_AUTH_HEADER_PREFIX = 'Bearer'

        response = self.csrf_client.post('/jwt/', {'example': 'example'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response['WWW-Authenticate'], 'Bearer realm="api"')

        # Restore original settings
        api_settings.JWT_AUTH_HEADER_PREFIX = DEFAULTS['JWT_AUTH_HEADER_PREFIX']
