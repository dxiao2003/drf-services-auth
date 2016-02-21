from __future__ import unicode_literals

from functools import wraps

from django.conf.urls import patterns, url, include
from django.contrib.auth.models import User
from django.test import TestCase

# Create your tests here.
from mock import patch, MagicMock
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse
from rest_framework_services_auth.serializers import SocialTokenSerializer
from social.apps.django_app.views import NAMESPACE

DEFAULT_BACKEND = 'backend'
DEFAULT_CODE = 'code'
DEFAULT_USERNAME = "test user"
DEFAULT_EMAIL = "test@test.com"


def patch_backend(f=None, **kwargs):
    test_backend = kwargs.get('backend', DEFAULT_BACKEND)
    test_code = kwargs.get('code', DEFAULT_CODE)
    test_username = kwargs.get('username', DEFAULT_USERNAME)
    test_email = kwargs.get('email', DEFAULT_EMAIL)

    if kwargs.get('user', None):
        test_user = kwargs['user']
    else:
        test_user = \
            User.objects.create(username=test_username, email=test_email)

    def decorator(func):
        @patch('rest_framework_services_auth.serializers.load_strategy')
        @patch('rest_framework_services_auth.serializers.load_backend')
        @wraps(func)
        def decorated(*args, **kwargs):
            arg_array = list(args)
            load_strategy_mock = arg_array.pop()
            load_backend_mock = arg_array.pop()
            load_strategy_mock.return_value = "test strategy"
            backend_mock = MagicMock()
            load_backend_mock.return_value = backend_mock
            backend_mock.auth_complete.return_value = test_user
            r = func(*arg_array, **kwargs)
            load_backend_mock.assert_called_with(
                "test strategy",
                test_backend,
                reverse(NAMESPACE + ":complete", args=(test_backend,))
            )
            request = load_strategy_mock.call_args[1]['request']
            assert request.data['code'] == test_code
            return r
        return decorated

    if f is None:
        return decorator
    elif callable(f):
        return decorator(f)


urlpatterns = patterns(
    '',
    url(r'^social-auth/',
        include('social.apps.django_app.urls', namespace=NAMESPACE))
)


class SocialTokenSerializerTestCase(TestCase):

    urls = 'tests.test_serializers'

    def test_login(self):
        mock_request = MagicMock()
        my_code = 'my test code'
        my_backend = 'my test backend'
        my_username = 'my test user'

        mock_request.configure_mock(data={'code': my_code})
        serializer = SocialTokenSerializer(
            data={
                'backend': my_backend,
                'code': my_code
            },
            context={
                'request': mock_request
            }
        )

        @patch_backend(backend=my_backend, code=my_code, username=my_username)
        def is_valid_call():
            return serializer.is_valid()

        is_valid = is_valid_call()

        token = serializer.validated_data['token']

        self.assertTrue(is_valid)
        self.assertEqual(Token.objects.get(key=token).user.username, my_username)

    def test_required_fields(self):
        serializer = SocialTokenSerializer(data={})

        @patch_backend
        def is_valid_call():
            return serializer.is_valid(raise_exception=True)

        self.assertRaises(ValidationError, is_valid_call)

        expected_error = {
            'backend': ['This field is required.'],
            'code': ['This field is required.']
        }

        self.assertEqual(serializer.errors, expected_error)
