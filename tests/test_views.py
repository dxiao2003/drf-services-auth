from __future__ import unicode_literals

from rest_framework_jwt.compat import get_user_model

from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase
from tests.test_serializers import patch_backend, DEFAULT_BACKEND, \
    DEFAULT_CODE


from django.conf.urls import patterns, include
from rest_framework_services_auth.views import SocialTokenAPIView
from social.apps.django_app.views import NAMESPACE

urlpatterns = patterns(
    '',
    (r'^auth-token-social/$', SocialTokenAPIView.as_view()),
    (r'^social/', include('social.apps.django_app.urls', namespace=NAMESPACE))
)

User = get_user_model()


class BaseTestCase(APITestCase):
    urls = 'tests.test_views'

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)

        self.data = {
            'username': self.username,
            'password': self.password
        }


class SocialTokenTestCase(BaseTestCase):

    def test_jwt_login_social(self):
        """
        Ensure JWT login view when posting test social credentials
        """
        client = APIClient(enforce_csrf_checks=True)

        @patch_backend(user=self.user)
        def do_login():
            return client.post('/auth-token-social/',
                               {'backend': DEFAULT_BACKEND,
                                'code': DEFAULT_CODE},
                               format='json')

        response = do_login()

        token = response.data['token']
        t = Token.objects.get(key=token)
        self.assertEqual(self.user, t.user)
