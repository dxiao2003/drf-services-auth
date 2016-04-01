from __future__ import unicode_literals

import base64

from django.conf import settings as django_settings

from rest_framework.settings import APISettings

USER_SETTINGS = getattr(django_settings, 'AUTH_SERVER', None)

DEFAULT_SETTINGS = {
    'JWT_VERIFICATION_KEY': '',
    'JWT_ALGORITHM': '',
    'JWT_AUDIENCE': '',
    'JWT_ISSUER': '',
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'SERVICE_USER_MODEL': 'rest_framework_services_auth.ServiceUser'
}

auth_settings = APISettings(
    USER_SETTINGS,
    DEFAULT_SETTINGS,
    {'None': None}  # put something non-empty so it's truthy
)

# try to decode verification from Base64 if possible
try:
    auth_settings.JWT_VERIFICATION_KEY = \
        base64.b64decode(auth_settings.JWT_VERIFICATION_KEY)
except:
    pass
