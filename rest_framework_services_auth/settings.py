from __future__ import unicode_literals

import base64

from django.conf import settings as django_settings

from rest_framework.settings import APISettings

USER_SETTINGS = getattr(django_settings, 'SERVICES_AUTH', None)

DEFAULT_SETTINGS = {
    # key must be either in base64 encoding for symmetric or X509 for public-key
    'JWT_VERIFICATION_KEY': '',
    'JWT_ALGORITHM': '',
    'JWT_AUDIENCE': '',
    'JWT_ISSUER': '',
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
    'JWT_ALTERNATE_AUTH_HEADER': None,
    'SERVICE_USER_MODEL': 'rest_framework_services_auth.ServiceUser'
}

auth_settings = APISettings(
    USER_SETTINGS,
    DEFAULT_SETTINGS,
    {'None': None}  # put something non-empty so it's truthy
)

if auth_settings.JWT_ALGORITHM.startswith("HS"):
    # try to decode verification from Base64 if possible
    auth_settings.JWT_VERIFICATION_KEY = \
        base64.b64decode(auth_settings.JWT_VERIFICATION_KEY)

if auth_settings.JWT_ALTERNATE_AUTH_HEADER:
    auth_settings.JWT_ALTERNATE_AUTH_HEADER_KEY = 'HTTP_' + \
        auth_settings.JWT_ALTERNATE_AUTH_HEADER.upper().replace('-', '_')
else:
    auth_settings.JWT_ALTERNATE_AUTH_HEADER_KEY = None
