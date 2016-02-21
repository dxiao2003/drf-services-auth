from __future__ import unicode_literals

from django.conf import settings
from rest_framework import exceptions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.settings import api_settings
from rest_framework_services_auth.models import DynamicUser
from .utils import jwt_payload_get_dynamic_user_id_handler,\
    jwt_dynamic_user_payload_handler
from django.utils.translation import ugettext as _
from django.db import transaction

# load the handler that handles dynamic user ID
api_settings.JWT_PAYLOAD_GET_DYNAMIC_USER_ID_HANDLER = \
    getattr(settings, 'JWT_AUTH', {}).get(
        'JWT_PAYLOAD_GET_DYNAMIC_USER_ID_HANDLER',
        jwt_payload_get_dynamic_user_id_handler)

jwt_get_dynamic_user_id_from_payload = \
    api_settings.JWT_PAYLOAD_GET_DYNAMIC_USER_ID_HANDLER

# unless a custom payload handler is specified, user the dynamic user ID
# payload handler instead of the default payload handler
if not hasattr(settings, 'JWT_AUTH') or \
        'JWT_PAYLOAD_HANDLER' not in settings.JWT_AUTH:
    api_settings.JWT_PAYLOAD_HANDLER = jwt_dynamic_user_payload_handler


class DynamicJSONWebTokenAuthentication(JSONWebTokenAuthentication):

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        User = get_user_model()
        dynamic_user_id = jwt_get_dynamic_user_id_from_payload(payload)

        if not dynamic_user_id:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user = User.objects.get(dynamic_user__pk=dynamic_user_id)
        except User.DoesNotExist:
            with transaction.atomic():
                user = User.objects.create_user(username=dynamic_user_id)
                DynamicUser.objects.create(id=dynamic_user_id, user=user)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)

        return user
