from __future__ import unicode_literals

from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse
from rest_framework.serializers import Serializer
from social.apps.django_app.utils import load_backend, load_strategy
from social.apps.django_app.views import NAMESPACE
from social.exceptions import MissingBackend
from social.utils import requests
from django.utils.translation import ugettext as _


class SocialTokenSerializer(Serializer):
    """
    Serializer class used to validate a social authorization code.  Uses
    `python-social-auth` to verify the social login.  Posted data should
    include a `backend` and a `code` to send to the authorization service
    in order to get an access token and load the user.
    """

    backend = serializers.CharField(max_length=256)
    code = serializers.CharField(max_length=1024)

    def validate(self, data):
        request = self.context['request']
        backend = data['backend']
        strategy = load_strategy(request=request)

        try:
            backend = load_backend(
                strategy,
                backend,
                reverse(NAMESPACE + ":complete", args=(backend,))
            )
        except MissingBackend:
            msg = 'Invalid token header. Invalid backend.'
            raise ValidationError(msg)

        try:
            user = backend.auth_complete()
        except requests.HTTPError as e:
            msg = e.response.text
            raise ValidationError(msg)

        if not user:
            msg = 'Bad credentials.'
            raise ValidationError(msg)
        else:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise ValidationError(msg)

            # make token
            token = Token.objects.create(user=user)
            return {
                'user': user,
                'token': token.key
            }
