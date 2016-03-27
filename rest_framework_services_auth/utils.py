from __future__ import unicode_literals

from django.apps import apps as django_apps

from datetime import datetime, timedelta

import jwt
from django.core.exceptions import ImproperlyConfigured
from jwt.exceptions import InvalidTokenError
from rest_framework_services_auth.settings import auth_settings

'''
Dealing with no UUID serialization support in json
'''
from json import JSONEncoder
from uuid import UUID
JSONEncoder_olddefault = JSONEncoder.default


def JSONEncoder_newdefault(self, o):
    if isinstance(o, UUID):
        return str(o)
    return JSONEncoder_olddefault(self, o)


JSONEncoder.default = JSONEncoder_newdefault


DEFAULT_EXPIRATION_DELAY = timedelta(seconds=15 * 60)  # 15 minutes


def jwt_encode_user(user, target, *args, **kwargs):
    return jwt_encode_uid(user.service_user.id, target, *args, **kwargs)


def jwt_encode_uid(uid, target, *args, **kwargs):
    if 'SECRET_KEY' not in target:
        raise ValueError("Must specify target's secret key")
    if 'ALGORITHM' not in target:
        raise ValueError("Must specify target's algorithm")
    if 'AUDIENCE' not in target:
        raise ValueError("Must specify target's audience")
    if not auth_settings.JWT_ISSUER:
        raise ValueError("Must specify issuer name")

    expiration_delay = target.get('EXPIRATION_DELAY', DEFAULT_EXPIRATION_DELAY)

    payload = {
        'uid': str(uid),
        'exp': datetime.utcnow() + expiration_delay,
        'nbf': datetime.utcnow(),
        'iat': datetime.utcnow(),
        'iss': auth_settings.JWT_ISSUER,
        'aud': target['AUDIENCE']
    }

    payload.update(kwargs.get('override', {}))

    return jwt.encode(
        payload,
        target['SECRET_KEY'],
        target['ALGORITHM']
    )


DEFAULT_LEEWAY = 5000


def jwt_decode_token(token):
    options = {
        'verify_exp': True,
        'verify_iss': True,
        'verify_aud': True,
        'verify_nbf': True,
        'verify_iat': True
    }

    if not auth_settings.JWT_VERIFICATION_KEY:
        raise ValueError("Must specify verification key")

    payload = jwt.decode(
        token,
        auth_settings.JWT_VERIFICATION_KEY,
        options=options,
        leeway=getattr(auth_settings, 'JWT_LEEWAY', DEFAULT_LEEWAY),
        audience=auth_settings.JWT_AUDIENCE,
        issuer=auth_settings.JWT_ISSUER,
        algorithms=[auth_settings.JWT_ALGORITHM]
    )

    if (hasattr(auth_settings, 'JWT_MAX_VALID_INTERVAL')):

        exp = int(payload['exp'])
        nbf = int(payload['nbf'])

        if (exp - nbf > int(auth_settings.JWT_MAX_VALID_INTERVAL)):
            raise ValidIntervalError(exp,
                                     nbf,
                                     auth_settings.JWT_MAX_VALID_INTERVAL)
    return payload


class ValidIntervalError(InvalidTokenError):
    def __init__(self, exp, nbf, max_valid_interval, *args, **kwargs):
        self.exp = exp
        self.nbf = nbf
        self.max_valid_interval = max_valid_interval

    def __str__(self):
        return "Valid interval of token too long: " +  \
               "(Starts at %s and ending at %s) " % (
                   datetime.utcfromtimestamp(self.nbf),
                   datetime.utcfromtimestamp(self.exp),
               ) + "Max interval length is %s" % (
                   timedelta(seconds=self.max_valid_interval)
               )


def get_service_user_model():
    """
    Returns the User model that is active in this project.
    """
    try:
        return django_apps.get_model(auth_settings.SERVICE_USER_MODEL)
    except ValueError:
        raise ImproperlyConfigured("SERVICE_USER_MODEL must be of the form 'app_label.model_name'")
    except LookupError:
        raise ImproperlyConfigured(
            "SERVICE_USER_MODEL refers to model '%s' that has not been installed" % auth_settings.SERVICE_USER_MODEL
        )
