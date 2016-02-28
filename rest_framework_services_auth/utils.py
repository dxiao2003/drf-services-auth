from __future__ import unicode_literals

from datetime import datetime, timedelta

import jwt
from django.conf import settings

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

DEFAULT_EXPIRATION_DELAY = timedelta(15 * 60 * 1000) # 15 minutes

def jwt_encode_user(user, target, *args, **kwargs):
    return jwt_encode_uid(user.dynamic_user.id, target, *args, **kwargs)

def jwt_encode_uid(uid, target, *args, **kwargs):
    if 'SECRET_KEY' not in target:
        raise ValueError("Must specify target's secret key")
    if 'ALGORITHM' not in target:
        raise ValueError("Must specify target's algorithm")
    if not hasattr(settings, 'JWT_ISSUER'):
        raise ValueError("Must specify issuer name")
    if 'AUDIENCE' not in target:
        raise ValueError("Must specify target's audience")

    expiration_delay = target.get('EXPIRATION_DELAY', DEFAULT_EXPIRATION_DELAY)

    payload = {
        'uid': str(uid),
        'exp': datetime.utcnow() + expiration_delay,
        'iss': settings.JWT_ISSUER,
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
        'verify_aud': True
    }

    return jwt.decode(
        token,
        settings.JWT_VERIFICATION_KEY,
        options=options,
        leeway=getattr(settings, 'JWT_LEEWAY', DEFAULT_LEEWAY),
        audience=settings.JWT_AUDIENCE,
        issuer=settings.JWT_ISSUER,
        algorithms=[settings.JWT_ALGORITHM]
    )