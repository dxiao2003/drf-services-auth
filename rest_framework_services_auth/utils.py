from __future__ import unicode_literals

from rest_framework_jwt.utils import jwt_payload_handler

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


def jwt_payload_get_dynamic_user_id_handler(payload):
    return payload.get('dynamic_user_id', None)


def jwt_dynamic_user_payload_handler(user):
    payload = jwt_payload_handler(user)
    payload['dynamic_user_id'] = str(user.dynamic_user.id)
    return payload
