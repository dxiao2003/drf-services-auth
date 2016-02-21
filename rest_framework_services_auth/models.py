from __future__ import unicode_literals

from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import UUIDField

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


# Create your models here.
class DynamicUserMixin(models.Model):
    """
    Additional info for the user that allows them to be dynamically created
    when new previously-unknown users are authenticated using JWTs.
    """

    id = UUIDField(default=uuid4, primary_key=True)
    user = models.OneToOneField(AUTH_USER_MODEL, related_name="dynamic_user")

    class Meta:
        abstract = True


class DynamicUser(DynamicUserMixin):
    pass
