from __future__ import unicode_literals

from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import UUIDField

AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


# Create your models here.
class ServiceUserMixin(models.Model):
    """
    Additional info for the user that allows them to be dynamically created
    when new previously-unknown users are authenticated using JWTs.
    """

    id = UUIDField(default=uuid4, primary_key=True)
    user = models.OneToOneField(AUTH_USER_MODEL,
                                on_delete=models.CASCADE,
                                related_name="service_user")

    class Meta:
        abstract = True


class ServiceUser(ServiceUserMixin):

    def __str__(self):
        return str(self.id) + " (%s)" % self.user

    class Meta:
        app_label = 'rest_framework_services_auth'
