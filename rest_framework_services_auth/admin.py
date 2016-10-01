from __future__ import absolute_import, unicode_literals

from django.contrib import admin

from rest_framework_services_auth.models import ServiceUser


@admin.register(ServiceUser)
class ServiceUserAdmin(admin.ModelAdmin):
    list_display = ("id", "user")
    fields = ("id", "user")
    readonly_fields = ("id",)
    search_fields = ("=id", "user__username", "user__first_name",
                     "user__last_name", "user__email")
    list_filter = ("user__is_staff", "user__is_active", "user__is_superuser")