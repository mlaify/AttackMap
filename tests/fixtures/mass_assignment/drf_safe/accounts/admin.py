# Test fixture (#242): safe binders.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import StaffUserChangeForm


class StaffUserAdmin(UserAdmin):
    form = StaffUserChangeForm
