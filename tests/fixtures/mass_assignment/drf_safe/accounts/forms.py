# Test fixture (#242): safe binders.
from django import forms
from django.contrib.auth.forms import UserChangeForm as DjangoUserChangeForm
from django.contrib.auth.models import User


class StaffUserChangeForm(DjangoUserChangeForm):
    class Meta:
        model = User
        fields = "__all__"
